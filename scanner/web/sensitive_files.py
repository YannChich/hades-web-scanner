"""
sensitive_files — probes well-known paths that expose credentials, config, or debug info.

A 200 status alone is never enough: each 200 is validated by **body length + content-type +
file-specific indicators** and compared against a soft-200/catch-all baseline before it is graded.
Genuine, content-confirmed exposures are reported (CRITICAL/HIGH by file type); a body that merely
looks plausible drops to medium confidence; an empty/near-empty body or a 200 whose content does not
match the file's expected signature degrades to a calm LOW "needs manual validation" finding rather
than a false-positive CRITICAL (e.g. an empty /.htaccess). A 403 means the path is access-controlled;
to avoid noise on hardened servers, a "blanket 403" probe collapses uniform 403s into a single
informational finding instead of one Medium per path. Catch-all (SPA / soft-404) servers that 200
everything are detected and suppressed via a baseline fingerprint and content-type heuristics.
"""
from __future__ import annotations

import enum
import hashlib
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

import httpx
from loguru import logger

from scanner import evidence as ev
from scanner.engine import Finding, Severity, ScanEngine

MODULE = "sensitive_files"


@dataclass(frozen=True)
class _Target:
    path: str
    label: str          # human description of what this file contains


_TARGETS: list[_Target] = [
    # --- Environment & credentials -----------------------------------------
    _Target("/.env",                 "Environment variables (credentials, API keys)"),
    _Target("/.env.local",           "Local environment overrides"),
    _Target("/.env.dev",             "Development environment variables"),
    _Target("/.env.development",     "Development environment variables"),
    _Target("/.env.staging",         "Staging environment variables"),
    _Target("/.env.production",      "Production environment variables"),
    _Target("/.env.backup",          "Backup environment file"),
    _Target("/.env.save",            "Saved environment file"),
    # --- Cloud provider credentials ----------------------------------------
    _Target("/.aws/credentials",     "AWS access keys"),
    _Target("/.aws/config",          "AWS CLI configuration"),
    _Target("/.s3cfg",               "S3cmd credentials"),
    _Target("/credentials.json",     "Google / generic service credentials"),
    _Target("/service-account.json", "GCP service-account key"),
    _Target("/.azure/accessTokens.json", "Azure CLI access tokens"),
    _Target("/.netrc",               "Machine login credentials (.netrc)"),
    _Target("/.npmrc",               "npm registry auth token"),
    _Target("/.pypirc",              "PyPI upload credentials"),
    _Target("/.dockercfg",           "Docker registry credentials"),
    _Target("/.docker/config.json",  "Docker registry credentials"),
    # --- Private keys -------------------------------------------------------
    _Target("/.ssh/id_rsa",          "SSH private key (RSA)"),
    _Target("/.ssh/id_ed25519",      "SSH private key (Ed25519)"),
    _Target("/.ssh/authorized_keys", "SSH authorised keys"),
    _Target("/id_rsa",               "SSH private key in web root"),
    _Target("/private.key",          "Private TLS/key material"),
    _Target("/server.key",           "Server private key"),
    # --- PHP / framework config --------------------------------------------
    _Target("/config.php",           "PHP application configuration"),
    _Target("/wp-config.php",        "WordPress database credentials"),
    _Target("/wp-config.php.bak",    "WordPress config backup"),
    _Target("/configuration.php",    "Joomla configuration (DB credentials)"),
    _Target("/settings.php",         "Drupal database credentials"),
    _Target("/config/config.php",    "Framework configuration file"),
    _Target("/settings.py",          "Django settings (SECRET_KEY, DB credentials)"),
    _Target("/local_settings.py",    "Django local settings override"),
    _Target("/web.config",           "IIS / ASP.NET configuration"),
    _Target("/appsettings.json",     ".NET Core application settings"),
    _Target("/next.config.js",       "Next.js configuration"),
    # --- Structured config --------------------------------------------------
    _Target("/config.yml",           "YAML application configuration"),
    _Target("/config.yaml",          "YAML application configuration"),
    _Target("/config.json",          "JSON application configuration"),
    _Target("/secrets.json",         "Secrets file (JSON)"),
    _Target("/secrets.yml",          "Secrets file (YAML)"),
    _Target("/app/config/config.yml","Symfony-style configuration"),
    _Target("/database.yml",         "Rails database credentials"),
    _Target("/database.yaml",        "Rails database credentials"),
    # --- VCS repositories ---------------------------------------------------
    _Target("/.git/config",          "Git repository configuration (remote URLs)"),
    _Target("/.git/HEAD",            "Git HEAD reference (confirms exposed .git dir)"),
    _Target("/.git/COMMIT_EDITMSG",  "Last commit message"),
    _Target("/.git/index",           "Git index (file listing)"),
    _Target("/.gitignore",           "Git ignore rules (reveals hidden paths)"),
    _Target("/.svn/entries",         "Subversion metadata"),
    _Target("/.svn/wc.db",           "Subversion working-copy database"),
    _Target("/.hg/store/00manifest.i","Mercurial repository manifest"),
    # --- CI/CD & containers -------------------------------------------------
    _Target("/.gitlab-ci.yml",       "GitLab CI pipeline (may leak tokens)"),
    _Target("/.travis.yml",          "Travis CI configuration"),
    _Target("/Jenkinsfile",          "Jenkins pipeline definition"),
    _Target("/docker-compose.yml",   "Docker Compose (services, env, secrets)"),
    _Target("/docker-compose.yaml",  "Docker Compose (services, env, secrets)"),
    _Target("/Dockerfile",           "Container build recipe"),
    # --- Apache / server config --------------------------------------------
    _Target("/.htpasswd",            "Apache password file (hashed credentials)"),
    _Target("/.htaccess",            "Apache rewrite rules and access controls"),
    # --- Diagnostics --------------------------------------------------------
    _Target("/phpinfo.php",          "PHP configuration dump (version, paths, env vars)"),
    _Target("/info.php",             "PHP info page"),
    _Target("/server-status",        "Apache server status (active connections, URLs)"),
    _Target("/server-info",          "Apache server information (modules, config)"),
    # --- Database dumps -----------------------------------------------------
    _Target("/backup.sql",           "SQL database dump"),
    _Target("/dump.sql",             "SQL database dump"),
    _Target("/database.sql",         "SQL database dump"),
    _Target("/db.sqlite3",           "SQLite database (Django default)"),
    _Target("/database.sqlite",      "SQLite database"),
    # --- Backups & archives -------------------------------------------------
    _Target("/backup.zip",           "Site backup archive"),
    _Target("/backup.tar.gz",        "Site backup archive"),
    _Target("/www.zip",              "Web-root backup archive"),
    _Target("/site.zip",             "Site backup archive"),
    _Target("/public_html.zip",      "Web-root backup archive"),
    # --- Shell history & logs ----------------------------------------------
    _Target("/.bash_history",        "Shell command history"),
    _Target("/.mysql_history",       "MySQL client history (may contain credentials)"),
    _Target("/error.log",            "Application error log"),
    _Target("/access.log",           "Web server access log"),
    _Target("/debug.log",            "Debug log (may contain stack traces, credentials)"),
    _Target("/storage/logs/laravel.log", "Laravel application log"),
    # --- Package manifests (low value, info only) --------------------------
    _Target("/composer.json",        "PHP dependencies manifest"),
    _Target("/package.json",         "Node.js dependencies manifest"),
    _Target("/.DS_Store",            "macOS directory metadata (reveals file listing)"),
]

# For a genuine 200, paths listed here MUST contain at least one of the given substrings
# (case-insensitive, any-match). These are the file-specific indicators that distinguish a real
# exposure from a soft-200 / placeholder / wrong-content response. A path with a signature whose
# content matches none of them is treated as ambiguous (NEEDS_MANUAL_VALIDATION), not confirmed.
_CONTENT_PATTERNS: dict[str, tuple[str, ...]] = {
    # --- Apache access control / rewrite config --------------------------------
    "/.htaccess":             ("rewriteengine", "rewriterule", "rewritecond", "options ",
                               "authtype", "authuserfile", "require ", "deny from",
                               "header set", "redirect", "order ", "<files", "addtype",
                               "errordocument"),
    # --- Environment & credentials ---------------------------------------------
    "/.env":                  ("=", "db_", "app_key", "secret", "token", "password", "api_key"),
    "/.env.local":            ("=", "db_", "app_key", "secret", "token", "password", "api_key"),
    "/.env.dev":              ("=", "db_", "app_key", "secret", "token", "password", "api_key"),
    "/.env.development":      ("=", "db_", "app_key", "secret", "token", "password", "api_key"),
    "/.env.staging":          ("=", "db_", "app_key", "secret", "token", "password", "api_key"),
    "/.env.production":       ("=", "db_", "app_key", "secret", "token", "password", "api_key"),
    "/.env.backup":           ("=", "db_", "app_key", "secret", "token", "password", "api_key"),
    "/.env.save":             ("=", "db_", "app_key", "secret", "token", "password", "api_key"),
    # --- VCS metadata ----------------------------------------------------------
    "/.git/HEAD":             ("ref: refs/heads/", "ref:"),
    "/.git/config":           ("[core]", "[remote", "repositoryformatversion"),
    # --- Cloud / package auth ---------------------------------------------------
    "/.aws/credentials":      ("aws_access_key_id",),
    "/.npmrc":                ("_authtoken",),
    "/.netrc":                ("machine",),
    "/.pypirc":               ("[pypi]",),
    # --- Framework config -------------------------------------------------------
    "/wp-config.php":         ("db_",),
    "/settings.py":           ("secret_key",),
    "/web.config":            ("<configuration", "<system.webserver", "<rewrite",
                               "<connectionstrings", "<appsettings"),
    "/appsettings.json":      ("connectionstrings",),
    # --- Diagnostics ------------------------------------------------------------
    "/phpinfo.php":           ("phpinfo",),
    "/info.php":              ("phpinfo",),
    "/server-status":         ("apache",),
    "/server-info":           ("apache",),
    # --- Private keys -----------------------------------------------------------
    "/.ssh/id_rsa":           ("begin",),
    "/.ssh/id_ed25519":       ("begin",),
    "/id_rsa":                ("begin",),
    "/private.key":           ("begin",),
    "/server.key":            ("begin",),
    # --- Database dumps ---------------------------------------------------------
    "/backup.sql":            ("insert", "create table", "-- mysql"),
    "/dump.sql":              ("insert", "create table", "-- mysql"),
    "/database.sql":          ("insert", "create table", "-- mysql"),
    # --- Containers -------------------------------------------------------------
    "/Dockerfile":            ("from ",),
    "/docker-compose.yml":    ("services:",),
    "/docker-compose.yaml":   ("services:",),
}

# Paths that legitimately return an HTML body — judged purely by signature above.
_MAY_BE_HTML: frozenset[str] = frozenset({
    "/phpinfo.php", "/info.php", "/server-status", "/server-info", "/web.config",
})

# Severity calibration: an exposed file is CRITICAL by default (it tends to hold secrets), but
# several targets are information/dependency disclosure rather than direct credential leakage and
# should not be rated CRITICAL on every site that serves them.
_EXPOSURE_SEVERITY: dict[str, Severity] = {
    # Dependency manifests / OS metadata — disclosure only, no secrets.
    "/composer.json": Severity.LOW, "/package.json": Severity.LOW,
    "/.gitignore": Severity.LOW, "/.DS_Store": Severity.LOW,
    # Diagnostics & CI config — sensitive info / sometimes tokens, but not a direct credential file.
    "/phpinfo.php": Severity.HIGH, "/info.php": Severity.HIGH,
    "/server-status": Severity.HIGH, "/server-info": Severity.HIGH,
    "/Dockerfile": Severity.MEDIUM, "/.travis.yml": Severity.MEDIUM,
    "/Jenkinsfile": Severity.MEDIUM, "/.gitlab-ci.yml": Severity.MEDIUM,
    "/next.config.js": Severity.MEDIUM,
    # Access-control / rewrite config disclosure — reveals internal paths and auth-file
    # locations, but is not a raw credential store like .htpasswd (which stays CRITICAL).
    "/.htaccess": Severity.HIGH,
}

# Threshold of uniform 403s above which we assume a blanket deny rule even if the
# random probe didn't conclusively 403 (defensive fallback). Also reused as the
# collapse threshold for many weak (empty/ambiguous) 200s.
_BLANKET_403_COUNT = 6

# Below this many non-whitespace characters a 200 body is treated as empty/near-empty:
# served-but-blank proves nothing, so it degrades to a calm LOW finding.
_MIN_BODY_BYTES = 8


# ---------------------------------------------------------------------------
# Baseline probes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _Baseline:
    catch_all: bool      # server returned 200 for a random path
    length: int
    digest: str


def _rand(n: int = 24) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _get_baseline(engine: ScanEngine) -> _Baseline:
    """Detect a catch-all (SPA/soft-404) server that 200s a random path."""
    try:
        resp = engine.get(f"/{_rand()}.{random.choice(('txt', 'php', 'json', 'cfg'))}")
    except httpx.HTTPError:
        return _Baseline(False, 0, "")
    if resp.status_code != 200:
        return _Baseline(False, 0, "")
    body = resp.text
    return _Baseline(True, len(body), hashlib.md5(body.encode("utf-8", "ignore")).hexdigest())


def _is_blanket_403(engine: ScanEngine) -> bool:
    """
    True if the server returns 403 for paths that should not exist — i.e. it has a
    broad deny rule rather than file-specific protection. Probes a random dotfile and
    a random sensitive-looking extension.
    """
    for probe in (f"/.{_rand(18)}", f"/{_rand(18)}.bak", f"/.git/{_rand(12)}"):
        try:
            resp = engine.get(probe)
        except httpx.HTTPError:
            continue
        if resp.status_code == 403:
            return True
    return False


# ---------------------------------------------------------------------------
# Probe + genuineness
# ---------------------------------------------------------------------------

def _probe(engine: ScanEngine, target: _Target) -> tuple[_Target, int, str, str, int, str]:
    """Return (target, status, snippet, content_type, body_len, body_digest)."""
    try:
        resp = engine.get(target.path)
        if resp.status_code != 200:
            return target, resp.status_code, "", "", 0, ""
        body = resp.text
        ctype = resp.headers.get("content-type", "")
        digest = hashlib.md5(body.encode("utf-8", "ignore")).hexdigest()
        return target, 200, body[:600], ctype, len(body), digest
    except httpx.HTTPError as exc:
        logger.debug(f"sensitive_files: {target.path} → {exc}")
        return target, 0, "", "", 0, ""


def _looks_like_html(content_type: str, snippet: str) -> bool:
    if "text/html" in content_type.lower():
        return True
    head = snippet.lstrip()[:256].lower()
    return (head.startswith("<!doctype html") or head.startswith("<html")
            or "<head" in head or "<body" in head)


class _Verdict(enum.Enum):
    """Outcome of validating a 200 response for a sensitive path."""
    SUPPRESS = "suppress"            # soft-200/catch-all or SPA fallback — no finding
    CONFIRMED = "confirmed"          # content-confirmed exposure (high confidence)
    PLAUSIBLE = "plausible"          # non-empty, non-HTML, but no strong signal (medium)
    NEEDS_MANUAL = "needs_manual"    # signature defined but content didn't match (low)
    EMPTY = "empty"                  # empty/near-empty body (low)


def _signature_match(target: _Target, snippet: str) -> bool | None:
    """None if no signature defined; else whether any expected substring is present."""
    patterns = _CONTENT_PATTERNS.get(target.path)
    if patterns is None:
        return None
    low = snippet.lower()
    return any(p in low for p in patterns)


def _looks_binary(snippet: str) -> bool:
    """A real archive / sqlite / key blob: contains a NUL byte or is mostly non-printable."""
    sample = snippet[:512]
    if not sample:
        return False
    if "\x00" in sample:
        return True
    printable = sum(1 for ch in sample if ch.isprintable() or ch in "\r\n\t")
    return printable / len(sample) < 0.7


def _classify(target: _Target, snippet: str, content_type: str,
              body_len: int, body_digest: str, baseline: _Baseline) -> _Verdict:
    """Grade a 200 response into one of the _Verdict tiers (see module docstring)."""
    # 1. Catch-all / soft-200: body matches the random-path baseline (covers empty-200 servers,
    #    whose blank bodies share the baseline digest, so they collapse here rather than spamming).
    if baseline.catch_all:
        if body_digest == baseline.digest:
            return _Verdict.SUPPRESS
        if baseline.length and abs(body_len - baseline.length) <= max(64, baseline.length // 20):
            return _Verdict.SUPPRESS
    # 2. Empty / near-empty body — served-but-blank proves nothing.
    if body_len < _MIN_BODY_BYTES or not snippet.strip():
        return _Verdict.EMPTY
    # 3. HTML body for a file that is never legitimately HTML → SPA/error fallback.
    if _looks_like_html(content_type, snippet) and target.path not in _MAY_BE_HTML:
        return _Verdict.SUPPRESS
    # 4. File-specific signature: confirmed when it matches, ambiguous when it doesn't.
    sig = _signature_match(target, snippet)
    if sig is True:
        return _Verdict.CONFIRMED
    if sig is False:
        return _Verdict.NEEDS_MANUAL
    # 5. No signature defined — a real binary blob is a confirmed leak; else merely plausible.
    if _looks_binary(snippet):
        return _Verdict.CONFIRMED
    return _Verdict.PLAUSIBLE


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def _exposed_finding(target: _Target, content_type: str, confirmed: bool) -> Finding:
    """A content-validated exposure. confirmed=True → high confidence; else a plausible match."""
    ctype_note = f" Served as Content-Type: {content_type}." if content_type else ""
    severity = _EXPOSURE_SEVERITY.get(target.path, Severity.CRITICAL)
    if confirmed:
        title = f"Sensitive File Exposed [200]: {target.path}"
        match_note = "Its content matches the expected signature for this file."
        confidence, validation = "high", "CONFIRMED"
    else:
        title = f"Sensitive File Likely Exposed [200]: {target.path}"
        match_note = ("Its content looks plausible but did not match a strong file-specific "
                      "signature — confirm manually.")
        confidence, validation = "medium", "MEDIUM"
    return Finding(
        module=MODULE,
        title=title,
        description=(
            f"{target.label} is publicly readable at {target.path}. {match_note} "
            "This file may contain credentials, secrets, or internal configuration."
            f"{ctype_note} Verify manually before acting."
        ),
        severity=severity,
        recommendation=(
            f"Immediately remove or block access to {target.path}. "
            "Rotate any exposed credentials and add a deny rule in your web server."
        ),
        raw={"path": target.path, "status_code": 200, "label": target.label,
             "content_type": content_type, "confidence": confidence, "validation": validation,
             "evidence": ev.from_parts(
                 "GET", target.path, 200, ctype=content_type,
                 indicator=("content matches the expected signature for this file" if confirmed
                            else "non-empty, non-HTML body but no strong signature — likely exposed"))},
    )


def _weak_200_finding(target: _Target, kind: _Verdict, content_type: str, body_len: int) -> Finding:
    """A calm LOW finding for a 200 with an empty/near-empty or signature-mismatched body."""
    is_dotfile = target.path.rsplit("/", 1)[-1].startswith(".")
    if kind is _Verdict.EMPTY:
        noun = "Dotfile" if is_dotfile else "Sensitive Path"
        title = f"{noun} Returned 200 With Empty Body: {target.path}"
        description = (
            f"{target.path} ({target.label}) returns HTTP 200 but the body is empty or near-empty "
            f"({body_len} bytes). This is not proof of exposure — many servers answer 200 with a blank "
            "body for blocked or non-existent files. Reported as low so it can be checked, not as a leak."
        )
        validation = "LOW"
    else:  # NEEDS_MANUAL
        title = f"Sensitive Path Needs Manual Validation [200]: {target.path}"
        description = (
            f"{target.path} ({target.label}) returns HTTP 200 with a non-empty body, but the content "
            "does not match the expected signature for this file. It may be a placeholder, an error page, "
            "or a genuine exposure in an unexpected format — verify manually before acting."
        )
        validation = "NEEDS_MANUAL_VALIDATION"
    ctype_note = f" Served as Content-Type: {content_type}." if content_type else ""
    return Finding(
        module=MODULE,
        title=title,
        description=description + ctype_note,
        severity=Severity.LOW,
        recommendation=(
            f"Manually open {target.path} to confirm. If it should not be served, remove it from the "
            "web root and add a deny rule regardless of the current response."
        ),
        raw={"path": target.path, "status_code": 200, "label": target.label,
             "content_type": content_type, "confidence": "low", "validation": validation,
             "body_len": body_len,
             "evidence": ev.from_parts(
                 "GET", target.path, 200, size=body_len, ctype=content_type,
                 indicator=("empty/near-empty body — not proof of exposure" if kind is _Verdict.EMPTY
                            else "200 but content did not match the expected signature"))},
    )


def _collapsed_weak_finding(paths: list[str], kind: _Verdict) -> Finding:
    """Collapse many weak (empty/ambiguous) 200s into one LOW finding to avoid noise."""
    sample = ", ".join(paths[:8]) + (" …" if len(paths) > 8 else "")
    if kind is _Verdict.EMPTY:
        title = f"Multiple Sensitive Paths Returned 200 With Empty Bodies ({len(paths)})"
        why = ("answer HTTP 200 with an empty/near-empty body — typical of a server that 200s "
               "blocked or non-existent files rather than genuine exposures")
        validation = "LOW"
    else:
        title = f"Multiple Sensitive Paths Need Manual Validation ({len(paths)})"
        why = ("answer HTTP 200 with content that does not match the expected signature for each "
               "file — likely placeholders/error pages, but worth a manual look")
        validation = "NEEDS_MANUAL_VALIDATION"
    return Finding(
        module=MODULE,
        title=title,
        description=(
            f"{len(paths)} sensitive path(s) {why}. Grouped into one low finding to keep the report "
            "calm. Paths: " + sample
        ),
        severity=Severity.LOW,
        recommendation=(
            "Spot-check a few of these manually. Any that should not be served must be removed from "
            "the web root and explicitly denied."
        ),
        raw={"paths": paths, "status_code": 200, "confidence": "low", "validation": validation},
    )


def _protected_finding(target: _Target) -> Finding:
    return Finding(
        module=MODULE,
        title=f"Sensitive File Present (Protected) [403]: {target.path}",
        description=(
            f"{target.label} exists at {target.path} but access is restricted (HTTP 403). "
            "The 403 (rather than 404) suggests the file is present; a misconfiguration could expose it."
        ),
        severity=Severity.MEDIUM,
        recommendation=(
            f"Remove {target.path} from the web root entirely if it should not be served — "
            "do not rely on access controls alone."
        ),
        raw={"path": target.path, "status_code": 403, "label": target.label,
             "confidence": "medium"},
    )


def _blanket_403_finding(paths: list[str]) -> Finding:
    sample = ", ".join(paths[:8]) + (" …" if len(paths) > 8 else "")
    return Finding(
        module=MODULE,
        title="Sensitive Paths Blocked by a Deny Rule (Good Hardening)",
        description=(
            f"The server returns HTTP 403 for {len(paths)} sensitive path(s) including non-existent "
            "ones, which means it enforces a broad deny rule rather than exposing individual files. "
            "This is good practice and not an exposure. Paths: " + sample
        ),
        severity=Severity.INFO,
        recommendation=(
            "No action required. As defence-in-depth, ensure these files are also kept out of the "
            "web root so a future misconfiguration cannot expose them."
        ),
        raw={"blocked_paths": paths, "status_code": 403, "confidence": "high"},
    )


def _git_exposed_finding() -> Finding:
    return Finding(
        module=MODULE,
        title="Exposed .git Directory — Source Code Downloadable",
        description=(
            "The /.git/ directory is publicly readable. An attacker can reconstruct the entire "
            "source code and commit history (e.g. with git-dumper), exposing secrets, credentials, "
            "and internal logic committed to the repository."
        ),
        severity=Severity.CRITICAL,
        recommendation=(
            "Block all access to /.git/ at the web server, and never deploy the .git directory to "
            "production. Rotate any secrets that were ever committed."
        ),
        raw={"path": "/.git/", "status_code": 200, "confidence": "high"},
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(engine: ScanEngine) -> list[Finding]:
    baseline = _get_baseline(engine)
    if baseline.catch_all:
        logger.info("sensitive_files: catch-all server detected — 200s will be content-verified")

    blanket_403 = _is_blanket_403(engine)
    if blanket_403:
        logger.info("sensitive_files: blanket 403 deny rule detected — collapsing 403 findings")

    findings: list[Finding] = []
    protected_paths: list[str] = []
    empty_targets: list[_Target] = []      # 200 with empty/near-empty body
    ambiguous_targets: list[_Target] = []  # 200 but content didn't match the signature
    weak_meta: dict[str, tuple[str, int]] = {}  # path -> (content_type, body_len)
    git_exposed = False
    suppressed = 0

    with ThreadPoolExecutor(max_workers=engine.threads) as pool:
        futures = {pool.submit(_probe, engine, t): t for t in _TARGETS}
        for future in as_completed(futures):
            target, status, snippet, ctype, body_len, digest = future.result()

            if status == 200:
                verdict = _classify(target, snippet, ctype, body_len, digest, baseline)
                if verdict in (_Verdict.CONFIRMED, _Verdict.PLAUSIBLE):
                    findings.append(_exposed_finding(
                        target, ctype, confirmed=verdict is _Verdict.CONFIRMED))
                    if verdict is _Verdict.CONFIRMED and target.path.startswith("/.git/"):
                        git_exposed = True
                elif verdict is _Verdict.EMPTY:
                    empty_targets.append(target)
                    weak_meta[target.path] = (ctype, body_len)
                elif verdict is _Verdict.NEEDS_MANUAL:
                    ambiguous_targets.append(target)
                    weak_meta[target.path] = (ctype, body_len)
                else:  # SUPPRESS
                    suppressed += 1
            elif status == 403:
                protected_paths.append(target.path)

    # Collapse blanket 403s into a single informational finding; otherwise report each.
    if protected_paths:
        if blanket_403 or len(protected_paths) >= _BLANKET_403_COUNT:
            findings.append(_blanket_403_finding(sorted(protected_paths)))
        else:
            for path in sorted(protected_paths):
                target = next(t for t in _TARGETS if t.path == path)
                findings.append(_protected_finding(target))

    # Weak (empty / ambiguous) 200s: report per-path, or collapse one finding when numerous.
    for weak, kind in ((empty_targets, _Verdict.EMPTY), (ambiguous_targets, _Verdict.NEEDS_MANUAL)):
        if not weak:
            continue
        if len(weak) >= _BLANKET_403_COUNT:
            findings.append(_collapsed_weak_finding(sorted(t.path for t in weak), kind))
        else:
            for target in sorted(weak, key=lambda t: t.path):
                ctype, body_len = weak_meta.get(target.path, ("", 0))
                findings.append(_weak_200_finding(target, kind, ctype, body_len))

    # Escalate an exposed .git directory to a single high-impact finding.
    if git_exposed:
        findings.append(_git_exposed_finding())

    if suppressed:
        logger.info(f"sensitive_files: suppressed {suppressed} false-positive 200 response(s)")

    findings.sort(key=lambda f: (f.severity.value, f.raw.get("path", "")))
    return findings
