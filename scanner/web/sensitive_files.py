"""
sensitive_files — probes well-known paths that expose credentials, config, or debug info.

A genuine 200 means the file is publicly readable (Critical). A 403 means the path is
access-controlled. To avoid noise on hardened servers that blanket-deny sensitive paths,
a "blanket 403" probe collapses uniform 403s into a single informational finding instead
of one Medium per path. Catch-all (SPA / soft-404) servers that 200 everything are
detected and suppressed via a baseline fingerprint and content-type heuristics.
"""
from __future__ import annotations

import hashlib
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

import httpx
from loguru import logger

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

# For a genuine 200, paths listed here MUST contain the given substring (case-insensitive).
# This guards against weak matches; everything else is judged by content-type.
_CONTENT_VERIFY: dict[str, str] = {
    "/.env":                  "=",
    "/.git/HEAD":             "ref:",
    "/.git/config":           "[core]",
    "/.aws/credentials":      "aws_access_key_id",
    "/.npmrc":                "_authtoken",
    "/.netrc":                "machine",
    "/.pypirc":               "[pypi]",
    "/wp-config.php":         "db_",
    "/settings.py":           "secret_key",
    "/web.config":            "<configuration",
    "/appsettings.json":      "connectionstrings",
    "/phpinfo.php":           "phpinfo",
    "/info.php":              "phpinfo",
    "/server-status":         "apache",
    "/server-info":           "apache",
    "/.ssh/id_rsa":           "begin",
    "/.ssh/id_ed25519":       "begin",
    "/id_rsa":                "begin",
    "/private.key":           "begin",
    "/server.key":            "begin",
    "/backup.sql":            "insert",
    "/dump.sql":              "insert",
    "/database.sql":          "insert",
    "/Dockerfile":            "from ",
    "/docker-compose.yml":    "services:",
    "/docker-compose.yaml":   "services:",
}

# Paths that legitimately return an HTML body — judged purely by signature above.
_MAY_BE_HTML: frozenset[str] = frozenset({
    "/phpinfo.php", "/info.php", "/server-status", "/server-info", "/web.config",
})

# Threshold of uniform 403s above which we assume a blanket deny rule even if the
# random probe didn't conclusively 403 (defensive fallback).
_BLANKET_403_COUNT = 6


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


def _signature_ok(target: _Target, snippet: str) -> bool | None:
    """None if no signature defined; else whether the required substring is present."""
    required = _CONTENT_VERIFY.get(target.path)
    if required is None:
        return None
    return required.lower() in snippet.lower()


def _is_genuine_200(target, snippet, content_type, body_len, body_digest, baseline) -> bool:
    # 1. Catch-all server: body matches the random-path baseline
    if baseline.catch_all:
        if body_digest == baseline.digest:
            return False
        if baseline.length and abs(body_len - baseline.length) <= max(64, baseline.length // 20):
            return False
    # 2. HTML body for a file that is never legitimately HTML → SPA/error fallback
    if _looks_like_html(content_type, snippet) and target.path not in _MAY_BE_HTML:
        return False
    # 3. Signature check (if any)
    sig = _signature_ok(target, snippet)
    if sig is not None:
        return sig
    return True


def _confidence_200(target: _Target) -> str:
    """High confidence when the path has a content signature that just matched."""
    return "high" if target.path in _CONTENT_VERIFY else "medium"


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def _exposed_finding(target: _Target, content_type: str) -> Finding:
    ctype_note = f" Served as Content-Type: {content_type}." if content_type else ""
    return Finding(
        module=MODULE,
        title=f"Sensitive File Exposed [200]: {target.path}",
        description=(
            f"{target.label} is publicly readable at {target.path}. "
            "This file may contain credentials, secrets, or internal configuration."
            f"{ctype_note} Verify manually before acting."
        ),
        severity=Severity.CRITICAL,
        recommendation=(
            f"Immediately remove or block access to {target.path}. "
            "Rotate any exposed credentials and add a deny rule in your web server."
        ),
        raw={"path": target.path, "status_code": 200, "label": target.label,
             "content_type": content_type, "confidence": _confidence_200(target)},
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
    git_exposed = False
    suppressed = 0

    with ThreadPoolExecutor(max_workers=engine.threads) as pool:
        futures = {pool.submit(_probe, engine, t): t for t in _TARGETS}
        for future in as_completed(futures):
            target, status, snippet, ctype, body_len, digest = future.result()

            if status == 200:
                if _is_genuine_200(target, snippet, ctype, body_len, digest, baseline):
                    findings.append(_exposed_finding(target, ctype))
                    if target.path.startswith("/.git/"):
                        git_exposed = True
                else:
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

    # Escalate an exposed .git directory to a single high-impact finding.
    if git_exposed:
        findings.append(_git_exposed_finding())

    if suppressed:
        logger.info(f"sensitive_files: suppressed {suppressed} false-positive 200 response(s)")

    findings.sort(key=lambda f: (f.severity.value, f.raw.get("path", "")))
    return findings
