"""
dir_scan — brute-forces common directories and functional paths.

Probes each wordlist entry (without following redirects) and classifies the result:
  • 200 with an open directory listing  → High
  • 200 normal page                     → Medium
  • 401 authentication required         → Low (path exists, gated)
  • 403 forbidden                       → Low, or one collapsed Info finding when the
                                          server blanket-denies (deny-all rule)
  • 3xx redirect to a non-trivial target→ Low (path exists)
  • 5xx server error                    → Info

A unified baseline (probing random paths) detects catch-all 200s, redirect-all, and
blanket-403 servers so brute-forcing does not produce false positives. Paths owned by
dedicated modules (sensitive_files, robots_txt, sitemap) are excluded to avoid duplicates.
Safe mode caps the list and lets the engine rate limiter pace requests.
"""
from __future__ import annotations

import hashlib
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import httpx
from loguru import logger
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn

from config import PROJECT_ROOT, SAFE_MODE_RATE_DELAY, WORDLIST_DIRS
from scanner import evidence as ev
from scanner.engine import Finding, Severity, ScanEngine

MODULE = "dir_scan"
_SAFE_MODE_LIMIT = 50
_BLANKET_403_COUNT = 8
_console = Console()

# Paths handled by dedicated, content-validating modules (sensitive_files / backup_files /
# git_dumper) — excluded here so dir_scan never reports them as a generic, unvalidated MEDIUM
# "Accessible Path" (a duplicate of, and weaker than, what those modules already do).
_EXCLUDED: frozenset[str] = frozenset({
    # env / dotfiles
    ".env", ".env.local", ".env.production", ".env.backup", ".env.example",
    ".env.dev", ".env.development", ".env.staging", ".env.save",
    ".git", ".svn", ".hg", ".bzr", ".htaccess", ".htpasswd", ".ds_store",
    ".npmrc", ".netrc", ".pypirc", ".dockercfg", ".bash_history", "id_rsa",
    # framework / app config + secrets
    "web.config", "wp-config.php", "configuration.php", "config.php",
    "config.json", "config.yml", "config.yaml", "settings.php", "settings.json",
    "settings.py", "local_settings.py", "appsettings.json",
    "secrets.json", "credentials.json", "database.yml", "database.yaml",
    # diagnostics / manifests / CI
    "phpinfo.php", "info.php", "adminer.php", "composer.json", "package.json",
    ".gitignore", ".gitlab-ci.yml", ".travis.yml", "jenkinsfile", "dockerfile",
    "docker-compose.yml", "docker-compose.yaml",
    # logs
    "error_log", "access_log", "error.log", "access.log",
    # owned by other modules
    "robots.txt", "sitemap.xml", "crossdomain.xml",
})

# A path under any of these directories is VCS/credential internals owned by sensitive_files /
# git_dumper (e.g. ".git/config", ".aws/credentials") — defer to them.
_EXCLUDED_PREFIXES: tuple[str, ...] = (
    ".git/", ".svn/", ".hg/", ".bzr/", ".aws/", ".ssh/", ".docker/", ".azure/",
)

# A path ending in any of these is a backup / database / key / log / archive artifact owned by
# backup_files / sensitive_files — defer to them rather than emit a generic MEDIUM.
_EXCLUDED_SUFFIXES: tuple[str, ...] = (
    ".sql", ".sql.gz", ".key", ".pem", ".log", ".bak", ".old", ".save", ".swp",
    ".dump", ".zip", ".tar", ".tar.gz", ".tgz", ".gz", ".rar", ".7z",
    ".sqlite", ".sqlite3", ".db",
)


def _is_excluded(norm: str) -> bool:
    """True if *norm* (a wordlist path, normalised to strip('/').lower()) is owned by a dedicated,
    content-validating module and should not be probed as a generic dir_scan path."""
    return (norm in _EXCLUDED
            or norm.startswith(_EXCLUDED_PREFIXES)
            or norm.endswith(_EXCLUDED_SUFFIXES))

# Markers that identify an auto-generated open directory listing.
_LISTING_MARKERS: tuple[str, ...] = (
    "index of /", "<title>index of", "[to parent directory]",
    "directory listing for", "parent directory</a>",
)


# ---------------------------------------------------------------------------
# Wordlist
# ---------------------------------------------------------------------------

def _is_safe_mode(engine: ScanEngine) -> bool:
    try:
        return engine._rate_limiter._delay >= SAFE_MODE_RATE_DELAY
    except AttributeError:
        return False


def _load_wordlist(engine: ScanEngine) -> list[str]:
    """Load paths from the custom or default wordlist, excluding other modules' paths."""
    raw_path: str = engine.wordlist or WORDLIST_DIRS
    wl_path = Path(raw_path)
    if not wl_path.is_absolute():
        wl_path = PROJECT_ROOT / raw_path

    if not wl_path.exists():
        logger.warning(f"dir_scan: wordlist not found: {wl_path}")
        return []

    paths: list[str] = []
    seen: set[str] = set()
    with wl_path.open(encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            norm = line.strip("/").lower()
            if _is_excluded(norm) or norm in seen:
                continue
            seen.add(norm)
            paths.append("/" + line.lstrip("/"))
    return paths


# ---------------------------------------------------------------------------
# Probing
# ---------------------------------------------------------------------------

@dataclass
class _Result:
    path: str
    status: int
    length: int
    digest: str
    location: str
    is_listing: bool


def _rand(n: int = 16) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=n))


def _digest(text: str) -> str:
    return hashlib.md5(text.encode("utf-8", "ignore")).hexdigest()


def _has_listing(body: str) -> bool:
    low = body[:4000].lower()
    return any(m in low for m in _LISTING_MARKERS)


def _probe(engine: ScanEngine, path: str) -> _Result:
    """Probe a path WITHOUT following redirects, capturing enough to classify it."""
    url = engine.url.rstrip("/") + path
    try:
        resp = engine.request("GET", url, follow_redirects=False)
    except httpx.HTTPError as exc:
        logger.debug(f"dir_scan: {path} → error: {exc}")
        return _Result(path, 0, 0, "", "", False)

    status = resp.status_code
    location = resp.headers.get("location", "")
    if status == 200:
        body = resp.text
        return _Result(path, 200, len(body), _digest(body), "", _has_listing(body))
    length = int(resp.headers.get("content-length", 0) or 0)
    return _Result(path, status, length, "", location, False)


@dataclass
class _Baseline:
    wildcard_200: bool = False
    wc_digest: str = ""
    wc_length: int = 0
    redirect_all: bool = False
    redirect_location: str = ""
    blanket_403: bool = False
    blanket_5xx: bool = False


def _get_baseline(engine: ScanEngine) -> _Baseline:
    """Probe random non-existent paths to learn the server's 'not found' behaviour."""
    bl = _Baseline()
    for _ in range(2):
        r = _probe(engine, f"/{_rand()}")
        if r.status == 200 and not bl.wildcard_200:
            bl.wildcard_200, bl.wc_digest, bl.wc_length = True, r.digest, r.length
        elif r.status in (301, 302, 307, 308) and not bl.redirect_all:
            bl.redirect_all, bl.redirect_location = True, r.location
        elif r.status == 403:
            bl.blanket_403 = True
        elif 500 <= r.status < 600:
            bl.blanket_5xx = True
    return bl


# ---------------------------------------------------------------------------
# Classification helpers
# ---------------------------------------------------------------------------

def _matches_wildcard(r: _Result, bl: _Baseline) -> bool:
    if not bl.wildcard_200:
        return False
    if r.digest and r.digest == bl.wc_digest:
        return True
    return bool(bl.wc_length) and abs(r.length - bl.wc_length) <= max(64, bl.wc_length // 20)


def _is_trivial_redirect(path: str, location: str, base_url: str) -> bool:
    """A redirect that just normalises the path (trailing slash / https upgrade / homepage)."""
    if not location:
        return True
    base = urlparse(base_url)
    loc = urlparse(location)
    loc_path = loc.path or "/"
    if loc_path in ("/", path, path + "/", path.rstrip("/")):
        return True
    # http→https upgrade to the same path on the same host
    if loc.netloc in ("", base.netloc) and loc_path.rstrip("/") == path.rstrip("/"):
        return True
    return False


def _finding(path: str, url: str, status: int, severity: Severity,
             title: str, detail: str, confidence: str, location: str = "") -> Finding:
    full_url = url.rstrip("/") + path
    return Finding(
        module=MODULE,
        title=title,
        description=f"{detail}: {full_url} (HTTP {status})"
                    + (f" → {location}" if location else ""),
        severity=severity,
        recommendation=(
            "Restrict access to this path or remove it if unintended. "
            "Disable automatic directory listing and enforce authentication."
        ),
        raw={"path": path, "url": full_url, "status_code": status, "confidence": confidence,
             "evidence": ev.from_parts("GET", path, status, indicator=detail)
             + ([f"redirects to: {location}"] if location else [])},
    )


def _blanket_403_finding(paths: list[str]) -> Finding:
    sample = ", ".join(paths[:8]) + (" …" if len(paths) > 8 else "")
    return Finding(
        module=MODULE,
        title="Paths Blocked by a Deny Rule (Good Hardening)",
        description=(
            f"The server returns HTTP 403 for {len(paths)} probed path(s) including non-existent "
            "ones — a broad deny rule rather than individual exposed directories. Paths: " + sample
        ),
        severity=Severity.INFO,
        recommendation="No action required; this reflects a hardened configuration.",
        raw={"blocked_paths": paths, "status_code": 403, "confidence": "high"},
    )


def _blanket_5xx_finding(paths: list[str]) -> Finding:
    sample = ", ".join(paths[:8]) + (" …" if len(paths) > 8 else "")
    return Finding(
        module=MODULE,
        title="Server Errors on Every Unknown Path (Results Unreliable)",
        description=(
            f"The server returns HTTP 5xx for {len(paths)} probed path(s) including non-existent ones, "
            "so it errors on any unrecognised route rather than returning a clean 404. These are not "
            "individual discoveries. It may indicate fragile error handling or a WAF/edge interfering "
            "with the scan. Paths: " + sample
        ),
        severity=Severity.INFO,
        recommendation=("Return proper 404s for unknown paths (a 500 can leak stack traces). If a WAF is "
                        "responsible, scan from an allowlisted network for accurate results."),
        raw={"error_paths": paths, "status_code": 500, "confidence": "high"},
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(engine: ScanEngine) -> list[Finding]:
    safe_mode = _is_safe_mode(engine)

    paths = _load_wordlist(engine)
    if not paths:
        logger.warning("dir_scan: empty wordlist — skipping")
        return []
    if safe_mode:
        paths = paths[:_SAFE_MODE_LIMIT]

    baseline = _get_baseline(engine)
    if baseline.wildcard_200:
        logger.warning("dir_scan: server returns 200 for random paths — only listings/anomalies reported")

    results: list[_Result] = []
    with Progress(
        SpinnerColumn(spinner_name="dots2"),
        TextColumn("[cyan]dir_scan[/cyan] [dim]{task.description}[/dim]"),
        BarColumn(bar_width=28),
        MofNCompleteColumn(),
        transient=True,
        console=_console,
    ) as progress:
        task = progress.add_task(
            f"{'safe mode, ' if safe_mode else ''}{len(paths)} paths", total=len(paths))

        if safe_mode:
            for path in paths:
                results.append(_probe(engine, path))
                progress.advance(task)
        else:
            with ThreadPoolExecutor(max_workers=engine.threads) as pool:
                futures = {pool.submit(_probe, engine, p): p for p in paths}
                for future in as_completed(futures):
                    results.append(future.result())
                    progress.advance(task)

    findings: list[Finding] = []
    protected_paths: list[str] = []
    server_error_paths: list[str] = []

    for r in sorted(results, key=lambda x: x.path):
        if r.status == 200:
            # A genuine directory listing is a strong signal — report it even on a
            # catch-all server (a soft-404 page never contains "Index of /" markers).
            if r.is_listing:
                findings.append(_finding(
                    r.path, engine.url, 200, Severity.HIGH,
                    f"Open Directory Listing [200]: {r.path}",
                    "Directory contents are publicly listed", "high"))
            elif _matches_wildcard(r, baseline):
                continue  # soft-404 / catch-all page
            else:
                findings.append(_finding(
                    r.path, engine.url, 200, Severity.MEDIUM,
                    f"Accessible Path [200]: {r.path}",
                    "Accessible path discovered", "medium"))
        elif r.status == 401:
            findings.append(_finding(
                r.path, engine.url, 401, Severity.LOW,
                f"Protected Path [401]: {r.path}",
                "Path exists but requires authentication", "high"))
        elif r.status == 403:
            protected_paths.append(r.path)
        elif r.status in (301, 302, 307, 308):
            if baseline.redirect_all and r.location == baseline.redirect_location:
                continue
            if _is_trivial_redirect(r.path, r.location, engine.url):
                continue
            findings.append(_finding(
                r.path, engine.url, r.status, Severity.LOW,
                f"Path Redirects [{r.status}]: {r.path}",
                "Path exists and redirects", "medium", location=r.location))
        elif 500 <= r.status < 600:
            server_error_paths.append(r.path)

    # Collapse blanket 403s; otherwise report each protected path individually.
    if protected_paths:
        if baseline.blanket_403 or len(protected_paths) >= _BLANKET_403_COUNT:
            findings.append(_blanket_403_finding(sorted(protected_paths)))
        else:
            for path in sorted(protected_paths):
                findings.append(_finding(
                    path, engine.url, 403, Severity.LOW,
                    f"Forbidden Path [403]: {path}",
                    "Path exists but access is forbidden", "medium"))

    # Collapse blanket 5xx (server errors on every unknown path); else report individually.
    if server_error_paths:
        if baseline.blanket_5xx or len(server_error_paths) >= _BLANKET_403_COUNT:
            findings.append(_blanket_5xx_finding(sorted(server_error_paths)))
        else:
            for path in sorted(server_error_paths):
                findings.append(_finding(
                    path, engine.url, 500, Severity.INFO,
                    f"Server Error [500]: {path}",
                    "Path triggers a server error", "low"))

    return findings
