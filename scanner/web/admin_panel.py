"""
admin_panel — discovers exposed administration / login interfaces.

Fingerprints the CMS from the homepage, then probes known admin paths. Rather than
flagging any 200/302 (which produces false positives on catch-all servers), each
response is content-verified so only genuine admin signals are reported:

  • 200 containing a login form                  → High  (exposed login panel)
  • 200 looking like an authenticated admin UI   → High  (possible unauth access — verify)
  • 401 with WWW-Authenticate                     → Medium (admin path behind HTTP auth)
  • 3xx redirecting to a login page               → Medium (admin path exists)

Catch-all (SPA/soft-404) and redirect-all servers are fingerprinted via a baseline so
generic 200s/redirects are suppressed.
"""
from __future__ import annotations

import hashlib
import random
import re
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import httpx
from loguru import logger

from config import PROJECT_ROOT, WORDLIST_ADMIN
from scanner import evidence as ev
from scanner.engine import Finding, Severity, ScanEngine

MODULE = "admin_panel"

# ---------------------------------------------------------------------------
# Path lists
# ---------------------------------------------------------------------------

_GENERIC_PATHS: list[str] = [
    "/admin", "/admin.php", "/admin/", "/administrator", "/administrator/",
    "/login", "/login.php", "/login/", "/dashboard", "/dashboard/",
    "/controlpanel", "/controlpanel/", "/backend", "/backend/",
    "/manage", "/manage/", "/management", "/cms", "/cms/",
    "/portal", "/portal/", "/panel", "/panel/", "/cp",
    "/user/login", "/account/login", "/auth/login", "/signin", "/sign-in",
]

_CMS_PATHS: dict[str, list[str]] = {
    "wordpress": ["/wp-admin/", "/wp-admin/admin.php", "/wp-login.php",
                  "/wp-admin/options-general.php"],
    "joomla":    ["/administrator/", "/administrator/index.php", "/joomla/administrator/"],
    "drupal":    ["/admin/", "/user/login", "/admin/config", "/admin/people"],
    "magento":   ["/admin/", "/admin/dashboard/", "/index.php/admin/", "/downloader/"],
    "typo3":     ["/typo3/", "/typo3/index.php", "/typo3cms/"],
    "prestashop":["/admin/", "/adminpanel/", "/admin123/"],
    "opencart":  ["/admin/", "/admin/index.php"],
    "phpmyadmin":["/phpmyadmin/", "/pma/", "/phpMyAdmin/", "/mysql/", "/myadmin/"],
}

_CMS_SIGNALS: list[tuple[str, str]] = [
    (r"/wp-content/|/wp-includes/|wp-login",  "wordpress"),
    (r"/administrator/|joomla",                "joomla"),
    (r"/sites/default/|Drupal",               "drupal"),
    (r"Mage\.Cookies|/skin/frontend/",        "magento"),
    (r"/typo3/|typo3temp",                    "typo3"),
    (r"/modules/ps_|PrestaShop",              "prestashop"),
    (r"route=common/home|/catalog/view/",     "opencart"),
]

# ---------------------------------------------------------------------------
# Content heuristics
# ---------------------------------------------------------------------------

_PASSWORD_INPUT = re.compile(r"""type\s*=\s*['"]?password\b""", re.IGNORECASE)
_LOGIN_KEYWORDS = ("sign in", "signin", "log in", "log-in", "login", "username",
                   "j_username", "authenticat", "mot de passe", "connexion")
_ADMIN_UI_NAV = ("dashboard", "admin", "settings", "manage", "control panel", "console")
_LOGOUT = ("logout", "log out", "sign out", "déconnexion")
_LOGIN_PATH_HINTS = ("login", "signin", "sign-in", "auth", "sso", "session/new", "account/login")


def _looks_like_login(body: str) -> bool:
    """True if the page contains a login form."""
    low = body.lower()
    if _PASSWORD_INPUT.search(low):
        return True
    return "<form" in low and any(k in low for k in _LOGIN_KEYWORDS)


def _looks_like_admin_ui(body: str) -> bool:
    """True if the page looks like an authenticated admin UI (logout link + admin nav)."""
    low = body.lower()
    return any(k in low for k in _LOGOUT) and any(k in low for k in _ADMIN_UI_NAV)


def _location_is_login(location: str) -> bool:
    path = urlparse(location).path.lower()
    return any(h in path for h in _LOGIN_PATH_HINTS)


def _detect_cms(html: str, headers: httpx.Headers) -> str | None:
    generator = headers.get("x-generator", "")
    for pattern, key in _CMS_SIGNALS:
        if re.search(pattern, html, re.IGNORECASE) or re.search(pattern, generator, re.IGNORECASE):
            return key
    return None


# ---------------------------------------------------------------------------
# Wordlist
# ---------------------------------------------------------------------------

def _load_wordlist_paths() -> list[str]:
    wl_path = Path(WORDLIST_ADMIN)
    if not wl_path.is_absolute():
        wl_path = PROJECT_ROOT / WORDLIST_ADMIN
    if not wl_path.exists():
        return []
    paths: list[str] = []
    with wl_path.open(encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                paths.append("/" + line.lstrip("/"))
    return paths


def _build_path_list(cms_key: str | None) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []

    def _add(paths: list[str]) -> None:
        for p in paths:
            if p not in seen:
                seen.add(p)
                ordered.append(p)

    if cms_key and cms_key in _CMS_PATHS:
        _add(_CMS_PATHS[cms_key])
    _add(_GENERIC_PATHS)
    _add(_load_wordlist_paths())
    return ordered


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
    www_auth: bool
    body: str


@dataclass
class _Baseline:
    catch_all: bool = False
    length: int = 0
    digest: str = ""
    redirect_all: bool = False
    redirect_location: str = ""


def _digest(text: str) -> str:
    return hashlib.md5(text.encode("utf-8", "ignore")).hexdigest()


def _rand() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=24))


def _probe(engine: ScanEngine, path: str) -> _Result:
    try:
        resp = engine.request("GET", engine.url.rstrip("/") + path, follow_redirects=False)
    except httpx.HTTPError as exc:
        logger.debug(f"admin_panel: {path} → {exc}")
        return _Result(path, 0, 0, "", "", False, "")

    status = resp.status_code
    if status == 200:
        body = resp.text
        return _Result(path, 200, len(body), _digest(body), "", False, body[:8000])
    return _Result(
        path, status, 0, "",
        resp.headers.get("location", ""),
        "www-authenticate" in resp.headers,
        "",
    )


def _get_baseline(engine: ScanEngine) -> _Baseline:
    bl = _Baseline()
    for _ in range(2):
        r = _probe(engine, f"/{_rand()}")
        if r.status == 200 and not bl.catch_all:
            bl.catch_all, bl.length, bl.digest = True, r.length, r.digest
        elif r.status in (301, 302, 307, 308) and not bl.redirect_all:
            bl.redirect_all, bl.redirect_location = True, r.location
    return bl


def _is_catch_all_200(r: _Result, bl: _Baseline, home_digest: str) -> bool:
    if r.digest == home_digest:
        return True
    if bl.catch_all:
        if r.digest == bl.digest:
            return True
        if bl.length and abs(r.length - bl.length) <= max(64, bl.length // 20):
            return True
    return False


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def _finding(path: str, engine: ScanEngine, status: int, severity: Severity,
             title: str, detail: str, confidence: str,
             cms_key: str | None = None, location: str = "") -> Finding:
    full_url = engine.url.rstrip("/") + path
    cms_note = f" ({cms_key.title()})" if cms_key and path in _CMS_PATHS.get(cms_key, []) else ""
    return Finding(
        module=MODULE,
        title=f"{title}{cms_note}: {path}",
        description=(
            f"{detail} at {full_url} (HTTP {status})"
            + (f" → {location}" if location else "")
            + ". Exposed admin/login interfaces are prime targets for brute-force and "
              "credential-stuffing attacks."
        ),
        severity=severity,
        recommendation=(
            "Restrict access by IP allowlist or VPN, enforce account lockout and MFA, "
            "disable default credentials, and consider moving the panel to a non-standard path."
        ),
        raw={"path": path, "url": full_url, "status_code": status,
             "cms": cms_key, "confidence": confidence,
             "evidence": ev.from_parts("GET", path, status, indicator=detail)
             + ([f"redirects to: {location}"] if location else [])},
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(engine: ScanEngine) -> list[Finding]:
    try:
        resp = engine.get()
    except httpx.HTTPError as exc:
        logger.warning(f"admin_panel: homepage request failed: {exc}")
        return []

    cms_key = _detect_cms(resp.text, resp.headers)
    if cms_key:
        logger.debug(f"admin_panel: CMS fingerprinted as '{cms_key}'")
    home_digest = _digest(resp.text)

    baseline = _get_baseline(engine)
    if baseline.catch_all:
        logger.info("admin_panel: catch-all server — generic 200s suppressed, "
                    "only verified login/admin pages reported")

    paths = _build_path_list(cms_key)
    findings: list[Finding] = []

    with ThreadPoolExecutor(max_workers=engine.threads) as pool:
        futures = {pool.submit(_probe, engine, p): p for p in paths}
        for future in as_completed(futures):
            r = future.result()

            if r.status == 200:
                if _is_catch_all_200(r, baseline, home_digest):
                    continue
                if _looks_like_login(r.body):
                    findings.append(_finding(
                        r.path, engine, 200, Severity.HIGH,
                        "Login Panel Exposed", "A login form is publicly reachable",
                        "high", cms_key))
                elif _looks_like_admin_ui(r.body):
                    findings.append(_finding(
                        r.path, engine, 200, Severity.HIGH,
                        "Possible Unauthenticated Admin Interface",
                        "An admin-style page (logout + admin navigation) is reachable without "
                        "logging in — verify whether authentication is actually enforced",
                        "medium", cms_key))
                # otherwise: a generic 200 page → dir_scan's job, skip here

            elif r.status == 401 and r.www_auth:
                findings.append(_finding(
                    r.path, engine, 401, Severity.MEDIUM,
                    "Admin Path Behind HTTP Auth",
                    "Path exists and is protected by HTTP authentication", "high", cms_key))

            elif r.status in (301, 302, 307, 308):
                if baseline.redirect_all and r.location == baseline.redirect_location:
                    continue
                if _location_is_login(r.location):
                    findings.append(_finding(
                        r.path, engine, r.status, Severity.MEDIUM,
                        "Admin Path Redirects to Login",
                        "Path exists and redirects to a login page", "high",
                        cms_key, location=r.location))

    findings.sort(key=lambda f: f.raw.get("path", ""))
    return findings
