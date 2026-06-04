"""
wayback — historical URL & parameter mining from the Wayback Machine.

Queries the Internet Archive's CDX API for every URL ever archived under the target domain.
Old URLs are gold for a red team: forgotten endpoints, parametrised URLs (injection surface),
and references to backups/config/admin paths that may still exist. Passive: it only reads the
public archive, it does not touch the target.
"""
from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, urlparse

import httpx
from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "wayback"

_LIMIT = 1000
_INTERESTING_RE = re.compile(
    r"(admin|backup|\.bak|\.old|\.sql|\.env|\.git|\.zip|\.tar|config|secret|token|"
    r"api[_/]|upload|private|internal|debug|phpinfo|wp-config|\.json\b|\.xml\b)", re.I)


def _fetch_cdx(engine: ScanEngine, host: str) -> list[str]:
    url = (f"http://web.archive.org/cdx/search/cdx?url={host}/*"
           f"&output=json&fl=original&collapse=urlkey&limit={_LIMIT}")
    try:
        resp = engine.request("GET", url, timeout=20.0)
    except httpx.HTTPError as exc:
        logger.debug(f"wayback: CDX query failed: {exc}")
        return []
    if resp.status_code != 200:
        return []
    try:
        rows = json.loads(resp.text)
    except json.JSONDecodeError:
        return []
    return [r[0] for r in rows[1:] if r]            # row 0 is the header


def run(engine: ScanEngine) -> list[Finding]:
    host = urlparse(engine.url).hostname or ""
    if not host:
        return []
    urls = _fetch_cdx(engine, host)
    if not urls:
        return []

    param_urls = [u for u in urls if "?" in u]
    params: set[str] = set()
    for u in param_urls:
        params.update(parse_qs(urlparse(u).query).keys())
    interesting = sorted({u for u in urls if _INTERESTING_RE.search(u)})

    findings: list[Finding] = [Finding(
        module=MODULE,
        title=f"Archived URLs Discovered ({len(urls)})",
        description=(
            f"The Wayback Machine has {len(urls)} archived URL(s) for {host}, including "
            f"{len(param_urls)} with parameters and {len(params)} unique parameter name(s). "
            "These expand the testable attack surface (feed them to the injection modules). "
            "Sample parameters: " + ", ".join(sorted(params)[:25]) + (" …" if len(params) > 25 else "")
        ),
        severity=Severity.INFO,
        recommendation=(
            "Review historical endpoints that may still be live; retire and block deprecated "
            "routes and parameters."
        ),
        raw={"total": len(urls), "param_urls": param_urls[:100], "parameters": sorted(params)[:100],
             "confidence": "high", "attack": "T1596 Search Open Technical Databases"},
    )]

    if interesting:
        findings.append(Finding(
            module=MODULE,
            title=f"Sensitive Paths in Archive History ({len(interesting)})",
            description=(
                "The archive references sensitive-looking paths (backups, config, admin, secrets) "
                "that may still exist or reveal the app's structure: "
                + ", ".join(interesting[:15]) + (" …" if len(interesting) > 15 else "")
            ),
            severity=Severity.MEDIUM,
            recommendation="Confirm these paths are no longer reachable and remove leftover files.",
            raw={"paths": interesting[:60], "confidence": "medium",
                 "attack": "T1596 Search Open Technical Databases"},
        ))
    logger.info(f"wayback: {len(urls)} archived URL(s), {len(interesting)} interesting")
    return findings
