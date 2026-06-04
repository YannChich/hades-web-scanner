"""
sitemap — fetches and parses XML sitemaps to enumerate declared URLs.

Looks for /sitemap.xml and /sitemap_index.xml (and any sitemaps declared in
robots.txt), extracts <loc> entries, and reports the URL count plus any sensitive
paths a sitemap advertises (admin, login, staging, backups, …). A sitemap index is
followed one level deep so nested sitemaps are also counted.
"""
from __future__ import annotations

import re

import httpx
from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "sitemap"

_CANDIDATES = ("/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml", "/sitemap1.xml")
_LOC_RE = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.IGNORECASE | re.DOTALL)
_MAX_SUBSITEMAPS = 5
_MAX_REPORTED = 15

# Path fragments worth flagging when a sitemap advertises them.
_SENSITIVE = (
    ("/admin", "admin area"), ("/administrator", "admin area"), ("/wp-admin", "WordPress admin"),
    ("/login", "login page"), ("/signin", "login page"), ("/dashboard", "dashboard"),
    ("/config", "configuration"), ("/backup", "backup"), ("/private", "private area"),
    ("/internal", "internal area"), ("/staging", "staging environment"),
    ("/dev", "development area"), ("/test", "test area"), ("/api", "API endpoint"),
    ("/.git", "git repository"), ("/phpmyadmin", "phpMyAdmin"),
)


def _fetch(engine: ScanEngine, path: str) -> str | None:
    try:
        resp = engine.get(path)
    except httpx.HTTPError as exc:
        logger.debug(f"sitemap: {path} → {exc}")
        return None
    if resp.status_code != 200:
        return None
    if "xml" not in resp.headers.get("content-type", "").lower() and "<loc>" not in resp.text.lower():
        return None
    return resp.text


def _robots_sitemaps(engine: ScanEngine) -> list[str]:
    try:
        resp = engine.get("/robots.txt")
    except httpx.HTTPError:
        return []
    if resp.status_code != 200:
        return []
    return re.findall(r"(?im)^\s*sitemap:\s*(\S+)", resp.text)


def _to_path(url_or_path: str, engine: ScanEngine) -> str:
    """Reduce a full URL (or path) to a path relative to the target."""
    p = url_or_path.replace(engine.url, "") or url_or_path
    return p if p.startswith("/") else "/" + p.lstrip("/")


def _flag_sensitive(urls: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for url in urls:
        low = url.lower()
        for frag, label in _SENSITIVE:
            if frag in low and frag not in seen:
                seen.add(frag)
                findings.append(Finding(
                    module=MODULE,
                    title=f"Sitemap Advertises Sensitive Path: {frag}",
                    description=(
                        f"The sitemap lists a URL containing '{frag}' ({label}): {url}. "
                        "Publishing this advertises its existence to crawlers and attackers."
                    ),
                    severity=Severity.LOW,
                    recommendation=f"Remove {label} URLs from the public sitemap and protect them with authentication.",
                    raw={"url": url, "fragment": frag, "confidence": "high"},
                ))
    return findings


def run(engine: ScanEngine) -> list[Finding]:
    candidates: list[str] = list(_CANDIDATES)
    for declared in _robots_sitemaps(engine):
        path = _to_path(declared, engine)
        if path not in candidates:
            candidates.append(path)

    found_path: str | None = None
    content: str | None = None
    for path in candidates:
        content = _fetch(engine, path)
        if content:
            found_path = path
            break

    if not content:
        return [Finding(
            module=MODULE,
            title="Sitemap Not Found",
            description="No XML sitemap was found at the common locations or in robots.txt.",
            severity=Severity.INFO,
            recommendation="",
            raw={"checked": candidates, "confidence": "high"},
        )]

    locs = _LOC_RE.findall(content)
    is_index = "<sitemapindex" in content.lower()

    all_urls: list[str] = []
    if is_index:
        for sub in locs[:_MAX_SUBSITEMAPS]:
            sub_content = _fetch(engine, _to_path(sub, engine))
            if sub_content:
                all_urls.extend(_LOC_RE.findall(sub_content))
    else:
        all_urls = locs

    findings: list[Finding] = [Finding(
        module=MODULE,
        title=f"Sitemap Found: {found_path}",
        description=(
            f"{'Sitemap index' if is_index else 'Sitemap'} at {found_path} lists {len(all_urls)} URL(s)"
            + (f" across {len(locs)} sub-sitemap(s)" if is_index else "")
            + ". Examples: " + ", ".join(all_urls[:_MAX_REPORTED])
            + (" …" if len(all_urls) > _MAX_REPORTED else "")
        ),
        severity=Severity.INFO,
        recommendation="",
        raw={"path": found_path, "url_count": len(all_urls), "is_index": is_index,
             "urls": all_urls[:200], "confidence": "high"},
    )]

    findings += _flag_sensitive(all_urls)
    return findings
