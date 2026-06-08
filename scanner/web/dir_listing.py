"""
dir_listing — detects open directory listings (autoindex) on the target.

Builds a candidate set of directories from two sources: the parent directories of every
URL the shared crawler discovered (so it tests directories that actually exist on the
site), plus a curated list of directories that commonly hold uploads/assets/backups.
Each candidate is fetched and checked for auto-index markers ("Index of /", IIS/Tornado
listings); an open listing is reported as High with a sample of the exposed entries.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup
from loguru import logger

from scanner import evidence as ev
from scanner.engine import Finding, Severity, ScanEngine

MODULE = "dir_listing"
_MAX_CANDIDATES = 40

_LISTING_MARKERS = ("index of /", "<title>index of", "[to parent directory]",
                    "directory listing for", "parent directory</a>")

_COMMON_DIRS = (
    "/uploads/", "/upload/", "/images/", "/img/", "/files/", "/file/",
    "/assets/", "/static/", "/media/", "/css/", "/js/", "/scripts/",
    "/documents/", "/docs/", "/downloads/", "/download/", "/data/",
    "/backup/", "/backups/", "/tmp/", "/temp/", "/includes/", "/inc/",
    "/lib/", "/vendor/", "/cache/", "/logs/", "/private/", "/.well-known/",
)


def _dirs_from_path(path: str) -> list[str]:
    """Return every parent directory of *path* (with trailing slash)."""
    segs = [s for s in path.split("/") if s]
    if segs and "." in segs[-1]:        # drop a trailing filename
        segs = segs[:-1]
    out, acc = [], ""
    for seg in segs:
        acc += "/" + seg
        out.append(acc + "/")
    return out


def _candidates(engine: ScanEngine) -> list[str]:
    dirs: set[str] = set(_COMMON_DIRS)
    try:
        crawl = engine.get_crawl()
        urls = set(crawl.internal_links) | set(crawl.pages.keys())
        for url in urls:
            for d in _dirs_from_path(urlparse(url).path):
                dirs.add(d)
    except Exception as exc:  # noqa: BLE001 — crawler is best-effort here
        logger.debug(f"dir_listing: crawl unavailable: {exc}")
    return sorted(dirs)[:_MAX_CANDIDATES]


def _listing_entries(html: str) -> list[str]:
    """Extract a few entry names from an autoindex page for evidence."""
    try:
        soup = BeautifulSoup(html, "html.parser")
        names = [a.get_text(strip=True) for a in soup.find_all("a", href=True)]
    except Exception:  # noqa: BLE001
        names = re.findall(r"<a[^>]*>([^<]+)</a>", html)
    names = [n for n in names if n and n.lower() not in ("parent directory", "..", "../")]
    return names[:10]


def _probe(engine: ScanEngine, path: str) -> tuple[str, bool, list[str]]:
    try:
        resp = engine.request("GET", engine.url.rstrip("/") + path, follow_redirects=False)
    except httpx.HTTPError as exc:
        logger.debug(f"dir_listing: {path} → {exc}")
        return path, False, []
    if resp.status_code != 200:
        return path, False, []
    body = resp.text
    if any(m in body[:4000].lower() for m in _LISTING_MARKERS):
        return path, True, _listing_entries(body)
    return path, False, []


def run(engine: ScanEngine) -> list[Finding]:
    candidates = _candidates(engine)
    if not candidates:
        return []

    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=engine.threads) as pool:
        futures = {pool.submit(_probe, engine, p): p for p in candidates}
        for future in as_completed(futures):
            path, is_listing, entries = future.result()
            if not is_listing:
                continue
            full_url = engine.url.rstrip("/") + path
            sample = ", ".join(entries) if entries else "(entries not parsed)"
            findings.append(Finding(
                module=MODULE,
                title=f"Open Directory Listing: {path}",
                description=(f"Directory listing is enabled at {full_url} — its contents are publicly "
                             f"browsable. Visible entries: {sample}."),
                severity=Severity.HIGH,
                recommendation=("Disable automatic directory indexing (Apache 'Options -Indexes', "
                                "nginx 'autoindex off') and add an index file."),
                raw={"path": path, "url": full_url, "entries": entries, "confidence": "high",
                     "evidence": ev.from_parts(
                         "GET", path, 200,
                         indicator="autoindex markers present" + (
                             f" — {len(entries)} entr{'y' if len(entries) == 1 else 'ies'} listed: "
                             f"{', '.join(entries[:5])}" if entries else ""))},
            ))

    if not findings:
        return [Finding(MODULE, "Directory Listing: None Found",
                        f"Checked {len(candidates)} director(y/ies); none exposed an open listing.",
                        Severity.INFO, "", {"checked": len(candidates), "confidence": "high"})]
    return findings
