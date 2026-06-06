"""
favicon_hash — computes the Shodan-style MurmurHash of the site favicon.

Favicons are a strong fingerprint: identical hashes across hosts reveal shared frameworks,
admin panels, or infrastructure. The hash is produced the same way Shodan does
(base64-encode the raw bytes, then mmh3.hash) so it can be pivoted on directly via
`http.favicon.hash:<value>`. A small built-in map labels a few well-known favicons.
"""
from __future__ import annotations

import base64
import re

import httpx
from bs4 import BeautifulSoup
from loguru import logger

try:
    import mmh3
except ImportError:                      # tiny optional dep — degrade gracefully if it's missing
    mmh3 = None  # type: ignore[assignment]

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "favicon_hash"

# A few well-known favicon hashes → product (illustrative, not exhaustive).
_KNOWN: dict[int, str] = {
    116323821:  "Apache default",
    -1277814690: "GitLab",
    1490343308:  "Jenkins",
    81586312:    "phpMyAdmin",
    -235701012:  "Spring Boot / Whitelabel",
    708578229:   "Grafana",
}


def _favicon_url(engine: ScanEngine) -> str:
    """Return the favicon reference from a <link rel=icon>, else /favicon.ico."""
    try:
        resp = engine.get()
        link = BeautifulSoup(resp.text, "html.parser").find(
            "link", rel=re.compile(r"icon", re.IGNORECASE), href=True)
        if link and link.get("href"):
            return str(link["href"])
    except Exception as exc:  # noqa: BLE001 — best-effort homepage parse
        logger.debug(f"favicon_hash: homepage parse failed: {exc}")
    return "/favicon.ico"


def _shodan_hash(content: bytes) -> int:
    """Reproduce Shodan's favicon hash: mmh3 over the base64-encoded bytes."""
    b64 = base64.encodebytes(content)
    return mmh3.hash(b64)


def run(engine: ScanEngine) -> list[Finding]:
    if mmh3 is None:
        return [Finding(MODULE, "Favicon Fingerprint Skipped",
                        "The optional 'mmh3' library is not installed, so the Shodan-style favicon "
                        "hash was not computed. Install it with: pip install mmh3",
                        Severity.INFO, "", {"confidence": "high"})]

    href = _favicon_url(engine)
    if href.startswith("http"):
        path, is_absolute = href, True
    else:
        path, is_absolute = "/" + href.lstrip("/"), False

    try:
        resp = engine.request("GET", path) if is_absolute else engine.get(path)
    except httpx.HTTPError as exc:
        logger.debug(f"favicon_hash: fetch failed: {exc}")
        return [Finding(MODULE, "Favicon Not Retrieved",
                        "The favicon could not be fetched.", Severity.INFO, "",
                        {"confidence": "high"})]

    ctype = resp.headers.get("content-type", "").lower()
    head = resp.content[:64].lstrip().lower()
    looks_html = "html" in ctype or head.startswith((b"<!doctype", b"<html", b"<"))
    is_image = "image" in ctype or "icon" in ctype or path.lower().endswith((".ico", ".png", ".svg", ".gif"))

    if resp.status_code != 200 or not resp.content or looks_html or not is_image:
        # A favicon endpoint returning HTML is a soft-404, not a real icon.
        return [Finding(MODULE, "Favicon Not Found",
                        f"No favicon was served at {path} (HTTP {resp.status_code}).",
                        Severity.INFO, "", {"path": path, "confidence": "high"})]

    fav_hash = _shodan_hash(resp.content)
    known = _KNOWN.get(fav_hash)
    note = f" Matches a known favicon: {known}." if known else ""

    return [Finding(
        module=MODULE,
        title=f"Favicon Hash: {fav_hash}",
        description=(
            f"The site favicon ({path}, {len(resp.content)} bytes) has Shodan hash {fav_hash}.{note} "
            f"Pivot on it with `http.favicon.hash:{fav_hash}` (Shodan) to find hosts sharing the same favicon."
        ),
        severity=Severity.INFO,
        recommendation=(
            "A default/framework favicon can fingerprint your stack — replace it with a custom icon "
            "to reduce passive identification." if known else ""
        ),
        raw={"path": path, "favicon_hash": fav_hash, "known": known,
             "bytes": len(resp.content), "confidence": "high"},
    )]
