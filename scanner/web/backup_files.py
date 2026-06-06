"""
backup_files — hunts for backup/temporary copies of the site and its source files.

Complements sensitive_files (which probes fixed names) by deriving candidates from the
*target itself*: archive names based on the hostname (example.zip, example.com.tar.gz),
common base-name archives (backup.zip, www.sql…), and editor/source backups of pages the
crawler found (index.php~, config.php.bak, .index.php.swp vim swap files).

A catch-all / blanket-403 baseline and a content-type guard (a real backup is an archive
or source text, never the HTML app shell) keep false positives down.
"""
from __future__ import annotations

import hashlib
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx
from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "backup_files"
_MAX_SOURCE_FILES = 15

_ARCHIVE_EXT = (".zip", ".tar.gz", ".tar", ".tgz", ".gz", ".rar", ".7z", ".bak", ".sql",
                ".sql.gz", ".old", ".backup", ".dump")
_SOURCE_BAK_SUFFIX = ("~", ".bak", ".old", ".save", ".orig", ".swp", ".copy", ".tmp", ".1")
_COMMON_BASES = ("backup", "www", "site", "web", "html", "public_html", "db", "database",
                 "dump", "data", "old", "new", "app", "release")

# Archive/content signatures (magic-byte prefixes) → confirms a real archive.
_MAGIC: dict[bytes, str] = {
    b"PK\x03\x04": "ZIP archive", b"\x1f\x8b": "gzip archive", b"Rar!": "RAR archive",
    b"7z\xbc\xaf": "7-Zip archive", b"BZh": "bzip2 archive", b"SQLite format 3": "SQLite database",
}


@dataclass(frozen=True)
class _Baseline:
    catch_all: bool
    length: int
    digest: str
    blanket_403: bool


def _rand(n: int = 20) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _baseline(engine: ScanEngine) -> _Baseline:
    catch_all = blanket_403 = False
    length, digest = 0, ""
    try:
        r = engine.get(f"/{_rand()}.zip")
        if r.status_code == 200:
            catch_all, length = True, len(r.content)
            digest = hashlib.md5(r.content[:4096]).hexdigest()
        elif r.status_code == 403:
            blanket_403 = True
    except httpx.HTTPError:
        pass
    return _Baseline(catch_all, length, digest, blanket_403)


def _candidates(engine: ScanEngine) -> list[str]:
    host = urlparse(engine.url).hostname or ""
    base_host = host.split(".")[0] if host else "site"
    names: set[str] = set()

    # Hostname-derived archives: example.zip, example.com.zip …
    for stem in {base_host, host, host.replace(".", "_") if host else ""}:
        if stem:
            for ext in _ARCHIVE_EXT:
                names.add(f"/{stem}{ext}")
    # Common base-name archives
    for base in _COMMON_BASES:
        for ext in _ARCHIVE_EXT:
            names.add(f"/{base}{ext}")
    # Source/editor backups of crawled files
    try:
        crawl = engine.get_crawl()
        files = [urlparse(u).path for u in crawl.internal_links if "." in urlparse(u).path.split("/")[-1]]
        for path in files[:_MAX_SOURCE_FILES]:
            for suf in _SOURCE_BAK_SUFFIX:
                names.add(path + suf)
            # vim swap: /dir/.file.ext.swp
            parts = path.rsplit("/", 1)
            if len(parts) == 2:
                names.add(f"{parts[0]}/.{parts[1]}.swp")
    except Exception as exc:  # noqa: BLE001 — crawler optional
        logger.debug(f"backup_files: crawl unavailable: {exc}")

    return sorted(names)


def _confirm(content: bytes, content_type: str) -> tuple[bool, str]:
    """Return (is_real_backup, label). HTML/asset responses are rejected; magic bytes / source text accepted."""
    ct = content_type.lower()
    if "html" in ct or content[:64].lstrip().lower().startswith((b"<!doctype", b"<html")):
        return False, ""
    for magic, label in _MAGIC.items():
        if content.startswith(magic):
            return True, label
    # An image/font/media/script/style response to a backup path is the server serving an asset or a
    # soft-404, never a real backup — reject it to avoid false positives.
    if (any(ct.startswith(p) for p in ("image/", "video/", "audio/", "font/"))
            or "javascript" in ct or ct.startswith("text/css")):
        return False, ""
    # Non-HTML text (e.g. a .bak of source code) is plausible.
    if "text" in ct:
        return True, "source/text backup"
    return True, "binary file"


def _probe(engine: ScanEngine, path: str, bl: _Baseline) -> Finding | None:
    try:
        resp = engine.get(path)
    except httpx.HTTPError:
        return None
    if resp.status_code != 200 or not resp.content:
        return None
    if bl.catch_all:
        if hashlib.md5(resp.content[:4096]).hexdigest() == bl.digest:
            return None
        if bl.length and abs(len(resp.content) - bl.length) <= max(64, bl.length // 20):
            return None

    is_real, label = _confirm(resp.content, resp.headers.get("content-type", ""))
    if not is_real:
        return None

    full_url = engine.url.rstrip("/") + path
    return Finding(
        module=MODULE,
        title=f"Backup File Exposed [200]: {path}",
        description=(f"A backup/temporary file ({label}, {len(resp.content)} bytes) is publicly "
                     f"downloadable at {full_url}. Backups frequently contain source code, "
                     "credentials, or full database dumps."),
        severity=Severity.CRITICAL,
        recommendation=("Remove the backup from the web root immediately and rotate any secrets it "
                        "may contain. Store backups outside the document root."),
        raw={"path": path, "url": full_url, "type": label, "bytes": len(resp.content),
             "confidence": "high"},
    )


def run(engine: ScanEngine) -> list[Finding]:
    bl = _baseline(engine)
    if bl.blanket_403:
        logger.info("backup_files: blanket 403 deny rule — backup probing suppressed")
        return [Finding(MODULE, "Backup Files: Blocked by Deny Rule (Good Hardening)",
                        "The server returns 403 for backup-style paths including non-existent ones.",
                        Severity.INFO, "", {"confidence": "high"})]

    candidates = _candidates(engine)
    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=engine.threads) as pool:
        futures = {pool.submit(_probe, engine, p, bl): p for p in candidates}
        for future in as_completed(futures):
            result = future.result()
            if result:
                findings.append(result)

    if not findings:
        return [Finding(MODULE, "Backup Files: None Found",
                        f"Probed {len(candidates)} backup candidate(s); none were downloadable.",
                        Severity.INFO, "", {"checked": len(candidates), "confidence": "high"})]
    findings.sort(key=lambda f: f.raw.get("path", ""))
    return findings
