"""
feed_downloader — sync the free public CVE feeds into the local database, and query NVD on demand.

Sources (all free, no API key):
  - CISA KEV JSON catalog          (curated known-exploited CVEs)
  - FIRST EPSS scores CSV           (exploit-probability enrichment)
  - NVD 2.0 REST API               (CVE detail + CPE version ranges, queried per detected product)

The KEV + EPSS feeds form the local base database; NVD data is fetched on demand for the products a
scan actually detects and cached locally. Everything is best-effort: a failed download never raises
past these helpers — if a database already exists the scan continues with it.
"""
from __future__ import annotations

import gzip
import os
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Callable

import httpx
from loguru import logger
from rich.console import Console

from scanner.cve import epss_parser, kev_parser, nvd_parser
from scanner.cve.alias_matcher import load_aliases
from scanner.cve.db import DB_PATH, db_age_days, db_exists, get_conn, set_sync_state

console = Console()

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# CISA's CDN (Akamai) 403s bot-like User-Agents, so present a browser UA for the feed downloads.
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

# Full-corpus pull tuning. NVD 2.0 caps a page at 2000 results and rate-limits to 5 requests / 30 s
# without a key (50 / 30 s with one), so we pace requests accordingly. A free, optional NVD_API_KEY
# env var (https://nvd.nist.gov/developers/request-an-api-key) speeds the build ~10x — never required.
_NVD_PAGE = 2000
_NVD_NOKEY_DELAY = 6.0
_NVD_KEY_DELAY = 0.6
_NVD_MAX_RETRY = 4
_NVD_WINDOW_DAYS = 110          # < NVD's 120-day lastModified window limit
ProgressCb = Callable[[int, int, int], None]


def _nvd_api_key() -> str:
    return os.environ.get("NVD_API_KEY", "").strip()


def _nvd_delay() -> float:
    return _NVD_KEY_DELAY if _nvd_api_key() else _NVD_NOKEY_DELAY


def _client() -> httpx.Client:
    headers = {"User-Agent": _UA, "Accept": "application/json, text/csv, */*"}
    key = _nvd_api_key()
    if key:
        headers["apiKey"] = key
    return httpx.Client(headers=headers, timeout=60.0, follow_redirects=True)


def download_kev() -> dict:
    with _client() as c:
        return c.get(_KEV_URL).raise_for_status().json()


def download_epss() -> str:
    with _client() as c:
        raw = c.get(_EPSS_URL).raise_for_status().content
    try:
        return gzip.decompress(raw).decode("utf-8", "replace")
    except OSError:
        return raw.decode("utf-8", "replace")   # already plain CSV


def query_nvd(virtual_match: str = "", keyword: str = "", results: int = 2000) -> dict:
    """Query the NVD 2.0 API for a CPE prefix (virtualMatchString) or a keyword. {} on failure."""
    params: dict[str, str | int] = {"resultsPerPage": results}
    if virtual_match:
        params["virtualMatchString"] = virtual_match
    elif keyword:
        params["keywordSearch"] = keyword
    else:
        return {}
    try:
        with _client() as c:
            resp = c.get(_NVD_URL, params=params)
            if resp.status_code != 200:
                logger.debug(f"cve: NVD query {virtual_match or keyword} -> HTTP {resp.status_code}")
                return {}
            return resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.debug(f"cve: NVD query failed: {exc}")
        return {}


# ---------------------------------------------------------------------------
# Full NVD corpus — bulk load for complete offline matching
# ---------------------------------------------------------------------------

def _nvd_date(dt: datetime) -> str:
    """NVD 2.0 extended ISO-8601, UTC: 2024-01-02T03:04:05.000+00:00."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def _date_windows(start: datetime, end: datetime) -> list[tuple[str, str]]:
    """Split [start, end] into <= 110-day (lastModStartDate, lastModEndDate) windows."""
    out: list[tuple[str, str]] = []
    cur, step = start, timedelta(days=_NVD_WINDOW_DAYS)
    while cur < end:
        nxt = min(cur + step, end)
        out.append((_nvd_date(cur), _nvd_date(nxt)))
        cur = nxt
    return out


def _nvd_get(client: httpx.Client, params: dict) -> dict:
    """One NVD page with backoff on the transient 403/429/503/504 NVD loves to return."""
    last = "no response"
    for attempt in range(_NVD_MAX_RETRY):
        try:
            r = client.get(_NVD_URL, params=params)
            if r.status_code == 200:
                return r.json()
            last = f"HTTP {r.status_code}"
            if r.status_code not in (403, 429, 500, 503, 504):
                logger.debug(f"cve: NVD page {last} (no retry)")
                return {}
        except (httpx.HTTPError, ValueError) as exc:
            last = type(exc).__name__
        time.sleep(min(30.0, 6.0 * (attempt + 1)))
    logger.debug(f"cve: NVD page failed after {_NVD_MAX_RETRY} tries: {last}")
    return {}


def has_full_nvd() -> bool:
    """True if the full NVD corpus has been bulk-loaded locally (enables offline matching)."""
    if not db_exists():
        return False
    conn = get_conn()
    try:
        row = conn.execute("SELECT total_records FROM sync_state WHERE source='nvd_full'").fetchone()
        return bool(row and row[0])
    except sqlite3.Error:
        return False
    finally:
        conn.close()


def nvd_corpus_size() -> int:
    """Number of CVEs currently stored locally."""
    if not db_exists():
        return 0
    conn = get_conn()
    try:
        return int(conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0])
    except sqlite3.Error:
        return 0
    finally:
        conn.close()


def build_full_nvd(progress: ProgressCb | None = None, since: datetime | None = None,
                   max_pages: int | None = None) -> int:
    """
    Bulk-load the entire NVD corpus (or everything modified since *since*) into the local DB,
    page by page. Returns the number of CVE records ingested. Best-effort: network failures stop
    the pull cleanly, keeping whatever was already committed.

    *progress(done, total, ingested)* is called after each page; *max_pages* bounds the pull
    (used by tests / smoke runs).
    """
    conn = get_conn()
    # Bulk-insert speed: this DB is a disposable cache, so durability is not a concern.
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=OFF")
    except sqlite3.Error:
        pass

    windows: list[tuple[str, str] | None]
    if since is not None:
        windows = list(_date_windows(since, datetime.now(timezone.utc))) or [None]
    else:
        windows = [None]

    delay = _nvd_delay()
    ingested = pages = 0
    try:
        with _client() as c:
            for win in windows:
                start, total = 0, 0
                while True:
                    params: dict[str, str | int] = {"resultsPerPage": _NVD_PAGE, "startIndex": start}
                    if win is not None:
                        params["lastModStartDate"], params["lastModEndDate"] = win
                    data = _nvd_get(c, params)
                    if not data:
                        break
                    total = int(data.get("totalResults", 0))
                    vulns = data.get("vulnerabilities", [])
                    if not vulns:
                        break
                    ingested += nvd_parser.ingest(conn, data)
                    pages += 1
                    start += int(data.get("resultsPerPage", len(vulns)))
                    if progress:
                        progress(min(start, total) if total else start, total, ingested)
                    if (max_pages and pages >= max_pages) or (total and start >= total):
                        break
                    time.sleep(delay)
                if max_pages and pages >= max_pages:
                    break
        set_sync_state(conn, "nvd_full", nvd_corpus_size_conn(conn))
        return ingested
    finally:
        conn.close()


def nvd_corpus_size_conn(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0])


def sync_full_nvd(force_full: bool = False, progress: ProgressCb | None = None,
                  max_pages: int | None = None) -> int:
    """Build the full corpus on first run, otherwise pull only what changed since the last sync."""
    last_iso = None
    if db_exists():
        conn = get_conn()
        try:
            row = conn.execute("SELECT last_sync FROM sync_state WHERE source='nvd_full'").fetchone()
            last_iso = row[0] if row else None
        except sqlite3.Error:
            last_iso = None
        finally:
            conn.close()

    if force_full or not last_iso:
        console.print("[dim]  - bulk-loading the full NVD corpus (one-time, this can take a while)…[/dim]")
        return build_full_nvd(progress=progress, max_pages=max_pages)

    last = datetime.fromisoformat(last_iso)
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    since = last - timedelta(days=1)   # small overlap so nothing slips through the cracks
    console.print("[dim]  - refreshing NVD corpus (incremental since last sync)…[/dim]")
    return build_full_nvd(progress=progress, since=since, max_pages=max_pages)


# ---------------------------------------------------------------------------
# Local database sync
# ---------------------------------------------------------------------------

def sync_aliases(conn: sqlite3.Connection) -> int:
    aliases = load_aliases()
    for name, e in aliases.items():
        conn.execute(
            "INSERT INTO aliases(detected_name,normalized_vendor,normalized_product,cpe_prefix,"
            "package_ecosystem,notes) VALUES(?,?,?,?,?,?) ON CONFLICT(detected_name) DO UPDATE SET "
            "normalized_vendor=excluded.normalized_vendor, normalized_product=excluded.normalized_product, "
            "cpe_prefix=excluded.cpe_prefix",
            (name, e.get("vendor", ""), e.get("product", ""), e.get("cpe_prefix", ""),
             e.get("package_ecosystem", ""), e.get("type", "")),
        )
    conn.commit()
    return len(aliases)


def build_database() -> bool:
    """Download the free feeds and (re)build the local base database. Returns True on success."""
    conn = get_conn()
    try:
        sync_aliases(conn)

        console.print("[dim]  - downloading CISA KEV catalog…[/dim]")
        kev = download_kev()
        n_kev = kev_parser.ingest(conn, kev)
        set_sync_state(conn, "cisa_kev", n_kev)

        console.print("[dim]  - downloading FIRST EPSS scores…[/dim]")
        epss_csv = download_epss()
        n_epss = epss_parser.ingest(conn, epss_csv)
        set_sync_state(conn, "epss", n_epss)

        console.print(f"[ok]  Local CVE database built: {n_kev} KEV entries, {n_epss} EPSS scores.[/ok]"
                      .replace("[ok]", "[green]").replace("[/ok]", "[/green]"))
        return True
    except Exception as exc:  # noqa: BLE001 — network/build failure must be reported, not raised
        logger.warning(f"cve: database build failed: {exc}")
        console.print(f"[yellow]  Could not build the CVE database: {exc}[/yellow]")
        return False
    finally:
        conn.close()


def update_vulndb_if_missing() -> bool:
    """Create and sync the database if it does not exist yet. Returns True if usable afterwards."""
    if db_exists():
        return True
    console.print("[yellow]  Local vulnerability database not found. Hades will create it now.[/yellow]")
    return build_database()


def update_vulndb_if_stale(max_age_days: int = 7) -> bool:
    """Update the database if it is older than *max_age_days*. Returns True if usable afterwards.

    When the full NVD corpus has been bulk-loaded, a stale refresh also pulls everything modified
    since the last sync (incremental, so it stays fast) — keeping the offline corpus current.
    """
    age = db_age_days()
    if age is None:
        return update_vulndb_if_missing()
    if age > max_age_days:
        console.print(f"[yellow]  Local CVE database is older than {max_age_days} days. "
                      "Updating database before scan…[/yellow]")
        ok = build_database()
        if has_full_nvd():
            try:
                sync_full_nvd()
            except Exception as exc:  # noqa: BLE001 — refresh is best-effort
                logger.warning(f"cve: incremental NVD refresh failed: {exc}")
        return ok or DB_PATH.is_file()   # keep using the old DB if the refresh failed
    return True
