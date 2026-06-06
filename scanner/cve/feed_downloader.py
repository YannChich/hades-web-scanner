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
import sqlite3
import time

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


def _client() -> httpx.Client:
    headers = {"User-Agent": _UA, "Accept": "application/json, text/csv, */*"}
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
    """Update the database if it is older than *max_age_days*. Returns True if usable afterwards."""
    age = db_age_days()
    if age is None:
        return update_vulndb_if_missing()
    if age > max_age_days:
        console.print(f"[yellow]  Local CVE database is older than {max_age_days} days. "
                      "Updating database before scan…[/yellow]")
        ok = build_database()
        return ok or DB_PATH.is_file()   # keep using the old DB if the refresh failed
    return True
