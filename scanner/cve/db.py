"""
db — local SQLite vulnerability database for the CVE module.

Holds the curated/exploitation feeds locally (CISA KEV, FIRST EPSS) plus any NVD CVE/CPE data
cached on demand, so option 8 can match offline against detected technologies. The schema and
indexes follow the module spec.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from config import PROJECT_ROOT

VULNDB_DIR = PROJECT_ROOT / "data" / "vulndb"
DB_PATH = VULNDB_DIR / "hades_vulndb.sqlite"
FEEDS_DIR = VULNDB_DIR / "feeds"
ALIASES_PATH = VULNDB_DIR / "aliases.json"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cves (
    cve_id          TEXT PRIMARY KEY,
    source          TEXT,
    published       TEXT,
    last_modified   TEXT,
    description     TEXT,
    cvss_score      REAL,
    cvss_vector     TEXT,
    severity        TEXT,
    cwe             TEXT,
    references_json TEXT,
    raw_json        TEXT
);
CREATE TABLE IF NOT EXISTS cpe_matches (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id                   TEXT,
    cpe_uri                  TEXT,
    vendor                   TEXT,
    product                  TEXT,
    exact_version            TEXT,
    version_start_including  TEXT,
    version_start_excluding  TEXT,
    version_end_including    TEXT,
    version_end_excluding    TEXT,
    vulnerable               INTEGER
);
CREATE TABLE IF NOT EXISTS cpe_dictionary (
    cpe_uri     TEXT PRIMARY KEY,
    vendor      TEXT,
    product     TEXT,
    version     TEXT,
    title       TEXT,
    deprecated  INTEGER,
    raw_json    TEXT
);
CREATE TABLE IF NOT EXISTS exploit_intel (
    cve_id                  TEXT PRIMARY KEY,
    kev                     INTEGER DEFAULT 0,
    kev_vendor_project      TEXT,
    kev_product             TEXT,
    kev_vulnerability_name  TEXT,
    kev_date_added          TEXT,
    kev_due_date            TEXT,
    kev_required_action     TEXT,
    epss                    REAL,
    epss_percentile         REAL
);
CREATE TABLE IF NOT EXISTS aliases (
    detected_name      TEXT PRIMARY KEY,
    normalized_vendor  TEXT,
    normalized_product TEXT,
    cpe_prefix         TEXT,
    package_ecosystem  TEXT,
    notes              TEXT
);
CREATE TABLE IF NOT EXISTS sync_state (
    source        TEXT PRIMARY KEY,
    last_sync     TEXT,
    total_records INTEGER,
    local_path    TEXT
);
CREATE INDEX IF NOT EXISTS idx_cves_id          ON cves(cve_id);
CREATE INDEX IF NOT EXISTS idx_cves_severity    ON cves(severity);
CREATE INDEX IF NOT EXISTS idx_cpe_cve          ON cpe_matches(cve_id);
CREATE INDEX IF NOT EXISTS idx_cpe_vendor_prod  ON cpe_matches(vendor, product);
CREATE INDEX IF NOT EXISTS idx_cpe_uri          ON cpe_matches(cpe_uri);
CREATE INDEX IF NOT EXISTS idx_intel_cve        ON exploit_intel(cve_id);
CREATE INDEX IF NOT EXISTS idx_intel_kev        ON exploit_intel(kev);
CREATE INDEX IF NOT EXISTS idx_intel_epss       ON exploit_intel(epss);
"""


def get_conn(path: Path | None = None) -> sqlite3.Connection:
    """Open (creating the directory if needed) and initialise the vuln database."""
    p = path or DB_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    return conn


def db_exists(path: Path | None = None) -> bool:
    """True if the database file exists and has at least KEV or EPSS synced."""
    p = path or DB_PATH
    if not p.is_file():
        return False
    try:
        conn = sqlite3.connect(str(p))
        row = conn.execute("SELECT COUNT(*) FROM sync_state WHERE source IN ('cisa_kev','epss')").fetchone()
        conn.close()
        return bool(row and row[0])
    except sqlite3.Error:
        return False


def set_sync_state(conn: sqlite3.Connection, source: str, total: int, local_path: str = "") -> None:
    conn.execute(
        "INSERT INTO sync_state(source,last_sync,total_records,local_path) VALUES(?,?,?,?) "
        "ON CONFLICT(source) DO UPDATE SET last_sync=excluded.last_sync, "
        "total_records=excluded.total_records, local_path=excluded.local_path",
        (source, datetime.now(timezone.utc).isoformat(), total, local_path),
    )
    conn.commit()


def db_age_days(path: Path | None = None) -> float | None:
    """Age (in days) of the most recent successful sync, or None if never synced."""
    p = path or DB_PATH
    if not p.is_file():
        return None
    try:
        conn = sqlite3.connect(str(p))
        row = conn.execute("SELECT MAX(last_sync) FROM sync_state").fetchone()
        conn.close()
    except sqlite3.Error:
        return None
    if not row or not row[0]:
        return None
    last = datetime.fromisoformat(row[0])
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - last).total_seconds() / 86400.0
