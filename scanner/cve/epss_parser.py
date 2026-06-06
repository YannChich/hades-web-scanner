"""epss_parser — parse the FIRST EPSS scores CSV into the DB (cve, epss, percentile)."""
from __future__ import annotations

import sqlite3


def parse(csv_text: str) -> list[tuple]:
    """Pure parse: EPSS CSV text -> list of (cve_id, epss, percentile)."""
    rows: list[tuple] = []
    for line in csv_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) < 3 or parts[0].lower() == "cve":
            continue
        try:
            rows.append((parts[0].strip(), float(parts[1]), float(parts[2])))
        except ValueError:
            continue
    return rows


def ingest(conn: sqlite3.Connection, csv_text: str) -> int:
    rows = parse(csv_text)
    conn.executemany(
        "INSERT INTO exploit_intel(cve_id,epss,epss_percentile) VALUES(?,?,?) "
        "ON CONFLICT(cve_id) DO UPDATE SET epss=excluded.epss, epss_percentile=excluded.epss_percentile",
        rows,
    )
    conn.commit()
    return len(rows)
