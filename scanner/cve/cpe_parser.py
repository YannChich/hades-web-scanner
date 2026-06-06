"""cpe_parser — parse NVD CPE 2.0 product entries into the cpe_dictionary table (optional source)."""
from __future__ import annotations

import json
import sqlite3


def parse(cpe_json: dict) -> list[dict]:
    """Pure parse: NVD CPE 2.0 response -> list of cpe_dictionary row dicts."""
    rows: list[dict] = []
    for item in cpe_json.get("products", []):
        cpe = item.get("cpe", {})
        uri = cpe.get("cpeName", "")
        if not uri:
            continue
        parts = uri.split(":")
        title = ""
        for t in cpe.get("titles", []):
            if t.get("lang") == "en":
                title = t.get("title", "")
                break
        rows.append({
            "cpe_uri": uri,
            "vendor": parts[3] if len(parts) > 3 else "",
            "product": parts[4] if len(parts) > 4 else "",
            "version": parts[5] if len(parts) > 5 else "",
            "title": title,
            "deprecated": 1 if cpe.get("deprecated") else 0,
        })
    return rows


def ingest(conn: sqlite3.Connection, cpe_json: dict) -> int:
    rows = parse(cpe_json)
    for r in rows:
        conn.execute(
            "INSERT INTO cpe_dictionary(cpe_uri,vendor,product,version,title,deprecated,raw_json) "
            "VALUES(?,?,?,?,?,?,?) ON CONFLICT(cpe_uri) DO UPDATE SET vendor=excluded.vendor, "
            "product=excluded.product, version=excluded.version, title=excluded.title, "
            "deprecated=excluded.deprecated",
            (r["cpe_uri"], r["vendor"], r["product"], r["version"], r["title"], r["deprecated"],
             json.dumps(r)),
        )
    conn.commit()
    return len(rows)
