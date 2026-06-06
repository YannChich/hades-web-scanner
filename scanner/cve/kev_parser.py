"""kev_parser — parse the CISA Known Exploited Vulnerabilities (KEV) JSON catalog into the DB."""
from __future__ import annotations

import sqlite3


def parse(kev_json: dict) -> list[dict]:
    """Pure parse: KEV catalog dict -> list of row dicts."""
    rows: list[dict] = []
    for v in kev_json.get("vulnerabilities", []):
        cid = v.get("cveID")
        if not cid:
            continue
        rows.append({
            "cve_id": cid,
            "kev_vendor_project": v.get("vendorProject", ""),
            "kev_product": v.get("product", ""),
            "kev_vulnerability_name": v.get("vulnerabilityName", ""),
            "kev_date_added": v.get("dateAdded", ""),
            "kev_due_date": v.get("dueDate", ""),
            "kev_required_action": v.get("requiredAction", ""),
            "short_description": v.get("shortDescription", ""),
        })
    return rows


def ingest(conn: sqlite3.Connection, kev_json: dict) -> int:
    """Write KEV rows into exploit_intel (kev=1) and seed minimal cves entries."""
    rows = parse(kev_json)
    for r in rows:
        conn.execute(
            "INSERT INTO exploit_intel(cve_id,kev,kev_vendor_project,kev_product,"
            "kev_vulnerability_name,kev_date_added,kev_due_date,kev_required_action) "
            "VALUES(?,1,?,?,?,?,?,?) "
            "ON CONFLICT(cve_id) DO UPDATE SET kev=1, kev_vendor_project=excluded.kev_vendor_project, "
            "kev_product=excluded.kev_product, kev_vulnerability_name=excluded.kev_vulnerability_name, "
            "kev_date_added=excluded.kev_date_added, kev_due_date=excluded.kev_due_date, "
            "kev_required_action=excluded.kev_required_action",
            (r["cve_id"], r["kev_vendor_project"], r["kev_product"], r["kev_vulnerability_name"],
             r["kev_date_added"], r["kev_due_date"], r["kev_required_action"]),
        )
        conn.execute(
            "INSERT OR IGNORE INTO cves(cve_id,source,description) VALUES(?,?,?)",
            (r["cve_id"], "cisa_kev", r["short_description"]),
        )
    conn.commit()
    return len(rows)
