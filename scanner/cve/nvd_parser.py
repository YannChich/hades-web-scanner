"""nvd_parser — parse an NVD 2.0 API response into cves rows and cpe_matches rows."""
from __future__ import annotations

import json
import sqlite3


def parse_vulnerability(vuln: dict) -> tuple[dict, list[dict]]:
    """Parse a single NVD 2.0 `vulnerabilities[]` item -> (cve_row, cpe_match_rows)."""
    cve = vuln.get("cve", {})
    cid = cve.get("id", "")

    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break

    score: float | None = None
    vector = ""
    severity = ""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m = metrics[key][0]
            data = m.get("cvssData", {})
            score = data.get("baseScore")
            vector = data.get("vectorString", "")
            severity = (m.get("baseSeverity") or data.get("baseSeverity") or "").lower()
            break

    cwe = ""
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            val = d.get("value", "")
            if val.startswith("CWE-"):
                cwe = val
                break
        if cwe:
            break

    references = [r.get("url") for r in cve.get("references", []) if r.get("url")]

    cve_row = {
        "cve_id": cid, "source": "nvd",
        "published": cve.get("published", ""), "last_modified": cve.get("lastModified", ""),
        "description": description, "cvss_score": score, "cvss_vector": vector,
        "severity": severity, "cwe": cwe, "references": references,
    }

    matches: list[dict] = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for cm in node.get("cpeMatch", []):
                crit = cm.get("criteria", "")
                parts = crit.split(":")          # cpe:2.3:a:vendor:product:version:...
                vendor = parts[3] if len(parts) > 3 else ""
                product = parts[4] if len(parts) > 4 else ""
                exact = parts[5] if len(parts) > 5 and parts[5] not in ("*", "-") else ""
                matches.append({
                    "cve_id": cid, "cpe_uri": crit, "vendor": vendor, "product": product,
                    "exact_version": exact,
                    "version_start_including": cm.get("versionStartIncluding", ""),
                    "version_start_excluding": cm.get("versionStartExcluding", ""),
                    "version_end_including": cm.get("versionEndIncluding", ""),
                    "version_end_excluding": cm.get("versionEndExcluding", ""),
                    "vulnerable": 1 if cm.get("vulnerable") else 0,
                })
    return cve_row, matches


def ingest(conn: sqlite3.Connection, nvd_json: dict) -> int:
    """Upsert every CVE + its CPE matches from an NVD 2.0 response. Returns CVE count."""
    n = 0
    for vuln in nvd_json.get("vulnerabilities", []):
        cve_row, matches = parse_vulnerability(vuln)
        if not cve_row["cve_id"]:
            continue
        conn.execute(
            "INSERT INTO cves(cve_id,source,published,last_modified,description,cvss_score,"
            "cvss_vector,severity,cwe,references_json,raw_json) VALUES(?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(cve_id) DO UPDATE SET source='nvd', published=excluded.published, "
            "last_modified=excluded.last_modified, description=excluded.description, "
            "cvss_score=excluded.cvss_score, cvss_vector=excluded.cvss_vector, "
            "severity=excluded.severity, cwe=excluded.cwe, references_json=excluded.references_json",
            (cve_row["cve_id"], "nvd", cve_row["published"], cve_row["last_modified"],
             cve_row["description"], cve_row["cvss_score"], cve_row["cvss_vector"],
             cve_row["severity"], cve_row["cwe"], json.dumps(cve_row["references"]), ""),
        )
        conn.execute("DELETE FROM cpe_matches WHERE cve_id=?", (cve_row["cve_id"],))
        for m in matches:
            conn.execute(
                "INSERT INTO cpe_matches(cve_id,cpe_uri,vendor,product,exact_version,"
                "version_start_including,version_start_excluding,version_end_including,"
                "version_end_excluding,vulnerable) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (m["cve_id"], m["cpe_uri"], m["vendor"], m["product"], m["exact_version"],
                 m["version_start_including"], m["version_start_excluding"],
                 m["version_end_including"], m["version_end_excluding"], m["vulnerable"]),
            )
        n += 1
    conn.commit()
    return n
