"""
cvelist_parser — parse a CVEProject/cvelistV5 record (CVE JSON 5.x) into a cves row.

Optional offline/raw source: clone https://github.com/CVEProject/cvelistV5 and feed individual
`CVE-YYYY-NNNN.json` records here. Not part of the default sync (the repo is large); the on-demand
NVD 2.0 API is the default CVE source.
"""
from __future__ import annotations


def parse_record(record: dict) -> dict | None:
    """Parse one cvelistV5 CVE record dict -> a cves row dict (or None if unusable)."""
    meta = record.get("cveMetadata", {})
    cid = meta.get("cveId")
    if not cid:
        return None
    cna = record.get("containers", {}).get("cna", {})

    description = ""
    for d in cna.get("descriptions", []):
        if d.get("lang", "").startswith("en"):
            description = d.get("value", "")
            break

    score: float | None = None
    vector = ""
    severity = ""
    for m in cna.get("metrics", []):
        for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
            if m.get(key):
                score = m[key].get("baseScore")
                vector = m[key].get("vectorString", "")
                severity = (m[key].get("baseSeverity") or "").lower()
                break

    cwe = ""
    for p in cna.get("problemTypes", []):
        for d in p.get("descriptions", []):
            if d.get("cweId"):
                cwe = d["cweId"]
                break
        if cwe:
            break

    references = [r.get("url") for r in cna.get("references", []) if r.get("url")]
    return {
        "cve_id": cid, "source": "cvelistv5",
        "published": meta.get("datePublished", ""), "last_modified": meta.get("dateUpdated", ""),
        "description": description, "cvss_score": score, "cvss_vector": vector,
        "severity": severity, "cwe": cwe, "references": references,
    }
