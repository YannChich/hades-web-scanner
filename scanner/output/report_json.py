"""
report_json — exports scan findings as a structured JSON report.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from scanner.engine import Finding

from scanner import evidence as ev
from scanner.output.attack_path import build_attack_path
from scanner.output.scorer import calculate_score
from scanner.severity import severity_counts


def _retest_block(retest: dict | None) -> dict | None:
    """Serialisable retest summary for the JSON report (None when --retest wasn't used).

    Current findings live in the top-level ``findings`` array (each carries its own ``retest``
    status), so here we only summarise counts, the previous run, and the ``fixed`` issues that
    have no current finding object.
    """
    if not retest:
        return None
    return {
        "baseline":       retest.get("baseline", False),
        "previous_date":  retest.get("previous_date"),
        "previous_score": retest.get("previous_score"),
        "previous_grade": retest.get("previous_grade"),
        "counts": {
            "new":           len(retest.get("new", [])),
            "still_present": len(retest.get("still_present", [])),
            "fixed":         len(retest.get("fixed", [])),
        },
        "fixed": [
            {"id": e.get("id"), "module": e.get("module"),
             "title": e.get("title"), "severity": e.get("severity")}
            for e in retest.get("fixed", [])
        ],
    }


def generate_json(
    findings: list[Finding],
    url: str,
    score: int,
    output_path: str = "reports",
    retest: dict | None = None,
) -> str | None:
    """
    Serialise findings to JSON and write to output_path/webscan_report_TIMESTAMP.json.
    Returns the file path on success, None on error.
    """
    _, grade = calculate_score(findings)
    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y%m%d_%H%M%S")

    counts = severity_counts(findings)

    payload = {
        "scan_date":       now.isoformat(),
        "target":          url,
        "score":           score,
        "grade":           grade,
        "findings_count":  counts,
        "retest":          _retest_block(retest),
        "attack_path":     build_attack_path(findings, url),
        "findings": [
            {
                "id":             f.finding_id,
                "module":         f.module,
                "title":          f.title,
                "description":    f.description,
                "severity":       f.severity.value,
                "retest":         (f.raw or {}).get("retest"),
                "confidence":     (f.raw or {}).get("confidence", ""),
                "verified":       bool(getattr(f, "verified", False)),
                "verification":   getattr(f, "verification", "") or "",
                "cvss":           f.cvss,
                "cwe":            f.cwe,
                "owasp":          f.owasp,
                "mitre_attack":   f.mitre,
                "evidence":       ev.as_list((f.raw or {}).get("evidence")),
                "references":     (f.raw or {}).get("references", []),
                "recommendation": f.recommendation,
                "poc":            f.poc,
                "redteam_tools":  f.redteam_tools,
                "playbooks":      [
                    {"name": s.get("name"), "url": s.get("href"),
                     "mitre": s.get("mitre", [])}
                    for s in (f.skill_refs or [])
                ],
                "remediation_playbooks": [
                    {"name": s.get("name"), "url": s.get("href"),
                     "mitre": s.get("mitre", [])}
                    for s in (getattr(f, "remediation_refs", None) or [])
                ],
                "raw":            f.raw,
            }
            for f in findings
        ],
    }

    os.makedirs(output_path, exist_ok=True)
    file_path = os.path.join(output_path, f"webscan_report_{timestamp}.json")

    try:
        with open(file_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
        logger.info(f"JSON report saved: {file_path}")
        return file_path
    except OSError as exc:
        logger.error(f"report_json: failed to write {file_path}: {exc}")
        return None
