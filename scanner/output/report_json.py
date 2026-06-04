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

from scanner.output.scorer import calculate_score


def generate_json(
    findings: list[Finding],
    url: str,
    score: int,
    output_path: str = "reports",
) -> str | None:
    """
    Serialise findings to JSON and write to output_path/webscan_report_TIMESTAMP.json.
    Returns the file path on success, None on error.
    """
    _, grade = calculate_score(findings)
    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y%m%d_%H%M%S")

    # Severity counts
    counts: dict[str, int] = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for f in findings:
        counts[f.severity.value] += 1

    payload = {
        "scan_date":       now.isoformat(),
        "target":          url,
        "score":           score,
        "grade":           grade,
        "findings_count":  counts,
        "findings": [
            {
                "module":         f.module,
                "title":          f.title,
                "description":    f.description,
                "severity":       f.severity.value,
                "recommendation": f.recommendation,
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
