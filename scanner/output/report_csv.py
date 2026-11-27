"""
report_csv — emit scan findings as a CSV for spreadsheet triage / tracker import.

The HTML report is for reading, JSON/SARIF are for tooling, Markdown is for pasting — but triage
teams live in spreadsheets and issue trackers that import CSV (Excel, Google Sheets, Jira, a GRC
tool). This renderer turns a finished scan into **one row per finding** with the columns a triager
actually sorts and filters on: severity, module, title, CWE, OWASP, MITRE, CVSS, confidence, whether
Hades *verified* it, the retest status and the proof URL.

It is a pure, dependency-free renderer built on the stdlib ``csv`` module (correct quoting for
embedded commas / quotes / newlines): :func:`build_csv` returns the string (easy to unit-test) and
:func:`generate_csv` writes it, degrading to ``None`` on any error so reporting can never abort a scan.
"""
from __future__ import annotations

import csv
import io
import os
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from loguru import logger

from scanner.severity import sort_by_severity

if TYPE_CHECKING:
    from scanner.engine import Finding

# Column order is stable — downstream imports and saved spreadsheet views depend on it, so new
# columns are only ever appended, never reordered.
COLUMNS: list[str] = [
    "id", "severity", "confidence", "verified", "verification", "module", "title",
    "cwe", "owasp", "mitre", "cvss", "retest", "url",
]


def _sev_value(f: "Finding") -> str:
    sev = getattr(f, "severity", None)
    return sev.value if hasattr(sev, "value") else str(sev)


def _proof_url(f: "Finding") -> str:
    """The most specific URL that locates the finding (proof URL > url > path), or ''."""
    raw = f.raw or {}
    return str(raw.get("proof_url") or raw.get("url") or raw.get("path") or "")


def _row(f: "Finding") -> dict[str, str]:
    raw = f.raw or {}
    return {
        "id":           f.finding_id,
        "severity":     _sev_value(f),
        "confidence":   str(raw.get("confidence", "")),
        "verified":     "yes" if bool(getattr(f, "verified", False)) else "no",
        "verification": getattr(f, "verification", "") or "",
        "module":       f.module,
        "title":        f.title,
        "cwe":          f.cwe or "",
        "owasp":        f.owasp or "",
        "mitre":        " ".join(f.mitre) if f.mitre else "",
        "cvss":         "" if f.cvss is None else f"{f.cvss:g}",
        "retest":       str(raw.get("retest", "") or ""),
        "url":          _proof_url(f),
    }


def build_csv(findings: list["Finding"]) -> str:
    """Render findings as a CSV string (header + one row per finding, most-severe first)."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=COLUMNS, extrasaction="ignore",
                            lineterminator="\n")
    writer.writeheader()
    for f in sort_by_severity(findings, key=_sev_value):
        writer.writerow(_row(f))
    return buf.getvalue()


def generate_csv(findings: list["Finding"], url: str, output_path: str = "reports") -> str | None:
    """Write findings to ``output_path/webscan_report_TIMESTAMP.csv``.

    ``url`` is accepted for signature parity with the other exporters (not embedded in the CSV
    body, which is one clean row per finding). Returns the path, or ``None`` on error (never raises).
    """
    try:
        doc = build_csv(findings)
        os.makedirs(output_path, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        file_path = os.path.join(output_path, f"webscan_report_{timestamp}.csv")
        with open(file_path, "w", encoding="utf-8", newline="") as fh:
            fh.write(doc)
        logger.info(f"CSV report saved: {file_path}")
        return file_path
    except Exception as exc:  # noqa: BLE001 — reporting must never abort a scan
        logger.error(f"report_csv: failed to write CSV: {exc}")
        return None
