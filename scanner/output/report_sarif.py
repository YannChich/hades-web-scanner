"""
report_sarif — emit findings as SARIF 2.1.0.

SARIF (Static Analysis Results Interchange Format) is the OASIS-standard JSON that GitHub code
scanning, Azure DevOps and most CI dashboards ingest natively. Exporting it lets a Hades scan light
up findings directly in a pull request's "Security" tab or a CI gate — the same way nuclei, CodeQL
and Semgrep results do — instead of living only in the HTML/JSON reports.

The mapping is deliberately conservative and schema-valid:

* one ``rule`` per distinct finding type (``finding_id``), carrying its CWE/OWASP/CVSS as tags and a
  ``security-severity`` score (GitHub uses it to bucket Critical/High/Medium/Low);
* one ``result`` per finding, with a ``level`` (error/warning/note) derived from severity, the
  target as the ``artifactLocation`` URI, and the evidence/recommendation in the message;
* ``partialFingerprints`` from the stable finding ID so re-scans dedupe cleanly in GitHub.

This module has no third-party dependencies and never raises to the caller — a serialisation problem
degrades to ``None`` so a scan is never aborted by its reporting layer.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from loguru import logger

from config import HADES_VERSION
from scanner import evidence as ev

if TYPE_CHECKING:
    from scanner.engine import Finding

_INFO_URI = "https://github.com/YannChich/hades-web-scanner"

# Severity → SARIF result level. SARIF has only error/warning/note, so critical+high collapse to
# "error" (the CVSS-derived security-severity below preserves the finer ranking for GitHub).
_LEVEL = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
    "info":     "note",
}

# GitHub buckets a result by its numeric security-severity; keep it aligned with our CVSS bands.
_SECURITY_SEVERITY = {
    "critical": "9.8",
    "high":     "7.5",
    "medium":   "5.3",
    "low":      "3.1",
    "info":     "0.0",
}


def _sev_value(f: "Finding") -> str:
    sev = f.severity
    return sev.value if hasattr(sev, "value") else str(sev)


def _rule_for(f: "Finding") -> dict[str, Any]:
    """A reusable SARIF ``reportingDescriptor`` (rule) for a finding type."""
    sev = _sev_value(f)
    tags = ["security"]
    if f.cwe:
        tags.append(f.cwe)
    if f.owasp:
        tags.append(f.owasp.split(" ")[0])          # just the "A03:2021" code
    tags.extend(f.mitre or [])

    help_uri = _INFO_URI
    if f.cwe and f.cwe.upper().startswith("CWE-") and f.cwe.split("-")[-1].isdigit():
        help_uri = f"https://cwe.mitre.org/data/definitions/{f.cwe.split('-')[-1]}.html"

    rule: dict[str, Any] = {
        "id":   f.finding_id or f.module,
        "name": f.module,
        "shortDescription": {"text": f.title},
        "fullDescription":  {"text": (f.description or f.title)[:1000]},
        "helpUri": help_uri,
        "defaultConfiguration": {"level": _LEVEL.get(sev, "warning")},
        "properties": {
            "tags": tags,
            "security-severity": _SECURITY_SEVERITY.get(sev, "0.0"),
        },
    }
    if f.recommendation:
        rule["help"] = {"text": f.recommendation}
    return rule


def _result_for(f: "Finding", url: str) -> dict[str, Any]:
    """A SARIF ``result`` for one finding, located at the scanned target."""
    sev = _sev_value(f)
    evidence = ev.as_list((f.raw or {}).get("evidence"))
    message = f.description or f.title
    if evidence:
        message += "\n\nEvidence:\n" + "\n".join(f"  - {line}" for line in evidence[:4])
    if f.recommendation:
        message += f"\n\nRecommendation: {f.recommendation}"

    proof_url = (f.raw or {}).get("proof_url") or url
    result: dict[str, Any] = {
        "ruleId": f.finding_id or f.module,
        "level":  _LEVEL.get(sev, "warning"),
        "message": {"text": message},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": proof_url},
            },
        }],
        "partialFingerprints": {"hadesFindingId": f.finding_id or f.module},
        "properties": {
            "severity":   sev,
            "confidence": (f.raw or {}).get("confidence", ""),
            "verified":   bool(getattr(f, "verified", False)),
            "cvss":       f.cvss,
        },
    }
    return result


def build_sarif(findings: list["Finding"], url: str) -> dict[str, Any]:
    """Build the SARIF 2.1.0 document (pure function — easy to unit-test)."""
    # One rule per distinct finding type, preserving first-seen order.
    rules: list[dict[str, Any]] = []
    seen: set[str] = set()
    for f in findings:
        rid = f.finding_id or f.module
        if rid not in seen:
            seen.add(rid)
            rules.append(_rule_for(f))

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Hades",
                    "informationUri": _INFO_URI,
                    "version": HADES_VERSION,
                    "rules": rules,
                },
            },
            "automationDetails": {
                "id": f"hades/{url}",
                "description": {"text": f"Hades web security scan of {url}"},
            },
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": datetime.now(timezone.utc).isoformat(),
            }],
            "results": [_result_for(f, url) for f in findings],
        }],
    }


def generate_sarif(findings: list["Finding"], url: str, output_path: str = "reports") -> str | None:
    """Serialise findings to SARIF and write ``output_path/webscan_report_TIMESTAMP.sarif``.

    Returns the file path on success, None on error (never raises — reporting must not abort a scan).
    """
    try:
        doc = build_sarif(findings, url)
        os.makedirs(output_path, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        file_path = os.path.join(output_path, f"webscan_report_{timestamp}.sarif")
        with open(file_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, default=str)
        logger.info(f"SARIF report saved: {file_path}")
        return file_path
    except Exception as exc:  # noqa: BLE001 — reporting must never abort a scan
        logger.error(f"report_sarif: failed to write SARIF: {exc}")
        return None
