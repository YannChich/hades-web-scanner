"""
report_schema — the published JSON Schema for Hades' JSON report (``reports/*.json``).

This is the *contract* for anyone who consumes a Hades JSON report programmatically (a CI
dashboard, a triage script, a ticket importer). ``hades --schema`` dumps it to stdout, and the
test-suite validates a freshly generated report against it, so the two can never silently drift.

The schema is JSON Schema draft 2020-12, hand-written (no third-party dependency) and deliberately
permissive about *extra* keys: Hades may add fields over time, so objects stay ``additionalProperties:
true`` while the fields that downstream tooling relies on are pinned by name and type. It mirrors the
payload built in :mod:`scanner.output.report_json`.
"""
from __future__ import annotations

SCHEMA_VERSION = "1.0.0"
SCHEMA_ID = "https://github.com/YannChich/hades-web-scanner/report.schema.json"

# Severity vocabulary, shared with scanner.severity (duplicated as literals here so the schema is a
# standalone artefact with no import-time coupling to the engine).
_SEVERITIES = ["critical", "high", "medium", "low", "info"]
_RETEST_STATES = ["new", "still-present"]

_SEVERITY_COUNTS = {
    "type": "object",
    "description": "Number of findings at each severity in this run.",
    "properties": {s: {"type": "integer", "minimum": 0} for s in _SEVERITIES},
    "additionalProperties": True,
}

_FINDING = {
    "type": "object",
    "description": "A single finding. Extra keys may appear; the ones below are the stable contract.",
    "required": ["id", "module", "title", "severity"],
    "properties": {
        "id":            {"type": "string", "description": "Stable finding ID, e.g. SQLI-3F9A."},
        "module":        {"type": "string", "description": "The scanner module that reported it."},
        "title":         {"type": "string"},
        "description":   {"type": "string"},
        "severity":      {"type": "string", "enum": _SEVERITIES},
        "retest":        {"type": ["string", "null"], "enum": _RETEST_STATES + [None],
                          "description": "Set only on a --retest run."},
        "first_seen":    {"type": ["string", "null"],
                          "description": "ISO-8601 time this finding was first observed (--retest)."},
        "days_open":     {"type": ["integer", "null"], "minimum": 0,
                          "description": "Whole days the finding has been outstanding (--retest)."},
        "confidence":    {"type": "string"},
        "verified":      {"type": "boolean",
                          "description": "True when backed by active request/response proof."},
        "verification":  {"type": "string"},
        "cvss":          {"type": ["number", "null"], "minimum": 0, "maximum": 10},
        "cwe":           {"type": "string"},
        "owasp":         {"type": "string"},
        "mitre_attack":  {"type": "array", "items": {"type": "string"}},
        "evidence":      {"type": "array", "items": {"type": "string"}},
        "references":    {"type": "array"},
        "recommendation": {"type": "string"},
        "poc":           {"type": "string"},
        "redteam_tools": {"type": "array", "items": {"type": "string"}},
        "playbooks":     {"type": "array"},
        "remediation_playbooks": {"type": "array"},
        "raw":           {"type": ["object", "null"]},
    },
    "additionalProperties": True,
}

_RETEST_BLOCK = {
    "type": ["object", "null"],
    "description": "Present (non-null) only on a --retest run; summarises change vs the last scan.",
    "properties": {
        "baseline":       {"type": "boolean"},
        "previous_date":  {"type": ["string", "null"]},
        "previous_score": {"type": ["integer", "null"]},
        "previous_grade": {"type": ["string", "null"]},
        "counts": {
            "type": "object",
            "properties": {
                "new":           {"type": "integer", "minimum": 0},
                "still_present": {"type": "integer", "minimum": 0},
                "fixed":         {"type": "integer", "minimum": 0},
            },
            "additionalProperties": True,
        },
        "fixed": {"type": "array", "items": {"type": "object"}},
    },
    "additionalProperties": True,
}

REPORT_SCHEMA: dict = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": SCHEMA_ID,
    "title": "Hades JSON report",
    "description": "The structure Hades writes to reports/webscan_report_*.json.",
    "x-hades-schema-version": SCHEMA_VERSION,
    "type": "object",
    "required": ["scan_date", "target", "score", "grade", "findings_count", "findings"],
    "properties": {
        "scan_date":      {"type": "string", "description": "ISO-8601 UTC time the scan finished."},
        "target":         {"type": "string", "description": "The scanned URL."},
        "score":          {"type": "integer", "minimum": 0, "maximum": 100},
        "grade":          {"type": "string", "description": "Letter grade derived from the score."},
        "findings_count": _SEVERITY_COUNTS,
        "retest":         _RETEST_BLOCK,
        "coverage":       {"type": ["object", "null"]},
        "attack_path":    {},
        "findings":       {"type": "array", "items": _FINDING},
    },
    "additionalProperties": True,
}


def get_schema() -> dict:
    """Return a copy-safe reference to the JSON Schema dict for the Hades JSON report."""
    return REPORT_SCHEMA


def schema_json(indent: int = 2) -> str:
    """The schema serialised as a JSON string (what ``hades --schema`` prints)."""
    import json
    return json.dumps(REPORT_SCHEMA, indent=indent)
