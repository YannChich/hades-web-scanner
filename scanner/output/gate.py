"""
gate — the CI exit-code contract (``--fail-on <severity>``).

Scanners earn their place in a pipeline by being able to *fail the build*: ``nuclei -severity high``,
``trivy --exit-code 1 --severity CRITICAL`` and friends all return non-zero when something at or above
a chosen severity is present, so a merge can be blocked automatically. This module gives Hades the same
contract on top of the existing scan — no new requests, no new findings, just a decision and an exit
code read off the final (already suppressed/scored) finding list.

It is intentionally tiny and pure so it is trivial to unit-test and impossible to make abort a scan:

* :func:`gate_findings` — the findings at or above a severity threshold (most-severe-inclusive).
* :func:`should_fail`   — whether the gate trips for a threshold.
* :data:`EXIT_FAIL_ON`  — the process exit code used when it does (distinct from the generic error 1).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Iterable

from scanner.severity import SEVERITY_ORDER, severity_rank

if TYPE_CHECKING:
    from scanner.engine import Finding

# Exit code returned when the --fail-on gate trips. Kept distinct from argparse's usage error (2 is
# argparse's own code, so we use a dedicated, documented value) and the generic unhandled-error 1.
EXIT_FAIL_ON: int = 3

# The severities a user may gate on, least-severe first (handy for CLI choices / docs).
FAIL_ON_CHOICES: list[str] = list(reversed(SEVERITY_ORDER))


def _sev_value(f: "Finding") -> str:
    sev = getattr(f, "severity", None)
    return sev.value if hasattr(sev, "value") else str(sev)


def gate_findings(findings: Iterable["Finding"], threshold: str | None) -> list["Finding"]:
    """Findings whose severity is at least as severe as *threshold* (most-severe-inclusive).

    ``threshold`` is a severity string (``"critical"`` … ``"info"``). A falsy or unknown threshold
    disables the gate and returns ``[]`` (fail-open — a typo must never silently block a pipeline).
    """
    if not threshold:
        return []
    key = str(threshold).strip().lower()
    if key not in SEVERITY_ORDER:
        return []
    limit = severity_rank(key)                      # critical=0 … info=4
    return [f for f in findings if severity_rank(_sev_value(f)) <= limit]


def should_fail(findings: Iterable["Finding"], threshold: str | None) -> bool:
    """True when at least one finding meets or exceeds the gate threshold."""
    return bool(gate_findings(findings, threshold))
