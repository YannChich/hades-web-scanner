"""
scorer — aggregates scan findings into a 0–100 security score with a letter grade.

The score starts at 100 and subtracts a penalty per finding. Penalties come from
config.SEVERITY_PENALTY (derived from the SEVERITY_SCORES risk bands), are damped by
diminishing returns within each module (so one noisy module can't sink the score),
and are scaled by an optional per-finding confidence (raw["confidence"]).
"""
from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

from config import SCORE_CONFIDENCE, SCORE_DIMINISHING, SEVERITY_PENALTY

if TYPE_CHECKING:
    from scanner.engine import Finding

_SEVERITY_RANK: dict[str, int] = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0,
}

_GRADES: list[tuple[int, str]] = [
    (90, "A"),
    (75, "B"),
    (60, "C"),
    (40, "D"),
    (0,  "F"),
]


def _diminish(index: int) -> float:
    """Weight for the *index*-th finding (0-based) within a module."""
    if index < len(SCORE_DIMINISHING):
        return SCORE_DIMINISHING[index]
    return SCORE_DIMINISHING[-1]


def _confidence_factor(finding: "Finding") -> float:
    conf = str(finding.raw.get("confidence", "high")).lower()
    return SCORE_CONFIDENCE.get(conf, 1.0)


def calculate_score(findings: list[Finding]) -> tuple[int, str]:
    """
    Return (score, grade) where score is 0–100.

    For each module, findings are ranked most-severe-first; the worst counts at full
    weight and each subsequent finding is damped by SCORE_DIMINISHING. Each penalty is
    also scaled by the finding's confidence. Grade: A ≥90, B ≥75, C ≥60, D ≥40, F <40.
    """
    by_module: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_module[f.module].append(f)

    total_penalty = 0.0
    for module_findings in by_module.values():
        # Most severe first so diminishing returns hit the lesser findings.
        ranked = sorted(
            module_findings,
            key=lambda f: _SEVERITY_RANK.get(f.severity.value, 0),
            reverse=True,
        )
        for i, f in enumerate(ranked):
            base = SEVERITY_PENALTY.get(f.severity.value, 0.0)
            if base == 0.0:
                continue
            total_penalty += base * _diminish(i) * _confidence_factor(f)

    score = max(0, round(100 - total_penalty))

    grade = "F"
    for threshold, letter in _GRADES:
        if score >= threshold:
            grade = letter
            break

    return score, grade


def score_findings(findings: list[Finding]) -> int:
    """Return the integer risk score 0–100 (drops the grade letter)."""
    score, _ = calculate_score(findings)
    return score
