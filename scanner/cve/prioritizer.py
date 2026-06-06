"""
prioritizer — the Hades CVE Priority Score (0-100).

Blends CVSS, EPSS, CISA KEV, internet exposure and detection confidence into a single, scan-aware
priority, then scales it by a confidence multiplier so a maybe-affected component never outranks a
confirmed, actively-exploited one.
"""
from __future__ import annotations

_CONFIDENCE_MULTIPLIER = {"CONFIRMED": 1.00, "LIKELY": 0.80, "POSSIBLE": 0.45, "INFO": 0.20}


def priority_score(cvss: float | None, epss: float | None, kev: bool,
                   internet_exposed: bool, confidence: str) -> int:
    """Return the 0-100 Hades CVE Priority Score."""
    cvss_pts = (min(cvss, 10.0) / 10.0) * 35 if cvss else 0.0   # max 35
    epss_pts = min(max(epss or 0.0, 0.0), 1.0) * 25             # max 25
    kev_pts = 25 if kev else 0                                  # max 25
    exposed_pts = 10 if internet_exposed else 0                 # max 10
    conf_bonus = 5 if confidence == "CONFIRMED" else (3 if confidence == "LIKELY" else 0)  # max 5

    base = cvss_pts + epss_pts + kev_pts + exposed_pts + conf_bonus
    score = round(base * _CONFIDENCE_MULTIPLIER.get(confidence, 0.5))
    return max(0, min(100, score))


def severity_from_score(score: int) -> str:
    """Map the priority score to a Hades severity (engine values are lowercase)."""
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 10:
        return "low"
    return "info"
