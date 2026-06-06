"""models — normalized data structures for the CVE Vulnerability Intelligence module."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DetectedTech:
    """A technology discovered on the target, normalised for CVE matching."""
    name: str
    version: str = ""
    type: str = ""            # web_server, cms, js_library, framework, language, runtime…
    source: str = ""          # where it was seen (Server header, meta generator, JS global…)
    confidence: float = 0.5   # 0..1 detection confidence
    evidence: str = ""        # human-readable proof string


@dataclass
class CpeCandidate:
    """An alias-resolved CPE target derived from a DetectedTech."""
    vendor: str
    product: str
    cpe_prefix: str
    type: str = ""


@dataclass
class CveFinding:
    """A matched, enriched and prioritised CVE result."""
    cve_id: str
    vendor: str
    product: str
    detected_version: str
    affected_range: str
    cvss_score: float | None
    cvss_vector: str
    severity: str                 # the CVE's own NVD severity
    cwe: str
    epss: float | None
    epss_percentile: float | None
    kev: bool
    confidence: str               # CONFIRMED | LIKELY | POSSIBLE | INFO
    priority_score: int           # 0..100 Hades CVE Priority Score
    priority_severity: str        # CRITICAL | HIGH | MEDIUM | LOW | INFO (from the score)
    evidence: str
    impact: str
    remediation: str
    references: list[str] = field(default_factory=list)
    description: str = ""
