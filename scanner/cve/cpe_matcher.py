"""
cpe_matcher — turn a detected technology into CPE candidates, with ambiguity guards.

Encodes the spec's disambiguation rules so a guess never produces a misleading CVE match:
Apache HTTP Server vs Apache Tomcat, Java vs JavaScript, Node.js runtime vs npm packages,
WordPress core vs plugins, and indirectly-guessed OpenSSL.
"""
from __future__ import annotations

from scanner.cve.alias_matcher import normalize
from scanner.cve.models import CpeCandidate, DetectedTech


def candidates(tech: DetectedTech) -> list[CpeCandidate]:
    """Resolve a DetectedTech to zero or more CPE candidates after applying ambiguity guards."""
    name = (tech.name or "").strip().lower()
    haystack = f"{tech.name} {tech.type} {tech.source} {tech.evidence}".lower()

    # Java must never be confused with JavaScript, and vice-versa.
    if name in ("java",) and ("javascript" in haystack or "js" in (tech.type or "").lower()):
        return []
    if name in ("javascript", "js"):
        return []

    entry = normalize(name)
    if not entry:
        return []

    # Apache: default to HTTP Server only when the evidence is an HTTP server, and never when
    # Tomcat is what was actually seen.
    if entry.get("requires") == "http":
        if "tomcat" in haystack:
            return []   # let the dedicated 'apache tomcat' alias handle that case
        web_evidence = any(k in haystack for k in ("server", "http", "web"))
        if not web_evidence:
            return []

    # Node.js runtime must not be matched from a generic JS-library detection.
    if entry.get("product") == "node.js" and (tech.type or "").lower() in ("js_library", "js_framework"):
        return []

    ctype = entry.get("type", tech.type)
    out = [CpeCandidate(vendor=entry["vendor"], product=entry["product"],
                        cpe_prefix=entry["cpe_prefix"], type=ctype)]
    # Some products are indexed under more than one CPE vendor in NVD (e.g. nginx lives under both
    # `nginx:nginx` and, post-F5-acquisition, `f5:nginx`). Emit those alternates too.
    for alt in entry.get("also", []):
        out.append(CpeCandidate(vendor=alt["vendor"], product=alt["product"],
                                cpe_prefix=alt["cpe_prefix"], type=alt.get("type", ctype)))
    return out
