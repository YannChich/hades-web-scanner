"""
version_matcher — version comparison, affected-range checks and confidence classification.

Robust enough for real CVE/CPE data: exact versions, partial versions, the four NVD range bounds
(start/end including/excluding), semantic versions, and suffixes like beta/rc/build. A release
always sorts above its own pre-releases (1.0.0 > 1.0.0-rc1).
"""
from __future__ import annotations

import re

# Lower rank = earlier (more "pre"). Unknown words rank high (treated as a normal token).
_PRE_RANK = {"alpha": 0, "a": 0, "beta": 1, "b": 1, "rc": 2, "pre": 2, "preview": 2, "dev": 0, "snapshot": 0}

_UNKNOWN = {"", "*", "-", "n/a", "unknown", "none", "latest"}


def version_known(v: str | None) -> bool:
    """True if *v* is a concrete version we can compare (contains a digit)."""
    if not v:
        return False
    s = str(v).strip().lower()
    return s not in _UNKNOWN and any(c.isdigit() for c in s)


def _tokens(v: str) -> list[str]:
    v = str(v).strip().lower()
    v = re.sub(r"^v", "", v)
    return [t for t in re.split(r"[.\-_+~ ]+", v) if t != ""]


def _cmp_token(a: str, b: str) -> int:
    an, bn = a.isdigit(), b.isdigit()
    if an and bn:
        ia, ib = int(a), int(b)
        return (ia > ib) - (ia < ib)
    if an and not bn:   # a numeric release token beats a pre-release word at the same slot
        return 1
    if bn and not an:
        return -1
    ra, rb = _PRE_RANK.get(a, 99), _PRE_RANK.get(b, 99)
    if ra != rb:
        return (ra > rb) - (ra < rb)
    return (a > b) - (a < b)


def version_compare(a: str, b: str) -> int:
    """Return -1/0/1 comparing version *a* to *b*."""
    ta, tb = _tokens(a), _tokens(b)
    for i in range(max(len(ta), len(tb))):
        x = ta[i] if i < len(ta) else "0"
        y = tb[i] if i < len(tb) else "0"
        c = _cmp_token(x, y)
        if c:
            return c
    return 0


def in_affected_range(version: str, match: dict) -> bool:
    """True if *version* falls inside the CPE match's affected range.

    A vulnerable match with no exact version and no bounds means *all* versions are affected.
    """
    if not version_known(version):
        return False
    exact = (match.get("exact_version") or "").strip()
    vsi = (match.get("version_start_including") or "").strip()
    vse = (match.get("version_start_excluding") or "").strip()
    vei = (match.get("version_end_including") or "").strip()
    vee = (match.get("version_end_excluding") or "").strip()

    if exact and exact not in _UNKNOWN:
        return version_compare(version, exact) == 0
    if not any([vsi, vse, vei, vee]):
        return True   # vulnerable, unbounded → every version of the product is affected
    if vsi and version_compare(version, vsi) < 0:
        return False
    if vse and version_compare(version, vse) <= 0:
        return False
    if vei and version_compare(version, vei) > 0:
        return False
    if vee and version_compare(version, vee) >= 0:
        return False
    return True


def affected_range_str(match: dict) -> str:
    """Human-readable affected range, e.g. '>= 1.0, < 1.18.1' or '= 1.2.3'."""
    exact = (match.get("exact_version") or "").strip()
    if exact and exact not in _UNKNOWN:
        return f"= {exact}"
    parts = []
    if match.get("version_start_including"):
        parts.append(f">= {match['version_start_including']}")
    if match.get("version_start_excluding"):
        parts.append(f"> {match['version_start_excluding']}")
    if match.get("version_end_including"):
        parts.append(f"<= {match['version_end_including']}")
    if match.get("version_end_excluding"):
        parts.append(f"< {match['version_end_excluding']}")
    return ", ".join(parts) if parts else "all versions"


def classify(version: str, match: dict, tech_confidence: float) -> str | None:
    """
    Confidence class for a (detected version, CPE match) pair, or None to skip
    (version is known and clearly NOT in the affected range → not vulnerable).
    """
    if not version_known(version):
        return "POSSIBLE"
    if in_affected_range(version, match):
        return "CONFIRMED" if tech_confidence >= 0.75 else "LIKELY"
    return None
