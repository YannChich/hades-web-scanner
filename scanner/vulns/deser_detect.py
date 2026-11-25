"""
deser_detect — flag insecure-deserialization *indicators* (heuristic, no gadget execution).

Passing attacker-controlled, serialized objects into a native deserializer (Java
``ObjectInputStream``, PHP ``unserialize``, Python ``pickle``, Ruby ``Marshal``, .NET
``LosFormatter``/ViewState) is a classic path to remote code execution (CWE-502). The giveaway is a
request parameter, cookie or hidden form field that carries a *serialized blob* — each serialization
format has a recognisable magic prefix.

This module inspects the inputs the shared crawl already discovered — query parameters, cookies set by
the target, and hidden form fields — and reports any value whose shape matches a known serialization
format. It is **detection / heuristic only**: it *recognises* serialized data, it never crafts a
gadget chain, never sends a payload, and never deserializes anything itself. Findings are therefore
unverified indicators (``verified=False``) — proof would require an authorised, ``--exploit``-gated
test. Evidence shows only the format and a short, sanitised prefix, never the full value (a serialized
blob can embed sensitive data).
"""
from __future__ import annotations

import base64
import binascii
import re
from urllib.parse import parse_qsl, urlparse

import httpx
from loguru import logger

from scanner import evidence as ev
from scanner.engine import Finding, Severity, ScanEngine

MODULE = "deser_detect"

# Minimum length before a value is worth testing — short strings can't be a serialized object and
# only generate noise.
_MIN_LEN = 8

# ── Plaintext signatures (value seen as-is, not base64) ───────────────────────────────────────────
# PHP serialize(): O:<len>:"Class":… / a:<len>:{… / s:<len>:"…" — anchored, length-typed, low-FP.
_PHP_RE = re.compile(r'^(?:O:\d+:"[^"]+":\d+:\{|a:\d+:\{|s:\d+:"|b:[01];|i:\d+;|O:\+?\d+:")')
# Java serialized stream, hex-encoded: AC ED 00 05.
_JAVA_HEX_RE = re.compile(r"^aced0005", re.I)


def _looks_base64(value: str) -> bool:
    if len(value) < _MIN_LEN or len(value) % 4 not in (0, 2, 3):
        # tolerate missing padding; just require a base64 alphabet and reasonable length
        pass
    return bool(re.fullmatch(r"[A-Za-z0-9+/=_-]+", value)) and len(value) >= _MIN_LEN


def _b64_magic(value: str) -> bytes:
    """Decode the first bytes of a (possibly URL-safe, possibly unpadded) base64 value; b'' on failure."""
    raw = value.strip()
    raw = raw.replace("-", "+").replace("_", "/")
    raw += "=" * (-len(raw) % 4)
    try:
        return base64.b64decode(raw, validate=False)[:8]
    except (binascii.Error, ValueError):
        return b""


# format name → (severity, human note)
_HIGH = Severity.HIGH
_MED = Severity.MEDIUM


def _classify(name: str, value: str) -> tuple[str, Severity, str] | None:
    """Return (format, severity, prefix-shown) if *value* looks serialized, else None."""
    v = value.strip()
    if len(v) < _MIN_LEN:
        return None

    # .NET ViewState: the parameter name is the strongest, lowest-FP signal.
    if name.lower() in ("__viewstate", "viewstate") and _looks_base64(v):
        return ".NET ViewState (LosFormatter)", _MED, v[:16]

    # Plaintext PHP serialized object/array.
    if _PHP_RE.match(v):
        return "PHP serialized object", (_HIGH if v.startswith("O:") else _MED), v[:24]

    # Java serialized stream, hex-encoded.
    if _JAVA_HEX_RE.match(v):
        return "Java serialized stream (hex)", _HIGH, v[:16]

    # Base64-encoded blobs — decode the magic bytes and match the format precisely.
    if _looks_base64(v):
        magic = _b64_magic(v)
        if magic[:2] == b"\xac\xed":
            return "Java serialized stream", _HIGH, v[:16]
        if magic[:1] == b"\x80" and len(magic) > 1 and magic[1] in (2, 3, 4, 5):
            return "Python pickle", _HIGH, v[:16]
        if magic[:2] == b"\x04\x08":
            return "Ruby Marshal", _HIGH, v[:16]
        # PHP serialized object, base64-wrapped.
        try:
            decoded = base64.b64decode(v + "=" * (-len(v) % 4), validate=False).decode("latin-1")
            if _PHP_RE.match(decoded):
                return "PHP serialized object (base64)", _HIGH, v[:16]
        except (binascii.Error, ValueError, UnicodeDecodeError):
            pass
    return None


def _finding(location: str, name: str, fmt: str, severity: Severity, prefix: str,
             evidence: list[str]) -> Finding:
    return Finding(
        module=MODULE,
        title=f"Insecure Deserialization Indicator: {fmt} in {location} '{name}'",
        description=(f"The {location} '{name}' carries a value shaped like a {fmt}. If the server "
                     "deserializes this client-controlled data with a native deserializer, an attacker "
                     "can tamper with object state or, with a suitable gadget chain, achieve remote "
                     "code execution (CWE-502). Reported as a heuristic indicator — Hades recognised "
                     "the serialization format but did not build or send any gadget."),
        severity=severity,
        recommendation=("Never deserialize untrusted input with a native deserializer. Prefer a "
                        "data-only format (JSON/Protobuf) with strict schema validation; if a native "
                        "format is unavoidable, sign the blob (HMAC) and verify before deserializing, "
                        "enforce type allowlists (e.g. Java look-ahead ObjectInputFilter), and keep the "
                        ".NET ViewState MAC enabled."),
        raw={"location": location, "parameter": name, "format": fmt,
             "value_prefix": ev.note(prefix), "confidence": "medium", "verified": False,
             "evidence": evidence},
    )


def _candidates(engine: ScanEngine) -> list[tuple[str, str, str]]:
    """Collect (location, name, value) triples from params, cookies and hidden form fields."""
    out: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()

    def _add(location: str, name: str, value: str) -> None:
        key = (location, name)
        if value and key not in seen:
            seen.add(key)
            out.append((location, name, value))

    # Query parameters — the scan target itself plus everything the crawl parametrised.
    urls: list[str] = [engine.url] + list(getattr(engine.get_crawl(), "parametrised_urls", []))
    for url in urls:
        for pname, pval in parse_qsl(urlparse(url).query, keep_blank_values=True):
            _add("URL parameter", pname, pval)

    # Cookies the target set on us, plus hidden/typed form fields discovered in the crawl.
    try:
        for cname, cval in engine._client.cookies.items():  # noqa: SLF001 — read-only access
            _add("cookie", cname, cval)
    except Exception:  # noqa: BLE001 — cookie jar optional
        pass
    try:
        for form in getattr(engine.get_crawl(), "forms", []):
            for fname, fval in (form.fields or {}).items():
                _add("form field", fname, fval)
    except Exception:  # noqa: BLE001 — forms optional
        pass
    return out


def run(engine: ScanEngine) -> list[Finding]:
    # Make sure the shared client has seen the homepage so target-set cookies are in the jar.
    try:
        engine.get()
    except httpx.HTTPError:
        pass

    candidates = _candidates(engine)
    if not candidates:
        return [Finding(MODULE, "Insecure Deserialization: No Inspectable Inputs",
                        "No query parameters, cookies or form fields were available to inspect for "
                        "serialized blobs.",
                        Severity.INFO, "", {"confidence": "high"})]

    findings: list[Finding] = []
    for location, name, value in candidates:
        hit = _classify(name, value)
        if hit is None:
            continue
        fmt, severity, prefix = hit
        evidence = [ev.note(f"{location} '{name}' value starts with: {prefix}… "
                            f"(matched {fmt} signature; full value not stored)")]
        findings.append(_finding(location, name, fmt, severity, prefix, evidence))

    if not findings:
        return [Finding(MODULE, "Insecure Deserialization: No Indicators",
                        f"Inspected {len(candidates)} input(s) (parameters, cookies, form fields); none "
                        "matched a known serialization format (Java, PHP, Python pickle, Ruby Marshal, "
                        ".NET ViewState).",
                        Severity.INFO, "", {"inputs_inspected": len(candidates), "confidence": "high"})]
    logger.info(f"deser_detect: {len(findings)} deserialization indicator(s)")
    return findings
