"""
waf_detect — identifies WAF and CDN providers protecting the target.

Fingerprints Cloudflare, CloudFront, Akamai, Sucuri, and other common
providers via response headers. Falls back to a generic probe: sending a
benign XSS payload and checking whether the response is blocked (403/406).
"""
from __future__ import annotations

from dataclasses import dataclass

import httpx
from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "waf_detect"

# Probe payload — obviously malicious-looking but harmless; a real WAF will block it.
_WAF_PROBE = "?q=<script>alert(1)</script>&id=1'%20OR%201=1--"
# Only 403/406 are reliable "this payload was blocked" signals. 429 (rate limit — possibly our own
# scan) and 503 (server unavailable) are too ambiguous to attribute to a WAF and caused false positives.
_BLOCK_CODES = {403, 406}


@dataclass
class _Signature:
    name: str
    check_header: str       # response header name (lowercase)
    check_value: str = ""   # substring to match in value; "" means presence-only


_SIGNATURES: list[_Signature] = [
    _Signature("Cloudflare",        "cf-ray"),
    _Signature("Cloudflare",        "server",         "cloudflare"),
    _Signature("AWS CloudFront",    "x-amz-cf-id"),
    _Signature("AWS CloudFront",    "x-amz-cf-pop"),
    _Signature("Akamai",            "x-check-cacheable"),
    _Signature("Akamai",            "x-akamai-transformed"),
    _Signature("Sucuri",            "x-sucuri-id"),
    _Signature("Sucuri",            "x-sucuri-cache"),
    _Signature("Imperva / Incapsula","x-iinfo"),
    _Signature("Imperva / Incapsula","x-cdn",         "imperva"),
    _Signature("Fastly",            "x-served-by",    "cache"),
    _Signature("F5 BIG-IP ASM",     "x-wa-info"),
    _Signature("Barracuda",         "x-barracuda-connect"),
    _Signature("ModSecurity",       "server",         "mod_security"),
]


def _finding(
    title: str,
    description: str,
    severity: Severity,
    recommendation: str = "",
    raw: dict | None = None,
) -> Finding:
    return Finding(
        module=MODULE,
        title=title,
        description=description,
        severity=severity,
        recommendation=recommendation,
        raw=raw or {},
    )


def _fingerprint_headers(headers: httpx.Headers) -> list[str]:
    """Return unique provider names matched from response headers."""
    detected: list[str] = []
    seen: set[str] = set()

    for sig in _SIGNATURES:
        if sig.name in seen:
            continue
        value = headers.get(sig.check_header, "")
        if value and (not sig.check_value or sig.check_value.lower() in value.lower()):
            detected.append(sig.name)
            seen.add(sig.name)

    return detected


def _probe_generic_waf(engine: ScanEngine, baseline_status: int) -> bool:
    """Send a WAF-triggering probe; True only if the *payload* is specifically blocked.

    Requires that the clean homepage was NOT already returning a block code, so a site that
    blanket-403s (or is simply down) is not mistaken for a WAF reacting to the payload.
    """
    if baseline_status in _BLOCK_CODES:
        return False
    probe_url = engine.url.rstrip("/") + _WAF_PROBE
    try:
        resp = engine.request("GET", probe_url)
        return resp.status_code in _BLOCK_CODES
    except httpx.HTTPError as exc:
        logger.debug(f"waf_detect: probe request failed: {exc}")
        return False


def run(engine: ScanEngine) -> list[Finding]:
    findings: list[Finding] = []

    try:
        resp = engine.get()
    except httpx.HTTPError as exc:
        logger.warning(f"waf_detect: baseline request failed: {exc}")
        return []

    detected = _fingerprint_headers(resp.headers)

    for provider in detected:
        findings.append(_finding(
            f"WAF/CDN Detected: {provider}",
            f"{provider} is protecting this target (identified via response headers).",
            Severity.INFO,
            raw={"provider": provider, "detection_method": "header_fingerprint"},
        ))

    if not detected:
        # Fall back to an active probe, compared against the clean homepage status.
        blocked = _probe_generic_waf(engine, resp.status_code)
        if blocked:
            findings.append(_finding(
                "Generic WAF Detected",
                f"An unidentified WAF blocked a malicious-looking probe to {engine.url + _WAF_PROBE} "
                f"(HTTP {sorted(_BLOCK_CODES)}) while the clean homepage returned {resp.status_code}. "
                "Provider could not be fingerprinted.",
                Severity.INFO,
                recommendation="The WAF provider is unknown; header signatures did not match any known product.",
                raw={"detection_method": "probe_blocked", "confidence": "medium"},
            ))
        else:
            # "No WAF" is a hardening recommendation, not a vulnerability — keep it informational.
            findings.append(_finding(
                "No WAF / CDN Detected",
                "No known WAF or CDN signatures were found in response headers, and a malicious "
                "probe was not blocked. The origin server may be directly exposed.",
                Severity.INFO,
                recommendation=(
                    "Consider placing the application behind a WAF or CDN such as "
                    "Cloudflare, AWS CloudFront, or Akamai to filter malicious traffic."
                ),
                raw={"detection_method": "none", "confidence": "high"},
            ))

    return findings
