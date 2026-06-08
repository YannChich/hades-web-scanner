"""
headers_check — audits HTTP security response headers.

Covers the core security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, Permissions-Policy), the modern cross-origin isolation headers
(COOP/COEP/CORP), and information-disclosure headers (Server, X-Powered-By, version
leaks). CSP is parsed directive-by-directive and HSTS is analysed for max-age,
includeSubDomains and preload. Cross-header logic adjusts severities (e.g. a CSP
frame-ancestors directive covers a missing X-Frame-Options).
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

import httpx
from loguru import logger

from scanner import evidence as ev
from scanner.engine import Finding, Severity, ScanEngine

MODULE = "headers_check"

_HSTS_MIN = 31536000  # 1 year


# ---------------------------------------------------------------------------
# Finding helpers
# ---------------------------------------------------------------------------

def _f(title: str, description: str, severity: Severity, recommendation: str,
       header: str, value: str | None, confidence: str = "high", **extra) -> Finding:
    raw = {"header": header, "value": value, "confidence": confidence}
    raw.update(extra)
    # Evidence is the exact header state that triggered the finding (present+value, or absent).
    raw.setdefault("evidence", [f"response header '{header}': {ev.note(value)[:160]}" if value
                                else f"response header '{header}': absent"])
    return Finding(module=MODULE, title=title, description=description,
                   severity=severity, recommendation=recommendation, raw=raw)


def _present(label: str, header: str, value: str) -> Finding:
    shown = value[:120] + ("…" if len(value) > 120 else "")
    return _f(f"{label}: Present", f"{label} is set: {shown}", Severity.INFO, "",
              header, value, confidence="high")


def _missing(label: str, header: str, severity: Severity, rec: str) -> Finding:
    return _f(f"{label}: Missing", f"The {label} header is absent from the response.",
              severity, rec, header, None)


# ---------------------------------------------------------------------------
# Content-Security-Policy — deep analysis
# ---------------------------------------------------------------------------

def _parse_csp(value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        toks = part.split()
        if toks:
            directives[toks[0].lower()] = [t.lower() for t in toks[1:]]
    return directives


def _check_csp(value: str) -> list[Finding]:
    findings = [_present("Content-Security-Policy", "content-security-policy", value)]
    d = _parse_csp(value)

    def add(sev, label, rec):
        findings.append(_f(f"CSP Weakness: {label}",
                           f"Content-Security-Policy issue — {label}.",
                           sev, rec, "content-security-policy", value, weakness=label))

    script_src = d.get("script-src", d.get("default-src", []))
    has_nonce_or_hash = any(s.startswith(("'nonce-", "'sha")) for s in script_src)

    if "default-src" not in d:
        add(Severity.MEDIUM, "no default-src fallback",
            "Add a restrictive default-src (e.g. default-src 'self') as a fallback for unset directives.")
    if "'unsafe-inline'" in script_src and not has_nonce_or_hash:
        add(Severity.MEDIUM, "script-src allows 'unsafe-inline'",
            "Remove 'unsafe-inline' from script-src; use nonces or hashes for inline scripts.")
    if "'unsafe-eval'" in script_src:
        add(Severity.MEDIUM, "script-src allows 'unsafe-eval'",
            "Remove 'unsafe-eval'; avoid eval()/new Function() and dynamic code.")
    if "*" in script_src:
        add(Severity.MEDIUM, "script-src is wildcard (*)",
            "Replace '*' with an explicit allowlist of trusted script origins.")
    if "data:" in script_src:
        add(Severity.MEDIUM, "script-src allows data: URIs",
            "Remove data: from script-src — it enables trivial XSS payloads.")
    if "object-src" not in d or "'none'" not in d.get("object-src", []):
        add(Severity.LOW, "object-src is not 'none'",
            "Set object-src 'none' to block plugins (Flash/Java) used in some XSS vectors.")
    if "base-uri" not in d:
        add(Severity.LOW, "no base-uri directive",
            "Add base-uri 'none' (or 'self') to prevent <base> tag injection.")
    if "frame-ancestors" not in d:
        add(Severity.LOW, "no frame-ancestors directive",
            "Add frame-ancestors 'none' or 'self' to defend against clickjacking via CSP.")
    return findings


# ---------------------------------------------------------------------------
# Strict-Transport-Security — HTTPS-aware analysis
# ---------------------------------------------------------------------------

def _check_hsts(value: str, is_https: bool) -> list[Finding]:
    if not is_https:
        return [_f("HSTS: Not Applicable (HTTP target)",
                   "Strict-Transport-Security is only honoured over HTTPS; the target was scanned over HTTP.",
                   Severity.INFO, "Serve the site over HTTPS and add HSTS there.",
                   "strict-transport-security", value or None)]
    if not value:
        return [_missing("Strict-Transport-Security (HSTS)", "strict-transport-security",
                         Severity.MEDIUM,
                         "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.")]

    findings = [_present("Strict-Transport-Security (HSTS)", "strict-transport-security", value)]
    low = value.lower()
    m = re.search(r"max-age\s*=\s*(\d+)", low)
    max_age = int(m.group(1)) if m else 0

    def add(sev, label, rec):
        findings.append(_f(f"HSTS Weakness: {label}",
                           f"Strict-Transport-Security issue — {label}.",
                           sev, rec, "strict-transport-security", value, weakness=label))

    if max_age == 0:
        add(Severity.MEDIUM, "max-age=0 disables HSTS",
            "max-age=0 instructs browsers to forget HSTS — set it to at least 31536000.")
    elif max_age < _HSTS_MIN:
        add(Severity.LOW, f"max-age={max_age} below recommended {_HSTS_MIN}",
            "Increase max-age to at least 31536000 (1 year).")
    if "includesubdomains" not in low:
        add(Severity.LOW, "missing includeSubDomains",
            "Add includeSubDomains so sub-domains are also forced onto HTTPS.")
    if "preload" not in low:
        add(Severity.LOW, "missing preload",
            "Add preload and submit the domain to hstspreload.org for built-in browser enforcement.")
    return findings


# ---------------------------------------------------------------------------
# Simple headers
# ---------------------------------------------------------------------------

def _check_xfo(value: str, csp: dict[str, list[str]]) -> list[Finding]:
    csp_covers = "frame-ancestors" in csp
    if not value:
        if csp_covers:
            return [_f("X-Frame-Options: Missing (covered by CSP frame-ancestors)",
                       "X-Frame-Options is absent, but CSP frame-ancestors provides clickjacking protection.",
                       Severity.INFO, "Optionally add X-Frame-Options: DENY for older browsers.",
                       "x-frame-options", None)]
        return [_missing("X-Frame-Options", "x-frame-options", Severity.MEDIUM,
                         "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' (or a CSP frame-ancestors directive). "
                         "The clickjacking module reports the actual exploitability.")]
    findings = [_present("X-Frame-Options", "x-frame-options", value)]
    if value.strip().lower().startswith("allow-from"):
        findings.append(_f("X-Frame-Options: Weak — ALLOW-FROM is obsolete",
                           "ALLOW-FROM is ignored by modern browsers.",
                           Severity.LOW, "Use CSP frame-ancestors instead of ALLOW-FROM.",
                           "x-frame-options", value))
    return findings


def _check_simple(label, header, value, missing_sev, missing_rec,
                  weak: tuple[str, Severity, str, str] | None = None) -> list[Finding]:
    if not value:
        return [_missing(label, header, missing_sev, missing_rec)]
    findings = [_present(label, header, value)]
    if weak:
        pattern, sev, wlabel, rec = weak
        if re.search(pattern, value, re.IGNORECASE):
            findings.append(_f(f"{label}: Weak — {wlabel}",
                               f"{label} is present but weak: {wlabel}.",
                               sev, rec, header, value, weakness=wlabel))
    return findings


# ---------------------------------------------------------------------------
# Information-disclosure headers
# ---------------------------------------------------------------------------

_DISCLOSURE: list[tuple[str, str, str]] = [
    ("x-powered-by",        "X-Powered-By",        "the application framework/version"),
    ("x-aspnet-version",    "X-AspNet-Version",    "the ASP.NET runtime version"),
    ("x-aspnetmvc-version", "X-AspNetMvc-Version", "the ASP.NET MVC version"),
    ("x-generator",         "X-Generator",         "the CMS/generator and version"),
]

_VERSION_RE = re.compile(r"\d+\.\d+")


def _check_disclosure(headers: httpx.Headers) -> list[Finding]:
    findings: list[Finding] = []

    # Server: only a concern when it leaks a version number.
    server = headers.get("server", "")
    if server and _VERSION_RE.search(server):
        findings.append(_f("Information Disclosure: Server version",
                           f"The Server header reveals software and version: '{server}'.",
                           Severity.LOW,
                           "Suppress the version (e.g. Apache ServerTokens Prod, nginx server_tokens off).",
                           "server", server))

    for header, label, what in _DISCLOSURE:
        value = headers.get(header, "")
        if value:
            findings.append(_f(f"Information Disclosure: {label}",
                               f"The {label} header reveals {what}: '{value}'.",
                               Severity.LOW, f"Remove the {label} header from responses.",
                               header, value))

    xxp = headers.get("x-xss-protection", "")
    if xxp and not xxp.strip().startswith("0"):
        findings.append(_f("X-XSS-Protection: Deprecated",
                           f"X-XSS-Protection ('{xxp}') is deprecated and can introduce vulnerabilities.",
                           Severity.LOW,
                           "Set 'X-XSS-Protection: 0' and rely on a strong Content-Security-Policy instead.",
                           "x-xss-protection", xxp))
    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(engine: ScanEngine) -> list[Finding]:
    try:
        resp = engine.head()
        if any(h not in resp.headers for h in ("content-security-policy", "strict-transport-security")):
            resp = engine.get()
    except httpx.HTTPError as exc:
        logger.warning(f"headers_check: request failed: {exc}")
        return []

    headers = resp.headers
    is_https = urlparse(engine.url).scheme == "https"
    csp_value = headers.get("content-security-policy", "")
    csp_parsed = _parse_csp(csp_value) if csp_value else {}

    findings: list[Finding] = []

    # Content-Security-Policy
    if csp_value:
        findings += _check_csp(csp_value)
    else:
        findings.append(_missing("Content-Security-Policy", "content-security-policy",
                                 Severity.MEDIUM,
                                 "Define a Content-Security-Policy, starting from default-src 'self'. "
                                 "Missing CSP is a defence-in-depth gap (it mitigates XSS) rather than a "
                                 "directly exploitable vulnerability."))

    # Strict-Transport-Security
    findings += _check_hsts(headers.get("strict-transport-security", ""), is_https)

    # X-Frame-Options (CSP-aware)
    findings += _check_xfo(headers.get("x-frame-options", ""), csp_parsed)

    # X-Content-Type-Options
    findings += _check_simple(
        "X-Content-Type-Options", "x-content-type-options",
        headers.get("x-content-type-options", ""),
        Severity.MEDIUM, "Add 'X-Content-Type-Options: nosniff' to block MIME sniffing.",
        weak=(r"^(?!nosniff\s*$).+", Severity.LOW, "value is not 'nosniff'",
              "Set X-Content-Type-Options to exactly 'nosniff'."))

    # Referrer-Policy
    findings += _check_simple(
        "Referrer-Policy", "referrer-policy", headers.get("referrer-policy", ""),
        Severity.LOW, "Add 'Referrer-Policy: strict-origin-when-cross-origin'.",
        weak=(r"unsafe-url|no-referrer-when-downgrade", Severity.MEDIUM, "leaks full URL cross-origin",
              "Use 'strict-origin-when-cross-origin' or stricter to avoid leaking URLs/paths."))

    # Permissions-Policy
    findings += _check_simple(
        "Permissions-Policy", "permissions-policy", headers.get("permissions-policy", ""),
        Severity.LOW, "Add a Permissions-Policy to restrict camera, microphone, geolocation, etc.")

    # Cross-Origin isolation headers
    findings += _check_simple(
        "Cross-Origin-Opener-Policy", "cross-origin-opener-policy",
        headers.get("cross-origin-opener-policy", ""),
        Severity.LOW, "Add 'Cross-Origin-Opener-Policy: same-origin' to isolate your browsing context.")
    findings += _check_simple(
        "Cross-Origin-Resource-Policy", "cross-origin-resource-policy",
        headers.get("cross-origin-resource-policy", ""),
        Severity.LOW, "Add 'Cross-Origin-Resource-Policy: same-origin' to limit cross-origin embedding.")

    # COEP is advanced/optional — only informational when absent.
    if "cross-origin-embedder-policy" in headers:
        findings.append(_present("Cross-Origin-Embedder-Policy", "cross-origin-embedder-policy",
                                 headers["cross-origin-embedder-policy"]))

    # Information disclosure
    findings += _check_disclosure(headers)

    return findings
