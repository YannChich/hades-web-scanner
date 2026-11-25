"""
clickjacking — determines whether the page can be framed and how exploitable that is.

headers_check reports the presence of X-Frame-Options / CSP; this module renders a
concrete clickjacking verdict: it combines both headers into a single "framable?" answer
and weights severity by whether the page contains interactive elements worth hijacking
(a login form, password field, or other forms). Framable + sensitive form → High;
framable with forms → Medium; framable but static → Low; protected → Info.
"""
from __future__ import annotations

import re

import httpx
from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "clickjacking"

_PASSWORD = re.compile(r"""type\s*=\s*['"]?password\b""", re.IGNORECASE)


def _frame_ancestors(csp: str) -> list[str] | None:
    for part in csp.split(";"):
        toks = part.split()
        if toks and toks[0].lower() == "frame-ancestors":
            return [t.lower() for t in toks[1:]]
    return None


def _is_protected(headers: httpx.Headers) -> tuple[bool, str]:
    """Return (protected, reason)."""
    xfo = headers.get("x-frame-options", "").strip().lower()
    if xfo in ("deny", "sameorigin"):
        return True, f"X-Frame-Options: {xfo.upper()}"

    fa = _frame_ancestors(headers.get("content-security-policy", ""))
    if fa is not None:
        # 'none' blocks all framing.
        if "'none'" in fa:
            return True, "CSP frame-ancestors 'none'"
        # A concrete allowlist ('self' / explicit hosts) protects — but a scheme-wide ('https:'),
        # wildcard ('*', '*.x'), or empty source lets arbitrary origins frame the page, which is NOT
        # protection. (Previously 'frame-ancestors https:' was wrongly treated as protected.)
        def _permissive(tok: str) -> bool:
            return (not tok) or tok == "*" or tok.endswith(":") or "*" in tok
        concrete = [t for t in fa if t]
        if concrete and not any(_permissive(t) for t in concrete):
            return True, f"CSP frame-ancestors {' '.join(fa)}"
    return False, ""


def run(engine: ScanEngine) -> list[Finding]:
    try:
        resp = engine.get()
    except httpx.HTTPError as exc:
        logger.warning(f"clickjacking: request failed: {exc}")
        return []

    protected, reason = _is_protected(resp.headers)
    if protected:
        return [Finding(
            module=MODULE, title="Clickjacking: Protected",
            description=f"The page cannot be framed by other origins ({reason}).",
            severity=Severity.INFO, recommendation="",
            raw={"protected": True, "reason": reason, "confidence": "high"},
        )]

    body = resp.text.lower()
    has_password = bool(_PASSWORD.search(body))
    has_form = "<form" in body

    xfo_raw = resp.headers.get("x-frame-options", "").strip()
    fa = _frame_ancestors(resp.headers.get("content-security-policy", ""))
    evidence = [
        f"X-Frame-Options: {xfo_raw}" if xfo_raw else "X-Frame-Options header absent",
        (f"CSP frame-ancestors: {' '.join(fa)}" if fa else "CSP frame-ancestors directive absent"),
        f"interactive targets — password field: {has_password}, form: {has_form}",
    ]

    if has_password:
        severity = Severity.HIGH
        impact = ("The page contains a password/login form, so a framing attack could trick users "
                  "into submitting credentials or performing authenticated actions.")
    elif has_form:
        severity = Severity.MEDIUM
        impact = ("The page contains interactive forms that an attacker could overlay to hijack "
                  "user clicks (UI redress).")
    else:
        severity = Severity.LOW
        impact = "The page is framable; impact is limited as no interactive forms were detected."

    return [Finding(
        module=MODULE,
        title="Clickjacking: Page Is Framable",
        description=(f"Neither X-Frame-Options nor a restrictive CSP frame-ancestors directive is set, "
                     f"so the page can be embedded in an attacker-controlled <iframe>. {impact}"),
        severity=severity,
        recommendation=("Add 'X-Frame-Options: DENY' (or SAMEORIGIN) and a "
                        "'Content-Security-Policy: frame-ancestors 'none'' directive."),
        raw={"protected": False, "has_password": has_password, "has_form": has_form,
             "confidence": "high", "evidence": evidence},
    )]
