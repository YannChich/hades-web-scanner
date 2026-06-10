"""
http_methods — audits which HTTP methods are enabled, and VERIFIES the dangerous ones.

The naive approach ("the Allow header lists PUT, so PUT is dangerous") produces false
positives: an Allow header is declarative, and treating "any status that isn't 405" as
"method enabled" counts 200/403/redirects as exploitable. This module instead actively
proves the risk where it can do so safely:

  • PUT   → uploads a unique harmless file to a NEW random path, then GETs it back. Only a
            successful round-trip is a confirmed arbitrary-file-upload (Critical). Otherwise
            it is merely advertised (Low). The test file is deleted afterwards.
  • TRACE → sends a tagged TRACE and checks the response echoes it (confirmed XST, Medium).
  • DELETE → never tested (it would be destructive); reported as advertised-only (Medium,
            verify manually).
  • CONNECT/PATCH → advertised-only (Medium/Low).

Active write tests run only outside the 'passive' profile and outside safe mode, so the
module stays read-only when it is supposed to.
"""
from __future__ import annotations

import uuid

import httpx
from loguru import logger

from scanner import evidence as ev
from scanner.engine import Finding, Severity, ScanEngine

MODULE = "http_methods"


def _parse_allow(headers: httpx.Headers) -> set[str]:
    raw = headers.get("allow", "") or headers.get("public", "")
    return {m.strip().upper() for m in raw.split(",") if m.strip()}


# ---------------------------------------------------------------------------
# Active verification
# ---------------------------------------------------------------------------

def _verify_put(engine: ScanEngine) -> tuple[str, str]:
    """
    Attempt a safe upload to a NEW random path and read it back.
    Returns (verdict, detail): 'confirmed' | 'processed' | 'rejected' | 'error'.
    """
    marker = uuid.uuid4().hex
    path = f"/hades_put_{marker}.txt"
    body = f"hades-put-test-{marker}"
    target = engine.url.rstrip("/") + path
    try:
        put = engine.request("PUT", target, content=body)
    except httpx.HTTPError as exc:
        logger.debug(f"http_methods: PUT probe error: {exc}")
        return "error", ""

    if put.status_code in (401, 403, 405, 501):
        return "rejected", f"PUT returned {put.status_code}"

    # Try to retrieve the uploaded file to confirm the write landed.
    try:
        got = engine.request("GET", target)
        if got.status_code == 200 and marker in got.text:
            try:
                engine.request("DELETE", target)   # best-effort cleanup
            except httpx.HTTPError:
                pass
            return "confirmed", f"uploaded and retrieved {path}"
    except httpx.HTTPError:
        pass

    if put.status_code in (200, 201, 204):
        return "processed", f"PUT returned {put.status_code} but the file was not retrievable"
    return "rejected", f"PUT returned {put.status_code}"


def _verify_trace(engine: ScanEngine) -> str:
    """Return 'confirmed' (XST), 'blocked', 'inconclusive', or 'error'."""
    marker = uuid.uuid4().hex
    try:
        resp = engine.request("TRACE", engine.url, headers={"X-Hades-Trace": marker})
    except httpx.HTTPError as exc:
        logger.debug(f"http_methods: TRACE probe error: {exc}")
        return "error"
    if resp.status_code == 200 and marker in resp.text:
        return "confirmed"
    if resp.status_code in (405, 501):
        return "blocked"
    return "inconclusive"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(engine: ScanEngine) -> list[Finding]:
    try:
        options = engine.request("OPTIONS", engine.url)
    except httpx.HTTPError as exc:
        logger.warning(f"http_methods: OPTIONS request failed: {exc}")
        return []

    advertised = _parse_allow(options.headers)
    active_ok = engine.profile != "passive" and not engine.is_safe_mode()
    findings: list[Finding] = []

    if advertised:
        findings.append(Finding(
            MODULE, "HTTP Methods Allowed",
            f"Server advertises the following methods (Allow header): {', '.join(sorted(advertised))}.",
            Severity.INFO, "",
            {"methods": sorted(advertised), "confidence": "high"}))

    # --- PUT: verify by actual upload (only when active testing is permitted) ---
    if active_ok:
        verdict, detail = _verify_put(engine)
        if verdict == "confirmed":
            findings.append(Finding(
                MODULE, "Arbitrary File Upload Confirmed via PUT",
                (f"A file was successfully uploaded and retrieved using the PUT method "
                 f"({detail}). An attacker can place arbitrary files (e.g. a web shell) on the server."),
                Severity.CRITICAL,
                "Disable PUT at the web server/proxy unless required; if WebDAV is needed, enforce "
                "authentication and restrict writable paths. Remove any uploaded test file.",
                {"method": "PUT", "verified": True, "confidence": "high",
                 "evidence": [f"PUT a unique file then GET it back: {detail}",
                              "round-trip succeeded → arbitrary file write confirmed"]}))
        elif verdict == "processed":
            findings.append(Finding(
                MODULE, "PUT Accepted but Upload Not Confirmed",
                (f"PUT was accepted ({detail}), but the file could not be read back — it may be handled "
                 "by the application rather than written to disk. Worth manual verification."),
                Severity.LOW,
                "Confirm whether PUT writes to the filesystem; restrict it if not required.",
                {"method": "PUT", "verified": False, "confidence": "medium"}))
        elif verdict == "rejected" and "PUT" in advertised:
            findings.append(Finding(
                MODULE, "PUT Advertised but Rejected on Test",
                "The Allow header lists PUT, but an upload attempt was rejected — likely declarative only.",
                Severity.LOW,
                "Remove PUT from the advertised methods if it is not used.",
                {"method": "PUT", "verified": False, "confidence": "high"}))
    elif "PUT" in advertised:
        findings.append(Finding(
            MODULE, "PUT Method Advertised (Not Actively Tested)",
            "The Allow header lists PUT. Active upload testing was skipped (passive/safe mode), so "
            "exploitability is unconfirmed.",
            Severity.LOW,
            "Verify whether PUT permits file upload; disable it if not required.",
            {"method": "PUT", "verified": False, "confidence": "low"}))

    # --- TRACE: verify echo (read-only, always allowed) ---
    trace = _verify_trace(engine)
    if trace == "confirmed":
        findings.append(Finding(
            MODULE, "TRACE Enabled — Cross-Site Tracing (XST)",
            "The server echoes requests back via TRACE, which historically enables stealing headers/"
            "cookies (XST). Impact is reduced by HttpOnly cookies and modern browsers, but it should be off.",
            Severity.MEDIUM,
            "Disable the TRACE method at the web server (e.g. Apache 'TraceEnable off').",
            {"method": "TRACE", "verified": True, "confidence": "high",
             "evidence": ["sent TRACE with a unique X-Hades-Trace header",
                          "the server echoed it back in the response body → XST confirmed"]}))
    elif "TRACE" in advertised:
        findings.append(Finding(
            MODULE, "TRACE Advertised", "The Allow header lists TRACE but it did not echo on test.",
            Severity.LOW, "Disable TRACE unless required.",
            {"method": "TRACE", "verified": False, "confidence": "medium"}))

    # --- DELETE: never tested destructively; advertised-only ---
    if "DELETE" in advertised:
        findings.append(Finding(
            MODULE, "DELETE Method Advertised",
            "The Allow header lists DELETE. It was NOT tested (a real deletion would be destructive). "
            "If unauthenticated DELETE works, an attacker could remove server-side resources.",
            Severity.MEDIUM,
            "Restrict DELETE to authenticated, authorised users — or disable it. Verify manually on a "
            "disposable resource.",
            {"method": "DELETE", "verified": False, "confidence": "medium"}))

    # --- CONNECT / PATCH: advertised-only ---
    if "CONNECT" in advertised:
        findings.append(Finding(
            MODULE, "CONNECT Method Advertised",
            "The Allow header lists CONNECT, which can be abused to tunnel traffic through the server "
            "if the server acts as an open proxy.",
            Severity.MEDIUM, "Disable CONNECT on the web server unless it is an intended proxy.",
            {"method": "CONNECT", "verified": False, "confidence": "medium"}))
    if "PATCH" in advertised:
        findings.append(Finding(
            MODULE, "PATCH Method Advertised",
            "The Allow header lists PATCH (partial resource modification). Ensure it is authenticated.",
            Severity.LOW, "Confirm PATCH is intentional and access-controlled.",
            {"method": "PATCH", "verified": False, "confidence": "medium"}))

    if not findings:
        findings.append(Finding(
            MODULE, "HTTP Methods: No Dangerous Methods Found",
            f"OPTIONS returned HTTP {options.status_code}; no dangerous methods were advertised or confirmed.",
            Severity.INFO, "", {"options_status": options.status_code, "confidence": "high"}))
    return findings
