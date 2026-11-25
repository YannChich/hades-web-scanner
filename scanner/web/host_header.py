"""
host_header — detect Host-header injection and web-cache-poisoning *indicators*.

Many frameworks build absolute URLs (password-reset links, redirects, canonical tags, loaded script
`src`s) from the request's ``Host`` header — or from a header a front-end cache forwards unvalidated
(``X-Forwarded-Host`` and friends). When that value is attacker-controlled and reflected, it enables:

* **Password-reset / routing poisoning** — a reset link built from a spoofed ``Host`` points at the
  attacker's domain.
* **Web-cache poisoning** — if a reflected, *unkeyed* header is cached, every later visitor is served
  the poisoned response.
* **Open-redirect via Host** — a ``Location`` built from the spoofed ``Host``.

This module is **detection only**. It sends a handful of requests carrying a unique, clearly-invalid
sentinel host and reports *reflection* — the sentinel coming back in the body or a ``Location`` header
— as an **indicator**. It never attempts to actually poison a cache or hijack a reset flow; that
active confirmation is intentionally left behind ``--exploit`` (see ROADMAP). Because the sentinel is
random and clearly bogus, a reflection can't come from the clean baseline, so there are no false
positives from pages that merely echo their own hostname.
"""
from __future__ import annotations

import secrets
from urllib.parse import urlparse

import httpx
from loguru import logger

from scanner import evidence as ev
from scanner.engine import Finding, Severity, ScanEngine

MODULE = "host_header"

# Headers a front-end / CDN / reverse proxy may forward to the app unvalidated ("unkeyed" inputs:
# usually not part of the cache key, which is exactly what makes them cache-poisoning vectors).
_FORWARD_HEADERS: tuple[str, ...] = (
    "X-Forwarded-Host",
    "X-Forwarded-Server",
    "X-Host",
    "X-Forwarded-For-Host",
    "Forwarded",
)


def _sentinel() -> str:
    """A unique, clearly-invalid host that cannot legitimately appear in a clean response."""
    return f"hades-hhi-{secrets.token_hex(4)}.invalid"


def _safe_request(engine: ScanEngine, headers: dict[str, str]) -> "httpx.Response | None":
    """One GET of the scan root with custom headers, redirects NOT followed (so we can read Location)."""
    try:
        return engine.request("GET", engine.url, headers=headers, follow_redirects=False)
    except httpx.HTTPError as exc:
        logger.debug(f"host_header: {engine.url} with {list(headers)} → {exc}")
        return None


def _location(resp: "httpx.Response") -> str:
    return resp.headers.get("location", "") or ""


def _reflected_where(resp: "httpx.Response | None", sentinel: str) -> str | None:
    """Return 'redirect Location', 'response body', or None — where the sentinel came back."""
    if resp is None or ev.is_block_page(resp):
        return None
    if sentinel.lower() in _location(resp).lower():
        return "redirect Location"
    try:
        if sentinel.lower() in resp.text.lower():
            return "response body"
    except Exception:  # noqa: BLE001 — unreadable body is not a reflection signal
        return None
    return None


def _finding(vector: str, where: str, sentinel: str, resp: "httpx.Response") -> Finding:
    in_location = where == "redirect Location"
    # A spoofed value steering a redirect is the higher-impact shape (reset-link / open-redirect
    # poisoning); body reflection is a cache-poisoning *candidate*. Both are reported as indicators —
    # active cache-poisoning confirmation stays behind --exploit.
    severity = Severity.MEDIUM if in_location else Severity.LOW
    impact = ("it is used to build a redirect target (Location) — enabling password-reset-link "
              "poisoning or an open redirect"
              if in_location else
              "it is reflected into the response body (e.g. an absolute URL, canonical tag or script "
              "src) — a web-cache-poisoning candidate if the response is cacheable")
    indicator = (f"sentinel host '{sentinel}' sent via {vector} came back in the {where}")
    return Finding(
        module=MODULE,
        title=f"Host-Header Injection Indicator via {vector} ({where})",
        description=(f"The value supplied in the '{vector}' header is reflected by {engine_url(resp)}: "
                     f"a unique sentinel host was injected and {impact}. This is reported as an "
                     "indicator — Hades did not attempt to poison a cache or hijack a reset flow."),
        severity=severity,
        recommendation=("Validate the Host header against an allowlist of expected hostnames and reject "
                        "unknown values; build absolute URLs from server-side configuration, not from "
                        "the request. Do not trust X-Forwarded-* headers unless set by a controlled "
                        "proxy, and ensure such headers are part of the cache key (or stripped) at the "
                        "CDN/edge."),
        raw={"vector": vector, "reflected_in": where, "sentinel": sentinel,
             "confidence": "high", "verified": True,
             "verification": f"sentinel reflected in the {where} (concrete request/response proof)",
             "evidence": ev.from_response(resp, indicator=indicator)},
    )


def engine_url(resp: "httpx.Response") -> str:
    """Best-effort origin for the description (the request we actually sent)."""
    try:
        p = urlparse(str(resp.request.url))
        return f"{p.scheme}://{p.netloc}"
    except Exception:  # noqa: BLE001
        return "the target"


def run(engine: ScanEngine) -> list[Finding]:
    findings: list[Finding] = []

    # 1) Override the real Host header with a bogus sentinel.
    s_host = _sentinel()
    resp = _safe_request(engine, {"Host": s_host})
    where = _reflected_where(resp, s_host)
    if where and resp is not None:
        findings.append(_finding("Host", where, s_host, resp))

    # 2) Keep the real Host, smuggle the sentinel through each forwarded-host header in turn.
    for header in _FORWARD_HEADERS:
        s = _sentinel()
        value = f"{s}" if header != "Forwarded" else f"host={s}"
        r = _safe_request(engine, {header: value})
        w = _reflected_where(r, s)
        if w and r is not None:
            findings.append(_finding(header, w, s, r))

    if not findings:
        return [Finding(MODULE, "Host-Header Injection: No Reflection Detected",
                        "Injected a unique sentinel host via the Host header and common "
                        "X-Forwarded-* headers; none was reflected in the body or a redirect "
                        "Location. No Host-header injection indicator found.",
                        Severity.INFO, "",
                        {"vectors_tested": 1 + len(_FORWARD_HEADERS), "confidence": "high"})]
    logger.info(f"host_header: {len(findings)} reflection indicator(s)")
    return findings
