"""
redirect_chain — follows the redirect chain from the target URL and audits it.

Manually walks each Location hop (without auto-following) and reports the full chain,
flagging security-relevant patterns: an HTTPS→HTTP downgrade (Medium), redirects to a
different registrable domain (Low), excessively long chains (Low), and a missing
HTTP→HTTPS upgrade when starting from http:// (Low).
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qs, urljoin, urlparse

import httpx
from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "redirect_chain"
_MAX_HOPS = 10
_LONG_CHAIN = 4

# Query-parameter names that carry credentials/secrets and must not travel in a redirect URL
# (they leak via browser history, proxy/server logs, and the Referer header — worse cross-domain).
_SENSITIVE_QS = {
    "token", "access_token", "id_token", "refresh_token", "code", "jwt", "session", "sessionid",
    "sid", "auth", "authorization", "apikey", "api_key", "password", "passwd", "secret", "key",
    "otp", "ticket", "assertion", "saml", "samlresponse",
}


@dataclass
class _Hop:
    url: str
    status: int
    location: str


def _registrable(host: str) -> str:
    host = host.split(":")[0].lower()
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _follow(engine: ScanEngine) -> list[_Hop]:
    hops: list[_Hop] = []
    url = engine.url
    seen: set[str] = set()
    for _ in range(_MAX_HOPS):
        if url in seen:
            break
        seen.add(url)
        try:
            resp = engine.request("GET", url, follow_redirects=False)
        except httpx.HTTPError as exc:
            logger.debug(f"redirect_chain: {url} → {exc}")
            break
        location = resp.headers.get("location", "")
        hops.append(_Hop(url, resp.status_code, location))
        if resp.status_code not in (301, 302, 303, 307, 308) or not location:
            break
        url = urljoin(url, location)
    return hops


def run(engine: ScanEngine) -> list[Finding]:
    hops = _follow(engine)
    if not hops:
        return [Finding(
            module=MODULE, title="Redirect Chain: Request Failed",
            description="The target URL could not be requested.",
            severity=Severity.INFO, recommendation="", raw={"confidence": "high"},
        )]

    redirects = [h for h in hops if h.status in (301, 302, 303, 307, 308)]
    if not redirects:
        return [Finding(
            module=MODULE, title="Redirect Chain: No Redirects",
            description=f"The target responded directly (HTTP {hops[0].status}) with no redirects.",
            severity=Severity.INFO, recommendation="",
            raw={"final_status": hops[0].status, "confidence": "high"},
        )]

    chain_str = " → ".join(f"{h.url} [{h.status}]" for h in hops)
    hop_evidence = [
        f"hop {i}: {h.url} → HTTP {h.status}" + (f" Location: {h.location}" if h.location else "")
        for i, h in enumerate(hops, 1)
    ]
    findings: list[Finding] = [Finding(
        module=MODULE,
        title=f"Redirect Chain: {len(redirects)} hop(s)",
        description=f"The target follows {len(redirects)} redirect(s): {chain_str}",
        severity=Severity.INFO, recommendation="",
        raw={"chain": [(h.url, h.status, h.location) for h in hops], "confidence": "high"},
    )]

    start = urlparse(engine.url)
    start_root = _registrable(start.netloc)

    # HTTPS → HTTP downgrade anywhere in the chain
    for h in hops:
        if urlparse(h.url).scheme == "https" and h.location:
            if urlparse(urljoin(h.url, h.location)).scheme == "http":
                findings.append(Finding(
                    module=MODULE, title="Insecure Redirect: HTTPS → HTTP Downgrade",
                    description=f"A redirect downgrades from HTTPS to HTTP: {h.url} → {h.location}. "
                                "This exposes the session to interception.",
                    severity=Severity.MEDIUM,
                    recommendation="Never redirect from HTTPS to HTTP; keep the whole chain on HTTPS.",
                    raw={"from": h.url, "to": h.location, "confidence": "high",
                         "evidence": [f"HTTPS→HTTP downgrade: {h.url} → {urljoin(h.url, h.location)}",
                                      *hop_evidence]},
                ))
                break

    # Sensitive data carried in a redirect URL (credential/token leakage).
    for h in hops:
        if not h.location:
            continue
        dest = urljoin(h.url, h.location)
        leaked = sorted(k for k in parse_qs(urlparse(dest).query) if k.lower() in _SENSITIVE_QS)
        if not leaked:
            continue
        dest_root = _registrable(urlparse(dest).netloc)
        cross = bool(dest_root) and dest_root != start_root
        findings.append(Finding(
            module=MODULE,
            title="Sensitive Data in Redirect URL" + (" (cross-domain)" if cross else ""),
            description=(f"A redirect carries sensitive parameter(s) {leaked} in the URL "
                         f"({h.url} → {dest}). URL parameters leak through browser history, server and "
                         "proxy logs, and the Referer header"
                         + (f" — and here the token is sent to a different domain ({dest_root})."
                            if cross else ".")),
            severity=Severity.MEDIUM if cross else Severity.LOW,
            recommendation=("Do not pass tokens/credentials as URL query parameters; use a POST body, "
                            "a secure cookie, or the OAuth authorization-code flow with PKCE."),
            raw={"params": leaked, "cross_domain": cross, "to": dest, "confidence": "high",
                 "evidence": [f"redirect URL carries {leaked}" + (f" cross-domain → {dest_root}" if cross else ""),
                              *hop_evidence]},
        ))
        break

    # Off-domain redirect
    final = hops[-1]
    final_root = _registrable(urlparse(final.url).netloc)
    if final_root and final_root != start_root:
        findings.append(Finding(
            module=MODULE, title=f"Redirect Leaves Original Domain: {final_root}",
            description=f"The chain ends on a different registrable domain ({start_root} → {final_root}: {final.url}). "
                        "Verify this destination is trusted.",
            severity=Severity.LOW,
            recommendation="Ensure off-site redirects are intended and the destination is controlled by you.",
            raw={"from_domain": start_root, "to_domain": final_root, "confidence": "high",
                 "evidence": [f"chain crosses domains: {start_root} → {final_root}", *hop_evidence]},
        ))

    # Missing HTTP→HTTPS upgrade
    if start.scheme == "http" and urlparse(final.url).scheme != "https":
        findings.append(Finding(
            module=MODULE, title="No HTTP → HTTPS Upgrade",
            description="The target was reached over HTTP and never redirected to HTTPS.",
            severity=Severity.LOW,
            recommendation="Redirect all HTTP traffic to HTTPS and serve HSTS.",
            raw={"confidence": "high"},
        ))

    # Excessively long chain
    if len(redirects) >= _LONG_CHAIN:
        findings.append(Finding(
            module=MODULE, title=f"Long Redirect Chain ({len(redirects)} hops)",
            description=f"The chain has {len(redirects)} redirects, which slows page loads and can hide open redirects.",
            severity=Severity.LOW,
            recommendation="Collapse the chain to a single redirect to the canonical URL.",
            raw={"hops": len(redirects), "confidence": "medium"},
        ))

    return findings
