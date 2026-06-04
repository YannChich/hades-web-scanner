"""
redirect_chain — follows the redirect chain from the target URL and audits it.

Manually walks each Location hop (without auto-following) and reports the full chain,
flagging security-relevant patterns: an HTTPS→HTTP downgrade (Medium), redirects to a
different registrable domain (Low), excessively long chains (Low), and a missing
HTTP→HTTPS upgrade when starting from http:// (Low).
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx
from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "redirect_chain"
_MAX_HOPS = 10
_LONG_CHAIN = 4


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
                    raw={"from": h.url, "to": h.location, "confidence": "high"},
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
            raw={"from_domain": start_root, "to_domain": final_root, "confidence": "high"},
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
