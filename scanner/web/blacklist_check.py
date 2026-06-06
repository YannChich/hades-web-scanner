"""
blacklist_check — checks the target's IP and domain against public DNS blocklists (DNSBLs).

Uses the standard, key-free DNSBL protocol: for IP a.b.c.d it queries d.c.b.a.<zone>, and
for the domain it queries <domain>.<domain-blocklist>. A successful DNS answer means the
host is listed. Being listed signals spam/malware history or a compromised host and harms
email deliverability and reputation.

Note: if the site is behind a CDN/WAF, the resolved IP is the edge, which is rarely listed
— results then describe the CDN, not the origin.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "blacklist_check"

# IP-based DNSBLs (query the reversed IP).
_IP_DNSBLS: list[str] = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
    "cbl.abuseat.org",
    "dnsbl-1.uceprotect.net",
]

# Domain-based blocklists (query the domain directly).
_DOMAIN_DNSBLS: list[str] = [
    "dbl.spamhaus.org",
    "multi.surbl.org",
]


def _resolve(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except OSError as exc:
        logger.debug(f"blacklist_check: cannot resolve {hostname}: {exc}")
        return None


def _is_listed(query: str) -> bool:
    """True only for a genuine DNSBL listing.

    A listing is encoded as an answer in 127.0.0.0/8 (e.g. 127.0.0.2). Resolving to anything
    else — or, crucially, to a 127.255.255.x *error* code (Spamhaus returns 127.255.255.254
    for queries via a public/open resolver, .252 for a config error, .255 for rate-limiting) —
    is NOT a listing. Counting those error codes produced false 'blocklisted' findings.
    """
    try:
        answer = socket.gethostbyname(query)
    except OSError:
        return False
    return answer.startswith("127.") and not answer.startswith("127.255.255.")


def _registrable(hostname: str) -> str:
    parts = hostname.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def run(engine: ScanEngine) -> list[Finding]:
    hostname = urlparse(engine.url).hostname or ""
    ip = _resolve(hostname)
    if not ip:
        return [Finding(MODULE, "Blacklist Check Skipped — DNS Resolution Failed",
                        f"Could not resolve {hostname}.", Severity.INFO, "",
                        {"hostname": hostname, "confidence": "high"})]

    reversed_ip = ".".join(reversed(ip.split(".")))
    domain = _registrable(hostname)

    checks: dict[str, str] = {}  # query → DNSBL label
    for zone in _IP_DNSBLS:
        checks[f"{reversed_ip}.{zone}"] = f"{zone} (IP {ip})"
    for zone in _DOMAIN_DNSBLS:
        checks[f"{domain}.{zone}"] = f"{zone} (domain {domain})"

    listed: list[str] = []
    with ThreadPoolExecutor(max_workers=max(engine.threads, 12)) as pool:
        futures = {pool.submit(_is_listed, q): label for q, label in checks.items()}
        for future in as_completed(futures):
            if future.result():
                listed.append(futures[future])

    if not listed:
        return [Finding(MODULE, f"Blacklist Check: Clean ({ip})",
                        f"{hostname} ({ip}) is not listed on any of the {len(checks)} checked DNSBLs.",
                        Severity.INFO, "",
                        {"ip": ip, "checked": len(checks), "confidence": "high"})]

    severity = Severity.HIGH if len(listed) >= 2 else Severity.MEDIUM
    return [Finding(
        module=MODULE,
        title=f"Listed on {len(listed)} Blocklist(s): {hostname}",
        description=(f"{hostname} ({ip}) is listed on {len(listed)} DNS blocklist(s): "
                     + "; ".join(sorted(listed)) + ". This indicates spam/malware history or a "
                     "compromise and damages email deliverability and reputation."),
        severity=severity,
        recommendation=("Investigate for compromise/open relays, remediate, then request delisting "
                        "from each blocklist. If behind a CDN, confirm whether the origin or edge is listed."),
        raw={"ip": ip, "hostname": hostname, "blocklists": sorted(listed), "confidence": "high"},
    )]
