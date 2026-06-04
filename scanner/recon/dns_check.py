"""
dns_check — queries DNS records relevant to email security and domain hygiene.

Checks MX, SPF (TXT), DMARC (_dmarc.<domain> TXT), and DKIM
(default._domainkey.<domain> TXT). Missing SPF is Medium; missing DMARC is High.
"""
from __future__ import annotations

from urllib.parse import urlparse

import dns.resolver
import dns.exception
from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "dns_check"

_DKIM_SELECTOR = "default"


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


def _resolve_txt(name: str) -> list[str]:
    """Return all TXT record strings for *name*, or [] if NXDOMAIN / no answer."""
    try:
        answer = dns.resolver.resolve(name, "TXT", lifetime=10)
        return [b.decode() for rdata in answer for b in rdata.strings]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.DNSException as exc:
        logger.debug(f"dns_check: TXT lookup failed for {name}: {exc}")
        return []


def _check_mx(domain: str) -> Finding:
    try:
        answer = dns.resolver.resolve(domain, "MX", lifetime=10)
        records = sorted(
            f"{r.preference} {r.exchange.to_text(omit_final_dot=True)}"
            for r in answer
        )
        return _finding(
            "MX Records",
            f"Mail servers: {', '.join(records)}",
            Severity.INFO,
            raw={"mx": records},
        )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return _finding(
            "MX Records — Not Found",
            f"No MX records found for {domain}. The domain may not handle email.",
            Severity.INFO,
            raw={"mx": []},
        )
    except dns.exception.DNSException as exc:
        logger.debug(f"dns_check: MX lookup failed for {domain}: {exc}")
        return _finding(
            "MX Records — Lookup Error",
            f"MX query failed: {exc}",
            Severity.INFO,
            raw={"error": str(exc)},
        )


def _check_spf(domain: str) -> Finding:
    txts = _resolve_txt(domain)
    spf = [t for t in txts if t.lower().startswith("v=spf1")]
    if spf:
        return _finding(
            "SPF Record",
            f"SPF policy present: {spf[0]}",
            Severity.INFO,
            raw={"spf": spf[0]},
        )
    return _finding(
        "SPF Record — Missing",
        f"No SPF TXT record found for {domain}. Attackers can spoof email from this domain.",
        Severity.MEDIUM,
        recommendation="Add a TXT record: \"v=spf1 include:<your-mail-provider> ~all\"",
        raw={"spf": None},
    )


def _check_dmarc(domain: str) -> Finding:
    dmarc_name = f"_dmarc.{domain}"
    txts = _resolve_txt(dmarc_name)
    dmarc = [t for t in txts if t.lower().startswith("v=dmarc1")]
    if dmarc:
        return _finding(
            "DMARC Record",
            f"DMARC policy present: {dmarc[0]}",
            Severity.INFO,
            raw={"dmarc": dmarc[0]},
        )
    return _finding(
        "DMARC Record — Missing",
        f"No DMARC TXT record found at {dmarc_name}. "
        "Without DMARC, spoofed emails cannot be rejected by receiving servers.",
        Severity.HIGH,
        recommendation=(
            "Add a TXT record at _dmarc." + domain +
            ": \"v=DMARC1; p=reject; rua=mailto:dmarc@" + domain + "\""
        ),
        raw={"dmarc": None},
    )


def _check_dkim(domain: str) -> Finding:
    dkim_name = f"{_DKIM_SELECTOR}._domainkey.{domain}"
    txts = _resolve_txt(dkim_name)
    dkim = [t for t in txts if "v=dkim1" in t.lower() or "p=" in t.lower()]
    if dkim:
        return _finding(
            "DKIM Record",
            f"DKIM key found at {dkim_name}: {dkim[0][:80]}{'...' if len(dkim[0]) > 80 else ''}",
            Severity.INFO,
            raw={"dkim_selector": _DKIM_SELECTOR, "dkim": dkim[0]},
        )
    return _finding(
        "DKIM Record — Not Found",
        f"No DKIM TXT record found at {dkim_name} (selector: \"{_DKIM_SELECTOR}\"). "
        "Other selectors may exist; this check uses the common default selector only.",
        Severity.LOW,
        recommendation="Ensure your mail provider has published a DKIM public key for your domain.",
        raw={"dkim_selector": _DKIM_SELECTOR, "dkim": None},
    )


def run(engine: ScanEngine) -> list[Finding]:
    hostname = urlparse(engine.url).hostname or ""
    domain = hostname.lstrip("www.") if hostname.startswith("www.") else hostname

    if not domain:
        logger.warning("dns_check: could not extract domain from URL")
        return []

    return [
        _check_mx(domain),
        _check_spf(domain),
        _check_dmarc(domain),
        _check_dkim(domain),
    ]
