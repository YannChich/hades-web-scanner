"""
whois_lookup — retrieves WHOIS registration data for the target domain.

Reports registrar, creation/expiration dates, name servers, and registrant
country as Info findings. Flags expiry within 30 days as Medium severity.
"""
from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlparse

import whois
from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "whois_lookup"
_EXPIRY_WARNING_DAYS = 30


def _info(title: str, description: str, raw: dict | None = None) -> Finding:
    return Finding(
        module=MODULE,
        title=title,
        description=description,
        severity=Severity.INFO,
        recommendation="",
        raw=raw or {},
    )


def _medium(title: str, description: str, recommendation: str, raw: dict | None = None) -> Finding:
    return Finding(
        module=MODULE,
        title=title,
        description=description,
        severity=Severity.MEDIUM,
        recommendation=recommendation,
        raw=raw or {},
    )


def _normalize_date(value: object) -> datetime | None:
    """Unwrap list-wrapped dates returned by python-whois."""
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, datetime):
        return value
    return None


# Hosting-platform suffixes: a target like "foo.vercel.app" is a sub-domain of the
# platform, so WHOIS on it is meaningless (and python-whois prints socket errors).
_PLATFORM_SUFFIXES: frozenset[str] = frozenset({
    "vercel.app", "netlify.app", "netlify.com", "herokuapp.com", "github.io",
    "gitlab.io", "pages.dev", "workers.dev", "web.app", "firebaseapp.com",
    "azurewebsites.net", "onrender.com", "render.com", "fly.dev", "glitch.me",
    "surge.sh", "now.sh", "repl.co", "replit.app", "wixsite.com", "blogspot.com",
})

# ccTLDs whose registrable domain spans the last three labels (e.g. example.co.uk).
_MULTI_PART_TLDS: frozenset[str] = frozenset({
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "org.nz", "co.jp", "or.jp", "ne.jp",
    "com.br", "com.cn", "co.in", "co.za", "com.mx", "com.tr", "co.kr",
})


def _registrable_domain(hostname: str) -> tuple[str | None, bool]:
    """
    Reduce *hostname* to the domain WHOIS should query.

    Returns (domain, is_platform). *domain* is None when WHOIS should be skipped
    (a hosting-platform sub-domain or a bare IP); *is_platform* distinguishes the two.
    """
    host = hostname.lower().strip(".")
    if not host:
        return None, False
    if host.replace(".", "").isdigit():      # bare IPv4 → no WHOIS
        return None, False
    if host.startswith("www."):              # proper prefix strip (not lstrip!)
        host = host[4:]

    for suffix in _PLATFORM_SUFFIXES:
        if host == suffix or host.endswith("." + suffix):
            return None, True

    labels = host.split(".")
    if len(labels) <= 2:
        return host, False
    if ".".join(labels[-2:]) in _MULTI_PART_TLDS:
        return ".".join(labels[-3:]), False
    return ".".join(labels[-2:]), False


def run(engine: ScanEngine) -> list[Finding]:
    findings: list[Finding] = []
    hostname = urlparse(engine.url).hostname or ""
    domain, is_platform = _registrable_domain(hostname)

    if domain is None:
        note = (
            f"WHOIS skipped: '{hostname}' is a sub-domain of a hosting platform, "
            "so registration data belongs to the provider, not this site."
            if is_platform else
            f"WHOIS skipped: '{hostname}' is not a registrable domain."
        )
        return [_info("WHOIS Not Applicable", note, {"hostname": hostname})]

    try:
        w = whois.whois(domain)
    except Exception as exc:
        logger.warning(f"whois_lookup: query failed for {domain}: {exc}")
        return findings

    # Registrar
    registrar = w.registrar
    if registrar:
        findings.append(_info(
            "WHOIS Registrar",
            f"Registrar: {registrar}",
            {"registrar": registrar},
        ))

    # Creation date
    creation = _normalize_date(w.creation_date)
    if creation:
        findings.append(_info(
            "Domain Creation Date",
            f"Created: {creation.strftime('%Y-%m-%d')}",
            {"creation_date": creation.isoformat()},
        ))

    # Expiration date — also drives the Medium-severity warning
    expiration = _normalize_date(w.expiration_date)
    if expiration:
        # Make both tz-aware for comparison
        now = datetime.now(timezone.utc)
        exp_aware = expiration.replace(tzinfo=timezone.utc) if expiration.tzinfo is None else expiration
        days_left = (exp_aware - now).days

        findings.append(_info(
            "Domain Expiration Date",
            f"Expires: {expiration.strftime('%Y-%m-%d')} ({days_left} days remaining)",
            {"expiration_date": expiration.isoformat(), "days_remaining": days_left},
        ))

        if days_left < _EXPIRY_WARNING_DAYS:
            findings.append(_medium(
                "Domain Expiring Soon",
                f"Domain '{domain}' expires in {days_left} day(s) ({expiration.strftime('%Y-%m-%d')}). "
                "An expired domain can be hijacked by a third party.",
                "Renew the domain registration immediately.",
                {"domain": domain, "expiration_date": expiration.isoformat(), "days_remaining": days_left},
            ))

    # Name servers
    name_servers = w.name_servers
    if name_servers:
        ns_list = sorted({ns.lower() for ns in name_servers if ns})
        findings.append(_info(
            "Name Servers",
            f"NS: {', '.join(ns_list)}",
            {"name_servers": ns_list},
        ))

    # Registrant country
    country = w.country
    if country:
        findings.append(_info(
            "Registrant Country",
            f"Country: {country}",
            {"country": country},
        ))

    return findings
