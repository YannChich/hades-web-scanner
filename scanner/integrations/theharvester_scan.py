"""
theharvester_scan — passive OSINT (emails / hosts / IPs) via the real theHarvester, when installed.

theHarvester gathers a domain's public footprint — e-mail addresses, sub-domains/hosts and IPs — from
search engines and OSINT sources (crt.sh, DuckDuckGo, OTX, RapidDNS, HackerTarget). It queries third
parties, not the target, so it is passive and runs even in safe mode. Harvested e-mails are a phishing /
credential-stuffing surface (Low); discovered hosts and IPs are reported as Info.

Optional: if theHarvester is absent, a single INFO hint is emitted. Detection-only OSINT — no probing of
the target.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine
from scanner.integrations._external import missing_finding, run_tool, which

MODULE = "theharvester_scan"
_TIMEOUT = 200.0
_SOURCES = "crtsh,duckduckgo,otx,rapiddns,hackertarget"   # keyless, generally reliable sources
_MAX_SHOWN = 40


def _domain(url: str) -> str:
    host = urlparse(url).hostname or ""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _parse(data: dict) -> tuple[list[str], list[str], list[str]]:
    """Extract (emails, hosts, ips) from theHarvester's JSON, defensively."""
    emails = [e.strip() for e in (data.get("emails") or []) if isinstance(e, str) and e.strip()]
    hosts: list[str] = []
    for h in (data.get("hosts") or []):
        if isinstance(h, str) and h.strip():
            hosts.append(h.split(":")[0].strip().lower())   # "host:ip" or "host"
    ips = [i.strip() for i in (data.get("ips") or []) if isinstance(i, str) and i.strip()]
    return sorted(set(emails)), sorted(set(h for h in hosts if h)), sorted(set(ips))


def _build_findings(domain: str, emails: list[str], hosts: list[str], ips: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    if emails:
        findings.append(Finding(
            MODULE, f"OSINT E-mails Harvested: {len(emails)}",
            (f"theHarvester found {len(emails)} public e-mail(s) for {domain}: "
             + ", ".join(emails[:_MAX_SHOWN]) + (" …" if len(emails) > _MAX_SHOWN else "")),
            Severity.LOW,
            "Public e-mails are a phishing / credential-stuffing surface — consider aliasing, monitoring "
            "for breaches, and staff awareness.",
            {"domain": domain, "emails": emails[:200], "confidence": "high",
             "evidence": [f"theHarvester -d {domain} -b {_SOURCES} → {len(emails)} e-mail(s)"]}))
    if hosts:
        findings.append(Finding(
            MODULE, f"OSINT Hosts / Sub-domains: {len(hosts)}",
            (f"theHarvester discovered {len(hosts)} host(s) for {domain}: "
             + ", ".join(hosts[:_MAX_SHOWN]) + (" …" if len(hosts) > _MAX_SHOWN else "")),
            Severity.INFO, "Review the externally-known hosts; restrict anything not meant to be public.",
            {"domain": domain, "hosts": hosts[:200], "confidence": "high"}))
    if ips:
        findings.append(Finding(
            MODULE, f"OSINT IP Addresses: {len(ips)}",
            f"theHarvester resolved {len(ips)} IP(s) for {domain}: " + ", ".join(ips[:_MAX_SHOWN]),
            Severity.INFO, "", {"domain": domain, "ips": ips[:200], "confidence": "high"}))
    if not findings:
        findings.append(Finding(MODULE, f"theHarvester: Nothing Found ({domain})",
                                f"theHarvester returned no e-mails, hosts or IPs for {domain}.",
                                Severity.INFO, "", {"domain": domain, "confidence": "high"}))
    return findings


def run(engine: ScanEngine) -> list[Finding]:
    harvester = which("theHarvester", "theharvester")
    if not harvester:
        return [missing_finding(MODULE, "theHarvester", "`pip install theHarvester`",
                                "OSINT e-mail/host harvesting")]

    domain = _domain(engine.url)
    if not domain:
        return [Finding(MODULE, "theHarvester Skipped", "No domain found in the target URL.",
                        Severity.INFO, "", {"confidence": "high"})]

    with tempfile.TemporaryDirectory() as tmp:
        stem = os.path.join(tmp, "harvest")
        _code, _out, err = run_tool(
            [harvester, "-d", domain, "-b", _SOURCES, "-l", "500", "-f", stem], _TIMEOUT)
        jpath = Path(stem + ".json")
        if not jpath.exists():
            return [Finding(MODULE, f"theHarvester: No Output ({domain})",
                            f"theHarvester produced no JSON for {domain} ({err or 'no result file'}).",
                            Severity.INFO, "", {"domain": domain, "error": err, "confidence": "high"})]
        try:
            data = json.loads(jpath.read_text(encoding="utf-8", errors="replace"))
        except (ValueError, OSError) as exc:
            logger.debug(f"theharvester_scan: cannot read JSON: {exc}")
            return [Finding(MODULE, "theHarvester Output Unparsable",
                            "theHarvester ran but its JSON output could not be parsed.",
                            Severity.INFO, "", {"domain": domain, "confidence": "high"})]

    emails, hosts, ips = _parse(data if isinstance(data, dict) else {})
    logger.info(f"theharvester_scan: {domain} → {len(emails)} email(s), {len(hosts)} host(s), {len(ips)} ip(s)")
    return _build_findings(domain, emails, hosts, ips)
