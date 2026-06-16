"""
nmap_scan — service/version (and best-effort OS) detection via the real Nmap, when installed.

Hades's built-in ``port_scan`` is a fast TCP-connect sweep; this optional module shells out to Nmap's
``-sV`` engine for accurate service + version fingerprints (and an OS guess) on the resolved host — the
depth a socket scan can't provide, and exactly what ``port_scan`` itself recommends. Each open port is
rated by what it exposes (databases / remote-access = High, cleartext = Medium, SSH = Low, web/mail =
Info). Optional: if Nmap is absent, a single INFO hint is emitted and the scan continues. Active scan,
so it is skipped in safe mode. Handshake/enumeration only — no exploitation, no NSE intrusive scripts.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from urllib.parse import urlparse

from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine
from scanner.integrations._external import missing_finding, run_tool, which

MODULE = "nmap_scan"
_TIMEOUT = 280.0
# Curated web/infra-relevant ports — bounded so `-sV` stays fast and deterministic.
_PORTS = ("21,22,23,25,53,80,110,135,139,143,443,445,1433,1521,3306,3389,5432,5601,"
          "5900,6379,8000,8080,8443,9200,11211,15672,27017")

# Port → severity when open (mirrors port_scan's risk model; unlisted ports are Info).
_PORT_SEV: dict[int, Severity] = {
    23: Severity.HIGH, 445: Severity.HIGH, 1433: Severity.HIGH, 1521: Severity.HIGH,
    3306: Severity.HIGH, 3389: Severity.HIGH, 5432: Severity.HIGH, 5900: Severity.HIGH,
    6379: Severity.HIGH, 9200: Severity.HIGH, 11211: Severity.HIGH, 27017: Severity.HIGH,
    21: Severity.MEDIUM, 135: Severity.MEDIUM, 139: Severity.MEDIUM, 5601: Severity.MEDIUM,
    15672: Severity.MEDIUM, 22: Severity.LOW,
}
_RISK_NOTE: dict[Severity, str] = {
    Severity.HIGH: "This service should never be exposed to the internet — restrict it to a private "
                   "network/VPN or firewall it off.",
    Severity.MEDIUM: "Limit exposure of this service and keep it patched and access-controlled.",
    Severity.LOW: "Exposed SSH is a brute-force surface — enforce key-only auth and rate limiting.",
    Severity.INFO: "",
}


def _parse(xml_text: str) -> tuple[list[tuple[int, str, str, str, str]], str]:
    """Parse `nmap -oX -` output → ([(port, proto, service, product, version)], os_guess)."""
    root = ET.fromstring(xml_text)
    host = root.find("host")
    if host is None:
        return [], ""
    os_guess = ""
    osmatch = host.find("os/osmatch")
    if osmatch is not None:
        os_guess = osmatch.get("name", "")
    ports: list[tuple[int, str, str, str, str]] = []
    for port in host.findall("ports/port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        svc = port.find("service")
        ports.append((
            int(port.get("portid", "0")),
            port.get("protocol", "tcp"),
            (svc.get("name", "") if svc is not None else ""),
            (svc.get("product", "") if svc is not None else ""),
            (svc.get("version", "") if svc is not None else ""),
        ))
    return ports, os_guess


def run(engine: ScanEngine) -> list[Finding]:
    if engine.is_safe_mode():
        return [Finding(MODULE, "Nmap Scan Skipped (Safe Mode)",
                        "Active service/version scanning was skipped because safe mode is enabled.",
                        Severity.INFO, "Re-run without safe mode on an authorised target.",
                        {"reason": "safe_mode", "confidence": "high"})]

    nmap = which("nmap")
    if not nmap:
        return [missing_finding(MODULE, "Nmap", "https://nmap.org/download — or `apt install nmap`",
                                "service/version scanning")]

    host = urlparse(engine.url).hostname or ""
    if not host:
        return [Finding(MODULE, "Nmap Scan Skipped", "No host found in the target URL.",
                        Severity.INFO, "", {"confidence": "high"})]

    code, out, err = run_tool([nmap, "-sV", "-Pn", "-T4", "-p", _PORTS, "-oX", "-", host], _TIMEOUT)
    if not out:
        return [Finding(MODULE, "Nmap Scan Did Not Complete",
                        f"Nmap produced no output for {host} ({err or 'unknown error'}).",
                        Severity.INFO, "", {"host": host, "error": err, "confidence": "high"})]
    try:
        ports, os_guess = _parse(out)
    except ET.ParseError as exc:
        logger.debug(f"nmap_scan: XML parse failed: {exc}")
        return [Finding(MODULE, "Nmap Output Unparsable",
                        "Nmap ran but its XML output could not be parsed.",
                        Severity.INFO, "", {"host": host, "confidence": "high"})]

    findings: list[Finding] = []
    for portid, proto, service, product, version in sorted(ports):
        sev = _PORT_SEV.get(portid, Severity.INFO)
        ver = " ".join(x for x in (product, version) if x).strip()
        findings.append(Finding(
            module=MODULE,
            title=f"Open Port {portid}/{proto} ({service or 'unknown'})" + (f" — {ver}" if ver else ""),
            description=(f"Nmap -sV found {service or 'a service'}"
                         f"{(' ' + ver) if ver else ''} listening on {host}:{portid}."),
            severity=sev,
            recommendation=_RISK_NOTE.get(sev, ""),
            raw={"host": host, "port": portid, "protocol": proto, "service": service,
                 "product": product, "version": version, "confidence": "high",
                 "evidence": [f"nmap -sV {host} → {portid}/{proto} open"
                              + (f": {service} {ver}".rstrip() if (service or ver) else "")]},
        ))

    if os_guess:
        findings.append(Finding(MODULE, f"OS Fingerprint (Nmap): {os_guess}",
                                f"Nmap's best-effort OS match for {host} is {os_guess!r}.",
                                Severity.INFO, "", {"host": host, "os": os_guess, "confidence": "medium"}))
    if not findings:
        return [Finding(MODULE, f"Nmap: No Open Ports ({host})",
                        f"Nmap -sV found none of the probed ports open on {host}.",
                        Severity.INFO, "", {"host": host, "confidence": "high"})]
    logger.info(f"nmap_scan: {len(ports)} open port(s) on {host}")
    return findings
