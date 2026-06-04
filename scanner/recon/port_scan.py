"""
port_scan — TCP connect scan of common service ports on the resolved host.

Resolves the target hostname to an IP and connects to a curated list of common ports,
classifying each open port by risk: exposed databases and remote-access services (MySQL,
Redis, MongoDB, RDP, VNC, SMB, Telnet) are High; cleartext services (FTP) Medium; SSH Low;
standard web/mail ports Info. When a port is open, a short banner grab is attempted to
confirm the service.

Reliability: firewalls/IPS/honeypots and some load balancers answer EVERY port (SYN-ACK to
all), which makes every port look open. An "accept-all" baseline probes random high ports
first; if those answer, the result is collapsed into a single advisory instead of dozens of
false positives — the TCP equivalent of the catch-all detection used by the HTTP modules.

Note: if the host sits behind a CDN/WAF, the scanned IP is the edge, so results describe the
edge, not the origin.
"""
from __future__ import annotations

import random
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "port_scan"
_TIMEOUT = 1.5
_BANNER_TIMEOUT = 1.0
_BANNER_BYTES = 256
_ACCEPT_ALL_PROBES = 4          # random high ports used to detect an accept-all host
_ACCEPT_ALL_THRESHOLD = 2       # this many open random ports ⇒ accept-all
_MAX_WORKERS = 64

# (port, service, severity-when-open)
_PORTS: list[tuple[int, str, Severity]] = [
    (21,    "FTP",            Severity.MEDIUM),
    (22,    "SSH",            Severity.LOW),
    (23,    "Telnet",         Severity.HIGH),
    (25,    "SMTP",           Severity.INFO),
    (53,    "DNS",            Severity.INFO),
    (80,    "HTTP",           Severity.INFO),
    (110,   "POP3",           Severity.INFO),
    (135,   "MSRPC",          Severity.MEDIUM),
    (139,   "NetBIOS",        Severity.MEDIUM),
    (143,   "IMAP",           Severity.INFO),
    (443,   "HTTPS",          Severity.INFO),
    (445,   "SMB",            Severity.HIGH),
    (1433,  "MSSQL",          Severity.HIGH),
    (1521,  "Oracle DB",      Severity.HIGH),
    (3306,  "MySQL",          Severity.HIGH),
    (3389,  "RDP",            Severity.HIGH),
    (5432,  "PostgreSQL",     Severity.HIGH),
    (5601,  "Kibana",         Severity.MEDIUM),
    (5900,  "VNC",            Severity.HIGH),
    (6379,  "Redis",          Severity.HIGH),
    (8080,  "HTTP-alt",       Severity.INFO),
    (8443,  "HTTPS-alt",      Severity.INFO),
    (9200,  "Elasticsearch",  Severity.HIGH),
    (11211, "Memcached",      Severity.HIGH),
    (15672, "RabbitMQ admin", Severity.MEDIUM),
    (27017, "MongoDB",        Severity.HIGH),
]

_RISK_NOTE: dict[Severity, str] = {
    Severity.HIGH: "This service should never be exposed to the internet — restrict it to a private "
                   "network or VPN, or firewall it off.",
    Severity.MEDIUM: "Limit exposure of this service and ensure it is patched and access-controlled.",
    Severity.LOW: "Exposed SSH is a brute-force surface — enforce key-only auth and rate limiting.",
    Severity.INFO: "",
}


def _resolve(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except OSError as exc:
        logger.debug(f"port_scan: cannot resolve {hostname}: {exc}")
        return None


def _probe_port(ip: str, port: int, timeout: float = _TIMEOUT) -> tuple[bool, str]:
    """Return (is_open, banner). Best-effort banner grab on a successful connect."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) != 0:
                return False, ""
            banner = ""
            try:
                sock.settimeout(_BANNER_TIMEOUT)
                data = sock.recv(_BANNER_BYTES)
                if data:
                    banner = data.decode("latin-1", "replace").strip().splitlines()[0][:120]
            except OSError:
                pass
            return True, banner
    except OSError:
        return False, ""


def _is_accept_all(ip: str, timeout: float = _TIMEOUT) -> bool:
    """True if the host answers random high ports that should be closed (firewall/IPS/honeypot)."""
    ports = random.sample(range(40000, 65500), _ACCEPT_ALL_PROBES)
    with ThreadPoolExecutor(max_workers=_ACCEPT_ALL_PROBES) as pool:
        opens = sum(1 for is_open, _ in pool.map(lambda p: _probe_port(ip, p, timeout), ports) if is_open)
    return opens >= _ACCEPT_ALL_THRESHOLD


def run(engine: ScanEngine) -> list[Finding]:
    hostname = urlparse(engine.url).hostname or ""
    ip = _resolve(hostname)
    if not ip:
        return [Finding(MODULE, "Port Scan Skipped — DNS Resolution Failed",
                        f"Could not resolve {hostname} to an IP address.",
                        Severity.INFO, "", {"hostname": hostname, "confidence": "high"})]

    # Accept-all detection: collapse the whole scan if the host answers everything.
    if _is_accept_all(ip):
        logger.info(f"port_scan: {ip} answers random closed ports — accept-all host, results unreliable")
        return [Finding(
            module=MODULE,
            title=f"Port Scan Unreliable — Host Answers All Ports ({ip})",
            description=(f"{hostname} ({ip}) accepts TCP connections on random, unused high ports, which "
                         "means a firewall/IPS, honeypot, or load balancer answers every port. Per-port "
                         "results would be false positives, so individual ports are not reported."),
            severity=Severity.INFO,
            recommendation=("Scan the real origin IP from an allowed network, or use SYN/service-version "
                            "scanning (e.g. nmap -sV) that can distinguish a real service from an accept-all device."),
            raw={"ip": ip, "hostname": hostname, "accept_all": True, "confidence": "high"},
        )]

    open_ports: list[tuple[int, str, Severity, str]] = []
    with ThreadPoolExecutor(max_workers=min(len(_PORTS), _MAX_WORKERS)) as pool:
        futures = {pool.submit(_probe_port, ip, port): (port, svc, sev)
                   for port, svc, sev in _PORTS}
        for future in as_completed(futures):
            port, svc, sev = futures[future]
            is_open, banner = future.result()
            if is_open:
                open_ports.append((port, svc, sev, banner))

    if not open_ports:
        return [Finding(MODULE, f"Port Scan: No Common Ports Open ({ip})",
                        f"None of the {len(_PORTS)} probed ports were open on {ip}.",
                        Severity.INFO, "", {"ip": ip, "confidence": "high"})]

    findings: list[Finding] = []
    for port, svc, sev, banner in sorted(open_ports):
        banner_note = f" Banner: {banner!r}." if banner else ""
        findings.append(Finding(
            module=MODULE,
            title=f"Open Port {port}/tcp ({svc})",
            description=f"Port {port} ({svc}) is open on {ip} ({hostname}).{banner_note}",
            severity=sev,
            recommendation=_RISK_NOTE[sev],
            raw={"ip": ip, "hostname": hostname, "port": port, "service": svc,
                 "banner": banner, "confidence": "high"},
        ))
    return findings
