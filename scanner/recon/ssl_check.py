"""
ssl_check — inspects the TLS/SSL certificate and protocol version of the target.

Checks expiry, self-signed status, hostname match, issuer/subject info,
and flags legacy TLS 1.0/1.1 as High severity.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "ssl_check"

_LEGACY_TLS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}


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


def _get_name_attr(name: x509.Name, oid: x509.ObjectIdentifier) -> str:
    try:
        return name.get_attributes_for_oid(oid)[0].value
    except IndexError:
        return ""


def _fetch_cert_and_protocol(hostname: str, port: int) -> tuple[x509.Certificate, str]:
    """Open a TLS connection and return the parsed cert + negotiated protocol string."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((hostname, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
            protocol = tls.version() or "unknown"
            der = tls.getpeercert(binary_form=True)

    cert = x509.load_der_x509_certificate(der)
    return cert, protocol


def _check_expiry(cert: x509.Certificate, hostname: str) -> list[Finding]:
    findings: list[Finding] = []
    now = datetime.now(timezone.utc)

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    days_left = (not_after - now).days

    # Always emit an Info finding with the validity window
    findings.append(_finding(
        "SSL Certificate Validity",
        f"Valid from {not_before.strftime('%Y-%m-%d')} to {not_after.strftime('%Y-%m-%d')} "
        f"({days_left} day(s) remaining)",
        Severity.INFO,
        raw={
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_remaining": days_left,
        },
    ))

    if days_left < 0:
        findings.append(_finding(
            "SSL Certificate Expired",
            f"Certificate for {hostname} expired {abs(days_left)} day(s) ago "
            f"({not_after.strftime('%Y-%m-%d')}). Browsers will block access.",
            Severity.CRITICAL,
            recommendation="Renew the SSL certificate immediately.",
            raw={"expired_days_ago": abs(days_left)},
        ))
    elif days_left < 7:
        findings.append(_finding(
            "SSL Certificate Expiring Very Soon",
            f"Certificate expires in {days_left} day(s) ({not_after.strftime('%Y-%m-%d')}).",
            Severity.HIGH,
            recommendation="Renew the SSL certificate within the next 24–48 hours.",
            raw={"days_remaining": days_left},
        ))
    elif days_left < 30:
        findings.append(_finding(
            "SSL Certificate Expiring Soon",
            f"Certificate expires in {days_left} day(s) ({not_after.strftime('%Y-%m-%d')}).",
            Severity.MEDIUM,
            recommendation="Schedule certificate renewal before expiry.",
            raw={"days_remaining": days_left},
        ))

    return findings


def _check_self_signed(cert: x509.Certificate) -> Finding | None:
    issuer_cn = _get_name_attr(cert.issuer, NameOID.COMMON_NAME)
    subject_cn = _get_name_attr(cert.subject, NameOID.COMMON_NAME)
    if cert.issuer == cert.subject:
        return _finding(
            "Self-Signed Certificate",
            f"Certificate is self-signed (issuer == subject: \"{issuer_cn or subject_cn}\"). "
            "Browsers will display a security warning.",
            Severity.LOW,
            recommendation="Replace with a certificate issued by a trusted CA (e.g. Let's Encrypt).",
            raw={"issuer": issuer_cn, "subject": subject_cn},
        )
    return None


def _check_hostname(cert: x509.Certificate, hostname: str) -> Finding | None:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        dns_names = []

    # Fall back to CN if no SAN
    if not dns_names:
        cn = _get_name_attr(cert.subject, NameOID.COMMON_NAME)
        dns_names = [cn] if cn else []

    def _matches(name: str) -> bool:
        if name.startswith("*."):
            return hostname.count(".") >= 1 and hostname.split(".", 1)[1] == name[2:]
        return name.lower() == hostname.lower()

    if not any(_matches(n) for n in dns_names):
        return _finding(
            "Hostname Mismatch",
            f"Certificate SANs {dns_names} do not match hostname \"{hostname}\". "
            "Clients will reject this certificate.",
            Severity.HIGH,
            recommendation="Obtain a certificate that covers the target hostname.",
            raw={"hostname": hostname, "cert_names": dns_names},
        )
    return None


def _check_protocol(protocol: str) -> Finding | None:
    # Normalise: ssl.version() returns e.g. "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"
    normalised = protocol.replace(".", "").replace(" ", "")  # "TLSv11", "TLSv12" …
    label = protocol  # keep original for display

    # Match against known-bad versions
    if protocol in _LEGACY_TLS or normalised in {"TLSv10", "TLSv11", "SSLv2", "SSLv3"}:
        return _finding(
            f"Legacy TLS Protocol: {label}",
            f"Server negotiated {label}, which is deprecated and cryptographically weak.",
            Severity.HIGH,
            recommendation="Disable TLS 1.0 and 1.1 on the server; require TLS 1.2 as minimum.",
            raw={"protocol": protocol},
        )
    return None


def run(engine: ScanEngine) -> list[Finding]:
    parsed = urlparse(engine.url)
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        return [_finding(
            "No TLS — Plain HTTP",
            f"{engine.url} uses HTTP; no SSL certificate to inspect.",
            Severity.HIGH,
            recommendation="Enable HTTPS and redirect all HTTP traffic to HTTPS.",
            raw={"scheme": parsed.scheme},
        )]

    if not hostname:
        logger.warning("ssl_check: could not extract hostname from URL")
        return []

    try:
        cert, protocol = _fetch_cert_and_protocol(hostname, port)
    except Exception as exc:
        logger.warning(f"ssl_check: connection failed for {hostname}:{port}: {exc}")
        return [_finding(
            "SSL Connection Failed",
            f"Could not establish TLS connection to {hostname}:{port}: {exc}",
            Severity.HIGH,
            recommendation="Verify the server is reachable and TLS is properly configured.",
            raw={"error": str(exc)},
        )]

    findings: list[Finding] = []

    # Issuer / subject info
    subject_cn = _get_name_attr(cert.subject, NameOID.COMMON_NAME)
    issuer_cn = _get_name_attr(cert.issuer, NameOID.COMMON_NAME)
    issuer_org = _get_name_attr(cert.issuer, NameOID.ORGANIZATION_NAME)
    findings.append(_finding(
        "SSL Certificate Info",
        f"Subject: {subject_cn} | Issuer: {issuer_org or issuer_cn} | Protocol: {protocol}",
        Severity.INFO,
        raw={
            "subject_cn": subject_cn,
            "issuer_cn": issuer_cn,
            "issuer_org": issuer_org,
            "protocol": protocol,
            "serial": str(cert.serial_number),
        },
    ))

    findings.extend(_check_expiry(cert, hostname))

    self_signed = _check_self_signed(cert)
    if self_signed:
        findings.append(self_signed)

    hostname_mismatch = _check_hostname(cert, hostname)
    if hostname_mismatch:
        findings.append(hostname_mismatch)

    proto_finding = _check_protocol(protocol)
    if proto_finding:
        findings.append(proto_finding)

    return findings
