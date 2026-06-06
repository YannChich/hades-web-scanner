"""
hephaestus_tls — offensive TLS/SSL attack-surface validation (the 'tls_scan' profile, menu option 9).

Forges a precise picture of a target's transport-layer crypto using the SSLyze handshake engine:
legacy protocols (SSLv2/3, TLS 1.0/1.1), weak/anonymous/NULL cipher suites, missing forward secrecy,
certificate trust/expiry/hostname/weak-signature problems, TLS compression (CRIME), insecure
renegotiation, and the known TLS vulnerability classes SSLyze can confirm with a handshake
(Heartbleed, ROBOT, OpenSSL CCS injection). Each weakness is rated by what it enables for an attacker
on the wire (downgrade, sniffing, AitM) and mapped to CWE / OWASP / MITRE ATT&CK.

It is handshake-only and read-only: no exploitation, no brute force, no DoS, no interception, no secret
extraction — only the safe probes SSLyze performs. DNS failures, timeouts, blocked connections and
hosts without TLS are handled gracefully. SSLyze is an optional dependency; without it the module
emits a single INFO finding telling the user to install it.
"""
from __future__ import annotations

import warnings
from datetime import datetime, timezone
from urllib.parse import urlparse

from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "hephaestus_tls"

# Protocol ordering for "strongest / weakest" posture analysis.
_PROTO_ORDER = ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]

# Reference material per weakness class (clickable in the HTML report).
_REF_DEPRECATION = ["https://datatracker.ietf.org/doc/html/rfc8996",
                    "https://wiki.mozilla.org/Security/Server_Side_TLS"]
_REF_CIPHERS = ["https://wiki.mozilla.org/Security/Server_Side_TLS", "https://ciphersuite.info/"]
_REF_FS = ["https://wiki.mozilla.org/Security/Server_Side_TLS#Forward_Secrecy"]
_REF_CERT = ["https://cwe.mitre.org/data/definitions/295.html"]
_REF_HEARTBLEED = ["https://nvd.nist.gov/vuln/detail/CVE-2014-0160", "https://heartbleed.com/"]
_REF_ROBOT = ["https://robotattack.org/", "https://nvd.nist.gov/vuln/detail/CVE-2017-13099"]
_REF_CCS = ["https://nvd.nist.gov/vuln/detail/CVE-2014-0224"]
_REF_CRIME = ["https://nvd.nist.gov/vuln/detail/CVE-2012-4929"]
_REF_RENEG = ["https://nvd.nist.gov/vuln/detail/CVE-2009-3555"]

_CWE_CRYPTO = "CWE-326"          # Inadequate Encryption Strength
_CWE_CERT = "CWE-295"            # Improper Certificate Validation
_OWASP = "A02:2021 Cryptographic Failures"
_MITM = ["T1557", "T1040"]       # Adversary-in-the-Middle + Network Sniffing

# Substrings that mark a cipher suite as weak (OpenSSL/IANA names, upper-cased).
_WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES-", "_DES_", "DES_CBC", "EXPORT", "EXP-", "MD5", "IDEA",
                        "SEED", "CAMELLIA")
_DEPRECATED_KX = ("_RSA_WITH", "TLS_RSA_")   # static-RSA key exchange (no forward secrecy)


# ---------------------------------------------------------------------------
# Finding builder
# ---------------------------------------------------------------------------

def _finding(title: str, severity: Severity, description: str, impact: str, evidence: list[str],
             host: str, port: int, cwe: str, owasp: str, mitre: list[str], remediation: str,
             references: list[str], category: str, confidence: str = "high") -> Finding:
    """Build a Hades Finding carrying the offensive TLS context (impact, evidence, refs)."""
    target = f"{host}:{port}"
    ev = evidence + [f"Target: {target}"]
    body = (f"{description}\n\nOffensive impact: {impact}\n\nEvidence:\n"
            + "\n".join(f"- {e}" for e in ev))
    return Finding(
        module=MODULE, title=title, description=body, severity=severity,
        recommendation=remediation, cwe=cwe, owasp=owasp, mitre=list(mitre),
        raw={"tls_category": category, "offensive_impact": impact, "evidence": ev,
             "affected_component": f"TLS/SSL endpoint ({target})", "references": references,
             "host": host, "port": port, "confidence": confidence},
    )


def _info(title: str, description: str, host: str = "", port: int = 0, **raw) -> Finding:
    raw.setdefault("confidence", "high")
    raw["tls_category"] = raw.get("tls_category", "info")
    return Finding(module=MODULE, title=title, description=description, severity=Severity.INFO,
                   recommendation="", raw=raw)


# ---------------------------------------------------------------------------
# SSLyze result helpers (read attributes so the analysis is unit-testable with fakes)
# ---------------------------------------------------------------------------

def _ok(attempt) -> bool:
    """True if a ScanCommandAttempt completed successfully."""
    return attempt is not None and getattr(getattr(attempt, "status", None), "name", "") == "COMPLETED"


def _accepted(attempt) -> list:
    return list(attempt.result.accepted_cipher_suites) if _ok(attempt) else []


# ---------------------------------------------------------------------------
# Protocol analysis
# ---------------------------------------------------------------------------

# (attribute on AllScanCommandsAttempts, human label, severity, attacker impact)
_PROTOCOLS: list[tuple[str, str, Severity, str]] = [
    ("ssl_2_0_cipher_suites", "SSL 2.0", Severity.HIGH,
     "SSLv2 is fundamentally broken (DROWN); an attacker can decrypt or downgrade sessions."),
    ("ssl_3_0_cipher_suites", "SSL 3.0", Severity.HIGH,
     "SSLv3 is broken by POODLE; an on-path attacker can decrypt traffic via padding-oracle downgrade."),
    ("tls_1_0_cipher_suites", "TLS 1.0", Severity.MEDIUM,
     "TLS 1.0 is deprecated (BEAST/downgrade); an on-path attacker may force weaker legacy negotiation."),
    ("tls_1_1_cipher_suites", "TLS 1.1", Severity.MEDIUM,
     "TLS 1.1 is deprecated; it widens the downgrade surface and lacks modern AEAD protections."),
]


def _analyze_protocols(sr, host: str, port: int) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    supported: set[str] = set()

    for attr, label, sev, impact in _PROTOCOLS:
        if _accepted(getattr(sr, attr, None)):
            supported.add(label)
            findings.append(_finding(
                f"{label} Enabled", sev,
                f"The server accepts {label} connections. {label} is deprecated/insecure and increases "
                "the attack surface for downgrade and legacy cryptographic attacks.",
                impact, [f"Protocol: {label}", "Status: Accepted"], host, port,
                _CWE_CRYPTO, _OWASP, _MITM,
                "Disable SSLv2, SSLv3, TLS 1.0 and TLS 1.1. Only allow TLS 1.2 and TLS 1.3.",
                _REF_DEPRECATION, "legacy_protocol"))

    tls12 = bool(_accepted(getattr(sr, "tls_1_2_cipher_suites", None)))
    tls13 = bool(_accepted(getattr(sr, "tls_1_3_cipher_suites", None)))
    if tls12:
        supported.add("TLS 1.2")
    if tls13:
        supported.add("TLS 1.3")
        findings.append(_info("TLS 1.3 Supported",
                              "The server supports TLS 1.3 — the strongest, modern TLS version with "
                              "AEAD-only cipher suites and forward secrecy by default.",
                              host, port, tls_category="modern_tls"))
    elif tls12:
        findings.append(_finding(
            "TLS 1.3 Not Supported", Severity.LOW,
            "The server does not support TLS 1.3. TLS 1.3 removes legacy cipher suites and weak "
            "key-exchange modes and reduces the downgrade surface.",
            "Without TLS 1.3 the server keeps a larger negotiation surface that downgrade attacks "
            "can probe.", ["Strongest version: TLS 1.2", "TLS 1.3: Not offered"], host, port,
            _CWE_CRYPTO, _OWASP, ["T1557"],
            "Enable TLS 1.3 alongside TLS 1.2 with a modern cipher configuration.",
            _REF_DEPRECATION, "suboptimal_tls", confidence="medium"))

    return findings, supported


# ---------------------------------------------------------------------------
# Cipher-suite analysis (weak / anonymous / NULL / forward secrecy)
# ---------------------------------------------------------------------------

def _cipher_name(accepted) -> str:
    cs = accepted.cipher_suite
    return (getattr(cs, "openssl_name", "") or getattr(cs, "name", "") or "").upper()


def _analyze_ciphers(sr, host: str, port: int) -> list[Finding]:
    findings: list[Finding] = []
    weak: list[str] = []
    anon_null: list[str] = []
    fs_attrs = ("tls_1_0_cipher_suites", "tls_1_1_cipher_suites", "tls_1_2_cipher_suites")
    all_pre13: list = []
    seen: set[str] = set()

    for attr in ("ssl_2_0_cipher_suites", "ssl_3_0_cipher_suites", *fs_attrs):
        for acc in _accepted(getattr(sr, attr, None)):
            all_pre13.append(acc)
            name = _cipher_name(acc)
            if name in seen:
                continue
            seen.add(name)
            cs = acc.cipher_suite
            if getattr(cs, "is_anonymous", False) or "NULL" in name or "ADH" in name or "AECDH" in name:
                anon_null.append(name)
            elif (any(m in name for m in _WEAK_CIPHER_MARKERS)
                  or (getattr(cs, "key_size", 256) or 256) < 128):
                weak.append(name)

    if anon_null:
        findings.append(_finding(
            "Anonymous/NULL Cipher Suites Accepted", Severity.HIGH,
            "The server accepts anonymous or NULL cipher suites, which provide no authentication "
            "and/or no encryption of the channel.",
            "An on-path attacker can man-in-the-middle the connection with no certificate, or read "
            "traffic in cleartext — a trivial AitM.",
            [f"Ciphers: {', '.join(anon_null[:6])}"], host, port, _CWE_CRYPTO, _OWASP, _MITM,
            "Disable all aNULL/eNULL/ADH/AECDH cipher suites; require authenticated AEAD ciphers.",
            _REF_CIPHERS, "anon_null_cipher"))

    if weak:
        findings.append(_finding(
            "Weak Cipher Suites Accepted", Severity.MEDIUM,
            "The server accepts weak/deprecated cipher suites (e.g. RC4, 3DES/DES, EXPORT, MD5, or "
            "keys under 128 bits).",
            "An attacker recording the traffic can attempt practical cryptanalysis (e.g. SWEET32 on "
            "3DES, RC4 biases) to recover plaintext such as session cookies.",
            [f"Weak ciphers: {', '.join(weak[:8])}"], host, port, _CWE_CRYPTO, _OWASP, _MITM,
            "Remove RC4, DES/3DES, EXPORT, MD5 and sub-128-bit ciphers; allow only strong AEAD suites.",
            _REF_CIPHERS, "weak_cipher"))

    # Forward secrecy: at least one accepted pre-1.3 cipher must use an ephemeral key (ECDHE/DHE).
    # TLS 1.3 always provides forward secrecy, so only flag when 1.3 is absent and 1.2/lower has none.
    if all_pre13 and not _accepted(getattr(sr, "tls_1_3_cipher_suites", None)):
        if not any(getattr(acc, "ephemeral_key", None) is not None for acc in all_pre13):
            findings.append(_finding(
                "No Forward Secrecy", Severity.MEDIUM,
                "No accepted cipher suite provides forward secrecy (no ECDHE/DHE key exchange) and "
                "TLS 1.3 is not offered.",
                "If the server's private key is ever compromised (or seized), an attacker who recorded "
                "past traffic can decrypt all of it retroactively.",
                ["Key exchange: static RSA only", "Ephemeral (ECDHE/DHE): none"], host, port,
                _CWE_CRYPTO, _OWASP, _MITM,
                "Prefer ECDHE/DHE key exchange (and enable TLS 1.3) so each session uses ephemeral keys.",
                _REF_FS, "no_forward_secrecy"))

    return findings


# ---------------------------------------------------------------------------
# Certificate analysis
# ---------------------------------------------------------------------------

def _hostname_matches(cert, host: str) -> bool | None:
    try:
        import cryptography.x509 as x509
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except Exception:  # noqa: BLE001 — no SAN or parse issue → unknown
        return None
    host = host.lower().rstrip(".")
    for name in (n.lower() for n in san):
        if name == host:
            return True
        if name.startswith("*.") and host.count(".") >= name.count(".") and \
                host.split(".", 1)[-1] == name[2:]:
            return True
    return False


def _cert_expiry(cert) -> datetime | None:
    dt = getattr(cert, "not_valid_after_utc", None) or getattr(cert, "not_valid_after", None)
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _extract_cert(dep, host: str) -> dict:
    """Pull the decision-relevant facts out of a SSLyze certificate deployment."""
    leaf = dep.received_certificate_chain[0]
    trusted = any(getattr(p, "verified_certificate_chain", None) is not None
                  for p in (dep.path_validation_results or []))
    self_signed = leaf.subject == leaf.issuer
    sig = getattr(getattr(leaf, "signature_hash_algorithm", None), "name", "") or ""
    weak_sig = sig.lower() in ("md5", "sha1") or bool(getattr(dep, "verified_chain_has_sha1_signature", False))
    expiry = _cert_expiry(leaf)
    days_left = int((expiry - datetime.now(timezone.utc)).total_seconds() // 86400) if expiry else None
    return {"trusted": trusted, "self_signed": self_signed, "weak_sig": weak_sig, "sig": sig,
            "expiry": expiry, "days_left": days_left, "hostname_match": _hostname_matches(leaf, host),
            "subject": leaf.subject.rfc4514_string()[:120]}


def _cert_findings(info: dict, host: str, port: int) -> list[Finding]:
    findings: list[Finding] = []
    days = info.get("days_left")

    if days is not None and days < 0:
        findings.append(_finding(
            "Certificate Expired", Severity.HIGH,
            f"The server's TLS certificate expired {abs(days)} day(s) ago.",
            "Clients see hard TLS errors; users habituated to clicking through them are primed for an "
            "AitM with an attacker-supplied certificate.",
            [f"Subject: {info.get('subject', '')}", f"Expired: {info.get('expiry')}"], host, port,
            _CWE_CERT, _OWASP, ["T1557"],
            "Renew and deploy a valid certificate; automate renewal (e.g. ACME).", _REF_CERT, "cert_expired"))
    elif days is not None and days <= 21:
        findings.append(_finding(
            "Certificate Expires Soon", Severity.LOW,
            f"The server's TLS certificate expires in {days} day(s).",
            "An imminent expiry leads to an outage or to users being trained to bypass TLS warnings.",
            [f"Subject: {info.get('subject', '')}", f"Expires: {info.get('expiry')}"], host, port,
            _CWE_CERT, _OWASP, [], "Renew the certificate before expiry and automate renewal.",
            _REF_CERT, "cert_expiring", confidence="high"))

    if info.get("hostname_match") is False:
        findings.append(_finding(
            "Certificate Hostname Mismatch", Severity.HIGH,
            f"The certificate is not valid for {host} (the hostname is absent from its SAN list).",
            "Mismatched certificates condition users to ignore TLS warnings, and may indicate a "
            "mis-deployment an attacker can leverage for AitM.",
            [f"Requested host: {host}", f"Subject: {info.get('subject', '')}"], host, port,
            _CWE_CERT, _OWASP, ["T1557"],
            "Deploy a certificate whose SAN covers the served hostname(s).", _REF_CERT, "cert_mismatch"))

    if info.get("self_signed"):
        findings.append(_finding(
            "Self-Signed / Untrusted Certificate", Severity.HIGH,
            "The leaf certificate is self-signed (issuer equals subject) and not anchored to a trusted CA.",
            "Self-signed certs train users to accept untrusted certificates, making an attacker's "
            "AitM certificate indistinguishable from the real one.",
            [f"Subject: {info.get('subject', '')}", "Issuer: self"], host, port, _CWE_CERT, _OWASP,
            ["T1557"], "Use a certificate issued by a publicly trusted CA.", _REF_CERT, "cert_self_signed"))
    elif not info.get("trusted"):
        findings.append(_finding(
            "Untrusted Certificate Chain", Severity.HIGH,
            "The certificate chain does not validate against the standard trust stores (untrusted or "
            "incomplete chain).",
            "An untrusted chain produces browser warnings users learn to bypass, weakening protection "
            "against AitM.",
            [f"Subject: {info.get('subject', '')}", "Chain validation: failed"], host, port, _CWE_CERT,
            _OWASP, ["T1557"], "Serve the full chain from a publicly trusted CA.", _REF_CERT, "cert_untrusted"))

    if info.get("weak_sig"):
        findings.append(_finding(
            "Weakly Signed Certificate", Severity.MEDIUM,
            f"The certificate (or its chain) uses a weak signature algorithm ({info.get('sig') or 'SHA-1'}).",
            "Weak signatures (MD5/SHA-1) are vulnerable to collision attacks that could let an attacker "
            "forge a trusted certificate.",
            [f"Signature: {info.get('sig') or 'sha1'}"], host, port, _CWE_CRYPTO, _OWASP, ["T1557"],
            "Re-issue the certificate with a SHA-256 (or stronger) signature.", _REF_CERT, "cert_weak_sig"))

    if not findings and info.get("trusted") and info.get("hostname_match") is not False:
        findings.append(_info("Valid Certificate Chain",
                              f"The certificate is trusted, matches {host}, and is not expired.",
                              host, port, tls_category="cert_ok"))
    return findings


# ---------------------------------------------------------------------------
# Known TLS vulnerability classes + config weaknesses
# ---------------------------------------------------------------------------

def _analyze_vulns(sr, host: str, port: int) -> list[Finding]:
    findings: list[Finding] = []

    hb = getattr(sr, "heartbleed", None)
    if _ok(hb) and getattr(hb.result, "is_vulnerable_to_heartbleed", False):
        findings.append(_finding(
            "Heartbleed (CVE-2014-0160)", Severity.CRITICAL,
            "The server is vulnerable to Heartbleed — a buffer over-read in OpenSSL's heartbeat extension.",
            "An attacker can dump up to 64 KB of process memory per request, repeatedly — leaking "
            "private keys, session cookies and credentials, leading to full TLS/private-key compromise.",
            ["Probe: TLS heartbeat over-read", "Status: Vulnerable"], host, port, _CWE_CRYPTO, _OWASP,
            ["T1557", "T1040"], "Upgrade OpenSSL immediately and rotate the private key and all secrets.",
            _REF_HEARTBLEED, "heartbleed"))

    ccs = getattr(sr, "openssl_ccs_injection", None)
    if _ok(ccs) and getattr(ccs.result, "is_vulnerable_to_ccs_injection", False):
        findings.append(_finding(
            "OpenSSL CCS Injection (CVE-2014-0224)", Severity.HIGH,
            "The server is vulnerable to the OpenSSL ChangeCipherSpec injection flaw.",
            "An on-path attacker can force a weak keying material and decrypt/modify traffic between "
            "client and server (AitM).",
            ["Probe: early CCS", "Status: Vulnerable"], host, port, _CWE_CRYPTO, _OWASP, _MITM,
            "Upgrade OpenSSL to a patched version.", _REF_CCS, "ccs_injection"))

    robot = getattr(sr, "robot", None)
    if _ok(robot):
        rr = getattr(getattr(robot.result, "robot_result", None), "name", "")
        if rr.startswith("VULNERABLE"):
            findings.append(_finding(
                "ROBOT Attack Exposure", Severity.HIGH,
                "The server is vulnerable to ROBOT (Return Of Bleichenbacher's Oracle Threat) via an "
                "RSA padding oracle in RSA key exchange.",
                "An attacker can perform RSA decryption or sign operations with the server's key, "
                "decrypting captured sessions or forging signatures (AitM).",
                [f"Oracle: {rr.replace('VULNERABLE_', '').replace('_', ' ').title()}"], host, port,
                _CWE_CRYPTO, _OWASP, _MITM,
                "Disable RSA key exchange (use ECDHE) and patch the TLS stack.", _REF_ROBOT, "robot"))

    comp = getattr(sr, "tls_compression", None)
    if _ok(comp) and getattr(comp.result, "supports_compression", False):
        findings.append(_finding(
            "TLS Compression Enabled (CRIME)", Severity.MEDIUM,
            "TLS-level compression is enabled, exposing the server to the CRIME attack.",
            "An on-path attacker observing compressed sizes can recover secrets such as session "
            "cookies from the encrypted stream.",
            ["TLS compression: Enabled"], host, port, _CWE_CRYPTO, _OWASP, _MITM,
            "Disable TLS compression at the server.", _REF_CRIME, "tls_compression"))

    reneg = getattr(sr, "session_renegotiation", None)
    if _ok(reneg) and not getattr(reneg.result, "supports_secure_renegotiation", True):
        findings.append(_finding(
            "Insecure Renegotiation Supported", Severity.MEDIUM,
            "The server supports insecure (legacy) TLS renegotiation without RFC 5746 protection.",
            "An attacker can prefix attacker-chosen plaintext into a victim's session (request "
            "injection) via a man-in-the-middle renegotiation.",
            ["Secure renegotiation (RFC 5746): No"], host, port, _CWE_CRYPTO, _OWASP, _MITM,
            "Enable secure renegotiation (RFC 5746) or disable client-initiated renegotiation.",
            _REF_RENEG, "insecure_reneg"))

    return findings


# ---------------------------------------------------------------------------
# Pure analysis entry point (testable without the network)
# ---------------------------------------------------------------------------

def analyze(scan_result, host: str, port: int) -> list[Finding]:
    """Turn a SSLyze AllScanCommandsAttempts result into Hades findings."""
    findings: list[Finding] = []

    # Certificate.
    ci = getattr(scan_result, "certificate_info", None)
    if _ok(ci):
        try:
            deployments = ci.result.certificate_deployments
            if deployments:
                findings.extend(_cert_findings(_extract_cert(deployments[0], host), host, port))
        except Exception as exc:  # noqa: BLE001 — never crash on an odd certificate
            logger.debug(f"hephaestus_tls: certificate analysis failed: {exc}")

    proto_findings, supported = _analyze_protocols(scan_result, host, port)
    findings.extend(proto_findings)
    findings.extend(_analyze_ciphers(scan_result, host, port))
    findings.extend(_analyze_vulns(scan_result, host, port))

    # Posture summary: strongest supported version + weakest accepted configuration.
    if supported:
        ordered = [v for v in _PROTO_ORDER if v in supported]
        strongest, weakest = ordered[-1], ordered[0]
        legacy = [v for v in ("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1") if v in supported]
        findings.append(_info(
            f"TLS Posture: strongest {strongest}, weakest {weakest}",
            f"Supported protocols: {', '.join(ordered)}. Strongest negotiable version is {strongest}; "
            f"the weakest accepted is {weakest}." + (f" Legacy/deprecated still enabled: {', '.join(legacy)}."
                                                     if legacy else " No legacy protocols enabled."),
            host, port, tls_category="posture", strongest=strongest, weakest=weakest,
            supported=ordered))
    return findings


# ---------------------------------------------------------------------------
# Module entry point — runs the SSLyze scan, then analyses it
# ---------------------------------------------------------------------------

def _host_port(url: str) -> tuple[str, int]:
    p = urlparse(url if "://" in url else "https://" + url)
    return (p.hostname or ""), (p.port or 443)


def run(engine: ScanEngine) -> list[Finding]:
    host, port = _host_port(engine.url)
    if not host:
        return [_info("TLS Scan Skipped — No Hostname", f"Could not extract a hostname from {engine.url}.")]

    try:
        from sslyze import (Scanner, ScanCommand, ServerNetworkLocation, ServerScanRequest,
                            ServerScanStatusEnum)
        from sslyze.errors import ServerHostnameCouldNotBeResolved
    except ImportError:
        return [_info("TLS Scan Skipped — SSLyze Not Installed",
                      "The hephaestus_tls module needs the SSLyze library. Install it with "
                      "`pip install sslyze` and re-run.", host, port, confidence="high")]

    # Build the server location (resolves DNS here — handle failures gracefully).
    try:
        location = ServerNetworkLocation(hostname=host, port=port)
    except ServerHostnameCouldNotBeResolved:
        return [_info("TLS Scan Skipped — DNS Resolution Failed",
                      f"Could not resolve {host}.", host, port)]
    except Exception as exc:  # noqa: BLE001
        return [_info("TLS Scan Skipped — Connection Error",
                      f"Could not prepare a TLS scan for {host}:{port}: {exc}", host, port)]

    commands = {
        ScanCommand.CERTIFICATE_INFO,
        ScanCommand.SSL_2_0_CIPHER_SUITES, ScanCommand.SSL_3_0_CIPHER_SUITES,
        ScanCommand.TLS_1_0_CIPHER_SUITES, ScanCommand.TLS_1_1_CIPHER_SUITES,
        ScanCommand.TLS_1_2_CIPHER_SUITES, ScanCommand.TLS_1_3_CIPHER_SUITES,
        ScanCommand.TLS_COMPRESSION, ScanCommand.SESSION_RENEGOTIATION,
        ScanCommand.HEARTBLEED, ScanCommand.ROBOT, ScanCommand.OPENSSL_CCS_INJECTION,
    }
    request = ServerScanRequest(server_location=location, scan_commands=commands)

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")          # silence noisy cryptography/trust-store warnings
            scanner = Scanner()
            scanner.queue_scans([request])
            results = list(scanner.get_results())
    except Exception as exc:  # noqa: BLE001 — network/timeout/blocked connection must not crash the scan
        logger.warning(f"hephaestus_tls: SSLyze scan failed for {host}:{port}: {exc}")
        return [_info("TLS Scan Failed — Connection Error",
                      f"The TLS scan of {host}:{port} could not complete ({type(exc).__name__}). The "
                      "host may be unreachable, not serving TLS on this port, or blocking the scan.",
                      host, port)]

    if not results:
        return [_info("TLS Scan — No Result", f"No TLS scan result was returned for {host}:{port}.",
                      host, port)]

    result = results[0]
    if getattr(getattr(result, "scan_status", None), "name", "") != "COMPLETED":
        return [_info("TLS Scan Skipped — No Connectivity",
                      f"Could not establish a TLS connection to {host}:{port} (host down, port closed, "
                      "no TLS, or the connection was blocked).", host, port)]

    try:
        findings = analyze(result.scan_result, host, port)
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"hephaestus_tls: analysis failed for {host}:{port}: {exc}")
        return [_info("TLS Scan — Analysis Error", f"TLS analysis failed: {exc}", host, port)]

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f.severity.value, 9))
    logger.info(f"hephaestus_tls: {host}:{port} → {len(findings)} TLS finding(s)")
    return findings
