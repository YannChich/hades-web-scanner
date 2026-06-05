"""
oob_detect — out-of-band (OAST) blind-vulnerability detection (the 'oob_scan' profile).

Catches the vulnerabilities that leave no trace in the HTTP response — blind SSRF, blind OS command
injection (RCE) and blind/stored XSS — by injecting payloads that make the *server* call back to a
self-hosted listener. Each payload carries a unique token; a received callback proves the bug and
pinpoints the exact injection point (the source IP of the callback is the target itself).

The target must be able to reach the listener. Its address is auto-detected (the host's primary IP)
and shown in the report; override it with --oob-host when you sit behind NAT (public IP / tunnel).
Detection-only probing with benign callbacks (an HTTP GET to your listener); skipped in safe mode.
"""
from __future__ import annotations

import os
import time

from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine
from scanner.oob.listener import OOBListener
from scanner.oob.tunnel import Tunnel
from scanner.severity import sort_by_severity
from scanner.vulns._common import is_safe_mode, iter_injectors

MODULE = "oob_detect"

# Cap the injection surface so an OOB run stays bounded.
_MAX_INJECTORS = 20
# Seconds to wait for callbacks after injecting (override via engine.oob_wait).
_GRACE = 8.0

# Per blind-vulnerability class: (title, severity, cwe, owasp, mitre, attack_category).
_CLASS_META: dict[str, tuple] = {
    "ssrf": ("Blind SSRF (out-of-band)", Severity.HIGH, "CWE-918",
             "A10:2021 Server-Side Request Forgery", ["T1190"], "ssrf"),
    "cmd":  ("Blind OS Command Injection / RCE (out-of-band)", Severity.CRITICAL, "CWE-78",
             "A03:2021 Injection", ["T1059"], "rce"),
    "xss":  ("Blind / Stored XSS (out-of-band)", Severity.HIGH, "CWE-79",
             "A03:2021 Injection", ["T1059"], "xss"),
}


def _payloads_for(vclass: str, url: str) -> list[str]:
    """Payloads that, if the bug exists, make the server fetch *url* (one token per class)."""
    if vclass == "ssrf":
        return [url]
    if vclass == "cmd":
        return [f";curl -s {url}", f"|curl -s {url}", f"`curl -s {url}`",
                f"$(curl -s {url})", f";wget -qO- {url}", f"& curl {url}"]
    if vclass == "xss":
        return [f'"><script src="{url}"></script>', f'"><img src="{url}">']
    return []


def _f(title: str, desc: str, sev: Severity, rec: str, category: str,
       cwe: str = "", owasp: str = "", mitre: list[str] | None = None, **raw) -> Finding:
    raw["oob_category"] = category
    raw.setdefault("confidence", "high")
    return Finding(module=MODULE, title=title, description=desc, severity=sev,
                   recommendation=rec, raw=raw, cwe=cwe, owasp=owasp, mitre=list(mitre or []))


def _resolve_oob(engine: ScanEngine) -> tuple[str | None, int]:
    host = getattr(engine, "oob_host", None) or os.environ.get("HADES_OOB_HOST") or None
    try:
        port = int(getattr(engine, "oob_port", 0) or os.environ.get("HADES_OOB_PORT") or 0)
    except (TypeError, ValueError):
        port = 0
    return host, port


def run(engine: ScanEngine) -> list[Finding]:
    if is_safe_mode(engine):
        return [_f("OOB Scan Skipped (Safe Mode)",
                   "Out-of-band probing was skipped because safe mode is enabled.",
                   Severity.INFO, "Re-run without safe mode on an authorised target.", "info")]

    injectors = iter_injectors(engine)
    if not injectors:
        return [_f("OOB: No Injectable Inputs Found",
                   "No URL parameters or form fields were discovered to test.",
                   Severity.INFO, "", "info")]

    host, port = _resolve_oob(engine)
    listener = OOBListener(public_host=host, port=port)
    try:
        listener.start()
    except OSError as exc:
        logger.warning(f"oob_detect: could not start the callback listener: {exc}")
        return [_f("OOB Listener Failed to Start",
                   f"Could not bind the out-of-band callback listener ({exc}). "
                   "Set --oob-port to a free port (and --oob-host to a reachable address).",
                   Severity.INFO, "", "info")]

    # Make the listener reachable by the target. Priority: explicit --oob-host > public tunnel
    # (cloudflared/ngrok, no account needed) > the host's local IP (LAN-only).
    tunnel: Tunnel | None = None
    if not host and getattr(engine, "oob_tunnel", True):
        tunnel = Tunnel()
        turl = tunnel.start(listener.port)
        if turl:
            listener.external_base = turl

    if tunnel and tunnel.tool:
        reach = (f"reachable from anywhere via a {tunnel.tool} tunnel. (The callback source IP will be "
                 "the tunnel's, not the target's.)")
    elif host:
        reach = "reachable at the address you provided (--oob-host)."
    else:
        reach = ("only reachable on this host's local network. Behind NAT, install cloudflared "
                 "(free, no account) for an automatic public tunnel, or pass --oob-host with a "
                 "public/tunnel address — otherwise the target cannot call back.")

    findings: list[Finding] = []
    try:
        findings.append(_f(
            f"OOB Callback Listener Active — {listener.base_url}",
            f"Hades is listening for out-of-band callbacks at {listener.base_url}, {reach} "
            "No callbacks may mean 'not vulnerable' OR 'listener not reachable'.",
            Severity.INFO, "", "info", listener=listener.base_url,
            tunnel=(tunnel.tool if tunnel else "")))

        # Inject every class into every input, one unique token per (input, class).
        pending: list[tuple[str, str, str, str]] = []   # (token, vclass, label, callback_url)
        for inj in injectors[:_MAX_INJECTORS]:
            for vclass in _CLASS_META:
                token = listener.new_token()
                url = listener.url_for(token)
                for payload in _payloads_for(vclass, url):
                    try:
                        inj.inject(payload)
                    except Exception as exc:  # noqa: BLE001
                        logger.debug(f"oob_detect: inject {vclass} into {inj.param} failed: {exc}")
                pending.append((token, vclass, inj.label, url))

        # Give the server time to call back (immediate for SSRF/RCE; stored XSS may never fire in-scan).
        time.sleep(float(getattr(engine, "oob_wait", _GRACE)))

        seen: set[tuple[str, str]] = set()
        for token, vclass, label, url in pending:
            hits = listener.hits_for(token)
            if not hits:
                continue
            key = (vclass, label)
            if key in seen:
                continue
            seen.add(key)
            title_base, sev, cwe, owasp, mitre, category = _CLASS_META[vclass]
            hit = hits[0]
            findings.append(_f(
                f"{title_base}: {label}",
                f"A callback from {hit.source_ip} confirmed {title_base.split(' (')[0].lower()} on {label}. "
                f"The server fetched the unique OAST URL {url} (method {hit.method}), proving the input is "
                "processed out-of-band — a blind bug that leaves no trace in the HTTP response.",
                sev, "Validate/allow-list inputs, block outbound to untrusted hosts, and never pass input "
                "to a shell or URL fetcher.", category, cwe=cwe, owasp=owasp, mitre=mitre,
                parameter=getattr(hit, "token", ""), proof_url=url, source_ip=hit.source_ip,
                exploit_cmd=f"curl -sk \"{url}\""))
    finally:
        listener.stop()
        if tunnel:
            tunnel.stop()

    blind = sum(1 for f in findings if f.raw.get("oob_category") not in (None, "info"))
    logger.info(f"oob_detect: {blind} blind vuln(s) confirmed via OAST")
    return sort_by_severity(findings)
