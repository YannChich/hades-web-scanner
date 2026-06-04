"""
ssti_detect — detects Server-Side Template Injection in parameters and form fields.

It injects a distinctive arithmetic expression in each major template syntax and confirms
the server EVALUATED it (the product appears in the response) rather than echoing it. The
product uses large primes so a coincidental match is essentially impossible. The firing
syntax fingerprints the likely engine (Jinja2/Twig, FreeMarker/Spring, ERB, Ruby/Thymeleaf).

A confirmed hit is CRITICAL (SSTI frequently leads to RCE). Skipped in safe mode. A ready
tplmap command is attached for exploitation on authorised targets.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.engine import Finding, Severity, ScanEngine
from scanner.vulns._common import Injector, is_safe_mode, iter_injectors

MODULE = "ssti_detect"

_A, _B = 9787, 7919          # primes; product is highly distinctive
_PRODUCT = str(_A * _B)      # "77523853"
_EXPR = f"{_A}*{_B}"

# (template syntax, likely engine)
_PROBES: list[tuple[str, str]] = [
    (f"{{{{{_EXPR}}}}}",   "Jinja2 / Twig / Nunjucks"),   # {{a*b}}
    (f"${{{_EXPR}}}",      "FreeMarker / Spring EL"),      # ${a*b}
    (f"#{{{_EXPR}}}",      "Ruby / Thymeleaf"),            # #{a*b}
    (f"<%= {_EXPR} %>",    "ERB / EJS"),                   # <%= a*b %>
    (f"@({_EXPR})",        "Razor (.NET)"),                # @(a*b)
    (f"*{{{_EXPR}}}",      "Thymeleaf"),                   # *{a*b}
]


def _finding(inj: Injector, payload: str, engine_name: str) -> Finding:
    proof_url = inj.proof(payload) if inj.proof else None
    tplmap = f'tplmap -u "{proof_url}"' if proof_url else None
    return Finding(
        module=MODULE,
        title=f"Server-Side Template Injection: {inj.param} ({engine_name})",
        description=(f"Input to {inj.label} is evaluated by a server-side template engine "
                     f"({engine_name}). The payload {payload!r} returned the computed value {_PRODUCT}. "
                     "SSTI commonly escalates to remote code execution."
                     + (f"\n\nExploit with tplmap (authorised targets only):\n  {tplmap}" if tplmap else "")),
        severity=Severity.CRITICAL,
        recommendation=("Never render user input as a template. Use logic-less templates or a sandbox, "
                        "and pass user data only as bound variables — never concatenated into the template."),
        raw={"location": inj.label, "parameter": inj.param, "engine": engine_name,
             "payload": payload, "proof_url": proof_url, "tplmap": tplmap, "confidence": "high"},
    )


def _test(inj: Injector) -> Finding | None:
    for payload, engine_name in _PROBES:
        resp = inj.inject(payload)
        # Evaluated if the product is present but the literal expression is not echoed back.
        if resp is not None and _PRODUCT in resp.text and _EXPR not in resp.text:
            return _finding(inj, payload, engine_name)
    return None


def run(engine: ScanEngine) -> list[Finding]:
    if is_safe_mode(engine):
        return [Finding(MODULE, "SSTI Scan Skipped (Safe Mode)",
                        "Active SSTI probing was skipped because safe mode is enabled.",
                        Severity.INFO, "Re-run without safe mode on an authorised target.",
                        {"reason": "safe_mode", "confidence": "high"})]

    injectors = iter_injectors(engine)
    if not injectors:
        return [Finding(MODULE, "SSTI: No Injectable Inputs Found",
                        "No URL parameters or form fields were discovered to test.",
                        Severity.INFO, "", {"confidence": "high"})]

    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=engine.threads) as pool:
        for result in pool.map(_test, injectors):
            if result:
                findings.append(result)

    if not findings:
        return [Finding(MODULE, "SSTI: None Detected",
                        f"Tested {len(injectors)} input(s) across {len(_PROBES)} template syntaxes.",
                        Severity.INFO, "", {"inputs_tested": len(injectors), "confidence": "high"})]
    return findings
