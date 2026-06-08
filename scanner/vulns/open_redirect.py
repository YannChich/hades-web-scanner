"""
open_redirect — detects open / unvalidated redirects in URL parameters.

For each parameter it injects a unique sentinel external URL and requests WITHOUT following
redirects, then confirms the server sends the user to the attacker-controlled host via the
Location header, a <meta http-equiv=refresh>, or a JavaScript location assignment.

Open redirects are abused in phishing (a link that starts on your trusted domain but lands
on the attacker's) and to bypass redirect allowlists in OAuth/login flows. MEDIUM (HIGH when
the parameter drives an authentication flow). Skipped in safe mode.
"""
from __future__ import annotations

import re
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import httpx
from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine
from scanner.vulns._common import Injector, evidence, is_safe_mode, iter_injectors

MODULE = "open_redirect"

_AUTH_HINTS = ("return", "next", "redirect", "redir", "callback", "continue", "back", "go")


def _sentinel() -> tuple[str, str]:
    host = f"hades-{uuid.uuid4().hex[:10]}.example"
    return host, f"https://{host}/"


def _redirects_to(resp: httpx.Response, sentinel_host: str) -> str | None:
    """Return the mechanism if the response sends the user to sentinel_host, else None."""
    loc = resp.headers.get("location", "")
    if loc and urlparse(loc if "//" in loc else "//" + loc).netloc.endswith(sentinel_host):
        return "Location header"
    body = resp.text[:4000]
    if re.search(rf'http-equiv=["\']?refresh[^>]*{re.escape(sentinel_host)}', body, re.IGNORECASE):
        return "meta refresh"
    if re.search(rf'(location\.(href|replace|assign)\s*[=(]|window\.location)\s*["\'][^"\']*{re.escape(sentinel_host)}',
                 body, re.IGNORECASE):
        return "JavaScript location"
    return None


def _finding(inj: Injector, payload: str, mechanism: str,
             proof_lines: list[str] | None = None) -> Finding:
    proof_url = inj.proof(payload) if inj.proof else None
    auth = any(h in inj.param.lower() for h in _AUTH_HINTS)
    return Finding(
        module=MODULE,
        title=f"Open Redirect: {inj.param}",
        description=(f"Parameter '{inj.param}' redirects to an arbitrary external URL ({mechanism}). "
                     f"Payload: {payload!r}. An attacker can craft a link on your domain that sends "
                     "victims to a malicious site (phishing), or bypass redirect allowlists in login/OAuth."),
        severity=Severity.HIGH if auth else Severity.MEDIUM,
        recommendation=("Do not redirect to user-supplied URLs. Use an allowlist of internal paths, or "
                        "map an opaque token to a fixed destination server-side."),
        raw={"location": inj.label, "parameter": inj.param, "payload": payload,
             "mechanism": mechanism, "proof_url": proof_url, "confidence": "high",
             "evidence": proof_lines or [f"injected into {inj.label}: {payload}"],
             "exploitation": _exploitation_steps(inj)},
    )


def _exploitation_steps(inj: Injector) -> list[dict]:
    """Weaponise a confirmed open redirect for phishing / OAuth token theft. Authorised targets only."""
    if inj.proof is None:
        return [{"step": 1, "description": "Set the redirect target to an attacker-controlled URL.",
                 "command": f"<set {inj.param} to https://attacker.example/login>"}]
    return [
        {"step": 1, "description": "Phishing: a link on the trusted domain that lands on the attacker site.",
         "command": inj.proof("https://attacker.example/login")},
        {"step": 2, "description": "Abuse OAuth/SSO redirect allowlists to capture the auth code/token.",
         "command": inj.proof("https://attacker.example/oauth-callback")},
    ]


def _test(engine: ScanEngine, inj: Injector) -> Finding | None:
    # Needs a timeable/buildable URL and no auto-redirect — URL parameters only.
    if inj.proof is None:
        return None
    host, payload = _sentinel()
    url = inj.proof(payload)
    try:
        resp = engine.request("GET", url, follow_redirects=False)
    except httpx.HTTPError as exc:
        logger.debug(f"open_redirect: {url} → {exc}")
        return None
    mechanism = _redirects_to(resp, host)
    if not mechanism:
        return None
    proof_lines = evidence(inj, payload, resp,
                           indicator=f"redirects to attacker host via {mechanism} → {host}")
    return _finding(inj, payload, mechanism, proof_lines)


def run(engine: ScanEngine) -> list[Finding]:
    if is_safe_mode(engine):
        return [Finding(MODULE, "Open Redirect Scan Skipped (Safe Mode)",
                        "Active redirect probing was skipped because safe mode is enabled.",
                        Severity.INFO, "Re-run without safe mode on an authorised target.",
                        {"reason": "safe_mode", "confidence": "high"})]

    injectors = [i for i in iter_injectors(engine) if i.proof is not None]
    if not injectors:
        return [Finding(MODULE, "Open Redirect: No Injectable Parameters Found",
                        "No URL parameters were discovered to test.",
                        Severity.INFO, "", {"confidence": "high"})]

    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=engine.threads) as pool:
        futures = {pool.submit(_test, engine, inj): inj for inj in injectors}
        for future in as_completed(futures):
            result = future.result()
            if result:
                findings.append(result)

    if not findings:
        return [Finding(MODULE, "Open Redirect: None Detected",
                        f"Tested {len(injectors)} parameter(s); none redirected to an external host.",
                        Severity.INFO, "", {"params_tested": len(injectors), "confidence": "high"})]
    return findings
