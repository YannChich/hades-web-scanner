"""
bruteforce — opt-in credential spraying (authorised targets only).

DISABLED BY DEFAULT. It only runs when the operator passes --bruteforce, because actively
submitting credentials to someone else's system can be illegal without permission. When
enabled, it sprays a SMALL curated list of the most common weak credentials against:

  * HTML login forms discovered by the crawler (operator-injection-style success detection)
  * HTTP Basic-Auth endpoints (401 WWW-Authenticate: Basic)

It is a light *spray* (a dozen pairs), not an exhaustive brute-force, and every request goes
through the engine's rate limiter. A confirmed login is reported as Critical.
"""
from __future__ import annotations

import re

import httpx
from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "bruteforce"

# Most common weak credential pairs (curated spray, not a wordlist brute-force).
_CREDS: list[tuple[str, str]] = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"), ("admin", "123456"),
    ("admin", "changeme"), ("admin", "Password1"), ("administrator", "administrator"),
    ("root", "root"), ("root", "toor"), ("test", "test"), ("user", "user"), ("guest", "guest"),
]

_BASIC_PATHS = ["/admin", "/administrator", "/manager", "/private", "/api", "/.git",
                "/server-status", "/phpmyadmin", "/dashboard"]

_FAIL_RE = re.compile(r"invalid|incorrect|failed|wrong|denied|not match|try again|"
                      r"authentication failed|login failed", re.I)
_AUTH_RE = re.compile(r"log\s*out|sign\s*out|welcome\b|dashboard|my ?account|logged ?in", re.I)


# ---------------------------------------------------------------------------
# Login-form spraying
# ---------------------------------------------------------------------------

def _form_success(base: "httpx.Response | None", attempt: "httpx.Response | None") -> bool:
    if base is None or attempt is None or attempt.status_code >= 500:
        return False
    if _FAIL_RE.search(base.text) and not _FAIL_RE.search(attempt.text):
        return True
    if _AUTH_RE.search(attempt.text) and not _AUTH_RE.search(base.text):
        return True
    return False


def _spray_forms(engine: ScanEngine) -> list[Finding]:
    try:
        forms = engine.get_crawl().forms
    except Exception:  # noqa: BLE001
        return []
    findings: list[Finding] = []
    for form in forms:
        pw = [f for f in form.fields if "pass" in f.lower()]
        if not pw or (form.method or "").lower() != "post":
            continue
        user_field = next((f for f in form.fields if f not in pw), None)
        if not user_field:
            continue
        try:
            base = engine.request("POST", form.action,
                                  data={**form.fields, user_field: "zzdoesnotexist", pw[0]: "zzbadpw"})
        except httpx.HTTPError:
            continue
        for user, pwd in _CREDS:
            data = {**form.fields, user_field: user}
            for f in pw:
                data[f] = pwd
            try:
                resp = engine.request("POST", form.action, data=data)
            except httpx.HTTPError:
                continue
            if _form_success(base, resp):
                findings.append(_finding(form.action, "login form", user, pwd))
                break
    return findings


# ---------------------------------------------------------------------------
# HTTP Basic-Auth spraying
# ---------------------------------------------------------------------------

def _spray_basic(engine: ScanEngine) -> list[Finding]:
    findings: list[Finding] = []
    for path in _BASIC_PATHS:
        try:
            probe = engine.request("GET", engine.url + path)
        except httpx.HTTPError:
            continue
        if probe.status_code != 401 or "basic" not in probe.headers.get("www-authenticate", "").lower():
            continue
        for user, pwd in _CREDS:
            try:
                resp = engine.request("GET", engine.url + path, auth=(user, pwd))
            except httpx.HTTPError:
                continue
            if resp.status_code in (200, 301, 302):
                findings.append(_finding(engine.url + path, "HTTP Basic-Auth", user, pwd))
                break
    return findings


def _finding(target: str, kind: str, user: str, pwd: str) -> Finding:
    return Finding(
        module=MODULE,
        title=f"Valid Credentials Found ({kind}): {user}/{pwd}",
        description=(
            f"The {kind} at {target} accepted the common credential pair '{user}:{pwd}'. "
            "An attacker gains authenticated access to protected functionality."
        ),
        severity=Severity.CRITICAL,
        recommendation=(
            "Change the password to a strong, unique value, enforce account lockout / rate "
            "limiting, and add multi-factor authentication."
        ),
        raw={"target": target, "kind": kind, "username": user, "password": pwd,
             "url": target, "proof_url": target, "confidence": "high",
             "attack": "T1110.003 Password Spraying"},
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(engine: ScanEngine) -> list[Finding]:
    # Hard gate: only ever runs with the explicit opt-in flag.
    if not getattr(engine, "bruteforce", False):
        return []
    logger.info("bruteforce: credential spraying enabled (--bruteforce)")
    findings: list[Finding] = []
    for fn in (_spray_forms, _spray_basic):
        try:
            findings.extend(fn(engine))
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"bruteforce: {fn.__name__} failed: {exc}")
    return findings
