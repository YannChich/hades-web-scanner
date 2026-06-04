"""
default_creds — advisory detection of services that ship with well-known default credentials.

This module is deliberately NON-INTRUSIVE: it fingerprints management interfaces
(phpMyAdmin, Tomcat Manager, Jenkins, Grafana, GitLab, Adminer, …) by their pages/realms
and reports the *documented* default credentials for manual verification. It never submits
login attempts — actively trying credentials against a third party is intrusive and may be
illegal. Findings are Medium: a prompt to confirm the defaults were changed.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

import httpx
from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "default_creds"


@dataclass(frozen=True)
class _Service:
    name: str
    path: str               # path that identifies the service
    signature: str          # case-insensitive substring (in body or WWW-Authenticate)
    defaults: str           # documented default credentials
    login_url: str          # where an operator would log in


_SERVICES: list[_Service] = [
    _Service("phpMyAdmin",      "/phpmyadmin/",       "phpmyadmin",        "root / (empty)", "/phpmyadmin/"),
    _Service("Adminer",         "/adminer.php",       "adminer",           "(server-dependent)", "/adminer.php"),
    _Service("Tomcat Manager",  "/manager/html",      "tomcat",            "tomcat/tomcat, admin/admin", "/manager/html"),
    _Service("Jenkins",         "/login",             "jenkins",           "(no default; check setup wizard)", "/login"),
    _Service("Grafana",         "/login",             "grafana",           "admin/admin", "/login"),
    _Service("Kibana",          "/app/kibana",        "kibana",            "elastic/changeme", "/login"),
    _Service("GitLab",          "/users/sign_in",     "gitlab",            "root/5iveL!fe (old installs)", "/users/sign_in"),
    _Service("WordPress",       "/wp-login.php",      "wordpress",         "admin/admin (if unchanged)", "/wp-login.php"),
    _Service("Jenkins script",  "/script",            "jenkins",           "(no default; check setup wizard)", "/script"),
    _Service("RabbitMQ",        "/",                  "rabbitmq",          "guest/guest", "/"),
    _Service("PgAdmin",         "/pgadmin4",          "pgadmin",           "(set at install)", "/pgadmin4"),
    _Service("Portainer",       "/",                  "portainer",         "admin/(set on first run)", "/"),
]


def _matches(resp: httpx.Response, sig: str) -> bool:
    sig = sig.lower()
    if sig in resp.headers.get("www-authenticate", "").lower():
        return True
    if resp.status_code in (200, 401, 403) and sig in resp.text.lower():
        return True
    return False


def _probe(engine: ScanEngine, svc: _Service) -> _Service | None:
    try:
        resp = engine.get(svc.path)
    except httpx.HTTPError as exc:
        logger.debug(f"default_creds: {svc.path} → {exc}")
        return None
    return svc if _matches(resp, svc.signature) else None


def run(engine: ScanEngine) -> list[Finding]:
    # Deduplicate probe paths (several services share '/').
    seen_paths: set[str] = set()
    to_probe: list[_Service] = []
    for svc in _SERVICES:
        if svc.path not in seen_paths or svc.signature not in {s.signature for s in to_probe}:
            seen_paths.add(svc.path)
            to_probe.append(svc)

    detected: list[_Service] = []
    with ThreadPoolExecutor(max_workers=engine.threads) as pool:
        futures = {pool.submit(_probe, engine, s): s for s in to_probe}
        for future in as_completed(futures):
            result = future.result()
            if result:
                detected.append(result)

    if not detected:
        return [Finding(MODULE, "Default Credentials: No Known Services Detected",
                        "No management interface with documented default credentials was fingerprinted.",
                        Severity.INFO, "", {"confidence": "high"})]

    findings: list[Finding] = []
    for svc in detected:
        full_url = engine.url.rstrip("/") + svc.login_url
        findings.append(Finding(
            module=MODULE,
            title=f"Default-Credential Risk: {svc.name}",
            description=(f"A {svc.name} interface was detected at {full_url}. Documented default "
                         f"credentials for {svc.name}: {svc.defaults}. This scan does NOT attempt to "
                         "log in — verify manually that the defaults have been changed."),
            severity=Severity.MEDIUM,
            recommendation=(f"Confirm {svc.name} is not using default credentials, enforce strong "
                            "unique passwords + MFA, and restrict the interface to a private network."),
            raw={"service": svc.name, "url": full_url, "default_credentials": svc.defaults,
                 "confidence": "medium"},
        ))
    return findings
