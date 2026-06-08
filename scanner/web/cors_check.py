"""
cors_check — detects CORS misconfigurations that allow cross-origin credential theft.

Sends probes with crafted Origin headers and inspects Access-Control-Allow-Origin
and Access-Control-Allow-Credentials to identify reflected-origin and wildcard issues.
"""
from __future__ import annotations

from urllib.parse import urlparse

import httpx
from loguru import logger

from scanner import evidence as ev
from scanner.engine import Finding, Severity, ScanEngine

MODULE = "cors_check"

_EVIL_ORIGIN = "https://evil.example.com"

# Additional probes: null origin (sandboxed iframe trick) and
# a subdomain-prefix bypass attempt against the target itself.
_EXTRA_ORIGINS = [
    "null",
    "https://evil.example.com",
]


def _probe(engine: ScanEngine, origin: str) -> httpx.Response | None:
    try:
        return engine.request("GET", engine.url, headers={"Origin": origin})
    except httpx.HTTPError as exc:
        logger.debug(f"cors_check: probe with Origin:{origin} failed: {exc}")
        return None


def _acao(resp: httpx.Response) -> str:
    return resp.headers.get("access-control-allow-origin", "").strip()


def _acac(resp: httpx.Response) -> bool:
    return resp.headers.get("access-control-allow-credentials", "").strip().lower() == "true"


def _subdomain_bypass_origin(target_url: str) -> str:
    """Return a crafted origin that prepends 'evil.' to the target host."""
    parsed = urlparse(target_url)
    return f"{parsed.scheme}://evil.{parsed.netloc}"


def run(engine: ScanEngine) -> list[Finding]:
    findings: list[Finding] = []
    reported: set[str] = set()   # deduplicate findings across probes

    def _add(finding: Finding) -> None:
        key = finding.title
        if key not in reported:
            reported.add(key)
            findings.append(finding)

    origins_to_test = [
        _EVIL_ORIGIN,
        "null",
        _subdomain_bypass_origin(engine.url),
    ]

    for origin in origins_to_test:
        resp = _probe(engine, origin)
        if resp is None:
            continue

        acao = _acao(resp)
        credentials = _acac(resp)

        if not acao:
            continue

        # ----------------------------------------------------------------
        # Case 1: wildcard + credentials — impossible per spec, but some
        #         servers do it anyway, meaning they ignore the spec check
        # ----------------------------------------------------------------
        if acao == "*" and credentials:
            _add(Finding(
                module=MODULE,
                title="CORS: Wildcard Origin with Allow-Credentials",
                description=(
                    "Server responds with 'Access-Control-Allow-Origin: *' and "
                    "'Access-Control-Allow-Credentials: true'. Browsers block this per spec, "
                    "but some non-browser clients (mobile apps, Electron) will honour it, "
                    "allowing any origin to make credentialed cross-origin requests."
                ),
                severity=Severity.CRITICAL,
                recommendation=(
                    "Never combine a wildcard ACAO with Allow-Credentials: true. "
                    "Maintain an explicit allowlist of trusted origins."
                ),
                raw={"acao": acao, "acac": credentials, "probe_origin": origin,
                     "evidence": ev.from_response(
                         resp, indicator=f"sent Origin: {origin} → ACAO: {acao or '(none)'}, "
                         f"ACAC: {str(credentials).lower()}")},
            ))

        # ----------------------------------------------------------------
        # Case 2: reflected arbitrary origin + credentials → exploitable CSRF/data theft
        # ----------------------------------------------------------------
        elif acao == origin and origin != "null" and credentials:
            _add(Finding(
                module=MODULE,
                title="CORS: Arbitrary Origin Reflected with Allow-Credentials",
                description=(
                    f"Server reflects the attacker-controlled Origin '{origin}' back in "
                    "Access-Control-Allow-Origin and also sets Allow-Credentials: true. "
                    "Any website can make authenticated cross-origin requests and read the response, "
                    "enabling session hijacking and data exfiltration."
                ),
                severity=Severity.CRITICAL,
                recommendation=(
                    "Validate the Origin header against an explicit allowlist of trusted origins. "
                    "Never echo back an arbitrary Origin value."
                ),
                raw={"acao": acao, "acac": credentials, "probe_origin": origin,
                     "evidence": ev.from_response(
                         resp, indicator=f"sent Origin: {origin} → ACAO: {acao or '(none)'}, "
                         f"ACAC: {str(credentials).lower()}")},
            ))

        # ----------------------------------------------------------------
        # Case 3: reflected arbitrary origin, no credentials — still a risk
        # ----------------------------------------------------------------
        elif acao == origin and origin != "null":
            _add(Finding(
                module=MODULE,
                title="CORS: Arbitrary Origin Reflected (No Credentials)",
                description=(
                    f"Server reflects the attacker-controlled Origin '{origin}' in "
                    "Access-Control-Allow-Origin. Without Allow-Credentials the impact is limited "
                    "to reading non-authenticated cross-origin responses, but this still violates "
                    "the same-origin policy and may expose API data."
                ),
                severity=Severity.MEDIUM,
                recommendation=(
                    "Validate the Origin header against an allowlist. "
                    "Do not dynamically reflect arbitrary origin values."
                ),
                raw={"acao": acao, "acac": credentials, "probe_origin": origin,
                     "evidence": ev.from_response(
                         resp, indicator=f"sent Origin: {origin} → ACAO: {acao or '(none)'}, "
                         f"ACAC: {str(credentials).lower()}")},
            ))

        # ----------------------------------------------------------------
        # Case 4: null origin reflected — sandboxed iframe / file:// bypass
        # ----------------------------------------------------------------
        elif acao == "null" and origin == "null":
            _add(Finding(
                module=MODULE,
                title="CORS: Null Origin Allowed",
                description=(
                    "Server permits 'Origin: null', which can be sent by sandboxed iframes, "
                    "local file:// pages, and data: URIs. An attacker can use a sandboxed iframe "
                    "to issue credentialed cross-origin requests if Allow-Credentials is also set."
                ),
                severity=Severity.HIGH if credentials else Severity.MEDIUM,
                recommendation=(
                    "Remove 'null' from the CORS allowlist. "
                    "Only explicitly trusted HTTPS origins should be permitted."
                ),
                raw={"acao": acao, "acac": credentials, "probe_origin": origin,
                     "evidence": ev.from_response(
                         resp, indicator=f"sent Origin: {origin} → ACAO: {acao or '(none)'}, "
                         f"ACAC: {str(credentials).lower()}")},
            ))

        # ----------------------------------------------------------------
        # Case 5: wildcard origin, no credentials
        # ----------------------------------------------------------------
        elif acao == "*":
            _add(Finding(
                module=MODULE,
                title="CORS: Wildcard Origin (Access-Control-Allow-Origin: *)",
                description=(
                    "Server sets 'Access-Control-Allow-Origin: *'. Without Allow-Credentials this is the "
                    "intended, safe configuration for public, read-only resources (CDNs, fonts, open APIs) "
                    "and cannot expose authenticated data — browsers refuse to send cookies. It is only "
                    "worth tightening if this specific endpoint serves per-user data."
                ),
                severity=Severity.LOW,
                recommendation=(
                    "No action needed for genuinely public resources. If THIS endpoint returns "
                    "authenticated/per-user data, replace the wildcard with an explicit allowlist of "
                    "trusted origins."
                ),
                raw={"acao": acao, "acac": credentials, "probe_origin": origin,
                     "evidence": ev.from_response(
                         resp, indicator=f"sent Origin: {origin} → ACAO: {acao or '(none)'}, "
                         f"ACAC: {str(credentials).lower()}")},
            ))

    if not findings:
        findings.append(Finding(
            module=MODULE,
            title="CORS: No Misconfiguration Detected",
            description="CORS probes with crafted Origin headers did not reveal a misconfiguration.",
            severity=Severity.INFO,
            recommendation="",
            raw={"probes": origins_to_test},
        ))

    return findings
