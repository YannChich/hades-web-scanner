"""
js_recon — offensive JavaScript reconnaissance.

Fetches the JavaScript referenced by the crawled pages (plus inline scripts and the page
HTML itself) and mines it for two things a red team wants early:

  1. **Leaked secrets** — API keys, tokens and private keys hard-coded in front-end code
     (AWS, Google, Stripe, GitHub, Slack, SendGrid, Twilio, private keys, JWTs…).
  2. **Hidden endpoints / parameters** — `/api/...`, `fetch()` / `axios` URLs and route
     strings that expand the attack surface for every injection module.

Detection only: it reads files the site already serves. Secrets are redacted in the report.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

import httpx
from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "js_recon"

# Hard cap so a big site with many bundles can't stall the scan.
_MAX_JS_FILES = 40
_MAX_JS_BYTES = 3_000_000

# (name, compiled pattern, severity). Patterns with a capture group expose the value in
# group(1); otherwise the whole match is the secret. Prefixes are specific to keep FP low.
_SECRETS: list[tuple[str, "re.Pattern[str]", Severity]] = [
    ("AWS Access Key ID", re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), Severity.CRITICAL),
    ("AWS Secret Access Key",
     re.compile(r"(?i)aws_secret_access_key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+]{40})"), Severity.CRITICAL),
    ("Google API Key", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), Severity.HIGH),
    ("Google OAuth Client", re.compile(r"\b([0-9]+-[0-9a-z]{32}\.apps\.googleusercontent\.com)\b"), Severity.MEDIUM),
    ("Stripe Live Secret Key", re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,})\b"), Severity.CRITICAL),
    ("Stripe Restricted Key", re.compile(r"\b(rk_live_[0-9a-zA-Z]{24,})\b"), Severity.HIGH),
    ("GitHub Personal Token", re.compile(r"\b(ghp_[0-9A-Za-z]{36})\b"), Severity.CRITICAL),
    ("GitHub OAuth Token", re.compile(r"\b(gh[ous]_[0-9A-Za-z]{36})\b"), Severity.CRITICAL),
    ("Slack Token", re.compile(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,48})\b"), Severity.CRITICAL),
    ("Slack Webhook", re.compile(r"(https://hooks\.slack\.com/services/[A-Za-z0-9/]+)"), Severity.HIGH),
    ("SendGrid API Key", re.compile(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"), Severity.CRITICAL),
    ("Twilio Account SID", re.compile(r"\b(AC[0-9a-fA-F]{32})\b"), Severity.HIGH),
    ("Mailgun API Key", re.compile(r"\b(key-[0-9a-zA-Z]{32})\b"), Severity.HIGH),
    ("Square Access Token", re.compile(r"\b(sq0atp-[0-9A-Za-z_\-]{22})\b"), Severity.HIGH),
    ("Private Key Block",
     re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)"), Severity.CRITICAL),
    ("Generic Secret Assignment",
     re.compile(r"(?i)(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key|client[_-]?secret|"
                r"auth[_-]?token|password)['\"]?\s*[:=]\s*['\"]([0-9a-zA-Z_\-]{16,64})['\"]"),
     Severity.MEDIUM),
]

# Interesting endpoints/routes referenced in code (attack-surface expansion).
_ENDPOINT_RE = re.compile(
    r"""['"`](/(?:api|v\d+|rest|graphql|gql|admin|internal|private|auth|oauth|login|"""
    r"""logout|user|users|account|accounts|profile|upload|download|export|import|"""
    r"""payment|billing|webhook|callback|debug|config|settings|token)"""
    r"""[A-Za-z0-9_\-/.]{0,80})['"`]""")

# Obvious non-secret placeholders to ignore (reduce false positives).
_PLACEHOLDER_RE = re.compile(
    r"(?i)your[_-]?api|example|xxxx|placeholder|<.*>|change[_-]?me|0{8,}|1234567|sample")


def _redact(value: str) -> str:
    if len(value) <= 10:
        return value[:2] + "…"
    return f"{value[:4]}…{value[-4:]} ({len(value)} chars)"


# ---------------------------------------------------------------------------
# JavaScript collection
# ---------------------------------------------------------------------------

def _script_srcs(html: str, page_url: str, host: str) -> list[str]:
    """Same-host <script src> URLs from one page, resolved to absolute."""
    out: list[str] = []
    for m in re.finditer(r"<script[^>]+src=['\"]([^'\"]+)['\"]", html, re.I):
        absolute = urljoin(page_url, m.group(1))
        if urlparse(absolute).hostname == host:
            out.append(absolute.split("#")[0])
    return out


def _collect_sources(engine: ScanEngine) -> dict[str, str]:
    """Return {source_label: text} for every page HTML, inline script, and same-host JS file."""
    try:
        crawl = engine.get_crawl()
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"js_recon: crawl unavailable: {exc}")
        return {}

    host = urlparse(engine.url).hostname or ""
    sources: dict[str, str] = {}
    js_urls: set[str] = set()

    for page_url, html in crawl.pages.items():
        sources[page_url] = html                       # scan the HTML itself (inline scripts)
        for src in _script_srcs(html, page_url, host):
            js_urls.add(src)

    for js_url in list(js_urls)[:_MAX_JS_FILES]:
        try:
            resp = engine.request("GET", js_url, timeout=10.0)
        except httpx.HTTPError as exc:
            logger.debug(f"js_recon: GET {js_url} → {exc}")
            continue
        if resp.status_code == 200 and len(resp.content) <= _MAX_JS_BYTES:
            sources[js_url] = resp.text
    return sources


# ---------------------------------------------------------------------------
# Mining
# ---------------------------------------------------------------------------

def _scan_secrets(sources: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for src, text in sources.items():
        for name, rx, sev in _SECRETS:
            for m in rx.finditer(text):
                value = m.group(1) if m.groups() else m.group(0)
                if _PLACEHOLDER_RE.search(value):
                    continue
                key = (name, value)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(
                    module=MODULE,
                    title=f"Leaked Secret in JavaScript: {name}",
                    description=(
                        f"A {name} is hard-coded in front-end code at {src}: {_redact(value)}. "
                        "Anyone can read it from the browser and abuse the associated service."
                    ),
                    severity=sev,
                    recommendation=(
                        "Remove the secret from client-side code, move it server-side, and "
                        "rotate/revoke the exposed key immediately."
                    ),
                    raw={"type": name, "source": src, "secret": _redact(value),
                         "confidence": "high" if name != "Generic Secret Assignment" else "medium",
                         "attack": "T1552.001 Credentials in Files"},
                ))
    return findings


def _scan_endpoints(sources: dict[str, str]) -> list[Finding]:
    endpoints: set[str] = set()
    for text in sources.values():
        for m in _ENDPOINT_RE.finditer(text):
            endpoints.add(m.group(1))
    if not endpoints:
        return []
    ordered = sorted(endpoints)[:60]
    return [Finding(
        module=MODULE,
        title=f"Hidden Endpoints Disclosed in JavaScript ({len(endpoints)})",
        description=(
            "The front-end JavaScript references internal/API endpoints that are not linked from "
            "the visible site. These expand the attack surface (test them for authz and injection): "
            + ", ".join(ordered[:25]) + (" …" if len(ordered) > 25 else "")
        ),
        severity=Severity.INFO,
        recommendation=(
            "Ensure every referenced endpoint enforces authentication and authorization; do not "
            "rely on the URL being unknown."
        ),
        raw={"endpoints": ordered, "count": len(endpoints), "confidence": "high",
             "attack": "T1595 Active Scanning"},
    )]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(engine: ScanEngine) -> list[Finding]:
    sources = _collect_sources(engine)
    if not sources:
        return []
    findings = _scan_secrets(sources)
    findings.extend(_scan_endpoints(sources))
    _order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: _order.get(f.severity.value, 9))
    logger.info(f"js_recon: scanned {len(sources)} source(s), {len(findings)} finding(s)")
    return findings
