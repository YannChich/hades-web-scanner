"""
subdomain_scan — enumerates sub-domains (active + passive) and checks for takeover.

Two discovery sources are merged:
  • Active  — DNS-resolves each label from the wordlist (with wildcard-DNS suppression).
  • Passive — Certificate Transparency logs via crt.sh (reveals sub-domains that were never
              guessable, with no requests to the target).

Every discovered sub-domain that resolves is then probed for a dangling-DNS / sub-domain
takeover: if it points at a cloud service whose resource is gone (S3 "NoSuchBucket",
GitHub Pages "isn't a GitHub Pages site", Heroku "No such app", …) an attacker could claim
it → High. Sensitive sub-domains (dev, staging, admin, vpn, git…) are flagged Low.
"""
from __future__ import annotations

import random
import socket
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import httpx
from loguru import logger

from config import PROJECT_ROOT, USER_AGENT, WORDLIST_SUBDOMAINS
from scanner.engine import Finding, Severity, ScanEngine

MODULE = "subdomain_scan"
_MAX_REPORTED = 30
_MAX_TAKEOVER_CHECKS = 40

_SENSITIVE_LABELS: dict[str, str] = {
    "dev": "development", "develop": "development", "development": "development",
    "staging": "staging", "stage": "staging", "test": "test", "testing": "test",
    "uat": "pre-production", "qa": "QA", "preprod": "pre-production",
    "admin": "admin", "administrator": "admin", "panel": "admin", "cpanel": "control panel",
    "vpn": "remote access", "remote": "remote access", "gateway": "gateway",
    "internal": "internal", "intranet": "internal", "private": "internal",
    "git": "source control", "gitlab": "source control", "jenkins": "CI/CD",
    "jira": "internal tooling", "confluence": "internal tooling", "grafana": "monitoring",
    "kibana": "monitoring", "phpmyadmin": "database admin", "db": "database",
    "backup": "backup", "old": "legacy", "legacy": "legacy", "beta": "pre-release",
}

# (service, fingerprint substring) — a match on a resolving sub-domain suggests takeover.
_TAKEOVER: list[tuple[str, str]] = [
    ("GitHub Pages", "there isn't a github pages site here"),
    ("AWS S3", "nosuchbucket"),
    ("AWS S3", "the specified bucket does not exist"),
    ("Heroku", "no such app"),
    ("Shopify", "sorry, this shop is currently unavailable"),
    ("Fastly", "fastly error: unknown domain"),
    ("Surge.sh", "project not found"),
    ("Bitbucket", "repository not found"),
    ("Ghost", "the thing you were looking for is no longer here"),
    ("Pantheon", "the gods are wise, but do not know of the site"),
    ("Tumblr", "whatever you were looking for doesn't currently exist"),
    ("Unbounce", "the requested url was not found on this server"),
    ("Help Scout", "no settings were found for this company"),
    ("Cargo", "404 not found · cargo"),
    ("Webflow", "the page you are looking for doesn't exist or has been moved"),
]


# ---------------------------------------------------------------------------
# Resolution / sources (mockable in tests)
# ---------------------------------------------------------------------------

def _registrable(hostname: str) -> str:
    parts = hostname.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def _resolve(host: str) -> set[str] | None:
    try:
        return {info[4][0] for info in socket.getaddrinfo(host, None)}
    except OSError:
        return None


def _load_labels() -> list[str]:
    wl = PROJECT_ROOT / WORDLIST_SUBDOMAINS
    if not wl.exists():
        logger.warning(f"subdomain_scan: wordlist not found: {wl}")
        return []
    out, seen = [], set()
    with wl.open(encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            label = line.strip().lower()
            if label and not label.startswith("#") and label not in seen:
                seen.add(label)
                out.append(label)
    return out


def _crtsh(domain: str) -> set[str]:
    """Passive enumeration via Certificate Transparency logs (crt.sh)."""
    subs: set[str] = set()
    try:
        resp = httpx.get(f"https://crt.sh/?q=%25.{domain}&output=json",
                         headers={"User-Agent": USER_AGENT}, timeout=20.0)
        if resp.status_code == 200:
            for entry in resp.json():
                for name in str(entry.get("name_value", "")).splitlines():
                    name = name.strip().lower().lstrip("*.")
                    if name == domain or name.endswith("." + domain):
                        subs.add(name)
    except Exception as exc:  # noqa: BLE001 — passive source is best-effort
        logger.debug(f"subdomain_scan: crt.sh lookup failed: {exc}")
    return subs


def _fetch_body(engine: ScanEngine, host: str) -> str | None:
    for scheme in ("https", "http"):
        try:
            return engine.request("GET", f"{scheme}://{host}").text
        except httpx.HTTPError:
            continue
    return None


def _takeover_service(body: str) -> tuple[str, str] | None:
    """Return (service, matched-fingerprint) on a takeover signature, else None."""
    low = body.lower()
    for service, sig in _TAKEOVER:
        if sig in low:
            return service, sig
    return None


def _rand_label() -> str:
    return "".join(random.choices(string.ascii_lowercase, k=16))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(engine: ScanEngine) -> list[Finding]:
    hostname = urlparse(engine.url).hostname or ""
    domain = _registrable(hostname)
    if not domain:
        return [Finding(MODULE, "Subdomain Scan Skipped", "No registrable domain.",
                        Severity.INFO, "", {"confidence": "high"})]

    labels = _load_labels()

    # Wildcard DNS: probe several random labels and union their answers. A single probe misses
    # CDN/round-robin wildcards that rotate IPs, which then leak guessed labels (dev, admin, git…)
    # as bogus "sensitive subdomains". A name is the wildcard if ALL its IPs are in that set.
    wildcard_ips: set[str] = set()
    for _ in range(3):
        probe = _resolve(f"{_rand_label()}.{domain}")
        if probe:
            wildcard_ips |= probe
    if wildcard_ips:
        logger.info(f"subdomain_scan: wildcard DNS for {domain} — wildcard-matching names suppressed")

    def _is_wildcard(ips: set[str]) -> bool:
        return bool(wildcard_ips) and ips <= wildcard_ips

    # --- Active brute force ---
    found: dict[str, set[str]] = {}
    if labels:
        with ThreadPoolExecutor(max_workers=max(engine.threads, 20)) as pool:
            futures = {pool.submit(_resolve, f"{label}.{domain}"): label for label in labels}
            for fut in as_completed(futures):
                ips = fut.result()
                if ips and not _is_wildcard(ips):
                    found[f"{futures[fut]}.{domain}"] = ips

    # --- Passive (CT logs) ---
    passive = _crtsh(domain)
    for name in passive:
        if name == domain or name in found:
            continue
        ips = _resolve(name)
        if ips and not _is_wildcard(ips):
            found.setdefault(name, ips)

    if not found:
        return [Finding(MODULE, f"Subdomain Scan: None Found ({domain})",
                        f"No sub-domains resolved (active wordlist + crt.sh passive).",
                        Severity.INFO, "", {"domain": domain, "confidence": "high"})]

    names = sorted(found)
    findings: list[Finding] = [Finding(
        MODULE, f"Subdomains Discovered: {len(names)}",
        (f"{len(names)} sub-domain(s) of {domain} resolve (active + crt.sh passive): "
         + ", ".join(names[:_MAX_REPORTED]) + (" …" if len(names) > _MAX_REPORTED else "")),
        Severity.INFO, "",
        {"domain": domain, "subdomains": names[:200],
         "passive_count": len(passive), "confidence": "high"})]

    # --- Sensitive labels ---
    for name in names:
        label = name.split(".")[0]
        if label in _SENSITIVE_LABELS:
            findings.append(Finding(
                MODULE, f"Sensitive Subdomain: {name}",
                (f"{name} ({_SENSITIVE_LABELS[label]}) is publicly resolvable "
                 f"({', '.join(sorted(found[name]))}); it widens the attack surface."),
                Severity.LOW,
                "Restrict non-public sub-domains to a VPN/allowlist and keep them patched.",
                {"subdomain": name, "category": _SENSITIVE_LABELS[label],
                 "ips": sorted(found[name]), "confidence": "high"}))

    # --- Subdomain takeover ---
    with ThreadPoolExecutor(max_workers=engine.threads) as pool:
        futures = {pool.submit(_fetch_body, engine, name): name for name in names[:_MAX_TAKEOVER_CHECKS]}
        for fut in as_completed(futures):
            body = fut.result()
            name = futures[fut]
            if not body:
                continue
            match = _takeover_service(body)
            if match:
                service, sig = match
                findings.append(Finding(
                    MODULE, f"Possible Subdomain Takeover: {name} ({service})",
                    (f"{name} resolves but {service} returns a 'resource not found' page — the DNS "
                     f"record dangles at an unclaimed {service} resource. An attacker could register "
                     "it and serve content on your sub-domain."),
                    Severity.HIGH,
                    (f"Remove the dangling DNS record for {name} or re-claim the {service} resource. "
                     "Audit DNS for other unused records pointing at third-party services."),
                    {"subdomain": name, "service": service, "confidence": "high",
                     "evidence": [
                         f"{name} resolves to {', '.join(sorted(found[name]))}",
                         f"served {service} dangling-resource page (matched fingerprint: \"{sig}\")"]}))

    return findings
