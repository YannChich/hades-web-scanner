"""
subdomain_scan — enumerates sub-domains (active + passive) and checks for takeover.

Two discovery sources are merged:
  • Active  — DNS-resolves each label from the wordlist (with wildcard-DNS suppression).
  • Passive — Certificate Transparency logs via crt.sh (reveals sub-domains that were never
              guessable, with no requests to the target).

Every discovered sub-domain that resolves is then probed for a dangling-DNS / sub-domain
takeover. To avoid false positives, a takeover is only reported when BOTH hold:
  1. the sub-domain's DNS actually points at the suspected service (its CNAME chain matches a
     service domain such as ``*.s3.amazonaws.com`` / ``*.herokudns.com``, or its IP is in a
     service range), AND
  2. the served page carries that service's "unclaimed resource" fingerprint (S3 "NoSuchBucket",
     GitHub Pages "isn't a GitHub Pages site", …).
A generic 404 alone (e.g. an App Engine ``*.appspot.com`` page) never matches — without DNS
correlation to the service it is not a dangling third-party resource. Strong-fingerprint services
report High; services whose only fingerprint is a generic 404 (Unbounce) report Medium "verify".
Sensitive sub-domains (dev, staging, admin, vpn, git…) are flagged Low.
"""
from __future__ import annotations

import random
import socket
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
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

@dataclass(frozen=True)
class _Service:
    """A takeover-prone service: its body fingerprints AND the DNS targets that prove a sub-domain
    actually points at it (a fingerprint alone is never enough — see _detect_takeover)."""
    name: str
    fingerprints: tuple[str, ...]          # lowercased body signatures of the "unclaimed" page
    cnames: tuple[str, ...]                # CNAME-chain domain suffixes owned by the service
    ips: tuple[str, ...] = ()              # stable service IPs (used when there is no CNAME)
    confidence: str = "high"              # "medium" when the only fingerprint is a generic 404

# DNS correlation is REQUIRED: a fingerprint match on a sub-domain whose DNS does not point at the
# service is treated as a generic 404, not a takeover (this is what made *.appspot.com a false positive).
_SERVICES: tuple[_Service, ...] = (
    _Service("GitHub Pages", ("there isn't a github pages site here",), ("github.io",),
             ("185.199.108.153", "185.199.109.153", "185.199.110.153", "185.199.111.153")),
    _Service("AWS S3", ("nosuchbucket", "the specified bucket does not exist"),
             ("amazonaws.com",)),
    _Service("Heroku", ("no such app",), ("herokudns.com", "herokuapp.com", "herokussl.com")),
    _Service("Shopify", ("sorry, this shop is currently unavailable",), ("myshopify.com",)),
    _Service("Fastly", ("fastly error: unknown domain",), ("fastly.net",)),
    _Service("Surge.sh", ("project not found",), ("surge.sh",)),
    _Service("Bitbucket", ("repository not found",), ("bitbucket.io",)),
    _Service("Ghost", ("the thing you were looking for is no longer here",), ("ghost.io",)),
    _Service("Pantheon", ("the gods are wise, but do not know of the site",), ("pantheonsite.io",)),
    _Service("Tumblr", ("whatever you were looking for doesn't currently exist",),
             ("domains.tumblr.com",)),
    # Unbounce's fingerprint is a generic Apache/App-Engine 404 — only meaningful with DNS correlation,
    # and even then reported Medium "verify manually" rather than High.
    _Service("Unbounce", ("the requested url was not found on this server",),
             ("unbouncepages.com", "unbounce.com"), confidence="medium"),
    _Service("Help Scout", ("no settings were found for this company",), ("helpscoutdocs.com",)),
    _Service("Cargo", ("404 not found · cargo",), ("cargocollective.com", "cargo.site")),
    _Service("Webflow", ("the page you are looking for doesn't exist or has been moved",),
             ("webflow.io", "proxy-ssl.webflow.com")),
)


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


def _cname_targets(host: str) -> set[str]:
    """CNAME-chain targets for *host* (lowercased, trailing dot stripped); empty on any failure.

    Used to correlate a takeover fingerprint with DNS that actually points at the suspected service —
    without this, a generic 404 from any host (e.g. App Engine) looks like a dangling third-party page.
    """
    targets: set[str] = set()
    try:
        import dns.resolver
    except Exception:  # noqa: BLE001 — dnspython missing/broken → no correlation possible
        return targets
    host_l = host.rstrip(".").lower()
    for rdtype in ("CNAME", "A"):
        try:
            ans = dns.resolver.resolve(host, rdtype, raise_on_no_answer=False)
        except Exception:  # noqa: BLE001 — NXDOMAIN / timeout / servfail
            continue
        cn = str(getattr(ans, "canonical_name", "") or "").rstrip(".").lower()
        if cn and cn != host_l:
            targets.add(cn)
        if rdtype == "CNAME":
            for rr in ans:
                try:
                    targets.add(str(rr.target).rstrip(".").lower())
                except Exception:  # noqa: BLE001
                    pass
    return targets


def _correlates(svc: _Service, cname_targets: set[str], ips: set[str]) -> str | None:
    """Return the DNS evidence (a CNAME target or IP) proving the sub-domain points at *svc*, else None."""
    for t in cname_targets:
        for c in svc.cnames:
            if t == c or t.endswith("." + c):
                return t
    for ip in ips:
        if ip in svc.ips:
            return ip
    return None


def _detect_takeover(body: str, cname_targets: set[str], ips: set[str]) -> tuple[_Service, str, str] | None:
    """Return (service, fingerprint, dns_evidence) only when DNS points at the service AND its
    unclaimed-resource fingerprint is present. A fingerprint without DNS correlation is ignored."""
    low = body.lower()
    for svc in _SERVICES:
        corr = _correlates(svc, cname_targets, ips)
        if not corr:
            continue
        sig = next((s for s in svc.fingerprints if s in low), None)
        if sig:
            return svc, sig, corr
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

    # --- Subdomain takeover (fingerprint AND DNS correlation required; see _detect_takeover) ---
    with ThreadPoolExecutor(max_workers=engine.threads) as pool:
        futures = {pool.submit(_fetch_body, engine, name): name for name in names[:_MAX_TAKEOVER_CHECKS]}
        for fut in as_completed(futures):
            body = fut.result()
            name = futures[fut]
            if not body:
                continue
            match = _detect_takeover(body, _cname_targets(name), found.get(name, set()))
            if not match:
                continue
            svc, sig, corr = match
            severity = Severity.HIGH if svc.confidence == "high" else Severity.MEDIUM
            caveat = ("" if svc.confidence == "high"
                      else f" Note: the {svc.name} fingerprint is a generic 404 — confirm the resource "
                           "is actually unclaimed before acting.")
            findings.append(Finding(
                MODULE, f"Possible Subdomain Takeover: {name} ({svc.name})",
                (f"{name} points at {svc.name} (DNS → {corr}) and serves {svc.name}'s unclaimed-resource "
                 f"page — the DNS record dangles at an unclaimed {svc.name} resource, so an attacker "
                 f"could register it and serve content on your sub-domain.{caveat}"),
                severity,
                (f"Remove the dangling DNS record for {name} or re-claim the {svc.name} resource. "
                 "Audit DNS for other unused records pointing at third-party services."),
                {"subdomain": name, "service": svc.name, "dns_target": corr,
                 "confidence": svc.confidence,
                 "evidence": [
                     f"{name} → {corr} (DNS points at {svc.name} infrastructure)",
                     f"served {svc.name} unclaimed-resource page (fingerprint: \"{sig}\")"]}))

    return findings
