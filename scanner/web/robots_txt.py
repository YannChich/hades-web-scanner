"""
robots_txt — parses /robots.txt and audits what it reveals.

robots.txt must list paths in clear text to hide them from crawlers, which paradoxically
advertises sensitive areas to attackers. This module:

  • Fully parses the file (User-agent groups, Disallow/Allow, Sitemap, Crawl-delay, wildcards).
  • Classifies each disallowed path with segment-aware matching (so '/login' is a login page,
    not a 'log' directory — a class of bug from naive substring matching).
  • Actively verifies each sensitive path: a disallowed path that is actually reachable
    (HTTP 200) is escalated, a 404 is a stale entry (down-graded), a 403 is noted as protected.
    A catch-all server is detected so verification stays meaningful.
  • Flags wildcard rules that leak the existence of file types (Disallow: /*.sql$).
  • Surfaces declared sitemaps to feed reconnaissance.
"""
from __future__ import annotations

import random
import re
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

import httpx
from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "robots_txt"
_MAX_VERIFY = 30

# Severity escalation when a disallowed sensitive path is actually reachable.
_ESCALATE: dict[Severity, Severity] = {
    Severity.INFO: Severity.LOW, Severity.LOW: Severity.MEDIUM,
    Severity.MEDIUM: Severity.HIGH, Severity.HIGH: Severity.HIGH, Severity.CRITICAL: Severity.CRITICAL,
}

# Segment-aware classification, ordered specific → generic (first match wins).
# Each keyword is bounded by a path delimiter so '/log' never matches '/login'.
_B = r"(?=$|[/.?_=&-])"   # trailing boundary
_CLASS: list[tuple[re.Pattern[str], str, Severity]] = [
    (re.compile(rf"(?:^|/)(?:login|logout|signin|sign-in|signout|sign-out|connexion){_B}", re.I),
     "Login/logout page", Severity.LOW),
    (re.compile(r"(?:^|/)wp-login", re.I), "WordPress login", Severity.LOW),
    (re.compile(r"(?:^|/)wp-admin", re.I), "WordPress admin", Severity.LOW),
    (re.compile(r"(?:^|/)wp-config", re.I), "WordPress configuration", Severity.MEDIUM),
    (re.compile(rf"(?:^|/)(?:administrator|admin|adminpanel|admincp|backend|controlpanel|cpanel){_B}", re.I),
     "Admin panel", Severity.LOW),
    (re.compile(rf"(?:^|/)(?:phpmyadmin|pma|adminer|myadmin){_B}", re.I),
     "Database admin", Severity.MEDIUM),
    (re.compile(r"(?:^|/)\.git(?=$|[/.])", re.I), "Git repository", Severity.MEDIUM),
    (re.compile(r"(?:^|/)\.svn", re.I), "SVN repository", Severity.MEDIUM),
    (re.compile(r"(?:^|/)\.env", re.I), "Environment file", Severity.MEDIUM),
    (re.compile(r"(?:^|/)\.ht(?:access|passwd)", re.I), "Apache config/passwords", Severity.MEDIUM),
    (re.compile(rf"(?:^|/)(?:backup|backups|bak|dump|dumps){_B}", re.I),
     "Backup/dump directory", Severity.MEDIUM),
    (re.compile(r"\.(?:sql|bak|old|zip|tar|gz|rar|7z|swp|dump)(?=$|[/?])", re.I),
     "Backup/archive file", Severity.MEDIUM),
    (re.compile(rf"(?:^|/)(?:config|conf|configuration|settings){_B}", re.I),
     "Configuration directory", Severity.MEDIUM),
    (re.compile(rf"(?:^|/)(?:database|databases|db|sql){_B}", re.I),
     "Database directory", Severity.MEDIUM),
    (re.compile(rf"(?:^|/)(?:secret|secrets|private|internal|confidential|hidden){_B}", re.I),
     "Private/internal area", Severity.LOW),
    (re.compile(rf"(?:^|/)(?:staging|stage|dev|development|test|testing|qa|uat|beta|sandbox|demo){_B}", re.I),
     "Non-production area", Severity.LOW),
    (re.compile(r"(?:^|/)logs?(?=$|[/.?])", re.I), "Log directory", Severity.LOW),
    (re.compile(rf"(?:^|/)(?:tmp|temp|cache){_B}", re.I), "Temporary files", Severity.LOW),
    (re.compile(rf"(?:^|/)(?:upload|uploads|files|media|attachments){_B}", re.I),
     "Uploads/files", Severity.LOW),
    (re.compile(rf"(?:^|/)(?:api|graphql|rest|v\d){_B}", re.I), "API endpoint", Severity.LOW),
    (re.compile(rf"(?:^|/)(?:user|users|account|accounts|members|profile){_B}", re.I),
     "User area", Severity.LOW),
]

# Wildcard rules whose extension leaks the existence of sensitive file types.
_WILDCARD_EXT = re.compile(r"\*?\.(sql|bak|old|zip|tar|gz|rar|7z|env|log|git|swp|conf|config|key|pem|sqlite)\b", re.I)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

@dataclass
class _Robots:
    disallows: list[tuple[str, str]] = field(default_factory=list)   # (path, user-agent)
    allows: list[tuple[str, str]] = field(default_factory=list)
    sitemaps: list[str] = field(default_factory=list)
    crawl_delay: str | None = None
    user_agents: set[str] = field(default_factory=set)
    block_all: bool = False


def _parse(content: str) -> _Robots:
    r = _Robots()
    current = "*"
    for raw in content.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        field_name, _, value = line.partition(":")
        field_name = field_name.strip().lower()
        value = value.strip()
        if field_name == "user-agent":
            current = value or "*"
            r.user_agents.add(current)
        elif field_name == "disallow":
            r.disallows.append((value, current))
            if value == "/" and current == "*":
                r.block_all = True
        elif field_name == "allow":
            r.allows.append((value, current))
        elif field_name == "sitemap":
            r.sitemaps.append(value)
        elif field_name == "crawl-delay":
            r.crawl_delay = value
    return r


def _parse_disallow(content: str) -> list[str]:
    """Unique Disallow paths — used by the shared crawler to honour robots.txt."""
    seen: set[str] = set()
    out: list[str] = []
    for path, _agent in _parse(content).disallows:
        if path and path not in seen:
            seen.add(path)
            out.append(path)
    return out


def _classify(path: str) -> tuple[str, Severity] | None:
    for pattern, label, sev in _CLASS:
        if pattern.search(path):
            return label, sev
    return None


def _norm(path: str) -> str:
    """Normalise for dedup: lowercase, strip framework prefix and trailing slash."""
    p = path.lower().split("?")[0].rstrip("/")
    p = re.sub(r"^/index\.(?:php|html?|aspx?)", "", p)
    return p or "/"


# ---------------------------------------------------------------------------
# Active verification
# ---------------------------------------------------------------------------

@dataclass
class _Baseline:
    catch_all: bool = False


def _baseline(engine: ScanEngine) -> _Baseline:
    try:
        slug = "".join(random.choices(string.ascii_lowercase, k=20))
        resp = engine.get(f"/{slug}")
        return _Baseline(catch_all=resp.status_code == 200)
    except httpx.HTTPError:
        return _Baseline(catch_all=False)


def _probe_status(engine: ScanEngine, path: str) -> int:
    # Only probe concrete paths (skip wildcard patterns).
    probe = path.split("*")[0].split("$")[0]
    if not probe.startswith("/"):
        probe = "/" + probe
    try:
        return engine.get(probe).status_code
    except httpx.HTTPError:
        return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(engine: ScanEngine) -> list[Finding]:
    try:
        resp = engine.get("/robots.txt")
    except httpx.HTTPError as exc:
        logger.warning(f"robots_txt: request failed: {exc}")
        return []

    if resp.status_code == 404:
        return [Finding(MODULE, "robots.txt Not Found",
                        "No /robots.txt was found. Not a risk, but it also means no crawl rules are published.",
                        Severity.INFO, "", {"status_code": 404, "confidence": "high"})]
    if resp.status_code != 200 or "<html" in resp.text[:200].lower():
        return [Finding(MODULE, "robots.txt Not Served",
                        f"/robots.txt did not return a valid text file (HTTP {resp.status_code}).",
                        Severity.INFO, "", {"status_code": resp.status_code, "confidence": "high"})]

    r = _parse(resp.text)

    findings: list[Finding] = [Finding(
        MODULE, "robots.txt Found",
        (f"/robots.txt has {len(r.disallows)} Disallow, {len(r.allows)} Allow, "
         f"{len(r.sitemaps)} Sitemap declaration(s) across user-agent(s): "
         f"{', '.join(sorted(r.user_agents)) or '*'}"
         + (f"; Crawl-delay={r.crawl_delay}" if r.crawl_delay else "")),
        Severity.INFO, "",
        {"disallow": [p for p, _ in r.disallows][:200], "allow": [p for p, _ in r.allows][:50],
         "sitemaps": r.sitemaps, "user_agents": sorted(r.user_agents), "confidence": "high"},
    )]

    if r.sitemaps:
        findings.append(Finding(
            MODULE, f"Sitemaps Declared in robots.txt ({len(r.sitemaps)})",
            "robots.txt declares sitemap(s): " + ", ".join(r.sitemaps[:10]),
            Severity.INFO, "Ensure sitemaps do not expose internal/admin URLs.",
            {"sitemaps": r.sitemaps, "confidence": "high"}))

    if r.block_all:
        findings.append(Finding(
            MODULE, "robots.txt Blocks All Crawling (Disallow: /)",
            "robots.txt disallows the entire site for all crawlers. Often intentional on staging, but "
            "on production it removes the site from search engines.",
            Severity.INFO, "Confirm this is intended; production sites usually allow indexing.",
            {"confidence": "high"}))

    # Wildcard extension leaks
    for path, _agent in r.disallows:
        if ("*" in path or "$" in path) and _WILDCARD_EXT.search(path):
            ext = _WILDCARD_EXT.search(path).group(1)
            findings.append(Finding(
                MODULE, f"robots.txt Wildcard Leaks File Type: .{ext}",
                f"The rule 'Disallow: {path}' reveals that '.{ext}' files exist on the server.",
                Severity.MEDIUM,
                f"Avoid referencing sensitive file types in robots.txt; store/serve .{ext} files outside the web root.",
                {"pattern": path, "extension": ext, "confidence": "high"}))

    # Classify + dedup sensitive paths
    grouped: dict[str, tuple[str, str, Severity]] = {}  # key → (representative_path, label, sev)
    for path, _agent in r.disallows:
        if not path or path == "/":
            continue
        cls = _classify(path)
        if not cls:
            continue
        label, sev = cls
        key = f"{label}::{_norm(path)}"
        if key not in grouped:
            grouped[key] = (path, label, sev)

    # Active verification (unless the server is a catch-all)
    baseline = _baseline(engine)
    items = list(grouped.values())[:_MAX_VERIFY]
    statuses: dict[str, int] = {}
    if not baseline.catch_all and items:
        with ThreadPoolExecutor(max_workers=engine.threads) as pool:
            futures = {pool.submit(_probe_status, engine, p): p for p, _, _ in items}
            for fut in as_completed(futures):
                statuses[futures[fut]] = fut.result()

    for path, label, base_sev in items:
        status = statuses.get(path, 0)
        url = engine.url.rstrip("/") + (path.split("*")[0] if "*" in path else path)

        if baseline.catch_all:
            sev, verdict = base_sev, "advertised in robots.txt (server is catch-all, not verified)"
        elif status == 200:
            sev, verdict = _ESCALATE[base_sev], "advertised in robots.txt AND publicly accessible (HTTP 200)"
        elif status in (401, 403):
            sev, verdict = base_sev, f"advertised in robots.txt and present but protected (HTTP {status})"
        elif status in (404, 410):
            sev, verdict = Severity.LOW, "advertised in robots.txt but not currently reachable (stale entry)"
        else:
            sev, verdict = base_sev, "advertised in robots.txt"

        findings.append(Finding(
            module=MODULE,
            title=f"Sensitive Path in robots.txt: {path}",
            description=(f"robots.txt discloses '{path}' ({label}) — {verdict}. Publishing it tells "
                         "attackers exactly where to look despite the crawler exclusion."),
            severity=sev,
            recommendation=("Do not rely on robots.txt to hide sensitive paths. Protect them with "
                            "authentication/allowlisting and remove them from robots.txt."),
            raw={"path": path, "url": url, "label": label, "status_code": status,
                 "confidence": "high"},
        ))

    return findings
