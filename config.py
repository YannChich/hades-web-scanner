"""
WebScan global settings, scan profiles, and constants.
All tuneable values live here — never scatter magic numbers across modules.
"""

from pathlib import Path

# ---------------------------------------------------------------------------
# Project root — the directory that holds main.py, config.py and wordlists/.
# Resolve relative to this file so wordlist paths work regardless of CWD.
# ---------------------------------------------------------------------------
PROJECT_ROOT: Path = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# HTTP client defaults
# ---------------------------------------------------------------------------
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36 Hades/1.0"
)
DEFAULT_TIMEOUT: float = 15.0       # seconds per HTTP request
DEFAULT_THREADS: int = 10
DEFAULT_RATE_DELAY: float = 0.5     # seconds between requests (normal)
SAFE_MODE_RATE_DELAY: float = 1.0   # seconds between requests (safe / polite)

# ---------------------------------------------------------------------------
# Shared crawler bounds (used by scanner/crawler.py via ScanEngine.get_crawl)
# ---------------------------------------------------------------------------
CRAWL_MAX_DEPTH: int = 2             # how many link-hops deep from the start URL
CRAWL_MAX_PAGES: int = 50           # hard cap on pages fetched per scan

# ---------------------------------------------------------------------------
# Wordlist paths (relative to project root)
# ---------------------------------------------------------------------------
WORDLIST_DIRS: str = "wordlists/directories.txt"
WORDLIST_ADMIN: str = "wordlists/admin_panels.txt"
WORDLIST_SUBDOMAINS: str = "wordlists/subdomains.txt"

# ---------------------------------------------------------------------------
# Scan profiles → ordered list of module dotted-paths
# ---------------------------------------------------------------------------
_RECON_ALL: list[str] = [
    "scanner.recon.basic_info",
    "scanner.recon.whois_lookup",
    "scanner.recon.dns_check",
    "scanner.recon.ssl_check",
    "scanner.recon.port_scan",
    "scanner.recon.waf_detect",
    "scanner.recon.tech_stack",
    "scanner.recon.js_recon",
    "scanner.recon.cloud_buckets",
    "scanner.recon.git_dumper",
    "scanner.recon.wayback",
]

_WEB_PASSIVE: list[str] = [
    "scanner.web.headers_check",
    "scanner.web.robots_txt",
    "scanner.web.sitemap",
    "scanner.web.cms_detect",
    "scanner.web.admin_panel",
    "scanner.web.broken_links",
    "scanner.web.http_methods",
    "scanner.web.cookie_analysis",
    "scanner.web.redirect_chain",
    "scanner.web.email_exposure",
    "scanner.web.favicon_hash",
    "scanner.web.cors_check",
    "scanner.web.clickjacking",
    "scanner.web.dir_listing",
    "scanner.web.blacklist_check",
    "scanner.web.screenshot",
]

_WEB_ACTIVE: list[str] = [
    "scanner.web.dir_scan",
    "scanner.web.subdomain_scan",
    "scanner.web.backup_files",
    "scanner.web.sensitive_files",
]

_VULNS: list[str] = [
    "scanner.vulns.sqli_detect",
    "scanner.vulns.xss_detect",
    "scanner.vulns.command_injection",
    "scanner.vulns.ssti_detect",
    "scanner.vulns.lfi_detect",
    "scanner.vulns.open_redirect",
    "scanner.vulns.ssrf_detect",
    "scanner.vulns.jwt_attacks",
    "scanner.vulns.auth_bypass",
    "scanner.vulns.bruteforce",
    "scanner.vulns.cve_mapping",
    "scanner.vulns.default_creds",
]

PROFILE_MODULES: dict[str, list[str]] = {
    "quick": [
        "scanner.recon.basic_info",
        "scanner.web.headers_check",
        "scanner.recon.ssl_check",
        "scanner.web.robots_txt",
    ],
    "passive": _RECON_ALL + _WEB_PASSIVE,
    "cms": [
        "scanner.recon.tech_stack",
        "scanner.web.cms_detect",
        "scanner.web.admin_panel",
        "scanner.vulns.cve_mapping",
        "scanner.vulns.default_creds",
    ],
    "full": _RECON_ALL + _WEB_PASSIVE + _WEB_ACTIVE + _VULNS,
    "db_scan": ["scanner.db.db_security"],
}

# ---------------------------------------------------------------------------
# Module catalog — used by the interactive menu to run a single module.
# Maps a display category to its module dotted-paths (grouped, ordered).
# ---------------------------------------------------------------------------
MODULE_CATALOG: dict[str, list[str]] = {
    "Recon":           _RECON_ALL,
    "Web":             _WEB_PASSIVE + _WEB_ACTIVE,
    "Vulnerabilities": _VULNS,
}

# Flat set of every runnable module dotted-path (for validation).
ALL_MODULES: list[str] = [m for mods in MODULE_CATALOG.values() for m in mods]

# ---------------------------------------------------------------------------
# Risk / severity score weights (used by scorer.py)
# ---------------------------------------------------------------------------
# Per-finding risk magnitude on a 0–100 scale (matches the CLAUDE.md bands).
SEVERITY_SCORES: dict[str, int] = {
    "info":     5,
    "low":     20,
    "medium":  45,
    "high":    70,
    "critical": 95,
}

# Penalty (points off 100) applied for the *most severe* finding of a given
# severity. Derived from SEVERITY_SCORES but tuned so a clean site scores ~100
# and a single critical lands the grade in D/F territory.
SEVERITY_PENALTY: dict[str, float] = {
    "info":      0.0,
    "low":       2.0,
    "medium":    6.0,
    "high":     12.0,
    "critical": 25.0,
}

# Diminishing-returns factors applied to the 2nd, 3rd, … finding within the
# same module, so one noisy module can't sink the whole score. The first
# finding of a module always counts at full weight (1.0); subsequent ones use
# these factors in order, and anything beyond the list uses the last value.
SCORE_DIMINISHING: list[float] = [1.0, 0.6, 0.4, 0.25, 0.15, 0.1]

# Confidence multipliers; a finding may set raw["confidence"] to one of these.
SCORE_CONFIDENCE: dict[str, float] = {
    "low":    0.5,
    "medium": 0.8,
    "high":   1.0,
}
