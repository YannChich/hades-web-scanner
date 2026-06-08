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
# Rate limiting is a concurrent token bucket: up to MAX_CONCURRENCY requests run in parallel (each
# respecting the per-lane delay), so the thread pool actually delivers throughput instead of being
# serialised to one request per delay. Effective ceiling ≈ MAX_CONCURRENCY / rate_delay req/s.
# Lower --threads to throttle; safe/passive mode falls back to a single polite lane.
MAX_CONCURRENCY: int = 5
# Wall-clock budget per module: a module running longer than this is abandoned so one slow/hung
# module can never stall the whole scan. Generous — it only catches genuine hangs, not real work.
MODULE_TIMEOUT: float = 300.0       # seconds
# Circuit breaker: after this many consecutive request timeouts/connection failures, the engine
# fast-fails subsequent requests for a cooldown instead of hammering an unresponsive target — so a
# slow/blocking host makes the scan finish quickly rather than grinding to the per-module budget.
CIRCUIT_BREAKER_FAILS: int = 8
CIRCUIT_BREAKER_COOLDOWN: float = 30.0   # seconds the breaker stays open before a half-open retry

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
    "scanner.vulns.idor_detect",
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
    "ai_scan": ["scanner.ai.llm_recon"],
    "engage": ["scanner.offensive.engage"],
    "oob_scan": ["scanner.oob.oob_detect"],
    "cve_scan": ["scanner.cve.detector"],
    "tls_scan": ["scanner.tls.hephaestus_tls"],
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

# ---------------------------------------------------------------------------
# Finding taxonomy — framework mapping applied to every Finding (see engine.py).
# Per-severity representative CVSS base score (a sensible default a module can
# override by passing cvss=... explicitly).
# ---------------------------------------------------------------------------
SEVERITY_CVSS: dict[str, float] = {
    "critical": 9.8,
    "high":     7.5,
    "medium":   5.3,
    "low":      3.1,
    # "info" intentionally absent → no CVSS for informational findings.
}

# Module → default framework tags. Finding.__post_init__ fills cwe/owasp/mitre
# from this table when a module does not set them explicitly, so the whole tool
# gains CWE / OWASP Top 10 / MITRE ATT&CK coverage from one place. db_security is
# omitted on purpose: its findings are heterogeneous and derive their ATT&CK
# technique per-category from raw["attack"].
FINDING_TAXONOMY: dict[str, dict[str, object]] = {
    # ── Injection / active vulns ──
    "sqli_detect":       {"cwe": "CWE-89",  "owasp": "A03:2021 Injection",                          "mitre": ["T1190"]},
    "xss_detect":        {"cwe": "CWE-79",  "owasp": "A03:2021 Injection",                          "mitre": ["T1059"]},
    "command_injection": {"cwe": "CWE-78",  "owasp": "A03:2021 Injection",                          "mitre": ["T1059"]},
    "ssti_detect":       {"cwe": "CWE-1336","owasp": "A03:2021 Injection",                          "mitre": ["T1059"]},
    "lfi_detect":        {"cwe": "CWE-22",  "owasp": "A01:2021 Broken Access Control",              "mitre": ["T1083"]},
    "open_redirect":     {"cwe": "CWE-601", "owasp": "A01:2021 Broken Access Control",              "mitre": []},
    "ssrf_detect":       {"cwe": "CWE-918", "owasp": "A10:2021 Server-Side Request Forgery",        "mitre": ["T1190"]},
    "jwt_attacks":       {"cwe": "CWE-347", "owasp": "A02:2021 Cryptographic Failures",             "mitre": ["T1212"]},
    "auth_bypass":       {"cwe": "CWE-287", "owasp": "A07:2021 Identification and Authentication Failures", "mitre": ["T1212"]},
    "idor_detect":       {"cwe": "CWE-639", "owasp": "A01:2021 Broken Access Control",              "mitre": ["T1190"]},
    "bruteforce":        {"cwe": "CWE-307", "owasp": "A07:2021 Identification and Authentication Failures", "mitre": ["T1110"]},
    "default_creds":     {"cwe": "CWE-1392","owasp": "A07:2021 Identification and Authentication Failures", "mitre": ["T1078.001"]},
    "cve_mapping":       {"cwe": "CWE-1035","owasp": "A06:2021 Vulnerable and Outdated Components",  "mitre": ["T1190"]},
    # ── Web hardening / exposure ──
    "headers_check":     {"cwe": "CWE-693", "owasp": "A05:2021 Security Misconfiguration",          "mitre": []},
    "cookie_analysis":   {"cwe": "CWE-614", "owasp": "A05:2021 Security Misconfiguration",          "mitre": []},
    "cors_check":        {"cwe": "CWE-942", "owasp": "A05:2021 Security Misconfiguration",          "mitre": []},
    "clickjacking":      {"cwe": "CWE-1021","owasp": "A05:2021 Security Misconfiguration",          "mitre": []},
    "dir_listing":       {"cwe": "CWE-548", "owasp": "A05:2021 Security Misconfiguration",          "mitre": ["T1083"]},
    "http_methods":      {"cwe": "CWE-650", "owasp": "A05:2021 Security Misconfiguration",          "mitre": []},
    "dir_scan":          {"cwe": "CWE-538", "owasp": "A05:2021 Security Misconfiguration",          "mitre": ["T1083"]},
    "admin_panel":       {"cwe": "CWE-200", "owasp": "A05:2021 Security Misconfiguration",          "mitre": ["T1190"]},
    # ── Information disclosure / secrets ──
    "sensitive_files":   {"cwe": "CWE-538", "owasp": "A01:2021 Broken Access Control",              "mitre": ["T1552.001"]},
    "backup_files":      {"cwe": "CWE-530", "owasp": "A05:2021 Security Misconfiguration",          "mitre": ["T1552.001"]},
    "git_dumper":        {"cwe": "CWE-527", "owasp": "A05:2021 Security Misconfiguration",          "mitre": ["T1552.001"]},
    "js_recon":          {"cwe": "CWE-615", "owasp": "A05:2021 Security Misconfiguration",          "mitre": ["T1552.001"]},
    "cloud_buckets":     {"cwe": "CWE-732", "owasp": "A05:2021 Security Misconfiguration",          "mitre": ["T1530"]},
    "email_exposure":    {"cwe": "CWE-200", "owasp": "A05:2021 Security Misconfiguration",          "mitre": ["T1589.002"]},
    # ── Transport / crypto ──
    "ssl_check":         {"cwe": "CWE-326", "owasp": "A02:2021 Cryptographic Failures",             "mitre": []},
}

# ---------------------------------------------------------------------------
# Skills knowledge base (Axe 2) — wire Hades findings to the external
# Anthropic-Cybersecurity-Skills library (754 expert playbooks). Optional: if the
# repo is not found next to the project, enrichment silently no-ops.
# Override the location with the HADES_SKILLS_PATH environment variable.
# ---------------------------------------------------------------------------
SKILLS_REPO_ENV: str = "HADES_SKILLS_PATH"

# Candidate locations searched (first existing wins). Resolved in skills_kb.py.
SKILLS_REPO_CANDIDATES: list[str] = [
    str(PROJECT_ROOT.parent.parent / "Anthropic-Cybersecurity-Skills"),  # …/Hades/<repo>
    str(PROJECT_ROOT.parent / "Anthropic-Cybersecurity-Skills"),
    str(PROJECT_ROOT / "Anthropic-Cybersecurity-Skills"),
]

# Hades module → relevant skill folder name(s). The first listed skill is the
# primary playbook; the rest are companions. Names must match folders under
# <repo>/skills/. Modules without a clean offensive skill are left out (a
# conservative keyword fallback in skills_kb.py may still match them).
MODULE_SKILL_MAP: dict[str, list[str]] = {
    "sqli_detect":      ["exploiting-sql-injection-vulnerabilities",
                         "exploiting-sql-injection-with-sqlmap",
                         "performing-second-order-sql-injection"],
    "xss_detect":       ["testing-for-xss-vulnerabilities",
                         "testing-for-xss-vulnerabilities-with-burpsuite"],
    "ssti_detect":      ["exploiting-template-injection-vulnerabilities"],
    "lfi_detect":       ["performing-directory-traversal-testing"],
    "open_redirect":    ["testing-for-open-redirect-vulnerabilities"],
    "ssrf_detect":      ["exploiting-server-side-request-forgery",
                         "performing-blind-ssrf-exploitation",
                         "performing-ssrf-vulnerability-exploitation"],
    "jwt_attacks":      ["testing-for-json-web-token-vulnerabilities",
                         "exploiting-jwt-algorithm-confusion-attack",
                         "performing-jwt-none-algorithm-attack"],
    "cors_check":       ["testing-cors-misconfiguration"],
    "clickjacking":     ["performing-clickjacking-attack-test"],
    "headers_check":    ["performing-security-headers-audit"],
    "llm_recon":        ["detecting-ai-model-prompt-injection-attacks"],
    "engage":           ["performing-web-application-penetration-test"],
    "oob_detect":       ["performing-blind-ssrf-exploitation",
                         "exploiting-server-side-request-forgery"],
    "cve_vulnerability":["performing-cve-prioritization-with-kev-catalog"],
    "subdomain_scan":   ["performing-subdomain-enumeration-with-subfinder"],
    "port_scan":        ["scanning-network-with-nmap-advanced"],
    "ssl_check":        ["performing-ssl-tls-security-assessment"],
    "hephaestus_tls":   ["performing-ssl-tls-security-assessment"],
    "cloud_buckets":    ["auditing-aws-s3-bucket-permissions",
                         "conducting-cloud-penetration-testing",
                         "performing-gcp-penetration-testing-with-gcpbucketbrute"],
    "cve_mapping":      ["performing-cve-prioritization-with-kev-catalog"],
    "dns_check":        ["performing-dns-enumeration-and-zone-transfer"],
    "waf_detect":       ["performing-web-application-firewall-bypass"],
    "command_injection":["exploiting-api-injection-vulnerabilities"],
    "idor_detect":      ["exploiting-idor-vulnerabilities",
                         "testing-for-broken-access-control",
                         "testing-api-for-broken-object-level-authorization"],
}

# ---------------------------------------------------------------------------
# Blue-team REMEDIATION map — module → curated *defensive* skill(s) from the library that explain
# how to detect/fix the finding (the complement to MODULE_SKILL_MAP's offensive playbooks). Names
# are verified to exist in Anthropic-Cybersecurity-Skills; only mapped where a genuinely relevant
# defensive skill exists, so a remediation badge is always accurate (never forced). Surfaced
# separately from the offensive playbook via Finding.remediation_refs.
# ---------------------------------------------------------------------------
MODULE_REMEDIATION_MAP: dict[str, list[str]] = {
    "sqli_detect":       ["implementing-web-application-logging-with-modsecurity"],
    "xss_detect":        ["implementing-web-application-logging-with-modsecurity"],
    "command_injection": ["implementing-web-application-logging-with-modsecurity"],
    "ssti_detect":       ["implementing-web-application-logging-with-modsecurity"],
    "lfi_detect":        ["implementing-web-application-logging-with-modsecurity"],
    "sensitive_files":   ["implementing-secret-scanning-with-gitleaks",
                          "implementing-secrets-management-with-vault"],
    "git_dumper":        ["implementing-secret-scanning-with-gitleaks",
                          "detecting-aws-credential-exposure-with-trufflehog"],
    "js_recon":          ["implementing-secret-scanning-with-gitleaks"],
    "ssl_check":         ["configuring-tls-1-3-for-secure-communications"],
    "hephaestus_tls":    ["configuring-tls-1-3-for-secure-communications"],
    "jwt_attacks":       ["implementing-jwt-signing-and-verification"],
    "cloud_buckets":     ["auditing-aws-s3-bucket-permissions"],
    "default_creds":     ["configuring-multi-factor-authentication-with-duo"],
    "bruteforce":        ["configuring-multi-factor-authentication-with-duo"],
    "auth_bypass":       ["implementing-passwordless-authentication-with-fido2"],
    "idor_detect":       ["detecting-broken-object-property-level-authorization"],
    "cve_mapping":       ["implementing-epss-score-for-vulnerability-prioritization"],
    "cve_vulnerability": ["implementing-epss-score-for-vulnerability-prioritization"],
    "db_security":       ["implementing-pam-for-database-access"],
}

# ---------------------------------------------------------------------------
# RedTeam-Tools cross-reference — name the relevant offensive tools per finding so
# a client report is self-contained (the tools' details live in the bundled
# Hades_RedTeam_Tools_Reference.pdf). Names match entries in the RedTeam-Tools repo.
# ---------------------------------------------------------------------------
REDTEAM_REPO_CANDIDATES: list[str] = [
    str(PROJECT_ROOT.parent.parent / "RedTeam-Tools"),   # …/Hades/RedTeam-Tools
    str(PROJECT_ROOT.parent / "RedTeam-Tools"),
    str(PROJECT_ROOT / "RedTeam-Tools"),
]

# Hades module → relevant RedTeam-Tools entries (exact names from that repo).
MODULE_REDTEAM_MAP: dict[str, list[str]] = {
    # ── Recon ──
    "basic_info":      ["Dismap", "Shodan.io"],
    "tech_stack":      ["Dismap"],
    "dns_check":       ["dnsrecon", "AORT (All in One Recon Tool)"],
    "subdomain_scan":  ["subzy", "reconftw", "crt.sh -> httprobe -> EyeWitness"],
    "port_scan":       ["skanuvaty", "Shodan.io"],
    "waf_detect":      ["nuclei"],
    "js_recon":        ["jsendpoints", "truffleHog"],
    "git_dumper":      ["GitHarvester", "Gitrob", "truffleHog"],
    "cloud_buckets":   ["AWSBucketDump", "CloudBrute"],
    "screenshot":      ["gowitness"],
    "email_exposure":  ["smtp-user-enum", "spoofcheck"],
    # ── Web content discovery ──
    "dir_scan":        ["gobuster", "feroxbuster"],
    "admin_panel":     ["gobuster", "feroxbuster"],
    "sensitive_files": ["feroxbuster", "nuclei"],
    "backup_files":    ["feroxbuster"],
    # ── Web vulnerabilities (nuclei = templated webapp scanning) ──
    "sqli_detect":       ["nuclei"],
    "xss_detect":        ["nuclei"],
    "command_injection": ["nuclei"],
    "ssti_detect":       ["nuclei"],
    "lfi_detect":        ["nuclei"],
    "open_redirect":     ["nuclei"],
    "ssrf_detect":       ["nuclei"],
    "cors_check":        ["nuclei"],
    "clickjacking":      ["nuclei"],
    "headers_check":     ["nuclei"],
    "cve_mapping":       ["nuclei"],
    "jwt_attacks":       ["nuclei"],
    # ── Credential attacks ──
    "bruteforce":      ["Hydra", "crackmapexec"],
    "default_creds":   ["Hydra"],
    "auth_bypass":     ["nuclei"],
    "idor_detect":     ["nuclei"],
    # ── AI / LLM (external red-team tools — not in the RedTeam-Tools catalogue) ──
    "llm_recon":       ["garak", "PyRIT", "promptfoo"],
    # ── Active exploitation engagement ──
    "engage":          ["nuclei", "Metasploit Framework", "msfvenom"],
    # ── Out-of-band / blind detection ──
    "oob_detect":      ["nuclei"],
    # ── CVE intelligence ──
    "cve_vulnerability": ["nuclei"],
    # ── Offensive TLS validation ──
    "hephaestus_tls":  ["testssl.sh", "sslscan"],
}

# Tools named by Hades that are NOT in the bundled RedTeam-Tools PDF (AI red-team
# tooling). Flagged with a footnote in the PDF cross-reference so the client knows.
AI_EXTERNAL_TOOLS: set[str] = {"garak", "PyRIT", "promptfoo"}

# db_security categories → RedTeam tools (one module, many attack categories).
DB_CATEGORY_REDTEAM_MAP: dict[str, list[str]] = {
    "sqli":       ["nuclei"],
    "nosql":      ["nuclei"],
    "authbypass": ["nuclei"],
    "unauth":     ["crackmapexec", "nuclei"],
    "admin_200":  ["gobuster", "feroxbuster"],
    "creds_leak": ["truffleHog"],
    "cloud_db":   ["AWSBucketDump"],
}

# db_security is one module spanning many categories — map by raw["db_category"].
DB_CATEGORY_SKILL_MAP: dict[str, list[str]] = {
    "sqli":      ["exploiting-sql-injection-vulnerabilities",
                  "exploiting-sql-injection-with-sqlmap"],
    "nosql":     ["exploiting-nosql-injection-vulnerabilities"],
    "authbypass":["exploiting-nosql-injection-vulnerabilities"],
    "graphql":   ["performing-graphql-introspection-attack",
                  "performing-graphql-security-assessment"],
    "cloud_db":  ["conducting-cloud-penetration-testing"],
}
