# Hades

> A terminal-based web security scanner inspired by Kali Linux tools.
> Performs 45+ automated checks across recon, web analysis, and vulnerability detection —
> plus an **offensive injection arsenal** with active verification and an opt-in **sqlmap launcher** —
> all from a single command.
>
> Every finding is mapped to **CWE / OWASP / MITRE ATT&CK** (with a CVSS score and a stable ID),
> linked to a step-by-step **expert playbook** and the relevant **RedTeam tools**, and woven into a
> single copy-paste **kill-chain attack path**. Ships a dedicated **AI/LLM security audit**
> (`ai_scan`) and a red-team **database audit** (`db_scan`).

```
 ██╗  ██╗ █████╗ ██████╗ ███████╗███████╗
 ██║  ██║██╔══██╗██╔══██╗██╔════╝██╔════╝
 ███████║███████║██║  ██║█████╗  ███████╗
 ██╔══██║██╔══██║██║  ██║██╔══╝  ╚════██║
 ██║  ██║██║  ██║██████╔╝███████╗███████║
 ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝
        web security scanner
```

> The tool is branded **Hades**; the Python package folder is still `webscan/`.

---

## Screenshots

> _Screenshots to be added after first full test run._
> Place terminal captures in `docs/screenshots/` and reference them here.

| Scan in progress | HTML Report |
|-----------------|-------------|
| _(terminal screenshot)_ | _(browser screenshot)_ |

---

## Features

### Recon Modules
- [x] Basic info — IP, server, load time, OS fingerprint
- [x] WHOIS lookup — registrar, creation/expiry dates, name servers
- [x] DNS security — MX, SPF, DMARC, DKIM checks
- [x] SSL/TLS — certificate expiry, self-signed, hostname mismatch, legacy protocols
- [x] Port scan — open port discovery with accept-all (honeypot/WAF) detection
- [x] WAF / CDN detection — Cloudflare, CloudFront, Akamai, Sucuri, Imperva, Fastly…
- [x] Technology stack — server, language, framework, JS libraries, CMS (Wappalyzer-style)
- [x] **JS recon** — mines JavaScript for leaked secrets (AWS/Google/Stripe/GitHub/Slack/private keys) and hidden API endpoints
- [x] **Cloud buckets** — discovers open/existing S3, GCS and Azure Blob storage buckets
- [x] **Git dumper** — extracts remotes, committer emails and the tracked-file list from an exposed `.git`
- [x] **Wayback mining** — pulls archived URLs & parameters from the Internet Archive (attack-surface expansion)

### Web Analysis Modules
- [x] Security headers — CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- [x] robots.txt — disallow entries, sensitive path exposure
- [x] Sitemap — sitemap.xml parsing
- [x] CMS detection — WordPress, Joomla, Drupal, Magento, Shopify, Wix, Squarespace, Ghost, TYPO3, PrestaShop
- [x] Admin panel discovery — CMS-targeted + generic path bruteforce
- [x] Directory scanning — wordlist bruteforce with wildcard/soft-404 detection
- [x] Subdomain enumeration
- [x] Broken links — internal dead link detection (WAF-403 collapse aware)
- [x] HTTP methods — OPTIONS probe, dangerous method flagging (PUT, DELETE, TRACE, CONNECT)
- [x] Backup files — `.bak`, `.old`, `.zip`, `.sql` exposure
- [x] Sensitive files — `.env`, `wp-config.php`, `.git/config`, `phpinfo.php`, `.htpasswd`…
- [x] Cookie analysis — HttpOnly, Secure, SameSite flags
- [x] Redirect chain — HTTP → HTTPS redirect analysis
- [x] Email exposure — scraped email addresses on pages
- [x] Favicon hash — fingerprinting via MurmurHash
- [x] CORS misconfiguration — reflected origin, wildcard, null origin, credentials
- [x] Clickjacking — X-Frame-Options / CSP frame-ancestors
- [x] Directory listing — open listing detection
- [x] Blacklist check — IP / domain reputation lookup
- [x] Screenshot — homepage capture via Playwright (self-healing browser install)

### Offensive Injection Arsenal (active verification)
Every injection module **proves** the bug (evaluated payload / timing / content signature), not
just reflection — so findings are high-confidence and low-noise. URL parameters **and** form
fields from the shared crawler are tested, and each finding carries a clickable **proof link**.

- [x] SQL injection — error / boolean-blind / time-blind, with a ready `sqlmap` command
- [x] XSS — context-aware reflected XSS on URL parameters and form inputs
- [x] Command injection — OS command exec (time-based + output signatures)
- [x] SSTI — Server-Side Template Injection (math-probe confirmation, engine fingerprint)
- [x] LFI / path traversal — `/etc/passwd`, `win.ini`, PHP wrapper, content-signature confirmed
- [x] Open redirect — sentinel-URL `Location`/meta/JS confirmation
- [x] SSRF — in-band (cloud metadata / `file://`) detection
- [x] **JWT attacks** — `alg:none`, weak HMAC secret cracking (offline wordlist), sensitive-claim disclosure
- [x] **Auth bypass** — 401/403 bypass via path mutations, `X-Original-URL`/`X-Forwarded-For` headers, verb tampering
- [x] **Credential spraying** — opt-in (`--bruteforce`): sprays common credentials at login forms & HTTP Basic-Auth (authorised targets only)
- [x] CVE mapping — NVD API lookup for detected software versions
- [x] Default credentials — advisory only (never submits credentials)

### Database Security Audit (`--profile db_scan`) — red team
A dedicated module (`scanner/db/db_security.py`) that turns Hades into a focused DB attack tool:

- [x] DB port scan + banner/version fingerprint (MySQL, PostgreSQL, MSSQL, Oracle, MongoDB, Redis, Elasticsearch, CouchDB, Cassandra, Memcached)
- [x] **Unauthenticated access** with live **data extraction** — Redis (keys sample + `DBSIZE`, plus `CONFIG`→RCE detection), Elasticsearch (indices + doc counts), CouchDB (`_all_dbs`), MongoDB, Memcached
- [x] SQL **and** NoSQL injection on crawled parameters (confirmed SQLi is sqlmap-exploitable)
- [x] **Secret-file hunting** — `.env`, `database.yml`, `my.cnf`, `wp-config.php`, `appsettings.json`, `docker-compose.yml`… (credentials redacted in the report)
- [x] Leaked DB connection strings in page/JS source, GraphQL introspection, exposed admin GUIs (phpMyAdmin, Adminer, Fauxton, Kibana…), dump/SQLite files, framework debug leaks, DB-port TLS posture
- [x] **Expanded attack surface** — SQL injection via **HTTP headers & cookies** (`User-Agent`, `Referer`, `X-Forwarded-For`…), **NoSQL authentication bypass** on login forms (`{"$ne":""}`), and **cloud database exposure** (Firebase Realtime DB `/.json`, Firestore REST, Supabase)
- [x] **DB Exposure Score** (0–100 + grade), an ordered **Attack Path** of copy-paste exploitation commands (tagged with **MITRE ATT&CK** techniques), and a **Loot** summary of the data actually pulled — in the console panel **and** the HTML report

### Active exploitation (opt-in, `--exploit`)
The `--exploit` flag turns `db_scan` from detection into a **red-team engagement** — it actively
**proves impact** on authorised targets and writes the extracted data as **evidence files** under
`loot/<host>_<timestamp>/`:
- [x] **Live data extraction** — dumps real Redis key values, Elasticsearch `_search` / CouchDB `_all_docs` sample records, and an **in-band SQLi** banner pull (DB version/user) without sqlmap
- [x] **Credential reuse** — replays credentials harvested from leaked `.env` / connection strings against the discovered DB hosts and confirms which ones actually open
- [x] Launches the real **sqlmap** against confirmed SQL injections (from both the injection arsenal and `db_scan`) after a per-target authorisation confirmation
- [x] **Detection-only by default** — nothing is extracted or exploited without `--exploit` + confirmation

### AI / LLM Security Audit (`--profile ai_scan`)
A dedicated module (`scanner/ai/llm_recon.py`) that audits the AI attack surface most scanners
ignore — mapped to the **OWASP LLM Top 10 (2025)** and **MITRE ATLAS**:

- [x] **AI technology fingerprinting** — detects LLM SDKs/providers in the page & JS (OpenAI, Anthropic, LangChain, LlamaIndex, HuggingFace, Cohere, Gemini, Vercel AI SDK, Gradio, Streamlit, Flowise, Ollama)
- [x] **Exposed AI API keys** — provider-specific patterns (`sk-ant-…`, `sk-…`, `hf_…`, `AIza…`, Replicate, Cohere), redacted in the report
- [x] **Unauthenticated local LLM servers** — Ollama (11434), LM Studio, vLLM, LocalAI, text-generation-webui — with model enumeration
- [x] **Exposed AI dev UIs / inference APIs** — Flowise, Gradio, open `/v1/models`
- [x] **Prompt-injection surface** — flags live chat/inference endpoints; with `--exploit`, sends a **benign canary** to actively confirm prompt injection (and probe system-prompt leakage)
- [x] Findings carry an **AI/LLM Exposure panel** plus OWASP-LLM + ATLAS tags, so they flow through the same scoring, playbook, attack-path and report machinery — detection-only by default

### Active Engagement (`--profile engage`) — auto-pwn
A dedicated orchestrator (`scanner/offensive/engage.py`) that turns Hades from a scanner into an
**auto-exploitation engine**. It runs the active injection arsenal to confirm bugs, then — only
with `--exploit` on an authorised target — actively **proves impact** with *benign* payloads and
writes evidence files under `loot/<host>_<timestamp>/`:

- [x] **Command injection → RCE proof** — runs a harmless command (`id`, `uname -a`) and captures the output
- [x] **LFI / path traversal → arbitrary file read** — reads and saves `/etc/passwd`
- [x] **SSRF → internal/cloud access** — fetches cloud-metadata / `file://` and saves the response
- [x] SQL injection continues through the dedicated **sqlmap launcher** (auto-offered with `--exploit`)
- [x] Emits a **💀 Active Engagement panel** (proven footholds + loot + evidence paths) and an engagement score; every step joins the kill-chain Attack Path
- [x] **Detection-only by default** — nothing is exploited without `--exploit` + the authorisation confirmation. No destructive actions, no persistence/backdoor, no DoS — proof of impact only

### Intelligence & Reporting Layer
Every finding (across all profiles) is enriched into an actionable, client-ready record:

- [x] **Framework mapping** — each finding carries a **CWE**, an **OWASP** category, **MITRE ATT&CK** technique(s), a representative **CVSS** score, a **stable finding ID** (diffable across runs), and a reproducible **PoC** command
- [x] **Expert playbooks** — findings are matched to step-by-step procedures from a local clone of the [Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) library (optional; silently skipped if absent). Set `HADES_SKILLS_PATH` to point at it
- [x] **RedTeam tools per finding** — each finding names the relevant offensive tools (`nuclei`, `gobuster`, `sqlmap`, `subzy`, `garak`…), so the report is self-contained for clients
- [x] **Unified kill-chain Attack Path** — all actionable findings are assembled into an ordered, copy-paste exploitation plan grouped by **MITRE ATT&CK tactic** (Reconnaissance → … → Impact), in console, JSON, and HTML
- [x] **RedTeam-Tools reference PDF** — `docs/make_redteam_tools.py` bundles the entire [RedTeam-Tools](https://github.com/A-poc/RedTeam-Tools) catalogue (150+ tools) into a single self-contained PDF with a *"Hades finding → RedTeam tools"* cross-reference, so a client needs no repo access

### Output
- [x] Rich terminal UI — coloured findings, progress bars, ASCII banner
- [x] Risk scorer — weighted 0–100 score with severity grade (INFO never affects the score)
- [x] Clickable verification/proof links for confirmed findings
- [x] Per-finding **framework badges** (CWE / OWASP / ATT&CK / CVSS), **playbook** links, and **RedTeam tool** references
- [x] **Kill-chain Attack Path** section (console + JSON + HTML)
- [x] JSON report export (findings, framework mapping, playbooks, attack path)
- [x] HTML report export — dark Kali-inspired theme, CSS gauges, attack-path, playbooks, DB & AI panels
- [x] PDF report export
- [x] Timestamped log files via loguru

---

## Installation

### Manual (pip)

**Requirements:** Python 3.10+

```bash
git clone https://github.com/yourname/webscan.git
cd webscan

pip install -r requirements.txt

# Install Playwright's bundled Chromium (needed for screenshots only; also self-heals at runtime)
playwright install chromium

# Optional — only needed for the --exploit sqlmap launcher
pip install sqlmap
```

### Docker

```bash
# Build the image
docker compose -f docker/docker-compose.yml build

# Run an interactive scan
docker compose -f docker/docker-compose.yml run --rm webscan
```

---

## Usage

### Interactive mode (prompts for URL and profile)

```bash
python main.py
```

### CLI mode

```bash
# Full scan with HTML report
python main.py --url https://example.com --profile full --output html

# Quick passive scan
python main.py --url https://example.com --profile quick

# Dedicated database security audit (red-team DB module)
python main.py --url https://example.com --profile db_scan --output html

# Dedicated AI/LLM security audit (prompt injection, exposed keys & LLM servers)
python main.py --url https://example.com --profile ai_scan --output html

# AI audit with active prompt-injection confirmation (canary; authorised targets only)
python main.py --url https://example.com --profile ai_scan --exploit

# Active engagement (auto-pwn): confirm vulns, then actively prove impact + collect loot
python main.py --url https://example.com --profile engage --exploit

# Database audit AND auto-launch sqlmap on any confirmed SQLi (authorised targets only)
python main.py --url http://testaspnet.vulnweb.com --profile db_scan --exploit

# Scan through Burp Suite proxy
python main.py --url https://example.com --proxy http://127.0.0.1:8080

# Authenticated scan with session cookie
python main.py --url https://example.com --cookies "session=abc123; token=xyz"

# Custom wordlist + bearer token
python main.py --url https://example.com --wordlist /path/to/list.txt --auth-token eyJ...

# Increase thread count for faster scanning
python main.py --url https://example.com --threads 20
```

### Docker

```bash
# Non-interactive with flags
docker compose -f docker/docker-compose.yml run --rm webscan \
  --url https://example.com --profile full --output html

# With NVD API key for CVE lookups
NVD_API_KEY=your-key docker compose -f docker/docker-compose.yml run --rm webscan \
  --url https://example.com
```

### All CLI options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--url` | `-u` | — | Target URL (required, or prompted interactively) |
| `--profile` | `-p` | `full` | Scan profile: `quick` `passive` `cms` `full` `db_scan` `ai_scan` `engage` |
| `--output` | `-o` | — | Export report: `json` `html` `pdf` |
| `--exploit` | | `false` | Opt-in: launch sqlmap on confirmed SQL injections (authorised targets only) |
| `--bruteforce` | | `false` | Opt-in: spray common credentials at login forms & Basic-Auth (authorised targets only) |
| `--proxy` | | — | HTTP/HTTPS proxy URL |
| `--threads` | `-t` | `10` | Concurrent thread count |
| `--ignore-robots` | | `false` | Ignore robots.txt restrictions |
| `--wordlist` | `-w` | built-in | Custom wordlist path |
| `--cookies` | | — | Cookie header string |
| `--auth-token` | | — | Bearer token for Authorization header |

---

## Scan Profiles

| Profile | Speed | Description | Modules |
|---------|-------|-------------|---------|
| `quick` | ⚡ Fast | Passive surface scan | basic\_info, headers, ssl, robots |
| `passive` | 🔍 Moderate | No active probing | All recon + web passive modules |
| `cms` | 🎯 Targeted | CMS-focused | CMS detect, admin panels, CVE mapping |
| `full` | 🔥 Thorough | Everything (default) | All 45+ modules incl. injection arsenal |
| `db_scan` | 🛢 Red team | Database security audit | `scanner/db/db_security.py` only |
| `ai_scan` | 🤖 Red team | AI/LLM attack surface (OWASP LLM Top 10 + ATLAS) | `scanner/ai/llm_recon.py` only |
| `engage` | 💀 Offensive | Active engagement — auto-exploit confirmed vulns (RCE/LFI/SSRF) | `scanner/offensive/engage.py` only |

---

## Output Files

| Type | Location | Created when |
|------|----------|-------------|
| Log file | `logs/webscan_YYYYMMDD_HHMMSS.log` | Every run |
| JSON report | `reports/webscan_report_YYYYMMDD_HHMMSS.json` | `--output json` |
| HTML report | `reports/webscan_report_YYYYMMDD_HHMMSS.html` | `--output html` |
| PDF report | `reports/webscan_report_YYYYMMDD_HHMMSS.pdf` | `--output pdf` |

There are also reference PDFs under `docs/`, regenerated by their scripts:
`docs/Hades_Modules_Guide.pdf` (`python docs/make_guide.py`), `docs/Hades_Flags_Cheatsheet.pdf`
(`python docs/make_flags.py`), and a complete **bilingual (FR/EN) Database Security manual**
`docs/Hades_Database_Security_Manual.pdf` (`python docs/make_db_manual.py`) — a beginner-friendly,
two-column guide to the `db_scan` module.

A self-contained **RedTeam-Tools reference PDF** is produced by `python docs/make_redteam_tools.py`
(`docs/Hades_RedTeam_Tools_Reference.pdf`, ~22 MB) — the full 150+ tool catalogue plus a
*"Hades finding → RedTeam tools"* cross-reference. It is **git-ignored** (large, regenerable);
run the script to (re)create it on demand.

---

## Technologies

| Library | Purpose |
|---------|---------|
| [httpx](https://www.python-httpx.org/) | Async-compatible HTTP client |
| [Rich](https://rich.readthedocs.io/) | Terminal colours, tables, progress bars |
| [dnspython](https://www.dnspython.org/) | DNS record queries |
| [python-whois](https://pypi.org/project/python-whois/) | WHOIS lookups |
| [cryptography](https://cryptography.io/) | SSL/TLS certificate parsing |
| [BeautifulSoup4](https://www.crummy.com/software/BeautifulSoup/) | HTML parsing |
| [Playwright](https://playwright.dev/python/) | Headless browser screenshots + RedTeam-Tools reference PDF |
| [Markdown](https://pypi.org/project/Markdown/) | Renders the RedTeam-Tools README into the reference PDF |
| [weasyprint](https://weasyprint.org/) | PDF report export (needs native GTK libs; unavailable on Windows) |
| [reportlab](https://www.reportlab.com/) | PDF generation for the modules guide / flags cheat-sheet |
| [loguru](https://loguru.readthedocs.io/) | Structured logging with timestamps |
| [mmh3](https://pypi.org/project/mmh3/) | MurmurHash3 for favicon fingerprinting |
| [sqlmap](https://sqlmap.org/) | **Optional** — launched by `--exploit` to exploit confirmed SQL injections |

---

## Project Structure

```
webscan/
├── main.py                  # Entry point — CLI, menu, argument parsing
├── config.py                # Global settings, scan profiles, constants
├── requirements.txt
├── scanner/
│   ├── engine.py            # Orchestration, threading, rate limiting
│   ├── crawler.py           # Shared site crawler (params, forms, links, emails)
│   ├── exploit.py           # Opt-in sqlmap launcher (--exploit)
│   ├── recon/               # Passive reconnaissance modules
│   ├── web/                 # Web analysis modules
│   ├── vulns/               # Injection arsenal + CVE / default-cred modules
│   ├── db/                  # db_scan profile — red-team database audit
│   ├── ai/                  # ai_scan profile — AI/LLM attack-surface audit (llm_recon.py)
│   ├── offensive/           # engage profile — active exploitation engagement (engage.py)
│   ├── intel/               # Skills-library enrichment (skills_kb.py)
│   └── output/              # Console, scoring, report generation, kill-chain attack_path.py
├── wordlists/               # Directory, admin path, and subdomain lists
├── docs/                    # Reference PDFs + their generator scripts
│   ├── make_guide.py        # Generates Hades_Modules_Guide.pdf
│   ├── make_flags.py        # Generates Hades_Flags_Cheatsheet.pdf
│   ├── make_db_manual.py    # Generates Hades_Database_Security_Manual.pdf (bilingual FR/EN)
│   └── make_redteam_tools.py # Generates Hades_RedTeam_Tools_Reference.pdf (git-ignored, ~22 MB)
├── tools/                   # Dev utilities (import-health check)
├── hook_check.py            # Claude Code PostToolUse hook entry point
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── logs/                    # Auto-created on first run
└── reports/                 # Auto-created on first run
```

---

## Legal Disclaimer

> **This tool is for authorised security testing only.**
> Scanning or exploiting systems, networks, or applications without explicit written permission
> from the owner is **illegal** in most jurisdictions and may violate computer fraud laws (CFAA,
> Computer Misuse Act, etc.).
> Active injection is **detection-only by default**; actual exploitation (`--exploit` → sqlmap)
> only runs after an explicit per-target authorisation confirmation.
> The author assumes **no liability** for any misuse, damage, or legal consequences arising from
> the use of this tool. Always obtain proper written authorisation before conducting any
> security assessment.

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-module`
3. Add at least one test in `tests/test_modules.py`
4. Open a pull request with a clear description of what the module detects

New scan modules must follow the `run(engine: ScanEngine) -> list[Finding]` signature and handle all exceptions gracefully without crashing the engine. Active injection modules must reuse `scanner/vulns/_common.py` (crawler params/forms, safe-mode check, proof URLs).

---

## License

MIT License — see [LICENSE](LICENSE) for details.
