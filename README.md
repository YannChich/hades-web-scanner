<p align="center">
  <img src="assets/hades.png" alt="Hades" width="760">
</p>

<h3 align="center">Find the vulnerability. Prove it. Map the path to impact.</h3>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-b3122a?style=for-the-badge&labelColor=0d0d0d" alt="License">
  <img src="https://img.shields.io/badge/python-3.10+-7b2fbf?style=for-the-badge&labelColor=0d0d0d&logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/github/repo-size/YannChich/hades-web-scanner?style=for-the-badge&labelColor=0d0d0d&color=b3122a" alt="Repo size">
  <img src="https://img.shields.io/badge/platform-Linux%20|%20macOS%20|%20Windows-7b2fbf?style=for-the-badge&labelColor=0d0d0d" alt="Platform">
  <img src="https://img.shields.io/badge/status-active-b3122a?style=for-the-badge&labelColor=0d0d0d" alt="Status: active">
</p>

---

**Hades is a terminal-based, red-team web security scanner that does not just *find* weaknesses — it *proves* them.**

It runs 43 checks across reconnaissance, misconfiguration and vulnerability detection, confirms each
finding with an evaluated payload / timing / content signature (no blind guessing), maps it to
**CWE / OWASP / MITRE ATT&CK** with a CVSS score, links a step-by-step **expert playbook**, and weaves
everything into a single copy-paste **kill-chain attack path** — then exports a polished, self-contained
HTML report. On top of the standard scan, dedicated red-team profiles audit **databases**, the
**AI/LLM** attack surface, run an **active exploitation engagement**, catch **blind, out-of-band**
vulnerabilities other scanners miss, and rank a target's **CVEs** by real-world exploitability
(**KEV + EPSS**). One command.

```text
python main.py --url https://target.tld
```

> [!IMPORTANT]
> Hades is for **authorised security testing only**. See the [Disclaimer](#disclaimer).

---

## Table of Contents

- [Why Hades](#why-hades)
- [Features](#features)
- [Reports Preview](#reports-preview)
- [Installation](#installation)
- [Usage](#usage)
- [Scan Profiles](#scan-profiles)
- [Modules](#modules)
- [Example Output](#example-output)
- [Cross-Referenced Integrations](#cross-referenced-integrations)
- [Roadmap](#roadmap)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Why Hades

Most scanners hand you a list of *maybe*. Hades is built around a different promise: **every finding is
evidence**, and every piece of evidence comes with the next move.

- **Proof, not noise.** Injection modules confirm the bug (evaluated math for SSTI, scaling time delays
  for blind injection, command output for RCE, file content for LFI) before reporting it.
- **Context for every finding.** CWE, OWASP category, MITRE ATT&CK technique, a representative CVSS
  score, a stable finding ID, a reproducible PoC command, the matching expert playbook, and the relevant
  offensive tools — attached automatically.
- **A path, not a pile.** All actionable findings are ordered into one kill-chain attack path
  (Reconnaissance to Impact), with copy-paste commands at each step.
- **Client-ready output.** A dark, self-contained HTML report is generated for *every* scan and opens in
  your browser automatically.

---

## Features

**Detection engine**
- 43 modules across reconnaissance, web/misconfiguration analysis and active vulnerability detection.
- Shared, rate-limited crawler feeds every module the same parameters, forms, links and emails.
- Anti-noise baselines (catch-all 200, blanket 403/5xx, accept-all ports, soft-404) keep results accurate.

**Offensive injection arsenal (active verification)**
- SQLi, XSS, command injection, SSTI, LFI/path traversal, open redirect and SSRF — each *proven*, with a
  clickable proof link and a ready exploitation command.
- JWT attacks (`alg:none`, weak-secret cracking, claim disclosure), 401/403 access-control bypass, CVE
  mapping via the NVD, and a default-credentials advisory.

**Dedicated red-team profiles**
- `db_scan` — database exposure audit: port/banner fingerprint, unauthenticated access with live data
  extraction, SQL/NoSQL injection, secret-file and connection-string hunting, exposed admin GUIs, a DB
  Exposure Score and an exploitation Attack Path.
- `ai_scan` — AI/LLM attack surface mapped to the OWASP LLM Top 10 and MITRE ATLAS: SDK fingerprinting,
  exposed AI keys, unauthenticated local LLM servers (Ollama, vLLM, LM Studio), and prompt-injection.
- `engage` — exploitation-first engagement that actively proves impact with benign payloads (RCE proof
  via `id`, arbitrary file read, SSRF to cloud metadata) and writes evidence files.
- `oob_scan` — out-of-band (OAST) detection of blind SSRF / RCE / stored XSS via a self-hosted callback
  listener, with an automatic public tunnel (cloudflared / ngrok) so it works behind NAT.
- `cve_scan` (interactive **menu option 8**) — CVE Vulnerability Intelligence: fingerprints the target's
  stack broadly (HTTP headers, JS/CSS/CMS/framework signatures, and SSH/FTP/mail/DB service banners),
  matches it to real CVEs from a local vulnerability database, and ranks each by a Hades CVE
  Priority Score that fuses CVSS, FIRST EPSS exploit probability and the CISA KEV catalog. 100% free,
  no API key — built from CISA KEV, FIRST EPSS and the NVD 2.0 API; the local SQLite database is
  auto-created and auto-refreshed. Run `python tools/build_vulndb.py` once to bulk-load the **entire
  NVD corpus** (~270k CVEs) for fully **offline** matching — incrementally refreshed thereafter.

**Intelligence and reporting layer**
- Framework mapping (CWE / OWASP / ATT&CK / CVSS), expert playbooks, per-finding RedTeam tools, and a
  unified kill-chain attack path — surfaced in the console, JSON and HTML.
- Weighted 0-100 risk score with an A-F grade (informational findings never affect the grade).
- Always-on HTML report (auto-opened), plus optional JSON and PDF export, and timestamped logs.

> A plain-language guide to every module — what it checks, the consequence of a finding, and the attack
> it enables — is generated as a PDF: [`docs/Hades_Modules_Guide.pdf`](docs/Hades_Modules_Guide.pdf).

---

## Reports Preview

Every scan produces a dark, self-contained HTML report (framework badges, a security-score gauge, the
kill-chain attack path, matched playbooks, and the DB/AI panels).

<p align="center">
  <img src="assets/screenshots/hades-report.png" alt="Hades HTML report" width="850">
</p>

<!--
  SCREENSHOTS — drop your images here and they will render above/below automatically:
    assets/screenshots/hades-report.png    HTML report (e.g. a scan of http://rest.vulnweb.com)
    assets/screenshots/hades-console.png   terminal output (findings table + attack path)
  Suggested demo target (authorised test site): http://rest.vulnweb.com
    python main.py --url http://rest.vulnweb.com --profile full
-->

> Terminal capture coming soon. To generate your own demo, scan an authorised test target such as
> `http://rest.vulnweb.com` and the HTML report opens automatically.

---

## Installation

**Requirements:** Python 3.10+

```bash
git clone https://github.com/YannChich/hades-web-scanner.git
cd hades-web-scanner

pip install -r requirements.txt

# Chromium for screenshots and PDF rendering (also self-heals at runtime)
playwright install chromium

# Optional — only for the --exploit sqlmap launcher
pip install sqlmap
```

**Docker**

```bash
docker compose -f docker/docker-compose.yml build
docker compose -f docker/docker-compose.yml run --rm webscan --url https://example.com
```

**Recommended — full local experience (optional)**

Hades cross-references two external knowledge bases. Clone them *next to* the project so every playbook
link and the RedTeam-Tools PDF resolve locally. Without them Hades still runs and falls back to GitHub
links — nothing breaks.

```bash
# run in the PARENT folder, alongside hades-web-scanner/
git clone https://github.com/mukul975/Anthropic-Cybersecurity-Skills   # expert playbooks
git clone https://github.com/A-poc/RedTeam-Tools                        # red-team tool catalogue
```

---

## Usage

**Interactive (menu-driven, minimal flags)** — run with just a URL and Hades walks you through the
scan type and exploitation choices:

```bash
python main.py --url http://testphp.vulnweb.com/
# or fully interactive (also prompts for the URL):
python main.py
```

Every scan always generates the HTML report and auto-opens it (`--no-open` to disable).

**Command line**

```bash
# Full scan (default profile)
python main.py --url https://example.com --profile full

# Quick passive surface scan
python main.py --url https://example.com --profile quick

# Database security audit (red-team)
python main.py --url https://example.com --profile db_scan

# AI / LLM attack-surface audit
python main.py --url https://example.com --profile ai_scan

# Active exploitation engagement (asks for authorisation)
python main.py --url https://example.com --profile engage

# Out-of-band / blind vulnerabilities (auto-tunnels via cloudflared behind NAT)
python main.py --url https://example.com --profile oob_scan

# CVE Vulnerability Intelligence — run the interactive menu and pick option 8
python main.py --url https://example.com          # then choose [8] CVE Vulnerability Intelligence

# (one-time) bulk-load the full NVD corpus for offline CVE matching — optional NVD_API_KEY speeds it up
python tools/build_vulndb.py                       # then cve_scan matches ~270k CVEs locally, offline

# Also export JSON or PDF on top of the HTML
python main.py --url https://example.com --output json

# Through a proxy, with a session cookie
python main.py --url https://example.com --proxy http://127.0.0.1:8080 --cookies "session=abc123"
```

<details>
<summary><b>All command-line options</b></summary>

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--url` | `-u` | — | Target URL (required, or prompted interactively) |
| `--profile` | `-p` | `full` | `quick` `passive` `cms` `full` `db_scan` `ai_scan` `engage` `oob_scan` (`cve_scan` is menu option 8) |
| `--output` | `-o` | — | Extra report format on top of the always-generated HTML: `json` `pdf` |
| `--no-open` | | `false` | Do not auto-open the HTML report in a browser |
| `--exploit` | | `false` | Launch sqlmap on confirmed SQL injections (authorised targets only) |
| `--bruteforce` | | `false` | Spray common credentials at login forms and Basic-Auth (authorised only) |
| `--oob-host` | | auto | Reachable callback address for `oob_scan` (public IP / tunnel) |
| `--oob-port` | | `0` | OAST callback listener port (`0` = auto-pick) |
| `--proxy` | | — | HTTP/HTTPS proxy URL |
| `--threads` | `-t` | `10` | Concurrent thread count |
| `--ignore-robots` | | `false` | Ignore robots.txt restrictions |
| `--wordlist` | `-w` | built-in | Custom wordlist path |
| `--cookies` | | — | Cookie header string |
| `--auth-token` | | — | Bearer token for the Authorization header |

</details>

---

## Scan Profiles

| Profile | Type | Description |
|---------|------|-------------|
| `quick` | Fast | Passive surface scan (basic info, headers, SSL, robots) |
| `passive` | Moderate | All recon and passive web modules, no active probing |
| `cms` | Targeted | CMS detection, admin panels, CVE mapping |
| `full` | Thorough | Everything, including the injection arsenal (default) |
| `db_scan` | Red team | Database security audit |
| `ai_scan` | Red team | AI/LLM attack surface (OWASP LLM Top 10 + ATLAS) |
| `engage` | Offensive | Active engagement — auto-exploit confirmed RCE/LFI/SSRF |
| `oob_scan` | Offensive | Out-of-band detection of blind SSRF/RCE/XSS |
| `cve_scan` | Intelligence | CVE Vulnerability Intelligence (menu option 8) — CVE matching + KEV/EPSS prioritisation |

---

## Modules

Each finding is enriched with CWE / OWASP / MITRE ATT&CK / CVSS, a PoC, a matched playbook and the
relevant RedTeam tools. Full plain-language explanations live in
[`docs/Hades_Modules_Guide.pdf`](docs/Hades_Modules_Guide.pdf).

<details open>
<summary><b>Reconnaissance (11)</b></summary>

`basic_info` &middot; `whois_lookup` &middot; `dns_check` (SPF/DKIM/DMARC) &middot; `ssl_check` &middot;
`port_scan` &middot; `waf_detect` &middot; `tech_stack` &middot; `js_recon` (leaked secrets + hidden
endpoints) &middot; `cloud_buckets` (S3/GCS/Azure) &middot; `git_dumper` (exposed `.git`) &middot;
`wayback` (archive URL mining)

</details>

<details>
<summary><b>Website &amp; Misconfiguration (20)</b></summary>

`headers_check` &middot; `robots_txt` &middot; `sitemap` &middot; `cms_detect` &middot; `admin_panel`
&middot; `dir_scan` &middot; `subdomain_scan` (+ takeover) &middot; `broken_links` &middot;
`http_methods` &middot; `backup_files` &middot; `sensitive_files` &middot; `cookie_analysis` &middot;
`redirect_chain` &middot; `email_exposure` &middot; `favicon_hash` &middot; `cors_check` &middot;
`clickjacking` &middot; `dir_listing` &middot; `blacklist_check` &middot; `screenshot`

</details>

<details>
<summary><b>Vulnerability Detection (12)</b></summary>

`sqli_detect` &middot; `xss_detect` &middot; `command_injection` &middot; `ssti_detect` &middot;
`lfi_detect` &middot; `open_redirect` &middot; `ssrf_detect` &middot; `jwt_attacks` &middot;
`auth_bypass` &middot; `bruteforce` (opt-in) &middot; `cve_mapping` &middot; `default_creds`

</details>

<details>
<summary><b>Red-team profiles</b></summary>

- **`db_scan`** — DB port/banner fingerprint, unauthenticated access with live extraction, SQL/NoSQL
  injection, secret-file and connection-string hunting, exposed admin GUIs, DB Exposure Score + Attack Path.
- **`ai_scan`** — AI SDK fingerprinting, exposed AI keys, unauthenticated local LLM servers, exposed AI
  UIs, prompt-injection surface (OWASP LLM Top 10 + MITRE ATLAS).
- **`engage`** — active exploitation: RCE proof, arbitrary file read, SSRF to cloud metadata, with evidence files.
- **`oob_scan`** — out-of-band detection of blind SSRF / RCE / stored XSS via a self-hosted callback listener.
- **`cve_scan`** (menu option 8) — CVE Vulnerability Intelligence: stack fingerprint → CPE → CVE matching
  against a local KEV/EPSS/NVD database, ranked by the Hades CVE Priority Score (CVSS + EPSS + CISA KEV).
  `tools/build_vulndb.py` bulk-loads the full NVD corpus (~270k CVEs) for offline matching.

</details>

---

## Example Output

The unified kill-chain attack path, grouped by MITRE ATT&CK tactic with copy-paste commands:

```text
────────────────────────── Attack Path — Kill Chain ───────────────────────────
  4 actionable step(s) across 3 ATT&CK phase(s), in attacker order.

▼ Initial Access  TA0001
   1.  CRITICAL  SQL Injection (error): id            SQLI-D65F · T1190
                 $ sqlmap -u 'http://t/p?id=1' --batch --dbs
                 playbook: exploiting-sql-injection-vulnerabilities    tools: nuclei
▼ Credential Access  TA0006
   2.  CRITICAL  .env file exposed                    SENSIT-7EDB · T1552.001
                 $ curl -sk "http://t/.env"
   3.  HIGH      Exposed .git directory               GIT-0D07 · T1552.001
                 $ git-dumper http://t/.git/ ./loot_src
▼ Discovery  TA0007
   4.  LOW       Open port 6379 (Redis)               PORT-1F15
                 $ nmap -sV -p 6379 10.0.0.5
```

Reports are written to `reports/` (HTML always; JSON/PDF on request) and logs to `logs/`.

---

## Cross-Referenced Integrations

Hades cross-references two open-source knowledge bases:
**[Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills)**
(expert playbooks) and **[RedTeam-Tools](https://github.com/A-poc/RedTeam-Tools)** (tool catalogue + PDF).

Cloning them gives the full local experience; a plain clone degrades gracefully:

| Capability | Both repos cloned | Plain clone (fallback) |
|------------|-------------------|------------------------|
| Scan, profiles, framework mapping, attack path | yes | yes |
| RedTeam tool references (per finding) | yes | yes (names are built in) |
| Playbook references | full local skill text + `file://` links | bundled index, links to GitHub |
| RedTeam-Tools reference PDF | offline build | README fetched from GitHub |

All credit for those catalogues goes to their authors ([@mukul975](https://github.com/mukul975),
[@A-poc](https://github.com/A-poc)); Hades only references and links to them.

---

## Roadmap

Hades is under active development. Planned and in-progress work:

- [ ] Blind SQL injection over DNS (OAST DNS listener)
- [ ] Authenticated / session-aware crawling and BOLA / IDOR testing
- [ ] WAF-aware payload mutation (auto-bypass and re-confirm)
- [ ] Nuclei template bridge (ingest results into the framework/playbook layer)
- [ ] Expanded MITRE ATLAS coverage for the AI/LLM profile
- [x] CVE Vulnerability Intelligence with KEV + EPSS prioritisation (menu option 8)
- [x] Out-of-band (OAST) blind-vulnerability detection with auto-tunnel
- [x] Unified kill-chain attack path across all profiles
- [x] AI/LLM and database red-team profiles

---

## Tech Stack

`httpx` (HTTP) &middot; `Rich` (terminal UI) &middot; `dnspython` &middot; `python-whois` &middot;
`cryptography` (TLS) &middot; `BeautifulSoup4` &middot; `Playwright` (Chromium screenshots + PDF) &middot;
`Markdown` &middot; `reportlab` / `weasyprint` (PDFs) &middot; `loguru` &middot; `mmh3` &middot;
`sqlmap` (optional, `--exploit`).

---

## Project Structure

```text
hades-web-scanner/
├── main.py                  # Entry point — CLI, interactive menu, argument parsing
├── config.py                # Profiles, taxonomy, cross-reference maps, constants
├── scanner/
│   ├── engine.py            # Orchestration, threading, rate limiting, HTML auto-open
│   ├── crawler.py           # Shared site crawler
│   ├── severity.py          # Single source of truth for severity ordering/styles
│   ├── recon/  web/  vulns/ # The 43 scan modules
│   ├── db/   ai/   offensive/   oob/   # Red-team profiles (db_scan, ai_scan, engage, oob_scan)
│   ├── cve/                 # CVE Vulnerability Intelligence (cve_scan, menu option 8)
│   ├── intel/               # Skills-library enrichment (playbooks)
│   └── output/              # Console, scoring, attack path, JSON/HTML/PDF reports
├── data/vulndb/            # CVE module: aliases.json (tracked) + local SQLite DB (git-ignored)
├── docs/                    # Reference PDFs + their generator scripts
├── tools/                   # Dev utilities (import check, playbook bundle builder)
├── tests/                   # pytest suite
└── docker/                  # Dockerfile + compose
```

---

## Contributing

Contributions are welcome.

1. Fork and create a feature branch: `git checkout -b feature/new-module`.
2. Add at least one test in `tests/test_modules.py`.
3. Open a pull request describing what the module detects.

New scan modules follow the `run(engine: ScanEngine) -> list[Finding]` signature and must handle their
own exceptions without crashing the engine. Active injection modules reuse `scanner/vulns/_common.py`
(crawler parameters/forms, safe-mode check, proof URLs).

---

## Disclaimer

Hades is intended for **authorised security testing only** — your own systems, or targets you have
**explicit written permission** to assess. Scanning or exploiting systems without authorisation is
illegal in most jurisdictions. Active exploitation is opt-in and gated behind a per-target confirmation;
the project ships detection-only by default. The author accepts no liability for misuse.

---

## License

Released under the [MIT License](LICENSE).

<p align="center"><sub>If Hades is useful to you, consider leaving a star — it helps the project grow.</sub></p>
