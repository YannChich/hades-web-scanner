# Changelog

All notable changes to **Hades** are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and the project aims to keep the CLI and the
JSON report backward-compatible.

## [Unreleased]

### Added
- **External tool integrations** (`scanner/integrations/`). Hades now drives best-in-class tools when
  they're installed and degrades gracefully (a single INFO hint) when they're not: **Nmap** (`-sV`
  service/version + OS on the resolved host), **Gobuster** (fast content discovery), **theHarvester**
  (passive OSINT — e-mails/hosts/IPs) and **Recon-ng** (passive host enumeration via a batch resource
  script → workspace DB). Active tools skip in safe mode; OSINT ones query third parties, not the target.
  Plus a **Maltego** export (`--maltego`) — the scan's entities (domain/hosts/IPs/e-mails) as a
  Maltego-importable CSV. All optional, all flowing through the normal report pipeline.
- **Stored & DOM-based XSS detection (`xss_detect`).** Beyond the existing context-aware *reflected*
  pass, `xss_detect` now (1) detects **server-rendered stored XSS** — it submits a form field and
  re-checks the *display* pages, not just the submission's own response — and (2) ships an optional
  **browser-verified DOM/stored** pass (`scanner/vulns/dom_xss.py`, headless Chromium via Playwright)
  that catches payloads written into the DOM by client-side JS (`innerHTML`, `location.hash`, …) which
  never appear in the HTTP response and only execute in a browser — covering **form-field**, **URL
  `#fragment`** and **reflected query-parameter** sinks. The last catches event-handler-attribute XSS
  (`onload="…('PARAM')…"`) where the server entity-encodes the quote (`&#39;`) but the browser decodes
  it before running the JS — which an HTTP-only check wrongly reads as safe; a browser-verified HIGH
  there supersedes the old "reflected but encoded" LOW. Benign, token-based, detection-only; degrades to an
  install hint when Playwright/Chromium is absent. A shared `scanner/browser.py` helper centralises the
  self-healing Chromium bootstrap (also used by `screenshot`).
- **Evidence-grade findings.** Every actionable finding now carries a structured proof block
  (`raw["evidence"]`) — the exact request sent, the response status/size/content-type, and the
  indicator that triggered it — rendered as a `⧉ evidence` line in the console, a green evidence box
  in the HTML report, and the `evidence` array in JSON. Backed by a single shared builder
  (`scanner/evidence.py`).
- **Exploitation walkthroughs.** Every exploitable finding ships an ordered, copy-paste kill chain
  (`raw["exploitation"]`) tailored to the real URL/parameter — sqlmap for SQLi, commix for command
  injection, tplmap for SSTI, file-read→RCE for LFI, cloud-metadata pivot for SSRF, dalfox for XSS,
  jwt_tool for JWT, git-dumper/aws-s3 for exposed `.git`/buckets, and more — shown as a `⛓ exploit
  chain` in the console and a collapsible **Exploitation walkthrough** in HTML.
- **Database audit (`db_scan`) red-team upgrades.** Modern MongoDB detection (OP_MSG 2013), new
  unauthenticated probes (ClickHouse, etcd, InfluxDB, Neo4j, Zookeeper, Cassandra), MSSQL default
  credentials, deeper `--exploit` extraction (Mongo/ClickHouse/Redis + richer in-band SQLi + Supabase
  RLS test), and version→CVE correlation.
- **AI/LLM audit (`ai_scan`) red-team upgrades.** More AI-infra engines (Ray/ShadowRay, MLflow,
  ComfyUI, Langflow, Xinference…), unauthenticated vector-DB detection (Qdrant/Weaviate/Chroma/Milvus),
  more provider key patterns + a GCP/Vertex service-account detector, MCP tool enumeration, model
  fingerprint + PII extraction under `--exploit`, and version→CVE correlation.
- A self-contained **example HTML report** under `docs/example-report/`.
- This `CHANGELOG.md`.

### Changed
- **Concurrent token-bucket rate limiter** so the thread pool actually parallelises (heavy modules
  finish instead of being cut off); safe/passive mode stays a single polite lane.
- Full-scan **orchestration hardening**: per-module timeout watchdog, pre-flight reachability check,
  shared idempotent-GET cache (homepage/robots/sitemap fetched once), a **circuit breaker** that backs
  off when the target stops responding, and an end-of-run timing summary.
- **Informational (INFO) findings are presented separately** from real vulnerabilities in both the
  console and the HTML report, so context never looks like a vulnerability.
- Safe-mode detection is now centralised on `ScanEngine.is_safe_mode()` (removing four duplicate
  per-module copies).

### Fixed
- **Subdomain-takeover false positives**: a takeover is now reported only when the sub-domain's DNS
  actually points at the suspected service (CNAME chain matches e.g. `*.amazonaws.com` /
  `*.herokudns.com`, or the IP is in a service range) **and** the page carries that service's
  unclaimed-resource fingerprint. A generic 404 alone (e.g. an App Engine `*.appspot.com` page) no
  longer matches, and services whose only fingerprint is a generic 404 (Unbounce) report Medium
  "verify" instead of High.
- **Sensitive-file false positives**: a `200` is validated by body length, content-type and
  file-specific indicators before it is confirmed; an empty/served-but-blank file (e.g. an empty
  `/.htaccess`) degrades to a calm low finding instead of a false-positive critical.
- **`dir_scan` no longer double-reports** specialist-owned sensitive/backup/VCS paths now present in
  the expanded wordlists — it defers them to the dedicated, content-validating modules.
- **Reflected XSS / injection in stateful (ASP.NET) POST forms** is detected by re-fetching fresh
  hidden tokens (`__VIEWSTATE`/`__EVENTVALIDATION`/CSRF) before each submission.
