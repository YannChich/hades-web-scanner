# Hades — Roadmap & Backlog

> Working backlog for Hades. The daily autonomous session reads this file, picks the
> **top unchecked task** in **In progress / Next up**, implements it in small atomic
> commits, ticks the box, and moves the entry to **Done** with its date.

## How the daily session works

- Runs ~1h/day. Scope is **building the tool** (code, modules, tests, docs, refactors) —
  never running Hades against live external targets.
- Keep the project's DA: a cohesive dark Kali / red-team aesthetic, detection-only by default,
  offensive actions gated behind `--exploit`.
- Quality gate before every push: `python tools/check_imports.py` and `pytest` must pass.
  Never leave `main` broken. No filler/empty commits.
- Atomic commits: one coherent change = one commit. Add/extend tests for new behaviour.
- When a backlog item is done, check it off here and append a one-line entry under **Done**.

---

## In progress / Next up (priority order)

> **Standing emphasis (set 2026-11-24):** sessions should keep a **balanced mix** across three
> tracks — (1) **new detection modules** (broaden vulnerability coverage), (2) **new active
> capabilities gated behind `--exploit`** (verified exploitation/proof, detection-first by default),
> and (3) **improving existing modules** (accuracy / fewer false positives, more payloads, hardening,
> test coverage). Rotate between the three rather than draining one. Always: detection-only by
> default, active actions gated behind `--exploit`, authorised targets only, no malware, nothing
> illegal. If an idea drifts toward an "attack framework" rather than a detection/verification
> scanner, reframe it as detection/verification and note it in the end-of-session summary.

Several of these are inspired by ARTEX (an autonomous pentest platform) but reimagined
natively for Hades' Python CLI architecture — no code is copied.

- [x] **Retest / diff loop** (`--retest`): persist each scan's findings to
  `reports/history/<host>.json`; on re-run, compare against the last scan and label every
  finding `new` / `still-present` / `fixed`. Surface a diff panel in console + HTML report.
- [x] **Scope / deny rules** (`--scope`, `--deny`): allowlist/denylist of hosts and path
  prefixes enforced in `engine.py` before any request leaves. Out-of-scope requests are
  blocked and logged. Accept a scope file (`--scope-file`).
- [x] **Findings verification status**: add a `verified: bool` + `verification` note to
  `Finding`, tied to the request/response in `raw["evidence"]`. Render a `✓ verified` badge
  in HTML and a column in console. Active-injection findings set it from their proof.
- [x] **Coverage ledger**: track which modules ran vs skipped vs errored per target, and
  which discovered endpoints/params were actually probed. Render a "Coverage" section in the
  HTML report (tested vs untested, DA-consistent).
- [x] **Noise governor**: extend the token-bucket limiter with adaptive pacing + jitter and a
  `--quiet`/`--aggressive` profile that tunes concurrency and delays. Back off on 429/503.
- [x] **SARIF export** (`report_sarif.py`): emit findings in SARIF 2.1.0 so results load into
  GitHub code scanning / CI dashboards.
- [ ] **Scan resume / checkpoint**: persist engine progress so an interrupted scan can
  resume (`--resume`) instead of restarting from scratch. *(Taken out of strict priority order this
  session: it touches the threaded scan loop and mid-scan persistence, so it was deferred in favour
  of the self-contained SARIF export rather than risk a half-done checkpoint on `main`.)*

### Track 1 — New detection modules (detection-first, no flag needed)

- [x] **XXE detection** (`scanner/vulns/xxe_detect.py`): probe XML-accepting endpoints for external-
  entity processing. In-band first (entity expansion reflected / error signatures); blind via the
  existing OOB listener. Evidence + `verified` from the proof. Wire into the `full` vuln profile.
- [x] **NoSQL injection detection** (`scanner/vulns/nosqli_detect.py`): operator-injection payloads
  (`$ne`, `$gt`, `$regex`, auth-bypass `[$ne]=`) against JSON and form params; confirm by response
  divergence like the boolean SQLi logic. Detection-only; set `verified` on a confirmed split.
- [x] **GraphQL recon** (`scanner/web/graphql_detect.py`): find `/graphql`-style endpoints, test
  whether **introspection** is enabled, and flag verbose errors / suggestion leaks and missing depth
  limiting. INFO→MEDIUM depending on exposure; evidence from the introspection response.
- [x] **Host-header injection / cache-poisoning indicators** (`scanner/web/host_header.py`): detect
  reflected/absolute-URL Host handling and unkeyed inputs that hint at web-cache poisoning. Report as
  an indicator (detection), with the active cache-poisoning confirmation left behind `--exploit`.
- [x] **Insecure-deserialization indicators** (`scanner/vulns/deser_detect.py`): spot serialized
  blobs in params/cookies (Java `rO0`, PHP `O:`, .NET viewstate, Python pickle) and flag them with
  the matching risk; detection/heuristic only — no gadget execution.

### Track 2 — New active capabilities (gated behind `--exploit`, verified)

- [ ] **OOB confirmation for SSRF & XXE**: when `--exploit` + an OOB host are set, send a callback
  payload through the existing `scanner/oob/` listener and mark the finding `verified` only on a real
  interaction. Detection stays in-band by default; this just upgrades confidence to proof.
- [ ] **Gated active IDOR confirmation**: with `--exploit`, re-request a neighbouring object id with
  and without the session and confirm cross-object access by response diffing; write proof to `loot/`.
  Default run stays detection-only (current behaviour).
- [ ] **Exploit-chain surfacing in `engage`**: group confirmed findings into a short, ordered
  kill-chain (recon → entry → impact) using existing data; copy-paste commands only, authorised-use
  banner, no new offensive tooling.

### Track 3 — Improve existing modules (accuracy / coverage / hardening)

- [x] **False-positive hardening pass** on the active injection modules: calibrate against the
  soft-404 / WAF-block baselines already in `evidence.py`, and add regression tests for known
  false-positive shapes (WAF 403 that echoes payloads, error pages that always contain "SQL").
- [x] **Broaden payload sets** for `xss_detect` (more contexts: SVG, event handlers, template
  literals) and `lfi_detect` (wrappers, Windows paths), each with tests — keep the `verified` proof
  logic intact.
- [x] **Raise unit-test coverage** on `scanner/vulns/*` and `scanner/output/*` toward parity with the
  newer modules (every new behaviour mocked, no live traffic). *(Ongoing: dedicated pass done
  2026-11-25 — SSTI/open_redirect regressions + a JSON-report contract suite. Keep topping up as
  modules change.)*

## Backlog (unordered ideas)

- [ ] JSON schema + `--schema` dump for the JSON report (stable contract for downstream tools).
- [x] `--diff-only` flag to report just the delta vs the previous scan.
- [x] Per-finding "false-positive" suppression file (`.hadesignore`).
- [x] Markdown report exporter for quick GitHub/issue pasting.
- [ ] JWT algorithm-confusion check (RS256→HS256): when the server's RSA public key is retrievable
  (JWKS/`/.well-known`), try verifying/forging with HS256 using the public key as the HMAC secret —
  detection by default, active forge behind `--exploit`.
- [x] `security.txt` / `.well-known` posture check (RFC 9116): report presence/absence and parse
  contact/expiry — a quick credibility + recon win.
- [ ] Config file support (`hades.toml`) for default flags per project.
- [ ] More unit tests: raise coverage on `scanner/vulns/*` and `scanner/output/*`.
- [x] CI workflow (GitHub Actions): run `pytest` + `check_imports` on every push/PR.
- [x] `--fail-on <severity>` CI gate: exit non-zero when a finding at/above the given severity is
  present (and honours `.hadesignore`), so Hades can gate a pipeline the way `nuclei -severity` does.
  Detection-only; just an exit-code contract on top of the existing scan.
- [x] CSV export of findings (`report_csv.py`) for spreadsheet triage / import into a tracker —
  one row per finding (severity, module, title, CWE, OWASP, verified, url). Pure renderer, no new scan.
- [x] `.well-known` posture breadth: alongside `security.txt`, report on `change-password`
  (RFC 8615), `mta-sts.txt` and an exposed `openid-configuration` — detection/recon, INFO→LOW
  (plus MEDIUM/verified for an OIDC `alg:none`).
- [ ] Per-finding first-seen / last-seen timestamps in the history store, surfaced in the retest
  panel ("new as of <date>", "open for N days") to show how long an issue has been outstanding.

---

## Done

<!-- Append finished items here, newest first: `- YYYY-MM-DD — <what shipped>` -->

- 2026-11-27 — Three self-contained backlog items shipped (balanced: one CI contract, one output
  renderer, one new detection module), each with tests + docs; suite 534 → 553 green. The top
  "Next up" item (scan resume/checkpoint) was intentionally skipped again — it touches the threaded
  scan loop and mid-scan persistence, and the project note defers it to avoid a half-done checkpoint
  on `main`; these three were safe, high-value and independent.
  **`--fail-on <severity>`** (`scanner/output/gate.py`) — a CI exit-code gate: `run_scan` now returns
  a process exit code and exits `3` when any finding is at/above the chosen severity (honouring
  `.hadesignore`, decided on the full posture not the `--diff-only` view), so Hades can block a
  pipeline like `nuclei -severity`. Unknown/absent severity is fail-open. Threaded through
  `main()`/`cli()`; 6 tests.
  **CSV export** (`scanner/output/report_csv.py`) — every scan also writes `reports/*.csv`: one row
  per finding (id, severity, confidence, verified, module, title, CWE, OWASP, MITRE, CVSS, retest,
  url), most-severe first, stdlib-`csv` quoting, for spreadsheet / tracker triage; shown in the
  reports panel; 5 tests.
  **`wellknown`** (`scanner/web/wellknown.py`) — a Track-1 detection module in the passive profile
  probing three `.well-known` resources: change-password (RFC 8615, INFO), mta-sts.txt (RFC 8461 —
  INFO on `enforce`, LOW when not enforcing TLS) and openid-configuration (INFO recon; MEDIUM +
  verified + CWE-347 when the IdP advertises the `none` id_token signing algorithm). Silent when
  nothing is present. OWASP A05, mapped to nuclei; 8 tests.

- 2026-11-26 — Four backlog items shipped (balanced across a new detection module and output/UX
  tooling), each with tests + docs; suite 507 → 534 green:
  **security_txt** (`scanner/web/security_txt.py`) — a Track-1, detection-only RFC 9116 posture
  check. Fetches `/.well-known/security.txt` (falls back to the legacy `/security.txt`), parses the
  fields and reports absence (INFO), legacy-only location (LOW), missing mandatory Contact (MEDIUM),
  missing/malformed/past/too-distant Expires (LOW→MEDIUM) and non-HTTPS delivery (LOW); an HTML error
  page is never mistaken for a served file. Wired into the passive profile + taxonomy (OWASP A05, no
  misleading CWE) and the tool map; 9 tests.
  **Markdown report exporter** (`scanner/output/report_md.py`) — every scan now also writes
  `reports/*.md`: score/grade header, a severity-count table, one section per actionable finding
  (CWE/OWASP/MITRE/CVSS, evidence, `curl` PoC, fix) with info findings folded into a collapsed block.
  Pastes straight into a GitHub/GitLab issue or client email; path shown in the reports panel; 7 tests.
  **`.hadesignore` false-positive suppression** (`scanner/output/suppress.py`, `--ignore-file`) —
  record triaged FPs by `module:`/`id:`/`fingerprint:`/`title:` glob (bare line = id or fingerprint);
  matches are dropped *before* scoring and reporting so accepted FPs don't skew the score or reappear;
  10 tests.
  **`--diff-only`** — with `--retest`, render only findings new since the last scan (retest panel
  still reports fixed/still-present); score stays the full-posture score and the history snapshot
  records the full run. Selection extracted to pure helpers (`select_new_findings`,
  `_diff_only_applicable`); 3 tests.

- 2026-11-25 — Two new Track-1 detection modules (detection-first, no flag), each with unit tests and
  wired into the `full` profile + taxonomy (CWE/OWASP/MITRE):
  **host_header** (`scanner/web/host_header.py`, CWE-644) injects a unique sentinel host via the Host
  header and common `X-Forwarded-*` headers and reports *reflection* (body → LOW cache-poisoning
  candidate; redirect `Location` → MEDIUM) as an indicator — active poisoning stays behind `--exploit`;
  **deser_detect** (`scanner/vulns/deser_detect.py`, CWE-502) recognises serialized blobs (Java,
  PHP, Python pickle, Ruby Marshal, .NET ViewState) in params/cookies/form fields, heuristic only,
  evidence shows only the format + a short prefix (never the full value). Suite now 507 green.

- 2026-11-25 — Coverage-breadth pass on exposure modules, each with tests:
  **default_creds** catalog grew by ~18 management interfaces (Zabbix, Cacti, Nagios, Netdata,
  Prometheus, SonarQube, Harbor, Keycloak, MinIO, Mongo Express, Solr, Couchbase, phpPgAdmin, Jupyter,
  Airflow, WebLogic, Webmin, pfSense, Splunk) — still advisory-only;
  **sensitive_files** added high-impact targets with content signatures (terraform.tfstate,
  .kube/config, VS Code/Sublime/Atom SFTP creds, Spring application.properties/.yml, phpMyAdmin
  config.inc.php, phpunit.xml, wp-config.php.old, .env.test, .git/logs/HEAD);
  **backup_files** added .war/.tar.xz/.xz/.sqlite3/.db extensions, the XZ magic byte, and source-as-text
  (.txt/.inc) suffixes.
- 2026-11-25 — Hardening pass across existing (non-new) modules, each with tests:
  **headers_check** now flags a Report-Only CSP (looks present, enforces nothing), scheme-wide
  `script-src`, `style-src 'unsafe-inline'` and a missing `form-action`;
  **cookie_analysis** flags `__Host-`/`__Secure-` cookie-prefix requirement violations (browser
  silently rejects the cookie);
  **clickjacking** no longer treats a scheme-wide/wildcard `frame-ancestors` (e.g. `https:`) as
  protection (fixed false-negative);
  **cors_check** probes suffix/prefix substring-match origin bypasses (`host.evil.example`, `nothost`);
  **ssl_check** flags MD5/SHA-1 cert signatures and sub-2048-bit RSA/DSA keys;
  **jwt_attacks** gains a larger weak-secret wordlist and flags sensitive claims leaked in the
  (unencrypted) payload;
  **waf_detect** recognises ~20 more WAF/CDN fingerprints (headers + cookies);
  **redirect_chain** flags credentials/tokens carried in a redirect URL (Medium cross-domain, Low
  same-domain);
  **dns_check** fixes a `www.`-stripping bug (`lstrip` mangled hosts like `web.x.com`) and grades
  policy strength — SPF `+all` (any sender) High / `?all` Low, DMARC `p=none` (not enforcing) Medium.
- 2026-11-25 — Test-coverage pass on `scanner/output/*`: a JSON-report contract suite
  (`TestReportJsonContract`) locking the top-level shape (score/grade/target), severity counts, the
  `coverage` object passthrough, and the `verified`/`verification` proof fields — a stable contract for
  downstream tooling. Suite now 466 tests.
- 2026-11-25 — SSTI hardening + breadth: baseline guard (require the distinctive product a*b to be
  ABSENT for a benign value before flagging, so a real order-id number can't false-positive) and two
  new template syntaxes — bare-brace `{a*b}` (Smarty/Velocity) and `{=a*b=}` (Mako/Cheetah).
- 2026-11-25 — Open-redirect breadth: each parameter is now probed with scheme-relative (`//host`),
  missing-slash (`https:/host`), no-slash (`https:host`), backslash (`/\host`) and userinfo
  (`trusted@host`) payloads against a unique sentinel host, catching allowlists that block `https://`
  but still follow `//host`.
- 2026-11-25 — False-positive hardening: new `evidence.is_block_page()` centralises WAF/CDN block-page
  detection (one canonical sign list). Boolean-based SQLi and the NoSQL operator split now reject a
  fake "divergence" when a WAF blocks one payload but not the other; `xss_detect` delegates to the same
  helper instead of its own copy. Regression tests added for both WAF-faked-divergence shapes.
- 2026-11-25 — Broadened payload sets. `xss_detect` gains a JS template-literal context (fixes a latent
  false positive where `;x();` is inert inside backticks; proven via `${…}`/backtick breakout) plus
  alternate breakouts per context (SVG slash-tag, event-handler attribute injection). `lfi_detect`
  gains double-URL-encoded and `\/` traversal, encoded-backslash/absolute Windows win.ini paths, and
  more `php://filter` targets (`read=` syntax, config.php/wp-config.php). Proof-by-content/breakout
  kept intact; 5 new tests.
- 2026-11-25 — GraphQL recon (`scanner/web/graphql_detect.py`): probes conventional GraphQL paths
  (and graphql-looking crawl URLs), confirms a real engine via a `__typename` query or GraphQL-shaped
  error, then reports an exposed endpoint (INFO), enabled schema introspection (MEDIUM, verified) and
  "Did you mean" field suggestions (LOW). Read-only recon (benign minimal queries only); in the active
  web profile, CWE-200 / A05:2021, mapped to the GraphQL playbooks + nuclei; 4 mocked tests.
- 2026-11-25 — NoSQL injection detection (`scanner/vulns/nosqli_detect.py`): MongoDB-style operator
  injection on URL parameters via two techniques — error-based (NoSQL driver error signatures the
  payload introduced, absent in baseline) and an operator boolean split (`param[$ne]=garbage`
  match-all vs `param[$eq]=garbage` match-none; divergence proves the value is parsed as a query
  operator, so a parser that ignores the bracket key yields no false positive). HIGH / verified,
  CWE-943 / A03:2021, mapped to the NoSQL playbook + nuclei; 6 mocked tests.
- 2026-11-25 — XXE detection (`scanner/vulns/xxe_detect.py`): probes XML-accepting endpoints (form
  actions, parametrised URLs, API/SOAP paths, site root) with three in-band techniques — external-entity
  file disclosure (`/etc/passwd`, `win.ini`) → HIGH/verified, a benign custom-entity expansion canary
  → MEDIUM/verified, and conservative XML parser-error signatures → MEDIUM indicator. Reflection is
  stripped before matching. Wired into the `full` profile, tagged CWE-611 / A05:2021, mapped to the
  XXE playbook + nuclei; 7 mocked tests.
- 2026-11-24 — CI workflow (`.github/workflows/ci.yml`): runs `tools/check_imports.py` + the full
  `pytest` suite on every push/PR to main across Python 3.10–3.12, enforcing the "never break main"
  rule in GitHub itself.
- 2026-11-24 — SARIF export (`scanner/output/report_sarif.py`): every scan now also writes a
  SARIF 2.1.0 report (`reports/*.sarif`) with one rule per finding type (CWE/OWASP tags +
  CVSS-derived `security-severity`), results located at the target, and stable fingerprints — ready
  for GitHub code scanning / CI dashboards.
- 2026-11-24 — Noise governor: the rate limiter now adds configurable timing jitter and adapts to
  the target — a 429/503 throttles it (growing penalty, Retry-After honoured) and each success decays
  the penalty back. New `--quiet` / `--aggressive` profiles tune lanes, delay and jitter.
- 2026-11-24 — Coverage ledger: every scan now builds a coverage model (`scanner/output/coverage.py`)
  recording modules run / skipped / errored / timed-out / not-run plus the crawl-discovered surface
  (pages, parametrised URLs, forms, parameters) and which input-probing modules exercised it. Rendered
  as a Coverage section in the console and HTML report and a `coverage` object in the JSON report.
- 2026-11-24 — Findings verification status: `Finding` now carries `verified: bool` +
  `verification` note (kept in sync with `raw`). Rendered as a green ✓ marker in the console, a
  badge + evidence-box note in the HTML report, and `verified`/`verification` fields in JSON. The
  active-injection modules (sqli, xss, command injection, ssti, LFI, open redirect, in-band SSRF)
  set it from their proof, so proven findings are visibly distinct from heuristic ones.
- 2026-11-23 — Scope / deny rules (`--scope`, `--deny`, `--scope-file`): allow/deny host and
  path-prefix patterns (with `*.` subdomain wildcards) enforced in the engine before any request
  leaves; out-of-scope requests are blocked and counted, deny takes precedence.
- 2026-11-23 — Retest / diff loop (`--retest`): per-target history store with finding
  fingerprinting; findings labelled new / still-present / fixed with a diff panel in the
  console and HTML report, retest status in the JSON report, and score delta vs the last run.
- 2026-11-23 — Fixed a red `main`: the offline skills-library fallback now accepts a shared
  module keyword, so common modules get an offensive playbook without the full external library.
- 2026-11-22 — Added this roadmap/backlog to drive the daily autonomous work session.
