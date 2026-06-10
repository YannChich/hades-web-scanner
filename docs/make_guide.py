"""Generate the Hades Modules Guide PDF — every module explained simply, with the
consequence of a finding and the type of attack it enables (beginner-friendly, English)."""
from __future__ import annotations

from datetime import date
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, KeepTogether, PageBreak,
    PageTemplate, Paragraph, Spacer, Table, TableStyle,
)

_OUT = Path(__file__).resolve().parent / "Hades_Modules_Guide.pdf"

RED = colors.HexColor("#b3122a")
DARKRED = colors.HexColor("#7a0d1c")
INK = colors.HexColor("#1c1c1c")
GREY = colors.HexColor("#555555")
LIGHT = colors.HexColor("#f4f1f2")
CYAN = colors.HexColor("#0b6e75")
GREEN = colors.HexColor("#0a7d3b")
ORANGE = colors.HexColor("#b5630a")

styles = getSampleStyleSheet()
H_TITLE = ParagraphStyle("HTitle", parent=styles["Title"], fontName="Helvetica-Bold",
                         fontSize=46, textColor=RED, spaceAfter=6, leading=50)
H_SUB = ParagraphStyle("HSub", parent=styles["Normal"], fontSize=13, textColor=GREY,
                       alignment=TA_CENTER, spaceAfter=4)
CAT = ParagraphStyle("Cat", parent=styles["Heading1"], fontName="Helvetica-Bold",
                     fontSize=20, textColor=colors.white, backColor=RED,
                     borderPadding=(6, 8, 6, 8), spaceBefore=8, spaceAfter=14, leading=24)
MOD = ParagraphStyle("Mod", parent=styles["Heading2"], fontName="Helvetica-Bold",
                     fontSize=13.5, textColor=DARKRED, spaceBefore=4, spaceAfter=1, leading=16)
MODSUB = ParagraphStyle("ModSub", parent=styles["Normal"], fontSize=9.5, textColor=CYAN,
                        fontName="Helvetica-Oblique", spaceAfter=5)
BODY = ParagraphStyle("Body", parent=styles["Normal"], fontSize=10, textColor=INK,
                      leading=14, spaceAfter=2.5, alignment=TA_LEFT)
NOTE = ParagraphStyle("Note", parent=styles["Normal"], fontSize=9, textColor=GREY,
                      leading=12.5, spaceAfter=3, leftIndent=6, backColor=LIGHT,
                      borderPadding=(4, 5, 4, 5))
LEAD = ParagraphStyle("Lead", parent=styles["Normal"], fontSize=11, textColor=INK,
                      leading=16, spaceAfter=8)
H2 = ParagraphStyle("H2b", parent=styles["Heading2"], fontSize=15, textColor=DARKRED,
                    spaceBefore=6, spaceAfter=8)


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def module(name, title, checks, consequence, attack, note=None):
    """One module card: what it checks, the consequence of a finding, the attack it enables."""
    e = [Paragraph(esc(name), MOD), Paragraph(esc(title), MODSUB),
         Paragraph(f'<b><font color="#0b6e75">What it checks:</font></b> {esc(checks)}', BODY),
         Paragraph(f'<b><font color="#b5630a">Consequence of a finding:</font></b> {esc(consequence)}', BODY),
         Paragraph(f'<b><font color="#b3122a">Possible attack:</font></b> {esc(attack)}', BODY)]
    if note:
        e.append(Paragraph(f"<b>Good to know:</b> {esc(note)}", NOTE))
    e.append(Spacer(1, 9))
    return KeepTogether(e)


# ===========================================================================
# 1 · RECONNAISSANCE  (11 modules)
# ===========================================================================
RECON = [
    module("basic_info", "Target Fingerprint",
        "Makes a first request and records the essentials: IP address, web-server software, load time, page title, and a guess of the operating system from the network TTL value.",
        "On its own harmless, but it is the attacker's very first step — knowing the server and OS narrows down which known weaknesses to try.",
        "Reconnaissance / fingerprinting — the groundwork for every targeted exploit that follows.",
        "Everything here is INFO and never lowers your score — it is context, not a problem."),
    module("whois_lookup", "Domain Registration Lookup",
        "Queries public WHOIS databases for who registered the domain, its creation/expiry dates and name servers (skips meaningless platform sub-domains).",
        "A domain about to expire can be lost and re-registered by anyone; registration details feed convincing social engineering.",
        "Domain hijacking (on expiry) and targeted phishing using real registration data.",
        "An expiry date that is very close is flagged because an expired domain can be taken over."),
    module("dns_check", "Email Security Records (DNS)",
        "Looks up the DNS records that protect email — SPF, DKIM, DMARC — and the MX mail servers.",
        "Missing SPF/DMARC means nothing proves an email truly came from your domain, so anyone can forge it.",
        "Email spoofing, phishing and CEO-fraud sent from your own domain name — one of the most common real-world weaknesses.",
        "Missing SPF/DMARC does not break the website, but it lets criminals impersonate your email address."),
    module("ssl_check", "TLS / Certificate Inspector",
        "Examines the HTTPS certificate: issuer, TLS version, days until expiry, and whether the site is served over plain HTTP with no encryption at all.",
        "No HTTPS exposes all traffic (passwords included) to anyone on the network; an expired certificate breaks trust and warns visitors away.",
        "Man-in-the-middle interception and traffic tampering on shared/public networks.",
        "A certificate expiring soon is flagged early so it can be renewed before browser warnings appear."),
    module("port_scan", "TCP Port Scanner",
        "Opens connections to ~26 common service ports (databases, RDP/VNC/SSH, web, mail) and grabs a banner to confirm the service; first probes random ports to detect an 'accept-all' host.",
        "An exposed database or remote-desktop port is a direct doorway into the server that should never face the internet.",
        "Brute-force of the exposed service, or exploitation of the service to take over the host.",
        "If the host answers EVERY port (firewall/honeypot), Hades reports one 'unreliable' note instead of dozens of fake open ports."),
    module("waf_detect", "Firewall / CDN Detection",
        "Inspects headers and behaviour to spot a protective layer (Cloudflare, Akamai, AWS, Fastly…) in front of the site.",
        "Confirms a defence layer exists; for an attacker it signals that payloads may be filtered.",
        "Drives WAF-bypass techniques (encoding, fragmentation) so injections still get through.",
        "A WAF is good news — but it also explains why other modules may get blocked (403s) during a scan."),
    module("tech_stack", "Technology Fingerprint",
        "Reads headers, HTML, scripts and cookies to identify the web server, language, frameworks, JS libraries and CMS — with version numbers when visible.",
        "Version numbers are gold: an old component with a published vulnerability is often exploitable with a ready-made tool.",
        "Targeted exploitation of a known CVE in an identified, out-of-date component (this module feeds the CVE lookup).",
        "Hiding version tokens (Server, X-Powered-By) makes an attacker's job noticeably harder."),
    module("js_recon", "JavaScript Secret & Endpoint Miner",
        "Downloads the site's JavaScript and mines it for leaked secrets (AWS/Google/Stripe/GitHub/Slack keys, private keys) and hidden API endpoints not linked anywhere on the page.",
        "A leaked key is an instant credential; hidden endpoints expose un-advertised, often less-protected functionality.",
        "Direct use of a stolen API key, and attacks against internal/admin API endpoints discovered in the code.",
        "Front-end JavaScript is fully public — never put a real secret or a private endpoint in it."),
    module("cloud_buckets", "Open Cloud Bucket Finder",
        "Derives likely S3 / Google Cloud Storage / Azure Blob bucket names from the target and checks whether they exist and are world-readable or listable.",
        "An open bucket can expose backups, user uploads, documents or source — sometimes the entire data store of a company.",
        "Data from cloud storage (MITRE T1530): anyone downloads or lists the bucket's contents directly.",
        "Buckets must be private by default; a single mis-set permission has caused many of the largest breaches."),
    module("git_dumper", "Exposed .git Repository Extractor",
        "Detects a publicly reachable /.git/ folder and extracts its metadata — remote URLs, committer emails and the tracked-file list.",
        "An exposed .git lets an attacker reconstruct your entire source code and read its history — including secrets that were committed and 'deleted'.",
        "Full source-code disclosure, then targeted exploitation and harvesting of any hard-coded credentials from history.",
        "Block access to .git in the web server, or deploy from outside the web root."),
    module("wayback", "Wayback / Archive URL Miner",
        "Pulls historical URLs and parameters for the domain from the Internet Archive (no traffic to the live site).",
        "Old, forgotten or removed pages and parameters reappear — often still working and less protected than current ones.",
        "Attack-surface expansion: probing archived endpoints/parameters for injection and access-control flaws.",
        "Passive recon — it queries the archive, not your server, so it is invisible to your logs."),
]

# ===========================================================================
# 2 · WEBSITE & MISCONFIGURATION  (20 modules)
# ===========================================================================
WEB = [
    module("headers_check", "HTTP Security Headers Audit",
        "Checks the response headers browsers use to enforce security — CSP (directive by directive), HSTS, X-Frame-Options, the cross-origin headers — and flags headers that leak versions.",
        "Missing headers remove browser-side defences, making other attacks far easier to land.",
        "No CSP → easier XSS; no HSTS → downgrade attacks; no X-Frame-Options → clickjacking.",
        "These are hardening gaps (mostly Medium): rarely exploitable alone, but they amplify everything else."),
    module("robots_txt", "robots.txt Analyzer",
        "Reads /robots.txt, classifies each disallowed path (admin, backups, .git…), then actively visits the sensitive ones to see if they are really reachable.",
        "robots.txt lists hidden paths in clear text — handing attackers a map of your sensitive areas.",
        "Direct access to a disallowed-but-reachable path (admin, backup, config).",
        "A path that returns 404 is a stale leftover; one that returns 200 is a real, reachable target."),
    module("sitemap", "Sitemap Parser",
        "Finds and reads XML sitemaps (including ones declared in robots.txt), follows sitemap indexes one level deep and flags any sensitive URL advertised.",
        "A sitemap that lists internal or admin URLs gives attackers a curated target list with zero guessing.",
        "Direct navigation to interesting endpoints surfaced by the sitemap.",
        "Sitemaps are meant to be public; the concern is only when they expose URLs that should stay private."),
    module("cms_detect", "CMS Detection",
        "Fingerprints the content-management system (WordPress, Joomla, Drupal, Magento…) and its version when possible.",
        "Each CMS has a huge catalogue of known plugin/theme vulnerabilities tied to specific versions.",
        "Picking a matching public exploit for the detected CMS/plugin version.",
        "WordPress powers a large share of the web and is the most-attacked CMS, so detecting it matters."),
    module("admin_panel", "Admin / Login Panel Finder",
        "Probes known admin paths and verifies by page content whether each is really a login or admin interface (not just a status code).",
        "An exposed admin panel is a prime target; one reachable without logging in can be instant full compromise.",
        "Brute-force / credential-stuffing against the panel, or direct use of an unauthenticated admin UI.",
        "Content verification means only genuine login/admin pages are reported, not every page on a catch-all site."),
    module("dir_scan", "Directory & Path Brute-Forcer",
        "Requests a wordlist of common paths to discover what exists, distinguishing open listings, normal paths, auth-protected (401), forbidden (403) and redirects.",
        "Discovered admin areas, backups or config folders are new entry points; an open listing exposes every file.",
        "Forced browsing to hidden functionality and direct download of exposed files.",
        "Smart baselines collapse the noise: if the server answers the same to everything, Hades reports one note instead of hundreds of fake hits."),
    module("subdomain_scan", "Subdomain Enumeration & Takeover",
        "Discovers sub-domains actively (DNS brute-force) and passively (Certificate Transparency / crt.sh), then checks each for a dangling-DNS takeover.",
        "Forgotten sub-domains widen the attack surface; a takeover lets an attacker host their own content on YOUR sub-domain.",
        "Subdomain takeover for convincing phishing, plus attacks on weaker dev/staging hosts.",
        "A wildcard-DNS check prevents false positives where every name resolves to the same address."),
    module("broken_links", "Broken Link Checker",
        "Checks the status of every crawled link and classifies it — dead (404/410), server error (5xx), access-controlled (401/403) or rate-limited (429).",
        "Dead links hurt usability/SEO; a wall of 403s usually means a WAF is blocking the scan, not broken links.",
        "Minimal direct attack value; mainly hygiene and WAF-behaviour insight.",
        "A 403 means 'forbidden', NOT 'broken' — the page likely works fine in a real browser."),
    module("http_methods", "HTTP Methods Auditor",
        "Discovers which HTTP verbs the server accepts and actively verifies the dangerous ones — a safe PUT upload read back, a TRACE echo check (DELETE is advertised-only, never tested).",
        "A confirmed PUT upload is critical; a real TRACE echo can be used to steal headers.",
        "Web-shell upload via PUT (then remote code execution), or Cross-Site Tracing (XST) via TRACE.",
        "Only a method proven to work is rated High/Critical; active write tests are skipped in safe mode."),
    module("backup_files", "Backup & Source File Hunter",
        "Looks for backups derived from the target — archive names from the hostname, common backup names, and editor backups of real pages (index.php~, config.php.bak, .swp), confirmed by magic bytes.",
        "A downloadable backup often contains the full source code, a database dump and hard-coded passwords — in one file.",
        "Direct download of source/secrets, leading to full compromise.",
        "It confirms a real archive by content, so an HTML 'not found' page is never mistaken for a backup."),
    module("sensitive_files", "Sensitive File Exposure",
        "Probes well-known paths that expose secrets — .env, .git, cloud credentials, SSH keys, framework configs, database dumps — with content checks to avoid false positives.",
        "A readable .env or .git can leak database passwords, API keys and the entire source code.",
        "Credential theft from config files, then direct database/server access.",
        "If the server blocks every sensitive path (a good deny-all rule), Hades reports one positive note instead of many false alarms."),
    module("cookie_analysis", "Cookie Security Flags",
        "Inspects the cookies the site sets for the Secure, HttpOnly and SameSite flags (and prefixes like __Host-).",
        "A session cookie missing these flags is far easier to steal or abuse.",
        "Session theft via XSS (no HttpOnly), leakage over HTTP (no Secure), or CSRF (no SameSite).",
        "These flags are the difference between an XSS bug being annoying and being account-takeover."),
    module("redirect_chain", "Redirect Chain Auditor",
        "Follows the redirect chain from the target URL and flags HTTPS→HTTP downgrades, off-domain redirects, a missing HTTP→HTTPS upgrade and over-long chains.",
        "A downgrade exposes traffic; an off-domain redirect makes a malicious link look like it starts on your trusted site.",
        "Traffic interception (downgrade) and phishing via open redirect.",
        "A clean single HTTP-to-HTTPS redirect is exactly what you want to see."),
    module("email_exposure", "Exposed Email Finder",
        "Collects email addresses from mailto links and page text across the crawl, separating on-domain from third-party addresses.",
        "Published addresses fuel spam and targeted social engineering; an on-domain one is a direct spear-phishing target.",
        "Spear-phishing of named staff and harvesting for credential-stuffing.",
        "Use contact forms or obfuscation instead of publishing mailboxes in plain text."),
    module("favicon_hash", "Favicon Fingerprint",
        "Computes a hash of the browser-tab icon (the way Shodan does) so identical icons can be searched across the internet.",
        "Identical favicon hashes quietly reveal shared frameworks, hidden panels or related infrastructure.",
        "Asset discovery — mapping an organisation's other servers/panels by their shared icon.",
        "A default framework favicon tells the world what software you run; a custom icon avoids that."),
    module("cors_check", "CORS Misconfiguration",
        "Sends a crafted Origin header to test whether the server reflects any origin AND allows credentials (the dangerous combination).",
        "A permissive policy lets a malicious site read a logged-in victim's authenticated responses from your site.",
        "Cross-origin data theft on behalf of an authenticated victim.",
        "'Allow-Origin: *' is usually fine; reflecting the caller's origin WITH credentials is the real danger."),
    module("clickjacking", "Clickjacking Verdict",
        "Combines X-Frame-Options and CSP frame-ancestors into one 'framable?' answer, weighting risk by whether the page has a login or other forms.",
        "A framable sensitive page can be hidden under a decoy to steal clicks.",
        "Clickjacking — tricking users into clicking real buttons (change settings, confirm actions) through an invisible frame.",
        "A framable page with no interactive elements is low impact; one with a login form is high."),
    module("dir_listing", "Open Directory Listing",
        "Detects folders whose entire contents are publicly browsable (the 'Index of /' page), checking crawled folders plus common upload/asset/backup paths.",
        "An open listing hands attackers a full inventory of files — often backups or documents never meant to be public.",
        "Direct browsing and download of every file in the exposed folder.",
        "It reuses the crawler's findings, so it tests folders that actually exist rather than guessing."),
    module("blacklist_check", "Reputation / Blocklist Check",
        "Checks the IP and domain against public DNS blocklists (Spamhaus, SpamCop, Barracuda) using the standard key-free protocol.",
        "Being listed signals past spam/malware — or a current compromise — and badly hurts email deliverability.",
        "Not an attack — an early warning that the server may already be hacked or abused.",
        "Behind a CDN the checked IP is the shared edge, so a clean result there means less."),
    module("screenshot", "Homepage Screenshot",
        "Opens the homepage in a real headless browser (Chromium) and saves a full-page PNG to screenshots/.",
        "Gives a human a quick visual of the target — useful for triage across many sites.",
        "Not an attack — pure situational awareness.",
        "If the browser engine is missing it self-heals or fails gracefully, never breaking the scan."),
]

# ===========================================================================
# 3 · VULNERABILITY DETECTION  (13 modules)
# ===========================================================================
VULNS = [
    module("sqli_detect", "SQL Injection Detection",
        "Injects test payloads into URL/form parameters using three techniques — error-based, boolean-blind (TRUE vs FALSE behave differently) and time-based blind (a SLEEP that makes the page hang for a scaling delay).",
        "SQL injection reaches the database directly: dumping all users and passwords, bypassing logins, sometimes taking over the server.",
        "Database exfiltration, authentication bypass, and (with file/OS privileges) remote code execution.",
        "It detects, it does not dump; on a hit it shows a ready sqlmap command and can launch it with --exploit. Skipped in safe mode."),
    module("xss_detect", "Cross-Site Scripting (XSS) — reflected, stored & DOM-based",
        "Three passes: (1) reflected — find where a marker is reflected (HTML, attribute, JS, comment) and send a context-specific breakout; (2) stored — submit a form, then re-check display pages for the value, not just the submission's own response; (3) DOM-based — an optional headless-browser pass that submits a benign payload and confirms it actually executes when the page renders it with client-side JavaScript (innerHTML), which never shows in the server response.",
        "XSS runs the attacker's JavaScript in a victim's browser — whether the value is reflected, saved and shown to others, or written into the page by client-side code.",
        "Session-cookie theft, actions performed as the victim, page defacement — account takeover when cookie flags are weak.",
        "Context analysis keeps it credible (encoded = Low, real breakout = High); the browser pass needs Playwright + Chromium and degrades to a hint if absent."),
    module("command_injection", "OS Command Injection",
        "Injects shell separators and commands (;id, | whoami, & dir, sleep) and confirms either by the command's OUTPUT appearing, or by a sleep that makes the response hang for a scaling delay.",
        "The attacker runs arbitrary operating-system commands on the server.",
        "Total server compromise — read/modify any file, install a backdoor, pivot into the internal network.",
        "Verified not guessed (a delay that scales rules out a slow page); a commix command is attached. Skipped in safe mode."),
    module("ssti_detect", "Server-Side Template Injection (SSTI)",
        "Injects a distinctive maths expression in every template syntax ({{7*7}}, ${7*7}, <%=7*7%>, #{7*7}) and flags it only if the server returns the COMPUTED result instead of the literal text.",
        "The input is evaluated by the template engine — code, not text.",
        "Usually remote code execution: reading secrets/files or taking over the server through the engine.",
        "Large numbers make a coincidence impossible; the firing syntax fingerprints the engine. A tplmap command is attached."),
    module("lfi_detect", "Local File Inclusion / Path Traversal",
        "Requests well-known system files via traversal payloads (../../../etc/passwd, ..\\windows\\win.ini, PHP filter wrappers) and confirms by the file's actual content.",
        "The attacker reads arbitrary server files — configuration, source code, credentials.",
        "Sensitive-file disclosure, chaining to remote code execution via log/session poisoning.",
        "Confirmed by file content, never by guesswork, so false positives are rare."),
    module("open_redirect", "Open Redirect",
        "Injects a unique external URL into redirect-style parameters (url, next, return…) and flags when the server forwards the user to that external host (Location, meta refresh or JS).",
        "A link that starts on your trusted domain lands on the attacker's site.",
        "Phishing that abuses your domain's trust, and bypassing redirect allowlists in login/OAuth flows.",
        "Severity rises to High when the parameter drives an authentication flow."),
    module("ssrf_detect", "Server-Side Request Forgery (SSRF)",
        "Injects internal and cloud-metadata URLs (127.0.0.1, 169.254.169.254, file://) into URL-shaped parameters and flags responses containing content only the server could fetch.",
        "The server makes requests on the attacker's behalf.",
        "Cloud-credential theft from the metadata service, internal network scanning, reaching never-exposed admin panels.",
        "In-band only — truly blind SSRF is caught by the oob_scan profile (out-of-band callbacks)."),
    module("jwt_attacks", "JSON Web Token (JWT) Attacks",
        "Finds JWTs (in cookies/headers) and tests them: the 'alg:none' unsigned-token trick, cracking a weak HMAC secret against a wordlist, and reading sensitive data from the claims.",
        "A forgeable or crackable token lets the attacker mint their own valid sessions.",
        "Authentication bypass and privilege escalation by forging a token (e.g. becoming admin).",
        "Sign tokens with a strong secret/asymmetric key and reject the 'none' algorithm server-side."),
    module("auth_bypass", "Access-Control Bypass (401/403)",
        "Re-requests forbidden paths with bypass tricks — path mutations (//, /./, %2e), spoofed headers (X-Original-URL, X-Forwarded-For) and HTTP verb tampering.",
        "A protected page becomes reachable without proper authorisation.",
        "Broken access control — viewing or using admin/internal functionality you should not reach.",
        "Enforce authorisation in the application, not at the proxy/header layer."),
    module("idor_detect", "IDOR / BOLA (Broken Object-Level Access)",
        "Tampers object-reference ids found in URL parameters and path segments (e.g. ?id=1 → 2, /invoice/1001) and compares responses; when scanning authenticated, it also re-fetches objects without the session to prove they are served with no access control.",
        "One user can read or modify another user's objects — accounts, invoices, messages — just by changing an id.",
        "Horizontal/vertical privilege escalation and bulk data harvesting by enumerating ids.",
        "JSON-aware and noise-calibrated to avoid false positives; interactive menu option 11 auto-finds the login page so it can run authenticated with just your credentials."),
    module("bruteforce", "Credential Spraying (opt-in)",
        "With the --bruteforce flag only, sprays a small list of common credentials against discovered login forms and HTTP Basic-Auth.",
        "A weak or default password opens a real account.",
        "Account takeover via brute-force / password spraying.",
        "Off by default and intrusive — only run it against systems you own or are explicitly authorised to test."),
    module("cve_mapping", "Known Vulnerability (CVE) Lookup",
        "Takes the versions found by tech_stack and asks the official NVD database for matching CVEs, with their CVSS severity score.",
        "A matching CVE often means a ready-made exploit already exists for your component.",
        "Direct exploitation of a public vulnerability in an outdated component.",
        "Set an NVD_API_KEY environment variable for a higher rate limit and more complete results."),
    module("default_creds", "Default Credentials Advisory",
        "Fingerprints interfaces famous for default passwords (phpMyAdmin, Tomcat Manager, Jenkins, Grafana…) and lists their documented defaults — without ever logging in.",
        "If a default password was never changed, anyone who finds the panel walks straight in.",
        "Instant access using documented default logins (admin/admin, tomcat/tomcat…).",
        "By design it never submits credentials — verify manually on your own systems."),
]

# ===========================================================================
# 4 · RED-TEAM PROFILES  (dedicated, deeper modules)
# ===========================================================================
DB = [
    module("db_scan", "Red-Team Database Security Audit",
        "A dedicated profile that scans database ports, fingerprints each engine (MySQL, PostgreSQL, MSSQL, Mongo, Redis, Elasticsearch, CouchDB…), tests for password-less access, and probes parameters for SQL and NoSQL injection.",
        "An open, unauthenticated database is an instant full data breach; an exposed Redis CONFIG becomes a server takeover.",
        "Direct data exfiltration, NoSQL auth-bypass on logins, and Redis→RCE (web shell / SSH key / cron).",
        "With --exploit it proves impact — pulls real Redis values / ES & CouchDB docs, an in-band SQLi banner — and writes evidence to loot/. Safe mode skips destructive checks."),
    module("db_scan — leak hunting", "Secrets, Connection Strings & Admin GUIs",
        "Hunts database credentials that leak through the site itself: secret/config files (.env, database.yml, my.cnf, wp-config.php…), hard-coded connection strings in page/JS, GraphQL introspection, exposed admin GUIs and SQL/SQLite dumps.",
        "A readable .env or a leaked connection string IS the password; an exposed admin GUI or dump is a one-click breach.",
        "Credential harvesting then direct database login; schema disclosure via GraphQL introspection.",
        "Every credential shown is masked — treat any leaked secret as compromised and rotate it immediately."),
    module("db_scan — score, attack path & loot", "Exploitation Plan & Extracted Data",
        "Assembles the result into a DB Exposure Score (0-100 + grade), an ordered Attack Path of copy-paste exploitation commands (sqlmap, redis-cli, curl…), each tagged with MITRE ATT&CK, and a Loot summary of data actually pulled.",
        "Turns a list of findings into an actionable engagement an operator can reproduce command by command.",
        "Full red-team exploitation workflow against the data tier, with evidence.",
        "Opt-in and authorisation-gated — Hades shows the commands; it only runs sqlmap when you pass --exploit and confirm."),
]

AI = [
    module("ai_scan", "AI / LLM Security Audit",
        "A dedicated profile that audits the AI layer most scanners ignore: it fingerprints LLM SDKs/providers, hunts exposed AI API keys (sk-ant-…, sk-…, hf_…), finds unauthenticated local LLM servers (Ollama, LM Studio, vLLM…) and exposed AI dev UIs, and locates the prompt-injection surface.",
        "A leaked AI key means billing theft and data access; an open LLM server means free inference and model theft; a live chat endpoint means the model can be manipulated.",
        "Prompt injection (the model obeys attacker instructions), sensitive-information disclosure, and unbounded-consumption (cost) attacks — mapped to OWASP LLM Top 10 & MITRE ATLAS.",
        "With --exploit it sends a benign canary to actively confirm prompt injection. Detection-only by default."),
    module("ai_scan — prompt injection", "The New Attack Surface",
        "Detects endpoints where user input reaches a language model and, in active mode, sends a harmless canary instruction ('reply with this token') to see if the model obeys it.",
        "If the model follows injected instructions, an attacker can override its system prompt, exfiltrate data it can see, or bypass its safety rules.",
        "LLM prompt injection (MITRE ATLAS AML.T0051) and system-prompt leakage (OWASP LLM07).",
        "Isolate system instructions from user input, constrain and validate model output, and add guardrails."),
]

ENGAGE = [
    module("engage", "Active Exploitation Engagement (auto-pwn)",
        "A dedicated offensive profile that first reuses the injection arsenal to confirm bugs, then — once you authorise it — actively proves impact with BENIGN payloads: runs id/uname (RCE proof), reads /etc/passwd (LFI), pulls cloud metadata (SSRF), writing evidence files to loot/.",
        "It converts 'a vulnerability probably exists' into 'here is the proven foothold' — a confirmed foothold is a breach.",
        "Real exploitation of command injection, file inclusion and SSRF, captured as evidence (no destructive actions, no persistence, no DoS).",
        "Exploitation-first: choosing the profile asks for authorisation (or pass --exploit). SQL injection still goes through the sqlmap launcher."),
]

OOB = [
    module("oob_scan", "Out-of-Band / Blind Vulnerabilities (OAST)",
        "A dedicated profile that catches the bugs which leave NO trace in the HTTP response, by making the server call back to a self-hosted listener. It injects unique-token callback URLs for blind SSRF, blind OS command injection and blind/stored XSS.",
        "Blind bugs are invisible to ordinary scanners yet just as dangerous — and often missed entirely.",
        "Blind SSRF (internal/cloud access), blind RCE (server takeover) and blind/stored XSS — confirmed out-of-band.",
        "Works behind NAT: if cloudflared (free, no account) or ngrok is installed Hades auto-opens a public tunnel; otherwise use --oob-host. A callback's source IP is the target itself."),
]

CVE = [
    module("cve_scan", "CVE Vulnerability Intelligence (menu option 8)",
        "A dedicated profile that fingerprints the target's stack broadly — Server / X-Powered-By headers, tech_stack (JS/CSS/CMS/framework signatures with versions), cms_detect, and SSH/FTP/mail/DB service banners from a port scan — normalises each product to a CPE, and matches real CVEs from a local vulnerability database.",
        "Knowing exactly which published CVEs affect the detected versions turns 'old software' into a concrete, prioritised exploit list.",
        "Maps detected products + versions to known CVEs (nginx, OpenSSH, jQuery, WordPress, Apache, MySQL…), classified CONFIRMED / LIKELY / POSSIBLE by version match.",
        "100% free, no API key: a local SQLite DB built from CISA KEV + FIRST EPSS, with NVD 2.0 queried on demand. Only CVEs from 2020 onward are reported (older ones are filtered out)."),
    module("cve_scan — prioritisation", "KEV + EPSS Priority Score",
        "Ranks every matched CVE by a Hades CVE Priority Score (0-100) fusing CVSS severity, FIRST EPSS exploit probability, and whether the CVE is in the CISA KEV catalog (actively exploited in the wild), plus internet exposure and match confidence.",
        "Hundreds of CVEs are noise; the score surfaces the handful that are genuinely exploitable right now.",
        "Focuses the operator on actively-exploited, high-probability CVEs first, instead of raw CVSS alone.",
        "Unknown-version products show only the top 10 CVEs (by KEV / EPSS / CVSS) to control noise."),
    module("cve_scan — offline corpus", "Full Local NVD Database",
        "Run tools/build_vulndb.py once to bulk-load the entire NVD corpus (~270k CVEs) into the local SQLite DB. The scan then matches completely offline with no per-product network calls, and the database refreshes incrementally afterwards.",
        "A complete local CVE bank means exhaustive, fast, repeatable matching even with no internet during the engagement.",
        "Offline CVE matching across the full NVD dataset; an optional free NVD_API_KEY speeds the one-time build ~10x.",
        "Detection-only intelligence — it reports exposure, it never exploits."),
]

TLS = [
    module("tls_scan", "Offensive TLS/SSL Attack Surface (menu option 9)",
        "A dedicated profile driven by the SSLyze handshake engine. It negotiates TLS the way an attacker probes it and flags legacy protocols (SSLv2/SSLv3, TLS 1.0/1.1), weak/anonymous/NULL cipher suites, missing forward secrecy, certificate trust/expiry/hostname/weak-signature problems, TLS compression (CRIME), and insecure renegotiation.",
        "Transport-layer crypto is what protects every credential and cookie in transit; a downgrade or weak cipher quietly undoes all of it.",
        "Enables on-path downgrade attacks, traffic decryption/sniffing and adversary-in-the-middle (MITRE T1557 / T1040), mapped to CWE-326 / CWE-295 and OWASP A02:2021.",
        "Handshake-only and read-only — no exploitation, brute force, DoS or interception. SSLyze is an optional dependency; the module degrades gracefully if it is missing."),
    module("tls_scan — known TLS vulns", "Heartbleed · ROBOT · CCS Injection",
        "Beyond configuration, it runs SSLyze's safe handshake probes for the high-impact TLS vulnerability classes: Heartbleed (CVE-2014-0160), ROBOT (RSA padding oracle), and the OpenSSL ChangeCipherSpec injection flaw (CVE-2014-0224).",
        "These are the bugs that leak private keys or let an attacker decrypt sessions outright — the difference between 'weak' and 'owned'.",
        "Heartbleed leaks process memory (keys/cookies) → Critical; ROBOT/CCS enable RSA decryption / AitM → High.",
        "Each finding includes attacker impact, technical evidence and references, and identifies the strongest supported and weakest accepted configuration."),
]

OUTPUT = [
    module("scorer", "Security Score & Grade",
        "Turns all findings into a single 0-100 score and an A-F grade, subtracting points by severity with diminishing returns per module and a confidence weighting.",
        "Your at-a-glance health indicator — a low grade means several real, actionable issues were found.",
        "Not an attack — a prioritisation aid for defenders.",
        "INFO findings are context only and NEVER affect the grade; the score reflects genuine problems (Low and above)."),
    module("HTML report references", "Clickable Framework Badges",
        "Every finding in the auto-generated HTML report carries reference badges — the CVE, CVSS, CWE, OWASP category, MITRE ATT&CK technique, the relevant RedTeam tool and the matched playbook. Each badge is a link to its canonical explanation page (NVD, the FIRST CVSS calculator, cwe.mitre.org, owasp.org, attack.mitre.org).",
        "One click takes you from a finding to the authoritative definition of the weakness or technique — no copy-pasting IDs into a search engine.",
        "A learning and triage aid: understand and verify every finding in context.",
        "Badges open in a new browser tab; the playbook badge opens the full step-by-step skill."),
]


def build():
    doc = BaseDocTemplate(str(_OUT), pagesize=A4,
                          leftMargin=18 * mm, rightMargin=18 * mm,
                          topMargin=16 * mm, bottomMargin=16 * mm,
                          title="Hades — Modules Guide", author="Hades")
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="main")

    def footer(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(GREY)
        canvas.drawString(doc.leftMargin, 10 * mm, "Hades — Web Security Scanner · Module guide")
        canvas.drawRightString(A4[0] - doc.rightMargin, 10 * mm, f"Page {d.page}")
        canvas.restoreState()

    doc.addPageTemplates([PageTemplate(id="main", frames=[frame], onPage=footer)])

    story = []
    # Cover
    story.append(Spacer(1, 50 * mm))
    story.append(Paragraph("HADES", H_TITLE))
    story.append(Paragraph("Web Security Scanner", H_SUB))
    story.append(Paragraph("Every Module Explained — Plain &amp; Simple", H_SUB))
    story.append(Spacer(1, 8 * mm))
    disclaimer = ("<b>For authorised security testing only.</b> Scanning systems without explicit "
                  "written permission is illegal. For each of the 44 scan modules — and the dedicated "
                  "Database, AI/LLM, Engagement, Out-of-Band, CVE Intelligence and TLS profiles — this guide "
                  "explains, in plain language: <b>what it checks</b>, the <b>consequence of a finding</b>, "
                  "and the <b>type of attack</b> it enables.")
    story.append(Table([[Paragraph(disclaimer, BODY)]], colWidths=[doc.width - 20 * mm],
                       style=TableStyle([("BOX", (0, 0), (-1, -1), 1, RED),
                                         ("BACKGROUND", (0, 0), (-1, -1), LIGHT),
                                         ("LEFTPADDING", (0, 0), (-1, -1), 10),
                                         ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                                         ("TOPPADDING", (0, 0), (-1, -1), 8),
                                         ("BOTTOMPADDING", (0, 0), (-1, -1), 8)])))
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph(f"Generated {date.today().isoformat()}", H_SUB))
    story.append(PageBreak())

    # How to read
    story.append(Paragraph("How to read this guide", H2))
    story.append(Paragraph(
        "Hades runs many small <b>modules</b>, each checking one thing about a website. Every module "
        "card below has the same three parts: "
        "<b><font color='#0b6e75'>What it checks</font></b> (in plain words), "
        "<b><font color='#b5630a'>Consequence of a finding</font></b> (what is at risk), and "
        "<b><font color='#b3122a'>Possible attack</font></b> (how it is abused). No prior knowledge "
        "needed — terms are explained as they appear.", LEAD))
    story.append(Paragraph("Severity levels", H2))
    sev = [["Level", "Meaning"],
           ["INFO", "Just information / context. Never affects the score."],
           ["LOW", "Minor hardening gap; little direct risk on its own."],
           ["MEDIUM", "Worth fixing; helps attackers or leaks information."],
           ["HIGH", "Serious; a likely path to compromise."],
           ["CRITICAL", "Severe; often a direct way in (secrets, code execution)."]]
    t = Table(sev, colWidths=[28 * mm, doc.width - 28 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), RED),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(t)
    story.append(PageBreak())

    for heading, mods in [("1 · Reconnaissance Modules (11)", RECON),
                          ("2 · Website &amp; Misconfiguration Modules (20)", WEB),
                          ("3 · Vulnerability Detection Modules (13)", VULNS),
                          ("4 · Database Security Audit — db_scan", DB),
                          ("5 · AI / LLM Security — ai_scan", AI),
                          ("6 · Active Engagement — engage", ENGAGE),
                          ("7 · Out-of-Band / Blind Vulns — oob_scan", OOB),
                          ("8 · CVE Vulnerability Intelligence — cve_scan", CVE),
                          ("9 · TLS / SSL Attack Surface — tls_scan", TLS),
                          ("10 · Scoring &amp; Output", OUTPUT)]:
        story.append(Paragraph(heading, CAT))
        story.extend(mods)
        story.append(PageBreak())

    doc.build(story)
    print(f"{_OUT} written")


if __name__ == "__main__":
    build()
