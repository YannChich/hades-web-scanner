"""Generate the Hades Modules Guide PDF (beginner-friendly, English)."""
from __future__ import annotations

from datetime import date

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, KeepTogether, NextPageTemplate, PageBreak,
    PageTemplate, Paragraph, Spacer, Table, TableStyle,
)

RED = colors.HexColor("#b3122a")
DARKRED = colors.HexColor("#7a0d1c")
INK = colors.HexColor("#1c1c1c")
GREY = colors.HexColor("#555555")
LIGHT = colors.HexColor("#f4f1f2")
CYAN = colors.HexColor("#0b6e75")

styles = getSampleStyleSheet()
H_TITLE = ParagraphStyle("HTitle", parent=styles["Title"], fontName="Helvetica-Bold",
                         fontSize=46, textColor=RED, spaceAfter=6, leading=50)
H_SUB = ParagraphStyle("HSub", parent=styles["Normal"], fontSize=13, textColor=GREY,
                       alignment=TA_CENTER, spaceAfter=4)
CAT = ParagraphStyle("Cat", parent=styles["Heading1"], fontName="Helvetica-Bold",
                     fontSize=20, textColor=colors.white, backColor=RED,
                     borderPadding=(6, 8, 6, 8), spaceBefore=8, spaceAfter=14, leading=24)
MOD = ParagraphStyle("Mod", parent=styles["Heading2"], fontName="Helvetica-Bold",
                     fontSize=14, textColor=DARKRED, spaceBefore=4, spaceAfter=1, leading=17)
MODSUB = ParagraphStyle("ModSub", parent=styles["Normal"], fontSize=9.5, textColor=CYAN,
                        fontName="Helvetica-Oblique", spaceAfter=5)
BODY = ParagraphStyle("Body", parent=styles["Normal"], fontSize=10, textColor=INK,
                      leading=14.5, spaceAfter=3, alignment=TA_LEFT)
NOTE = ParagraphStyle("Note", parent=styles["Normal"], fontSize=9, textColor=GREY,
                      leading=13, spaceAfter=3, leftIndent=6, backColor=LIGHT,
                      borderPadding=(4, 5, 4, 5))
LEAD = ParagraphStyle("Lead", parent=styles["Normal"], fontSize=11, textColor=INK,
                      leading=16, spaceAfter=8)
H2 = ParagraphStyle("H2b", parent=styles["Heading2"], fontSize=15, textColor=DARKRED,
                    spaceBefore=6, spaceAfter=8)


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def module(name, title, does, looks, attack, note=None):
    e = [Paragraph(esc(name), MOD), Paragraph(esc(title), MODSUB),
         Paragraph(f"<b>What it really does &amp; looks for:</b> {esc(does)} {esc(looks)}", BODY),
         Paragraph(f"<b>If it finds something — the attack:</b> {esc(attack)}", BODY)]
    if note:
        e.append(Paragraph(f"<b>Good to know:</b> {esc(note)}", NOTE))
    e.append(Spacer(1, 9))
    return KeepTogether(e)


# ---------------------------------------------------------------------------
# Document content
# ---------------------------------------------------------------------------

RECON = [
    module("basic_info", "Target Fingerprint",
        "Makes a first request to the site and records the essentials.",
        "It reports the IP address the domain points to, the web-server software, the page load time, the page title, and guesses the operating system from a network value called TTL (a number that counts how many hops a packet can take).",
        "On its own this is harmless reconnaissance, but it is the attacker's first step: knowing the server software and OS tells them which known weaknesses to try next.",
        "Everything here is INFO and never lowers your security score — it is context, not a problem."),
    module("whois_lookup", "Domain Registration Lookup",
        "Queries public registration databases (WHOIS) for the domain.",
        "It returns who registered the domain (the registrar), when it was created, when it expires, and the name servers. It is smart enough to skip platform sub-domains like yoursite.vercel.app where WHOIS is meaningless.",
        "Attackers use the expiry date (a domain about to expire can be hijacked) and registration details for social-engineering or phishing that looks legitimate.",
        "An expiry date that is very close is flagged because an expired domain can be taken over by anyone."),
    module("dns_check", "Email Security Records (DNS)",
        "Looks up the domain's DNS records that protect email.",
        "It checks for SPF, DKIM, and DMARC (three records that prove an email truly came from your domain) and MX records (the mail servers).",
        "If SPF/DMARC are missing, an attacker can send emails that look like they come from your domain — classic phishing and CEO-fraud. This is one of the most common real-world weaknesses.",
        "Missing SPF or DMARC does not break your website, but it lets criminals impersonate your email address."),
    module("ssl_check", "TLS / Certificate Inspector",
        "Examines the HTTPS certificate that encrypts traffic.",
        "It reads the certificate issuer, the TLS protocol version, and how many days until the certificate expires; it also flags a site served over plain HTTP (no encryption at all).",
        "No HTTPS means anyone on the same network (public Wi-Fi, a malicious router) can read or modify the traffic — passwords included. An expired certificate breaks trust and can hide an attacker.",
        "A certificate expiring soon is flagged early so it can be renewed before visitors see scary browser warnings."),
    module("port_scan", "TCP Port Scanner",
        "Tries to open a network connection to common service ports on the server's IP.",
        "It checks ~26 ports (databases like MySQL/Redis/MongoDB, remote access like RDP/VNC/SSH, web/mail) and grabs a short 'banner' to confirm the service. It first probes random unused ports to detect an 'accept-all' host.",
        "An exposed database or remote-desktop port is a direct doorway: attackers brute-force the login or exploit the service to take over the server. Databases should never be reachable from the internet.",
        "If the host answers EVERY port (a firewall/honeypot trick), Hades reports one 'unreliable' note instead of dozens of fake 'open ports'. Behind a CDN, the scanned IP is the edge, not the real server."),
    module("waf_detect", "Firewall / CDN Detection",
        "Inspects response headers and behaviour to spot a protective layer in front of the site.",
        "It identifies WAFs and CDNs such as Cloudflare, Akamai, AWS, or Fastly.",
        "Knowing a WAF exists tells an attacker their payloads may be filtered, so they will craft bypass techniques. For a defender it confirms a protection layer is active.",
        "A WAF is good news — but it also explains why other modules may get blocked (403s) during a scan."),
    module("tech_stack", "Technology Fingerprint",
        "Reads headers, HTML, scripts, and cookies to identify the software powering the site.",
        "It detects the web server, programming language, frameworks, JavaScript libraries (jQuery, React…), CMS, and — crucially — their version numbers when visible.",
        "Versions are gold for attackers: an old library with a published vulnerability (CVE) can often be exploited with a ready-made tool. This module feeds the CVE lookup.",
        "Hiding version numbers (server tokens, X-Powered-By) makes an attacker's job harder."),
]

WEB = [
    module("headers_check", "HTTP Security Headers Audit",
        "Reads the response headers that browsers use to enforce security rules.",
        "It deeply checks Content-Security-Policy (parsed directive by directive), HSTS (forces HTTPS), X-Frame-Options, the cross-origin headers (COOP/COEP/CORP), and flags headers that leak software versions.",
        "Missing headers remove browser-side defences: no CSP makes XSS far easier, no HSTS allows downgrade attacks, no X-Frame-Options enables clickjacking.",
        "These are 'hardening' gaps — rarely exploitable alone, but they make every other attack easier. CSP missing is the highest-impact one."),
    module("robots_txt", "robots.txt Analyzer",
        "Downloads /robots.txt and studies what it reveals.",
        "It classifies each disallowed path (admin, login, backups, .git…) with precise matching, then ACTIVELY visits each sensitive path to see if it is really reachable, and flags wildcard rules that leak file types.",
        "robots.txt must list paths in clear text to hide them from search engines — which paradoxically hands attackers a map of your sensitive areas. A disallowed path that is also reachable is escalated.",
        "A path here that returns 404 is a 'stale' leftover (low value); one that returns 200 is a real, reachable target."),
    module("sitemap", "Sitemap Parser",
        "Finds and reads XML sitemaps (and any declared in robots.txt).",
        "It counts the listed URLs, follows sitemap indexes one level deep, and flags any sensitive URL the sitemap advertises (admin, staging, .git…).",
        "A sitemap that lists internal or admin URLs gives attackers a curated list of interesting targets without any guessing.",
        "Sitemaps are meant to be public; the only concern is when they expose URLs that should stay private."),
    module("cms_detect", "CMS Detection",
        "Fingerprints the content-management system running the site.",
        "It identifies WordPress, Joomla, Drupal, and similar platforms (and their version where possible).",
        "Each CMS has a huge catalogue of known plugin/theme vulnerabilities. Knowing the CMS and version lets an attacker pick a matching exploit immediately.",
        "WordPress powers a large share of the web and is the most-attacked CMS, so detecting it matters."),
    module("admin_panel", "Admin / Login Panel Finder",
        "Probes known admin paths and VERIFIES whether each is really a login or admin interface.",
        "Instead of trusting status codes, it checks the page content for a real login form, an authenticated admin UI, HTTP authentication, or a redirect to a login page.",
        "An exposed admin panel is a prime brute-force and credential-stuffing target. A panel reachable without logging in can be an instant full compromise.",
        "Thanks to content verification, it no longer cries 'admin found' for every page on a catch-all site — only genuine login/admin pages are reported."),
    module("dir_scan", "Directory & Path Brute-Forcer",
        "Requests a wordlist of common directories/paths to discover what exists on the server.",
        "It distinguishes open directory listings (High), normal accessible paths, auth-protected paths (401), forbidden paths (403), and redirects. It learns the server's 'not found' behaviour first.",
        "Discovered admin areas, backups, or config folders give attackers new entry points. An open directory listing exposes every file in a folder.",
        "Smart baselines collapse the noise: if the server answers 200 (or 403, or 500) to everything, Hades reports one note instead of hundreds of fake hits."),
    module("subdomain_scan", "Subdomain Enumeration & Takeover",
        "Discovers sub-domains both actively (DNS brute-force) and passively, then checks each for takeover.",
        "Active resolving is combined with Certificate Transparency logs (crt.sh) to reveal sub-domains that were never guessable. Each one is then probed for dangling-DNS takeover.",
        "Forgotten sub-domains (dev, staging, old) widen the attack surface and are often less protected. A 'subdomain takeover' lets an attacker host their own content on YOUR sub-domain — perfect for phishing.",
        "A wildcard-DNS check prevents false positives where every name resolves to the same address."),
    module("broken_links", "Broken Link Checker",
        "Checks the HTTP status of every link the crawler found and classifies it correctly.",
        "It separates genuinely dead links (404/410), server errors (5xx), access-controlled links (401/403), and rate-limiting (429).",
        "A 404 is just broken usability/SEO. But a wall of 403s usually means a WAF is blocking the scanner — not broken links — so it is grouped into one advisory instead of dozens of false alarms.",
        "A 403 means 'forbidden', NOT 'broken' — the page likely works fine in a real browser."),
    module("http_methods", "HTTP Methods Auditor",
        "Discovers which HTTP methods the server accepts and actively verifies the dangerous ones.",
        "For PUT it tries a safe upload of a unique harmless file and reads it back; for TRACE it checks for echo (XST); DELETE is reported as advertised-only (never tested, that would be destructive).",
        "A confirmed PUT upload is critical: an attacker can place a web shell and run commands on the server. A real TRACE echo can be used to steal headers.",
        "It no longer trusts the 'Allow' header blindly — only a method proven to work is rated High/Critical. Active write tests are skipped in passive/safe mode."),
    module("backup_files", "Backup & Source File Hunter",
        "Looks for backup or temporary copies derived from the target itself.",
        "It tries archive names based on the hostname (site.zip, site.tar.gz), common backup names, and editor backups of real pages (index.php~, config.php.bak, vim .swp files), confirming archives by their magic bytes.",
        "A downloadable backup often contains the full source code, database dumps, and hard-coded passwords — effectively the keys to the kingdom in one file.",
        "It confirms a real archive by content, so an HTML 'not found' page is never mistaken for a backup."),
    module("sensitive_files", "Sensitive File Exposure",
        "Probes well-known paths that expose secrets, configuration, or source control.",
        "It checks for .env files, .git repositories, cloud credentials (AWS/GCP), SSH keys, framework configs, database dumps, and more — with content checks to avoid false positives.",
        "A readable .env or .git directory can leak database passwords, API keys, and the entire source code, leading directly to full compromise.",
        "If the server blocks every sensitive path (a good 'deny-all' rule), Hades reports one positive note instead of many false alarms."),
    module("cookie_analysis", "Cookie Security Flags",
        "Inspects the cookies the site sets in the browser.",
        "It checks for the Secure flag (only sent over HTTPS), HttpOnly (hidden from JavaScript), and SameSite (limits cross-site sending), plus prefixes like __Host-.",
        "A session cookie without HttpOnly can be stolen by XSS to hijack a user's session; without Secure it can leak over plain HTTP; without SameSite it enables CSRF.",
        "These flags are the difference between an XSS bug being annoying and being account-takeover."),
    module("redirect_chain", "Redirect Chain Auditor",
        "Follows the chain of redirects starting from the target URL.",
        "It records every hop and flags an HTTPS-to-HTTP downgrade, redirects that leave your domain, missing HTTP-to-HTTPS upgrade, and chains that are too long.",
        "A downgrade redirect exposes traffic to interception; an open/off-domain redirect can be abused in phishing to make a malicious link look like it starts on your trusted site.",
        "A clean single HTTP-to-HTTPS redirect is exactly what you want to see."),
    module("email_exposure", "Exposed Email Finder",
        "Collects email addresses that appear across the crawled pages.",
        "It harvests addresses from mailto links and page text, separating on-domain addresses from third-party ones.",
        "Published addresses fuel spam, phishing, and targeted social-engineering. An on-domain address is a direct spear-phishing target for staff.",
        "Use contact forms or obfuscation instead of publishing personal mailboxes in plain text."),
    module("favicon_hash", "Favicon Fingerprint",
        "Computes a hash of the site's little browser-tab icon, the same way Shodan does.",
        "It produces a number you can search (http.favicon.hash:VALUE) to find other servers using the same icon, and recognises a few well-known default favicons.",
        "Identical favicon hashes reveal shared frameworks, hidden admin panels, or related infrastructure — a quiet way to map an organisation's assets.",
        "A default framework favicon quietly tells the world what software you run; a custom icon avoids that."),
    module("cors_check", "CORS Misconfiguration",
        "Sends requests with a crafted Origin header to test cross-origin sharing rules.",
        "It checks whether the server reflects any origin and allows credentials (the dangerous combination).",
        "A permissive CORS policy lets a malicious website read authenticated responses from your site on behalf of a logged-in victim — leaking their private data.",
        "CORS bugs are subtle: 'Access-Control-Allow-Origin: *' is usually fine, but reflecting the caller's origin WITH credentials is the real danger."),
    module("clickjacking", "Clickjacking Verdict",
        "Decides whether the page can be loaded inside an attacker's invisible frame, and how risky that is.",
        "It combines X-Frame-Options and CSP frame-ancestors into a single 'framable?' answer, and weights the risk by whether the page has a login form or other forms.",
        "If framable, an attacker overlays an invisible copy of your page over a decoy and tricks users into clicking real buttons (changing settings, confirming actions) without realising it.",
        "A framable page with no interactive elements is low impact; one with a login form is high."),
    module("dir_listing", "Open Directory Listing",
        "Detects folders whose entire contents are publicly browsable.",
        "It checks directories discovered by the crawler plus common upload/asset/backup folders for the tell-tale 'Index of /' auto-index page, and lists the exposed files.",
        "An open listing hands attackers a full inventory of files — often including backups, uploads, or documents that were never meant to be public.",
        "It reuses the crawler's findings, so it tests folders that actually exist on the site rather than guessing blindly."),
    module("blacklist_check", "Reputation / Blocklist Check",
        "Checks the site's IP and domain against public DNS blocklists (DNSBLs).",
        "Using the standard, key-free DNSBL protocol it queries lists like Spamhaus, SpamCop, and Barracuda.",
        "Being listed signals a history of spam or malware — or a current compromise — and badly hurts email deliverability and reputation. It can be an early warning that a server is already hacked.",
        "Behind a CDN the checked IP is the shared edge, which is rarely listed — so a clean result is less meaningful there."),
    module("screenshot", "Homepage Screenshot",
        "Opens the homepage in a real headless browser and saves a picture of it.",
        "It captures a full-page PNG into the screenshots/ folder using Chromium.",
        "Not an attack itself — it gives a human a quick visual of what the target looks like, useful for triage across many sites.",
        "If the browser engine is not installed it fails gracefully with a hint, never breaking the scan."),
]

VULNS = [
    module("sqli_detect", "SQL Injection Detection",
        "Injects test payloads into URL/form parameters to see if they reach a database query.",
        "It uses three techniques: error-based (triggering a database error message), boolean-based blind (a TRUE condition behaves like normal, a FALSE one differs), and time-based blind (a SLEEP payload makes the page hang for a measurable, scaling delay).",
        "SQL injection lets an attacker read or modify the database directly — dumping all users and passwords, bypassing logins, sometimes taking over the server. It is one of the most damaging web vulnerabilities.",
        "It DETECTS the flaw; it does not dump data itself. On a confirmed hit Hades shows a ready sqlmap command and, with the --exploit flag, can launch sqlmap for you (authorised targets only). Skipped in safe mode."),
    module("xss_detect", "Cross-Site Scripting (XSS) Detection",
        "Injects a marker into inputs and analyses exactly where and how it is reflected back.",
        "It first finds the reflection context (HTML text, an attribute, a JavaScript string, or a comment), then sends the minimal 'breakout' payload for that context and checks whether the special characters survive unencoded.",
        "Reflected XSS lets an attacker run their JavaScript in a victim's browser: stealing session cookies, performing actions as the victim, or defacing the page. Combined with weak cookie flags it becomes account takeover.",
        "Context analysis makes results credible: a reflection whose special characters are encoded is reported only as Low (likely safe), while a real breakout is High."),
    module("command_injection", "OS Command Injection",
        "Injects shell separators and commands (;id, | whoami, & dir, sleep) into parameters and form fields.",
        "It confirms a hit two ways: the command's OUTPUT appears in the page (uid=0(root), Volume Serial Number), or an injected sleep makes the response hang for a measurable delay that SCALES with the requested time.",
        "Command injection is total compromise: the attacker runs arbitrary operating-system commands on the server — read or change any file, install a backdoor, pivot into the internal network. It is among the most severe web flaws.",
        "Verified, never guessed: a delay that scales (5s clearly longer than 2s) rules out a merely slow page. A ready commix command is attached. Skipped in safe mode."),
    module("ssti_detect", "Server-Side Template Injection (SSTI)",
        "Injects a distinctive maths expression in every template syntax ({{7*7}}, ${7*7}, <%= 7*7 %>, #{7*7}…).",
        "It flags the input only if the server returned the COMPUTED result (e.g. the product) instead of the literal text — proof the value is evaluated as a template, not just echoed.",
        "SSTI usually escalates to remote code execution: the attacker runs code inside the template engine to read secrets, files, or take over the server.",
        "The maths uses large numbers so a coincidental match is impossible, and the firing syntax fingerprints the engine (Jinja2, Twig, FreeMarker…). A tplmap command is attached."),
    module("lfi_detect", "Local File Inclusion / Path Traversal",
        "Requests well-known system files through traversal payloads (../../../etc/passwd, ..\\windows\\win.ini, PHP filter wrappers).",
        "It confirms the read by the file's ACTUAL content (the root:x:0:0: line of /etc/passwd, the [fonts] section of win.ini, or base64 that decodes to PHP source).",
        "LFI lets an attacker read arbitrary server files — configuration, source code, credentials — and can chain to remote code execution via log or session poisoning.",
        "Confirmed by file content, never by guesswork, so false positives are rare."),
    module("open_redirect", "Open Redirect",
        "Injects a unique external URL into redirect-style parameters (url, next, return, redirect…).",
        "It requests the page without following redirects and flags when the server forwards the user to that external host (Location header, meta refresh, or JavaScript).",
        "An open redirect makes a link that STARTS on your trusted domain land on the attacker's site — ideal for phishing — and can bypass redirect allowlists in login/OAuth flows.",
        "Severity rises to High when the parameter drives an authentication flow."),
    module("ssrf_detect", "Server-Side Request Forgery (SSRF)",
        "Injects internal and cloud-metadata URLs (127.0.0.1, 169.254.169.254, file:///etc/passwd) into URL-shaped parameters.",
        "It flags responses that come back containing content only the SERVER could fetch — cloud metadata, or the contents of a local file.",
        "SSRF makes the server send requests on the attacker's behalf: stealing cloud credentials from the metadata service, scanning the internal network, or reaching admin panels never exposed to the internet.",
        "In-band detection only; truly blind SSRF needs an out-of-band (OOB) test, planned as a future addition."),
    module("cve_mapping", "Known Vulnerability (CVE) Lookup",
        "Takes the software versions found by tech_stack and asks the official NVD database for matching vulnerabilities.",
        "For each versioned component it retrieves the top CVEs (public vulnerability records) with their severity score (CVSS).",
        "A matching CVE often means a ready-made exploit exists: an attacker just runs it against your outdated component. This turns 'old version' into 'known way in'.",
        "Set an NVD_API_KEY environment variable for a higher rate limit and more complete results."),
    module("default_creds", "Default Credentials Advisory",
        "Fingerprints management interfaces that are famous for shipping with default passwords.",
        "It detects things like phpMyAdmin, Tomcat Manager, Jenkins, or Grafana and lists their documented default logins — WITHOUT ever trying to log in.",
        "If an admin never changed the default password (admin/admin, tomcat/tomcat…), anyone who finds the panel walks straight in. This is an extremely common real-world breach cause.",
        "By design it never submits credentials — actively trying passwords against someone else's system is intrusive and can be illegal. Verify manually on your own systems."),
]

DB = [
    module("db_security (db_scan)", "Red-Team Database Security Audit",
        "A single dedicated module (run with --profile db_scan) that hunts database exposure end to end and then helps exploit it.",
        "It scans the common database ports and fingerprints the engine from its banner (MySQL, PostgreSQL, MSSQL, Oracle, MongoDB, Redis, Elasticsearch, CouchDB, Cassandra, Memcached); tests each for access WITHOUT a password and, when open, actually pulls proof-of-data — Redis keys plus a CONFIG check that means remote code execution, Elasticsearch index names and document counts, CouchDB database names; probes crawled parameters for SQL and NoSQL injection; and checks TLS on the database port.",
        "An open, unauthenticated database is an instant full data breach: anyone on the internet reads or modifies everything. A confirmed SQL injection is dumpable, and an exposed Redis CONFIG turns into a server takeover (web shell / SSH key / cron).",
        "Confirmed SQL injection found here is exploitable with the same --exploit sqlmap launcher. Destructive checks (default creds, time-based SQLi, NoSQL) are skipped in safe mode."),
    module("db_security — data-leak hunting", "Secrets, Connection Strings & Admin GUIs",
        "Beyond the live engines, it aggressively hunts for database credentials that leak through the website itself.",
        "It requests well-known secret/config files (.env, config/database.yml, my.cnf, wp-config.php, appsettings.json, docker-compose.yml…) and extracts DB credentials from them (passwords redacted in the report); it scans page and inline-JS source for hard-coded connection strings (mongodb://, postgres://, jdbc:…); it tests GraphQL endpoints for introspection (full schema disclosure); and it looks for exposed admin GUIs (phpMyAdmin, Adminer, Fauxton, Kibana…), downloadable SQL/SQLite dumps, and framework debug endpoints that print the DB config.",
        "Any one of these can hand over the database directly — a readable .env or a leaked connection string is the password itself; an exposed admin GUI or dump is a one-click breach.",
        "Every credential shown is masked. A leaked secret found here should be treated as compromised and the password rotated immediately."),
    module("db_security — attack path & loot", "Exploitation Plan & Extracted Data",
        "After the audit it assembles a red-team view of the result, surfaced in the console panel and the HTML report.",
        "It computes a DB Exposure Score (0-100 with a grade), prints an ordered Attack Path of copy-paste exploitation commands (the sqlmap line for each SQLi, redis-cli for Redis, curl for Elasticsearch/CouchDB/secret files…), and a Loot summary listing the data actually pulled during the scan (sample keys, index names, leaked secrets, default credentials).",
        "This turns a list of findings into an actionable engagement plan: an operator can copy each command and reproduce the access, exactly as in a real assessment.",
        "Everything is opt-in and authorisation-gated — Hades shows the commands; it only runs sqlmap itself when you pass --exploit and confirm you are authorised."),
]

OUTPUT = [
    module("scorer", "Security Score & Grade",
        "Turns all findings into a single 0-100 score and an A-F grade.",
        "Each finding subtracts points based on its severity, with diminishing returns per module (so one noisy module cannot sink the score) and an optional confidence weighting.",
        "Not an attack — it is your at-a-glance health indicator. A low grade means several real, actionable issues were found.",
        "INFO findings are context only and NEVER affect the grade — the score reflects genuine problems (Low and above) only."),
]


def build():
    doc = BaseDocTemplate("Hades_Modules_Guide.pdf", pagesize=A4,
                          leftMargin=18 * mm, rightMargin=18 * mm,
                          topMargin=16 * mm, bottomMargin=16 * mm,
                          title="Hades — Modules Guide", author="Hades")
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="main")

    def footer(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(GREY)
        canvas.drawString(doc.leftMargin, 10 * mm, "Hades — Web Security Scanner · Educational module guide")
        canvas.drawRightString(A4[0] - doc.rightMargin, 10 * mm, f"Page {d.page}")
        canvas.restoreState()

    doc.addPageTemplates([PageTemplate(id="main", frames=[frame], onPage=footer)])

    story = []
    # Cover
    story.append(Spacer(1, 55 * mm))
    story.append(Paragraph("HADES", H_TITLE))
    story.append(Paragraph("Web Security Scanner", H_SUB))
    story.append(Paragraph("A Beginner's Guide to Every Module", H_SUB))
    story.append(Spacer(1, 10 * mm))
    disclaimer = ("<b>For authorised security testing only.</b> Scanning systems without explicit "
                  "written permission is illegal. This guide explains what each module checks and "
                  "why it matters, in plain language for people new to cybersecurity.")
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
        "Hades runs many small <b>modules</b>. Each one checks one thing about a website. For every "
        "module below you will find: <b>what it really does and looks for</b>, <b>what an attacker "
        "could do if it finds a problem</b>, and a short <b>good-to-know</b> tip. You do not need any "
        "prior knowledge — terms are explained as they appear.", LEAD))
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

    for heading, mods in [("1 · Reconnaissance Modules", RECON),
                          ("2 · Website &amp; Misconfiguration Modules", WEB),
                          ("3 · Vulnerability Modules", VULNS),
                          ("4 · Database Security Audit (db_scan)", DB),
                          ("5 · Scoring &amp; Output", OUTPUT)]:
        story.append(Paragraph(heading, CAT))
        story.extend(mods)
        story.append(PageBreak())

    doc.build(story)
    print("Hades_Modules_Guide.pdf written")


if __name__ == "__main__":
    build()
