"""Generate the Hades CLI Flags cheat-sheet PDF (English)."""
from __future__ import annotations

from datetime import date
from pathlib import Path

from reportlab.lib import colors

_OUT = Path(__file__).resolve().parent / "Hades_Flags_Cheatsheet.pdf"
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageBreak, PageTemplate, Paragraph, Spacer, Table, TableStyle,
)

RED = colors.HexColor("#b3122a")
INK = colors.HexColor("#1c1c1c")
GREY = colors.HexColor("#555555")
LIGHT = colors.HexColor("#f4f1f2")
MONO_BG = colors.HexColor("#23232b")

styles = getSampleStyleSheet()
TITLE = ParagraphStyle("T", parent=styles["Title"], fontName="Helvetica-Bold",
                       fontSize=34, textColor=RED, spaceAfter=2, leading=38)
SUB = ParagraphStyle("S", parent=styles["Normal"], fontSize=12, textColor=GREY,
                     alignment=TA_CENTER, spaceAfter=2)
H = ParagraphStyle("H", parent=styles["Heading1"], fontName="Helvetica-Bold",
                   fontSize=16, textColor=colors.white, backColor=RED,
                   borderPadding=(5, 7, 5, 7), spaceBefore=10, spaceAfter=10, leading=20)
CELL = ParagraphStyle("Cell", parent=styles["Normal"], fontSize=9, textColor=INK, leading=12)
CODE = ParagraphStyle("Code", parent=styles["Normal"], fontName="Courier-Bold",
                      fontSize=9, textColor=RED, leading=12)
CODEW = ParagraphStyle("CodeW", parent=styles["Normal"], fontName="Courier",
                       fontSize=8.5, textColor=colors.white, leading=13, leftIndent=4)
BODY = ParagraphStyle("B", parent=styles["Normal"], fontSize=10, textColor=INK, leading=14, spaceAfter=4)


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# flag, short, argument, description  (mirrors the argparse definition in main.py)
FLAGS = [
    ("--url", "-u", "URL", "Target URL to scan. Must start with http:// or https://. If omitted, Hades asks for it interactively."),
    ("--profile", "-p", "PROFILE", "Which set of modules to run: quick, passive, cms, full, db_scan, ai_scan, engage, oob_scan, tls_scan. If omitted, an interactive menu is shown (menu option 8 = CVE Vulnerability Intelligence)."),
    ("--module", "-m", "NAME", "Run ONE module only (e.g. headers_check). Overrides --profile. Great for quick targeted checks."),
    ("--no-open", "", "(flag)", "Do not auto-open the HTML report in a browser when the scan finishes (the HTML + JSON reports are still written)."),
    ("--arsenal", "", "(flag)", "Open the RedTeam Arsenal — a searchable page of offensive tools by attack type. No scan (also menu option 666)."),
    ("--skills", "", "(flag)", "Open the Skills Library — a searchable page of the expert playbooks Hades draws on, by subdomain. No scan (also menu option 10)."),
    ("--exploit", "", "(flag)", "After the scan, launch sqlmap against any CONFIRMED SQL injection. Requires sqlmap. Authorised targets only."),
    ("--bruteforce", "", "(flag)", "Opt-in: spray common credentials against discovered login forms and HTTP Basic-Auth. Authorised targets only."),
    ("--oob-host", "", "HOST", "Reachable callback address for oob_scan (public IP / tunnel). Auto-detected if omitted."),
    ("--oob-port", "", "PORT", "Port for the out-of-band callback listener (oob_scan). 0 = auto-pick a free port."),
    ("--proxy", "", "URL", "Route all traffic through an HTTP/HTTPS proxy, e.g. Burp Suite at http://127.0.0.1:8080."),
    ("--threads", "-t", "N", "Number of concurrent worker threads (default: 10). Higher = faster but noisier/heavier."),
    ("--ignore-robots", "", "(flag)", "Ignore robots.txt Disallow rules during active scanning. Use only on targets you fully control."),
    ("--wordlist", "-w", "FILE", "Use a custom wordlist file instead of the built-in lists (affects dir_scan / admin_panel)."),
    ("--cookies", "", "STRING", "Send a Cookie header, e.g. \"session=abc123; token=xyz\". Use to scan as a logged-in user."),
    ("--auth-token", "", "TOKEN", "Send an Authorization: Bearer <TOKEN> header. Use for API / token-protected targets."),
    ("--login-url", "", "URL", "Log in before scanning so the crawler + active modules run authenticated (form action / login page). Use with --login-data."),
    ("--login-data", "", "STRING", "Login credentials as form data, e.g. \"username=admin&password=secret\". CSRF hidden fields are auto-replayed."),
    ("--login-check", "", "STRING", "Text that proves the session is authenticated (e.g. \"Logout\") — confirms the login worked."),
    ("--help", "-h", "(flag)", "Show the built-in help message listing all flags, then exit."),
]

PROFILES = [
    ("quick", "Fast surface scan: basic info, security headers, SSL/TLS, robots.txt."),
    ("passive", "All reconnaissance + passive web checks. No active probing (no SQLi/XSS/brute-force)."),
    ("cms", "CMS-focused: CMS detection, admin panels, and CVE mapping."),
    ("full", "Everything — the most thorough scan (this is the default behaviour)."),
    ("db_scan", "Red-team database security audit: DB ports, unauth access + data extraction, SQL/NoSQL injection, leaked secrets/connection strings, GraphQL, admin GUIs, dumps; emits a DB exposure score, attack path and loot. Pair with --exploit to launch sqlmap on confirmed SQLi."),
    ("ai_scan", "Red-team AI/LLM audit: SDK/provider fingerprint, exposed AI keys, unauthenticated local LLM servers, exposed AI UIs and the prompt-injection surface (OWASP LLM Top 10 + MITRE ATLAS)."),
    ("engage", "Active exploitation engagement: confirms bugs then proves impact with benign payloads (RCE via id/uname, LFI read, SSRF to cloud metadata), writing evidence to loot/. Authorisation-gated."),
    ("oob_scan", "Out-of-band (OAST) blind-vuln detection: blind SSRF / RCE / stored XSS via a self-hosted callback listener; auto public tunnel (cloudflared/ngrok) so it works behind NAT."),
    ("cve_scan", "CVE Vulnerability Intelligence (also interactive menu option 8): fingerprints the stack, matches real CVEs (2020+) from a local KEV/EPSS/NVD database, ranked by a Hades CVE Priority Score. Build the full offline corpus once with tools/build_vulndb.py."),
    ("tls_scan", "Offensive TLS/SSL audit (also interactive menu option 9) via SSLyze: legacy protocols, weak/anon ciphers, no forward secrecy, certificate trust/expiry/hostname issues, TLS compression, insecure renegotiation, and Heartbleed/ROBOT/CCS injection. Handshake-only; needs the optional sslyze package."),
]

MODULES = [
    "Recon:  basic_info · whois_lookup · dns_check · ssl_check · port_scan · waf_detect · tech_stack ·",
    "        js_recon · cloud_buckets · git_dumper · wayback",
    "Web:    headers_check · robots_txt · sitemap · cms_detect · admin_panel · dir_scan · subdomain_scan ·",
    "        broken_links · http_methods · backup_files · sensitive_files · cookie_analysis · redirect_chain ·",
    "        email_exposure · favicon_hash · cors_check · clickjacking · dir_listing · blacklist_check · screenshot",
    "Vulns:  sqli_detect · xss_detect · command_injection · ssti_detect · lfi_detect · open_redirect ·",
    "        ssrf_detect · jwt_attacks · auth_bypass · idor_detect · bruteforce · cve_mapping · default_creds",
    "DB:     db_security   (run via --profile db_scan — dedicated red-team database audit)",
    "CVE:    cve_vulnerability   (menu option 8 — CVE intelligence; build the corpus with tools/build_vulndb.py)",
    "TLS:    hephaestus_tls   (menu option 9 / --profile tls_scan — offensive TLS audit via SSLyze)",
]

EXAMPLES = [
    ("Interactive menu (asks URL + scan type)", "python hades.py"),
    ("Quick scan of a site", "python hades.py --url https://example.com --profile quick"),
    ("Full scan (HTML + JSON written automatically)", "python hades.py -u https://example.com -p full"),
    ("Run only one module", "python hades.py -u https://example.com -m headers_check"),
    ("Scan through Burp Suite proxy", "python hades.py -u https://example.com --proxy http://127.0.0.1:8080"),
    ("Authenticated scan (form login + CSRF)", "python hades.py -u https://example.com --login-url https://example.com/login --login-data \"username=admin&password=secret\" --login-check \"Logout\""),
    ("Authenticated scan (with a cookie)", "python hades.py -u https://example.com --cookies \"session=abc123\""),
    ("More threads (faster)", "python hades.py -u https://example.com -t 25"),
    ("Detect + launch sqlmap on SQLi", "python hades.py -u \"http://testaspnet.vulnweb.com/Comments.aspx?id=1\" --exploit"),
    ("Database security audit", "python hades.py -u https://example.com -p db_scan"),
    ("DB audit + auto-exploit confirmed SQLi", "python hades.py -u http://testaspnet.vulnweb.com -p db_scan --exploit"),
    ("CVE intelligence (interactive menu, option 8)", "python hades.py -u https://example.com"),
    ("Build the full offline CVE corpus (once)", "python tools/build_vulndb.py"),
    ("Offensive TLS/SSL audit (SSLyze)", "python hades.py -u https://example.com -p tls_scan"),
    ("RedTeam Arsenal (no scan)", "python hades.py --arsenal"),
    ("Skills Library (no scan)", "python hades.py --skills"),
    ("Show all flags", "python hades.py --help"),
]


def code_block(cmd):
    return Table([[Paragraph(esc(cmd), CODEW)]], colWidths=[170 * mm],
                 style=TableStyle([("BACKGROUND", (0, 0), (-1, -1), MONO_BG),
                                   ("LEFTPADDING", (0, 0), (-1, -1), 8),
                                   ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                                   ("TOPPADDING", (0, 0), (-1, -1), 5),
                                   ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))


def build():
    doc = BaseDocTemplate(str(_OUT), pagesize=A4,
                          leftMargin=15 * mm, rightMargin=15 * mm,
                          topMargin=15 * mm, bottomMargin=15 * mm,
                          title="Hades — CLI Flags Cheat-Sheet", author="Hades")
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="m")

    def footer(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(GREY)
        canvas.drawString(doc.leftMargin, 9 * mm, "Hades — CLI flags cheat-sheet")
        canvas.drawRightString(A4[0] - doc.rightMargin, 9 * mm, f"Page {d.page}")
        canvas.restoreState()

    doc.addPageTemplates([PageTemplate(id="m", frames=[frame], onPage=footer)])

    story = [Spacer(1, 4 * mm),
             Paragraph("HADES", TITLE),
             Paragraph("Command-Line Flags — Cheat Sheet", SUB),
             Paragraph(f"Run with:  python hades.py [flags]    ·    {date.today().isoformat()}", SUB),
             Spacer(1, 6 * mm)]

    # Flags table
    story.append(Paragraph("All available flags", H))
    rows = [[Paragraph("<b>Flag</b>", CELL), Paragraph("<b>Short</b>", CELL),
             Paragraph("<b>Value</b>", CELL), Paragraph("<b>What it does</b>", CELL)]]
    for flag, short, arg, desc in FLAGS:
        rows.append([Paragraph(esc(flag), CODE), Paragraph(esc(short) or "—", CODE),
                     Paragraph(esc(arg), CELL), Paragraph(esc(desc), CELL)])
    t = Table(rows, colWidths=[37 * mm, 13 * mm, 18 * mm, 112 * mm], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), RED),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)

    # Profiles
    story.append(Paragraph("Scan profiles  (--profile)", H))
    prows = [[Paragraph("<b>Profile</b>", CELL), Paragraph("<b>What it runs</b>", CELL)]]
    for name, desc in PROFILES:
        prows.append([Paragraph(esc(name), CODE), Paragraph(esc(desc), CELL)])
    pt = Table(prows, colWidths=[28 * mm, 152 * mm], repeatRows=1)
    pt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), RED), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(pt)

    story.append(PageBreak())

    # Modules
    story.append(Paragraph("Module names  (--module NAME)", H))
    story.append(Paragraph("Use any of these with <b>--module</b> to run just that one check:", BODY))
    for line in MODULES:
        story.append(Paragraph(esc(line), CODE))
    story.append(Spacer(1, 4 * mm))

    # Examples
    story.append(Paragraph("Example commands", H))
    for desc, cmd in EXAMPLES:
        story.append(Paragraph(esc(desc), BODY))
        story.append(code_block(cmd))
        story.append(Spacer(1, 3 * mm))

    doc.build(story)
    print(f"{_OUT} written")


if __name__ == "__main__":
    build()
