"""Generate the Hades CLI Flags cheat-sheet PDF (English)."""
from __future__ import annotations

from datetime import date

from reportlab.lib import colors
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


# flag, short, argument, description
FLAGS = [
    ("--url", "-u", "URL", "Target URL to scan. Must start with http:// or https://. If omitted, Hades asks for it interactively."),
    ("--profile", "-p", "PROFILE", "Which set of modules to run: quick, passive, cms, full, or db_scan. If omitted, an interactive menu is shown."),
    ("--module", "-m", "NAME", "Run ONE module only (e.g. headers_check). Overrides --profile. Great for quick targeted checks."),
    ("--output", "-o", "FORMAT", "Export the report to a file: json, html, or pdf. If omitted, results are only shown in the terminal."),
    ("--proxy", "", "URL", "Route all traffic through an HTTP/HTTPS proxy, e.g. Burp Suite at http://127.0.0.1:8080."),
    ("--threads", "-t", "N", "Number of concurrent worker threads (default: 10). Higher = faster but noisier/heavier."),
    ("--ignore-robots", "", "(flag)", "Ignore robots.txt Disallow rules during active scanning. Use only on targets you fully control."),
    ("--exploit", "", "(flag)", "After the scan, launch sqlmap against any CONFIRMED SQL injection. Requires sqlmap. Authorised targets only."),
    ("--wordlist", "-w", "FILE", "Use a custom wordlist file instead of the built-in lists (affects dir_scan / admin_panel)."),
    ("--cookies", "", "STRING", "Send a Cookie header, e.g. \"session=abc123; token=xyz\". Use to scan as a logged-in user."),
    ("--auth-token", "", "TOKEN", "Send an Authorization: Bearer <TOKEN> header. Use for API / token-protected targets."),
    ("--help", "-h", "(flag)", "Show the built-in help message listing all flags, then exit."),
]

PROFILES = [
    ("quick", "Fast surface scan: basic info, security headers, SSL/TLS, robots.txt."),
    ("passive", "All reconnaissance + passive web checks. No active probing (no SQLi/XSS/brute-force)."),
    ("cms", "CMS-focused: CMS detection, admin panels, and CVE mapping."),
    ("full", "Everything — the most thorough scan (this is the default behaviour)."),
    ("db_scan", "Red-team database security audit: DB ports, unauth access + data extraction, SQL/NoSQL injection, leaked secrets/connection strings, GraphQL, admin GUIs, dumps; emits a DB exposure score, attack path and loot. Pair with --exploit to launch sqlmap on confirmed SQLi."),
]

MODULES = [
    "Recon:  basic_info · whois_lookup · dns_check · ssl_check · port_scan · waf_detect · tech_stack",
    "Web:    headers_check · robots_txt · sitemap · cms_detect · admin_panel · dir_scan · subdomain_scan ·",
    "        broken_links · http_methods · backup_files · sensitive_files · cookie_analysis · redirect_chain ·",
    "        email_exposure · favicon_hash · cors_check · clickjacking · dir_listing · blacklist_check · screenshot",
    "Vulns:  sqli_detect · xss_detect · command_injection · ssti_detect · lfi_detect ·",
    "        open_redirect · ssrf_detect · cve_mapping · default_creds",
    "DB:     db_security   (run via --profile db_scan — dedicated red-team database audit)",
]

EXAMPLES = [
    ("Interactive menu (asks URL + scan type)", "py main.py"),
    ("Quick scan of a site", "py main.py --url https://example.com --profile quick"),
    ("Full scan + HTML report", "py main.py -u https://example.com -p full -o html"),
    ("Run only one module", "py main.py -u https://example.com -m headers_check"),
    ("Scan through Burp Suite proxy", "py main.py -u https://example.com --proxy http://127.0.0.1:8080"),
    ("Authenticated scan (with a cookie)", "py main.py -u https://example.com --cookies \"session=abc123\""),
    ("More threads (faster)", "py main.py -u https://example.com -t 25"),
    ("Detect + launch sqlmap on SQLi", "py main.py -u \"http://testaspnet.vulnweb.com/Comments.aspx?id=1\" --exploit"),
    ("Database security audit + HTML report", "py main.py -u https://example.com -p db_scan -o html"),
    ("DB audit + auto-exploit confirmed SQLi", "py main.py -u http://testaspnet.vulnweb.com -p db_scan --exploit"),
    ("Show all flags", "py main.py --help"),
]


def code_block(cmd):
    return Table([[Paragraph(esc(cmd), CODEW)]], colWidths=[170 * mm],
                 style=TableStyle([("BACKGROUND", (0, 0), (-1, -1), MONO_BG),
                                   ("LEFTPADDING", (0, 0), (-1, -1), 8),
                                   ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                                   ("TOPPADDING", (0, 0), (-1, -1), 5),
                                   ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))


def build():
    doc = BaseDocTemplate("Hades_Flags_Cheatsheet.pdf", pagesize=A4,
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
             Paragraph(f"Run with the 'py' launcher, e.g.  py main.py [flags]    ·    {date.today().isoformat()}", SUB),
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
    print("Hades_Flags_Cheatsheet.pdf written")


if __name__ == "__main__":
    build()
