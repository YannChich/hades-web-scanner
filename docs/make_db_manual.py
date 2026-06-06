"""Generate the Hades Database Security manual PDF — English.

A complete, beginner-friendly manual for the db_scan profile (scanner/db/db_security.py):
what a database is, why it matters, how to run the audit, every check explained, how to read
the output (exposure score / attack path / loot), exploitation, a glossary and a remediation
checklist — written in plain English, no prior security knowledge required.
"""
from __future__ import annotations

from datetime import date
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, KeepTogether, PageBreak, PageTemplate,
    Paragraph, Spacer, Table, TableStyle,
)

RED = colors.HexColor("#b3122a")
DARKRED = colors.HexColor("#7a0d1c")
INK = colors.HexColor("#1c1c1c")
GREY = colors.HexColor("#555555")
LIGHT = colors.HexColor("#f4f1f2")
SUBBG = colors.HexColor("#f0d9dd")
CYAN = colors.HexColor("#0b6e75")

styles = getSampleStyleSheet()
H_TITLE = ParagraphStyle("HTitle", parent=styles["Title"], fontName="Helvetica-Bold",
                         fontSize=44, textColor=RED, spaceAfter=6, leading=48)
H_SUB = ParagraphStyle("HSub", parent=styles["Normal"], fontSize=13, textColor=GREY,
                       alignment=TA_CENTER, spaceAfter=4)
CAT = ParagraphStyle("Cat", parent=styles["Heading1"], fontName="Helvetica-Bold",
                     fontSize=16, textColor=colors.white, backColor=RED,
                     borderPadding=(6, 8, 6, 8), spaceBefore=8, spaceAfter=10, leading=20)
LEAD = ParagraphStyle("Lead", parent=styles["Normal"], fontSize=11, textColor=INK,
                      leading=16, spaceAfter=8)
H2 = ParagraphStyle("H2b", parent=styles["Heading2"], fontSize=15, textColor=DARKRED,
                    spaceBefore=6, spaceAfter=8)
SUB_HEADING = ParagraphStyle("SubHeading", parent=styles["Normal"], fontName="Helvetica-Bold",
                             fontSize=11.5, textColor=DARKRED, backColor=SUBBG,
                             borderPadding=(5, 7, 5, 7), spaceBefore=10, spaceAfter=6, leading=15)
BODY = ParagraphStyle("Body", parent=styles["Normal"], fontSize=10.5, textColor=INK,
                      leading=15, spaceAfter=8, alignment=TA_LEFT)
DISC = ParagraphStyle("Disc", parent=styles["Normal"], fontSize=10, textColor=INK, leading=14)


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def code(s: str) -> str:
    """Inline monospace (no escaping of the supplied <font> wrapper)."""
    return f'<font face="Courier" color="#b3122a">{esc(s)}</font>'


# ---------------------------------------------------------------------------
# Content model: each section is a list of rows.
#   ("sub",  text)  -> a tinted sub-heading bar
#   ("body", text)  -> a normal content paragraph (HTML allowed)
# ---------------------------------------------------------------------------

SECTIONS: list[tuple[str, list[tuple[str, str]]]] = [

    ("1 · Introduction — What is a database?", [
        ("body",
         "A database is a website's 'vault': it stores accounts, passwords, orders, messages — all "
         "the data. If someone reaches it without authorisation, that is a major, often "
         "irreversible, data breach."),
        ("sub", "The engines Hades knows"),
        ("body",
         "Hades knows MySQL / MariaDB, PostgreSQL, Microsoft SQL Server, Oracle, MongoDB, Redis, "
         "Elasticsearch, CouchDB, Cassandra and Memcached. Some 'speak' the SQL language (MySQL, "
         "PostgreSQL); others are called 'NoSQL' (MongoDB, Redis) and use different formats."),
        ("sub", "No prior knowledge required"),
        ("body",
         "This manual assumes no security background. Every technical term is explained as it "
         "appears, and there is a glossary at the end."),
    ]),

    ("2 · Why audit database security", [
        ("body",
         "A database exposed to the Internet is one of the most common causes of massive leaks: "
         "millions of customer records have been stolen from MongoDB or Elasticsearch databases "
         "left open with no password at all. Exposed Redis servers have been used to deploy "
         "ransomware."),
        ("sub", "What an attacker looks for"),
        ("body",
         "1) a database port reachable from the Internet; 2) the absence of a password; 3) "
         "credentials written in plain text in a file or the site's code; 4) a SQL injection that "
         "lets them read the database through the website itself. The db_scan module tests exactly "
         "these four things — and more."),
    ]),

    ("3 · The Hades db_scan module", [
        ("body",
         "db_scan is a dedicated scan profile: a single specialised module "
         f"({code('scanner/db/db_security.py')}) that performs a complete audit of a target's "
         "'database' surface, end to end, then helps you exploit what it finds."),
        ("sub", "In one sentence"),
        ("body",
         "It scans database ports, tests password-free access (and extracts data to prove it), "
         "hunts for SQL / NoSQL injection, tracks down leaked secret and credential files, then "
         "computes an exposure score, an attack plan, and a summary of the 'loot' collected."),
        ("sub", "Detection first, exploitation second"),
        ("body",
         "By default, Hades only DETECTS. Real exploitation (launching the actual sqlmap tool) "
         f"happens only if you add the {code('--exploit')} option and confirm you are authorised. "
         "Nothing is ever exploited automatically."),
    ]),

    ("4 · Installation and prerequisites", [
        ("body",
         f"Requirements: Python 3.10 or newer. Install the dependencies with "
         f"{code('pip install -r requirements.txt')}. That is all you need for detection."),
        ("sub", "Optional: sqlmap"),
        ("body",
         f"For SQL-injection exploitation ({code('--exploit')}), install sqlmap: "
         f"{code('pip install sqlmap')}. Hades finds it automatically, even if it is not on the "
         "PATH (it looks in Python's Scripts folder)."),
    ]),

    ("5 · Usage — the commands", [
        ("sub", "Basic audit"),
        ("body",
         f"{code('python hades.py --url https://target.com --profile db_scan')}<br/>"
         "Runs the full database audit and prints the result in the terminal."),
        ("sub", "Reports (always written)"),
        ("body",
         "Every scan automatically writes a styled HTML report (dark theme, with the attack path "
         f"and the loot) and a structured JSON report to {code('reports/')}, and opens the HTML in "
         "your browser. No extra flag is needed."),
        ("sub", "Audit + exploiting confirmed SQLi"),
        ("body",
         f"{code('python hades.py -u http://testaspnet.vulnweb.com -p db_scan --exploit')}<br/>"
         "After the audit, offers to launch sqlmap on each confirmed SQL injection (double "
         "confirmation required)."),
        ("body",
         "Tip: <b>testphp.vulnweb.com</b> and <b>testaspnet.vulnweb.com</b> are public test sites "
         "(Acunetix) made for practising legally."),
    ]),

    ("6 · Safe mode and legality", [
        ("body",
         "<b>Only audit systems you own or are explicitly authorised to test.</b> Scanning or "
         "exploiting a database without written permission is illegal in most countries (CFAA, "
         "Computer Misuse Act, etc.)."),
        ("sub", "Safe mode"),
        ("body",
         "In safe mode, Hades skips the 'destructive' or intrusive tests: default credentials, "
         "time-based SQL injection, and NoSQL injection. The port scan is limited to the 5 most "
         "common database ports. An INFO note tells you so."),
    ]),

    ("7 · The checks explained one by one", [
        ("sub", "7.1  Port scan and fingerprint"),
        ("body",
         "Hades tries to open a connection to known database ports (3306 MySQL, 5432 PostgreSQL, "
         "6379 Redis, 27017 MongoDB, 9200 Elasticsearch...). For each open port it reads the "
         "service 'banner' to identify the engine and its version. If the host answers EVERY port "
         "(firewall/honeypot), the scan is skipped to avoid false positives."),

        ("sub", "7.2  Unauthenticated access + data extraction"),
        ("body",
         "For Redis, Memcached, Elasticsearch, CouchDB and MongoDB, Hades checks whether it can "
         "talk WITHOUT a password. If so, it does not just say it: it extracts proof — a sample of "
         "Redis keys and their count, Elasticsearch index names and document counts, the CouchDB "
         "database list. That is concrete proof an attacker could read everything. Severity: "
         "CRITICAL."),

        ("sub", "7.3  Redis CONFIG -> remote code execution (RCE)"),
        ("body",
         "If an open Redis also allows the CONFIG command, it is far worse than a data leak: an "
         "attacker can rewrite where Redis stores its files to drop a 'web shell', an SSH key or a "
         "scheduled task, and thus fully take over the server (RCE). Hades flags this case "
         "separately as CRITICAL."),

        ("sub", "7.4  SQL injection"),
        ("body",
         "Hades injects test payloads into the site's parameters (URL and forms) to see whether "
         "they reach a database query. Three techniques: via an error message, via a true/false "
         "condition (blind boolean), and via timing (a 'sleep 2 seconds' payload that slows the "
         "page measurably). Severity: CRITICAL. A ready-to-use sqlmap command is attached."),

        ("sub", "7.5  NoSQL injection"),
        ("body",
         "On NoSQL databases (e.g. MongoDB), Hades sends special operators ("
         + code('{"$ne": null}') + ", " + code('{"$gt": ""}')
         + "...) and watches whether the response changes markedly (status or size). A clear "
         "change suggests the input is treated as a query — to be verified manually. Tested "
         "outside safe mode only."),

        ("sub", "7.6  Secret files (.env, my.cnf...)"),
        ("body",
         "Very often the database password sits in a configuration file left readable: .env, "
         "config/database.yml, wp-config.php, my.cnf, appsettings.json, docker-compose.yml... "
         "Hades probes about thirty such paths, reads the content, and extracts the database "
         "credentials. The password is MASKED in the report. Severity: CRITICAL."),

        ("sub", "7.7  Leaked connection strings"),
        ("body",
         "Hades also reads the source of the site's pages and scripts looking for hard-coded "
         f"connection strings ({code('mongodb://user:pass@...')}, {code('postgres://...')}, "
         f"{code('jdbc:...')}). A single such line can be enough to connect straight to the "
         "database. Password masked, severity CRITICAL."),

        ("sub", "7.8  GraphQL introspection"),
        ("body",
         "If the site exposes a GraphQL API with 'introspection' enabled, anyone can download the "
         "full schema: every query, mutation and hidden data type. Hades detects it and lists the "
         "exposed types. Severity: HIGH."),

        ("sub", "7.9  Admin interfaces"),
        ("body",
         "Hades looks for database management web interfaces (phpMyAdmin, Adminer, pgAdmin, "
         "CouchDB's Fauxton, Kibana, mongo-express...). An interface reachable in the clear is "
         "CRITICAL; an interface that exists but is password-protected is HIGH (remove it from the "
         "public web if not needed)."),

        ("sub", "7.10  Dumps and SQLite files"),
        ("body",
         "Hades tries to download database backups left in the web root (backup.sql, dump.sql.gz, "
         "database.sqlite, .mdb...). A SQLite file is recognised by its signature bytes. A "
         "downloadable dump often contains the whole database — data and passwords. Severity: "
         "CRITICAL."),

        ("sub", "7.11  Framework leaks"),
        ("body",
         "Some frameworks expose debug pages that print the configuration, including database "
         "credentials (e.g. Spring Actuator /actuator/env, Rails). Hades probes them and reports "
         "any credential leak. Severity: CRITICAL."),

        ("sub", "7.12  TLS on database ports"),
        ("body",
         "Hades checks whether the database connection is encrypted (TLS). An open port without "
         "TLS means traffic — credentials included — may travel in clear text; a self-signed "
         "certificate is also flagged. Severity: LOW to MEDIUM."),

        ("sub", "7.13  Injection via HTTP headers and cookies"),
        ("body",
         "Developers often forget that HEADERS (User-Agent, Referer, X-Forwarded-For) and cookies "
         "sometimes end up in a SQL query (logging, analytics). So Hades injects its SQL payloads "
         "into these headers and cookies too, not only URL parameters — doubling the attack "
         "surface. Severity: CRITICAL if a SQL error comes out."),

        ("sub", "7.14  NoSQL authentication bypass"),
        ("body",
         "On MongoDB applications, a poorly coded login form can be tricked by sending an operator "
         "instead of a password: `{\"$ne\": \"\"}` means 'not equal to empty', i.e. 'any "
         "password'. Hades submits this kind of payload to login forms and detects whether a "
         "session opens — a full authentication bypass. Severity: CRITICAL."),

        ("sub", "7.15  Cloud databases (Firebase, Firestore, Supabase)"),
        ("body",
         "Many mobile/web apps use a cloud database whose address is written in the code. Hades "
         "spots it and tests whether it is publicly readable: an open Firebase Realtime Database "
         "returns ALL the data at the `/.json` address — one of the most common leaks of the "
         "modern web. Severity: CRITICAL."),
    ]),

    ("8 · Understanding the output", [
        ("sub", "The exposure score"),
        ("body",
         "At the end, Hades computes a 'DB Exposure Score' from 0 to 100 and a grade: SECURE "
         "(0-15), AT RISK (16-40), EXPOSED (41-70), CRITICAL (71-100). The higher the score, the "
         "more exposed the database. Each category of problem adds points once."),
        ("sub", "The console panel"),
        ("body",
         "A dedicated 'Database Security Audit' panel shows: the list of findings coloured by "
         "severity, the score bar, a summary table (ports, auth issues, injection points, data "
         "leaks, interfaces), then the two key sections below."),
        ("sub", "Loot — the extracted data"),
        ("body",
         "This section summarises the DATA actually retrieved during the audit: a sample of Redis "
         "keys, Elasticsearch index names, CouchDB databases, GraphQL types, leaked connection "
         "strings and secrets, default credentials. It is the 'what an attacker would walk away "
         "with' view."),
        ("sub", "Attack path — the exploitation plan"),
        ("body",
         "Hades turns exploitable findings into an ordered list (most to least severe) of "
         "ready-to-copy commands: the sqlmap line for each SQL injection, redis-cli for Redis, "
         "curl for Elasticsearch / CouchDB / secret files. An operator can reproduce the access "
         "step by step."),
        ("sub", "The HTML report"),
        ("body",
         "The HTML report (written automatically for every scan) contains a 'Database Security' "
         "section with the score gauge, the findings table, the attack path (commands in green) "
         "and the loot, plus a per-engine remediation list."),
    ]),

    ("9 · Exploitation with --exploit (sqlmap)", [
        ("body",
         "Hades does not reinvent exploitation: it launches the real industry-standard tool, "
         "sqlmap, against confirmed SQL injections (from both the injection arsenal AND db_scan)."),
        ("sub", "How it works"),
        ("body",
         "After the scan, if a SQLi is confirmed, Hades shows a warning panel, then asks for TWO "
         "confirmations: launch sqlmap on this parameter, and confirm you are authorised. Only "
         "then does it run sqlmap. Without those confirmations (or without "
         f"{code('--exploit')}), nothing is exploited."),
        ("sub", "Active extraction = proof of impact"),
        ("body",
         f"With {code('--exploit')}, db_scan no longer just reports: it EXTRACTS real data to "
         "prove impact — actual Redis key values, Elasticsearch/CouchDB documents, and the "
         "database banner via an 'in-band' SQL injection (without sqlmap). Everything is saved as "
         f"EVIDENCE in the {code('loot/<host>_<date>/')} folder."),
        ("sub", "Credential reuse"),
        ("body",
         "If Hades found database credentials (in a .env or a connection string), it REPLAYS them "
         "against the discovered database servers to verify whether they actually work — "
         "confirming full access. The password stays masked in the report."),
        ("sub", "Red-team report (MITRE ATT&CK)"),
        ("body",
         "Each attack-path step is tagged with a MITRE ATT&CK technique (e.g. T1190, T1078) — the "
         "standard language of security teams — and points to the matching evidence file. This "
         "turns the scan into a real engagement report."),
    ]),

    ("10 · Glossary", [
        ("body",
         "<b>Port</b>: a numbered door on a server where a service listens.<br/>"
         "<b>Banner</b>: text a service returns when introducing itself (name, version).<br/>"
         "<b>Authentication</b>: identity verification (password, key).<br/>"
         "<b>SQL injection</b>: making the database run your own commands via a site field.<br/>"
         "<b>NoSQL</b>: databases without the SQL language (MongoDB, Redis...).<br/>"
         "<b>RCE</b>: remote code execution = full control of the server.<br/>"
         "<b>Dump</b>: a complete copy/backup of a database.<br/>"
         "<b>TLS</b>: encryption of communications (the 's' in https)."),
    ]),

    ("11 · Remediation checklist", [
        ("body",
         "• Never expose a database port directly to the Internet (VPN / allowlist).<br/>"
         "• Require a STRONG, unique password on every database (never the default values).<br/>"
         "• Move secrets out of the web root; deny .env and config files at the server level.<br/>"
         "• Never hard-code credentials in front-end code.<br/>"
         "• Remove admin interfaces (phpMyAdmin, Adminer...) from public access.<br/>"
         "• Move dumps/backups out of the web root.<br/>"
         "• Use parameterised queries against SQL/NoSQL injection.<br/>"
         "• Disable GraphQL introspection in production.<br/>"
         "• Enable TLS for database connections.<br/>"
         "• After any leak, rotate the affected password immediately."),
    ]),
]


def build_section(title: str, rows: list[tuple[str, str]]):
    """Render one section: a red banner title, then sub-heading bars and body paragraphs."""
    flow = [Paragraph(esc(title), CAT)]
    i, n = 0, len(rows)
    while i < n:
        kind, text = rows[i]
        if kind == "sub":
            # Glue a sub-heading to its first paragraph so a heading never sits alone at page foot.
            group = [Paragraph(text, SUB_HEADING)]
            j = i + 1
            if j < n and rows[j][0] == "body":
                group.append(Paragraph(rows[j][1], BODY))
                j += 1
            flow.append(KeepTogether(group))
            i = j
        else:
            flow.append(Paragraph(text, BODY))
            i += 1
    flow.append(Spacer(1, 8))
    return flow


def build():
    doc = BaseDocTemplate(str(Path(__file__).resolve().parent / "Hades_Database_Security_Manual.pdf"),
                          pagesize=A4,
                          leftMargin=18 * mm, rightMargin=18 * mm,
                          topMargin=15 * mm, bottomMargin=16 * mm,
                          title="Hades — Database Security Manual", author="Hades")
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="main")

    def footer(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(GREY)
        canvas.drawString(doc.leftMargin, 10 * mm,
                          "Hades — Database Security Manual")
        canvas.drawRightString(A4[0] - doc.rightMargin, 10 * mm, f"Page {d.page}")
        canvas.restoreState()

    doc.addPageTemplates([PageTemplate(id="main", frames=[frame], onPage=footer)])

    story: list = []
    # Cover
    story.append(Spacer(1, 42 * mm))
    story.append(Paragraph("HADES", H_TITLE))
    story.append(Paragraph("Database Security — Complete Manual", H_SUB))
    story.append(Paragraph("The db_scan module explained for beginners", H_SUB))
    story.append(Spacer(1, 10 * mm))
    disc = ("<b>For authorised security testing only.</b><br/>"
            "Scanning or exploiting a database without written permission is illegal. This manual "
            "explains what the Database Security module checks, how to run it, how to read its "
            "output, and how to remediate the issues it finds.")
    story.append(Table([[Paragraph(disc, DISC)]],
        colWidths=[doc.width - 20 * mm],
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
    story.append(Paragraph("How to read this manual", H2))
    story.append(Paragraph(
        "This manual walks through the db_scan profile from the ground up: what it does, how to "
        "run it, every check it performs, and how to act on the results. Pale-pink bars are "
        "sub-headings. No prior knowledge is required.", LEAD))
    story.append(Spacer(1, 4 * mm))

    for title, rows in SECTIONS:
        story.extend(build_section(title, rows))

    doc.build(story)
    print(f"{Path(__file__).resolve().parent / 'Hades_Database_Security_Manual.pdf'} written")


if __name__ == "__main__":
    build()
