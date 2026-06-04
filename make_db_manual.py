"""Generate the Hades Database Security manual PDF — bilingual (Français / English).

A complete, beginner-friendly manual for the db_scan profile (scanner/db/db_security.py):
what a database is, why it matters, how to run the audit, every check explained, how to read
the output (exposure score / attack path / loot), exploitation, a glossary and a remediation
checklist — all presented in two parallel columns: French on the left, English on the right.
"""
from __future__ import annotations

from datetime import date

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
HEADCELL = ParagraphStyle("HeadCell", parent=styles["Normal"], fontName="Helvetica-Bold",
                          fontSize=10, textColor=colors.white, leading=13)
SUBCELL = ParagraphStyle("SubCell", parent=styles["Normal"], fontName="Helvetica-Bold",
                         fontSize=10.5, textColor=DARKRED, leading=14)
CELL = ParagraphStyle("Cell", parent=styles["Normal"], fontSize=9.2, textColor=INK,
                      leading=13, alignment=TA_LEFT)


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def code(s: str) -> str:
    """Inline monospace (no escaping of the supplied <font> wrapper)."""
    return f'<font face="Courier" color="#b3122a">{esc(s)}</font>'


# ---------------------------------------------------------------------------
# Content model: each section is a list of rows.
#   ("sub",  fr, en)  -> a tinted bilingual sub-heading row
#   ("body", fr, en)  -> a normal bilingual content row (HTML allowed in fr/en)
# ---------------------------------------------------------------------------

SECTIONS: list[tuple[str, list[tuple[str, str, str]]]] = [

    ("1 · Introduction — Qu'est-ce qu'une base de donnees ?  /  What is a database?", [
        ("body",
         "Une base de donnees est le « coffre-fort » d'un site web : elle stocke les comptes, les "
         "mots de passe, les commandes, les messages — bref, toutes les donnees. Si quelqu'un y "
         "accede sans autorisation, c'est une fuite de donnees majeure, souvent irreversible.",
         "A database is a website's 'vault': it stores accounts, passwords, orders, messages — all "
         "the data. If someone reaches it without authorisation, that is a major, often "
         "irreversible, data breach."),
        ("sub", "Les moteurs reconnus", "The engines Hades knows"),
        ("body",
         "Hades reconnait MySQL / MariaDB, PostgreSQL, Microsoft SQL Server, Oracle, MongoDB, "
         "Redis, Elasticsearch, CouchDB, Cassandra et Memcached. Certains « parlent » le langage "
         "SQL (MySQL, PostgreSQL) ; d'autres sont dits « NoSQL » (MongoDB, Redis) et utilisent "
         "d'autres formats.",
         "Hades knows MySQL / MariaDB, PostgreSQL, Microsoft SQL Server, Oracle, MongoDB, Redis, "
         "Elasticsearch, CouchDB, Cassandra and Memcached. Some 'speak' the SQL language (MySQL, "
         "PostgreSQL); others are called 'NoSQL' (MongoDB, Redis) and use different formats."),
        ("sub", "Aucune connaissance requise", "No prior knowledge required"),
        ("body",
         "Ce manuel n'exige aucune base en cyber. Chaque terme technique est explique au moment ou "
         "il apparait, et un glossaire se trouve a la fin.",
         "This manual assumes no security background. Every technical term is explained as it "
         "appears, and there is a glossary at the end."),
    ]),

    ("2 · Pourquoi auditer la securite des bases de donnees  /  Why audit database security", [
        ("body",
         "Une base exposee sur Internet est l'une des causes les plus frequentes de fuites "
         "massives : des millions de dossiers clients ont deja ete voles via des bases MongoDB ou "
         "Elasticsearch laissees ouvertes, sans le moindre mot de passe. Des serveurs Redis "
         "exposes ont servi a installer des rancongiciels (ransomware).",
         "A database exposed to the Internet is one of the most common causes of massive leaks: "
         "millions of customer records have been stolen from MongoDB or Elasticsearch databases "
         "left open with no password at all. Exposed Redis servers have been used to deploy "
         "ransomware."),
        ("sub", "Ce que cherche un attaquant", "What an attacker looks for"),
        ("body",
         "1) un port de base de donnees joignable depuis Internet ; 2) l'absence de mot de passe ; "
         "3) des identifiants ecrits en clair dans un fichier ou le code du site ; 4) une "
         "injection SQL qui permet de lire la base via le site lui-meme. Le module db_scan teste "
         "exactement ces quatre points — et plus encore.",
         "1) a database port reachable from the Internet; 2) the absence of a password; 3) "
         "credentials written in plain text in a file or the site's code; 4) a SQL injection that "
         "lets them read the database through the website itself. The db_scan module tests exactly "
         "these four things — and more."),
    ]),

    ("3 · Le module db_scan de Hades  /  The Hades db_scan module", [
        ("body",
         "db_scan est un profil de scan dedie : un seul module specialise "
         f"({code('scanner/db/db_security.py')}) qui realise un audit complet de la surface "
         "« base de donnees » d'une cible, du debut a la fin, puis vous aide a exploiter ce qu'il "
         "trouve.",
         "db_scan is a dedicated scan profile: a single specialised module "
         f"({code('scanner/db/db_security.py')}) that performs a complete audit of a target's "
         "'database' surface, end to end, then helps you exploit what it finds."),
        ("sub", "En une phrase", "In one sentence"),
        ("body",
         "Il scanne les ports de bases de donnees, teste l'acces sans mot de passe (et extrait "
         "des donnees pour le prouver), cherche des injections SQL / NoSQL, traque les fichiers de "
         "secrets et identifiants fuites, puis calcule un score d'exposition, un plan d'attaque et "
         "un resume du « butin » recupere.",
         "It scans database ports, tests password-free access (and extracts data to prove it), "
         "hunts for SQL / NoSQL injection, tracks down leaked secret and credential files, then "
         "computes an exposure score, an attack plan, and a summary of the 'loot' collected."),
        ("sub", "Detection d'abord, exploitation ensuite",
         "Detection first, exploitation second"),
        ("body",
         "Par defaut, Hades ne fait que DETECTER. L'exploitation reelle (lancer le vrai outil "
         f"sqlmap) n'a lieu que si vous ajoutez l'option {code('--exploit')} et confirmez que vous "
         "etes autorise. Rien n'est jamais exploite automatiquement.",
         "By default, Hades only DETECTS. Real exploitation (launching the actual sqlmap tool) "
         f"happens only if you add the {code('--exploit')} option and confirm you are authorised. "
         "Nothing is ever exploited automatically."),
    ]),

    ("4 · Installation et prerequis  /  Installation and prerequisites", [
        ("body",
         f"Prerequis : Python 3.10 ou plus recent. Installez les dependances avec "
         f"{code('pip install -r requirements.txt')}. C'est tout pour la detection.",
         f"Requirements: Python 3.10 or newer. Install the dependencies with "
         f"{code('pip install -r requirements.txt')}. That is all you need for detection."),
        ("sub", "Optionnel : sqlmap", "Optional: sqlmap"),
        ("body",
         f"Pour l'exploitation des injections SQL ({code('--exploit')}), installez sqlmap : "
         f"{code('pip install sqlmap')}. Hades le trouve automatiquement, meme s'il n'est pas dans "
         "le PATH (il regarde le dossier Scripts de Python).",
         f"For SQL-injection exploitation ({code('--exploit')}), install sqlmap: "
         f"{code('pip install sqlmap')}. Hades finds it automatically, even if it is not on the "
         "PATH (it looks in Python's Scripts folder)."),
    ]),

    ("5 · Utilisation — les commandes  /  Usage — the commands", [
        ("sub", "Audit de base", "Basic audit"),
        ("body",
         f"{code('py main.py --url https://cible.com --profile db_scan')}<br/>"
         "Lance l'audit base de donnees complet et affiche le resultat dans le terminal.",
         f"{code('py main.py --url https://target.com --profile db_scan')}<br/>"
         "Runs the full database audit and prints the result in the terminal."),
        ("sub", "Avec un rapport HTML", "With an HTML report"),
        ("body",
         f"{code('py main.py -u https://cible.com -p db_scan -o html')}<br/>"
         "Genere en plus un rapport HTML (theme sombre) avec le plan d'attaque et le butin.",
         f"{code('py main.py -u https://target.com -p db_scan -o html')}<br/>"
         "Also generates an HTML report (dark theme) with the attack path and the loot."),
        ("sub", "Audit + exploitation des SQLi confirmees",
         "Audit + exploiting confirmed SQLi"),
        ("body",
         f"{code('py main.py -u http://testaspnet.vulnweb.com -p db_scan --exploit')}<br/>"
         "Apres l'audit, propose de lancer sqlmap sur chaque injection SQL confirmee (double "
         "confirmation requise).",
         f"{code('py main.py -u http://testaspnet.vulnweb.com -p db_scan --exploit')}<br/>"
         "After the audit, offers to launch sqlmap on each confirmed SQL injection (double "
         "confirmation required)."),
        ("body",
         "Astuce : <b>testphp.vulnweb.com</b> et <b>testaspnet.vulnweb.com</b> sont des sites de "
         "test publics (Acunetix) faits pour s'entrainer legalement.",
         "Tip: <b>testphp.vulnweb.com</b> and <b>testaspnet.vulnweb.com</b> are public test sites "
         "(Acunetix) made for practising legally."),
    ]),

    ("6 · Mode sur et legalite  /  Safe mode and legality", [
        ("body",
         "<b>N'auditez que des systemes que vous possedez ou que vous etes explicitement autorise "
         "a tester.</b> Scanner ou exploiter une base sans autorisation ecrite est illegal dans la "
         "plupart des pays (CFAA, Computer Misuse Act, etc.).",
         "<b>Only audit systems you own or are explicitly authorised to test.</b> Scanning or "
         "exploiting a database without written permission is illegal in most countries (CFAA, "
         "Computer Misuse Act, etc.)."),
        ("sub", "Le mode sur (safe mode)", "Safe mode"),
        ("body",
         "En mode sur, Hades saute les tests « destructifs » ou intrusifs : les identifiants par "
         "defaut, l'injection SQL temporisee (time-based) et l'injection NoSQL. Le scan de ports "
         "est limite aux 5 ports de bases de donnees les plus courants. Une note INFO vous le "
         "signale.",
         "In safe mode, Hades skips the 'destructive' or intrusive tests: default credentials, "
         "time-based SQL injection, and NoSQL injection. The port scan is limited to the 5 most "
         "common database ports. An INFO note tells you so."),
    ]),

    ("7 · Les verifications expliquees une par une  /  The checks explained one by one", [
        ("sub", "7.1  Scan de ports et empreinte", "7.1  Port scan and fingerprint"),
        ("body",
         "Hades essaie d'ouvrir une connexion vers les ports de bases de donnees connus (3306 "
         "MySQL, 5432 PostgreSQL, 6379 Redis, 27017 MongoDB, 9200 Elasticsearch...). Pour chaque "
         "port ouvert, il lit la « banniere » du service afin d'identifier le moteur et sa "
         "version. Si l'hote repond a TOUS les ports (pare-feu/leurre), le scan est ignore pour "
         "eviter de faux positifs.",
         "Hades tries to open a connection to known database ports (3306 MySQL, 5432 PostgreSQL, "
         "6379 Redis, 27017 MongoDB, 9200 Elasticsearch...). For each open port it reads the "
         "service 'banner' to identify the engine and its version. If the host answers EVERY port "
         "(firewall/honeypot), the scan is skipped to avoid false positives."),

        ("sub", "7.2  Acces sans authentification + extraction de donnees",
         "7.2  Unauthenticated access + data extraction"),
        ("body",
         "Pour Redis, Memcached, Elasticsearch, CouchDB et MongoDB, Hades verifie s'il peut "
         "dialoguer SANS mot de passe. Si oui, il ne se contente pas de le dire : il extrait une "
         "preuve — un echantillon des cles Redis et leur nombre, les noms d'index Elasticsearch et "
         "le nombre de documents, la liste des bases CouchDB. C'est la preuve concrete qu'un "
         "attaquant pourrait tout lire. Severite : CRITIQUE.",
         "For Redis, Memcached, Elasticsearch, CouchDB and MongoDB, Hades checks whether it can "
         "talk WITHOUT a password. If so, it does not just say it: it extracts proof — a sample of "
         "Redis keys and their count, Elasticsearch index names and document counts, the CouchDB "
         "database list. That is concrete proof an attacker could read everything. Severity: "
         "CRITICAL."),

        ("sub", "7.3  Redis CONFIG -> execution de code (RCE)",
         "7.3  Redis CONFIG -> remote code execution (RCE)"),
        ("body",
         "Si un Redis ouvert autorise aussi la commande CONFIG, c'est bien pire qu'une fuite de "
         "donnees : un attaquant peut reecrire l'emplacement des fichiers de Redis pour deposer un "
         "« web shell », une cle SSH ou une tache planifiee, et ainsi prendre le controle total du "
         "serveur (RCE). Hades signale ce cas separement en CRITIQUE.",
         "If an open Redis also allows the CONFIG command, it is far worse than a data leak: an "
         "attacker can rewrite where Redis stores its files to drop a 'web shell', an SSH key or a "
         "scheduled task, and thus fully take over the server (RCE). Hades flags this case "
         "separately as CRITICAL."),

        ("sub", "7.4  Injection SQL", "7.4  SQL injection"),
        ("body",
         "Hades injecte des charges de test dans les parametres du site (URL et formulaires) pour "
         "voir si elles atteignent une requete de base de donnees. Trois techniques : par message "
         "d'erreur, par condition vraie/fausse (booleen aveugle) et par temporisation (une charge "
         "« dors 2 secondes » qui ralentit la page de facon mesurable). Severite : CRITIQUE. Une "
         "commande sqlmap prete a l'emploi est jointe.",
         "Hades injects test payloads into the site's parameters (URL and forms) to see whether "
         "they reach a database query. Three techniques: via an error message, via a true/false "
         "condition (blind boolean), and via timing (a 'sleep 2 seconds' payload that slows the "
         "page measurably). Severity: CRITICAL. A ready-to-use sqlmap command is attached."),

        ("sub", "7.5  Injection NoSQL", "7.5  NoSQL injection"),
        ("body",
         "Sur les bases NoSQL (type MongoDB), Hades envoie des operateurs speciaux ("
         + code('{"$ne": null}') + ", " + code('{"$gt": ""}')
         + "...) et observe si la reponse change nettement (code ou taille). Un changement net "
         "suggere que l'entree est interpretee comme une requete — a verifier manuellement. Teste "
         "hors mode sur uniquement.",
         "On NoSQL databases (e.g. MongoDB), Hades sends special operators ("
         + code('{"$ne": null}') + ", " + code('{"$gt": ""}')
         + "...) and watches whether the response changes markedly (status or size). A clear "
         "change suggests the input is treated as a query — to be verified manually. Tested "
         "outside safe mode only."),

        ("sub", "7.6  Fichiers de secrets (.env, my.cnf...)",
         "7.6  Secret files (.env, my.cnf...)"),
        ("body",
         "Tres souvent, le mot de passe de la base se trouve dans un fichier de configuration "
         "laisse accessible : .env, config/database.yml, wp-config.php, my.cnf, appsettings.json, "
         "docker-compose.yml... Hades sonde une trentaine de ces chemins, lit le contenu et en "
         "extrait les identifiants de base de donnees. Le mot de passe est MASQUE dans le rapport. "
         "Severite : CRITIQUE.",
         "Very often the database password sits in a configuration file left readable: .env, "
         "config/database.yml, wp-config.php, my.cnf, appsettings.json, docker-compose.yml... "
         "Hades probes about thirty such paths, reads the content, and extracts the database "
         "credentials. The password is MASKED in the report. Severity: CRITICAL."),

        ("sub", "7.7  Chaines de connexion fuitees", "7.7  Leaked connection strings"),
        ("body",
         "Hades lit aussi le code source des pages et des scripts du site a la recherche de "
         f"chaines de connexion ecrites en dur ({code('mongodb://user:pass@...')}, "
         f"{code('postgres://...')}, {code('jdbc:...')}). Une seule de ces lignes peut suffire a se "
         "connecter directement a la base. Mot de passe masque, severite CRITIQUE.",
         "Hades also reads the source of the site's pages and scripts looking for hard-coded "
         f"connection strings ({code('mongodb://user:pass@...')}, {code('postgres://...')}, "
         f"{code('jdbc:...')}). A single such line can be enough to connect straight to the "
         "database. Password masked, severity CRITICAL."),

        ("sub", "7.8  Introspection GraphQL", "7.8  GraphQL introspection"),
        ("body",
         "Si le site expose une API GraphQL avec « l'introspection » activee, n'importe qui peut "
         "telecharger le schema complet : toutes les requetes, mutations et types de donnees "
         "caches. Hades le detecte et liste les types exposes. Severite : ELEVEE.",
         "If the site exposes a GraphQL API with 'introspection' enabled, anyone can download the "
         "full schema: every query, mutation and hidden data type. Hades detects it and lists the "
         "exposed types. Severity: HIGH."),

        ("sub", "7.9  Interfaces d'administration", "7.9  Admin interfaces"),
        ("body",
         "Hades cherche les interfaces web de gestion de bases (phpMyAdmin, Adminer, pgAdmin, "
         "Fauxton de CouchDB, Kibana, mongo-express...). Une interface accessible en clair est "
         "CRITIQUE ; une interface presente mais protegee par mot de passe est ELEVEE (a retirer "
         "du web public si inutile).",
         "Hades looks for database management web interfaces (phpMyAdmin, Adminer, pgAdmin, "
         "CouchDB's Fauxton, Kibana, mongo-express...). An interface reachable in the clear is "
         "CRITICAL; an interface that exists but is password-protected is HIGH (remove it from the "
         "public web if not needed)."),

        ("sub", "7.10  Dumps et fichiers SQLite", "7.10  Dumps and SQLite files"),
        ("body",
         "Hades tente de telecharger des sauvegardes de base laissees dans la racine web "
         "(backup.sql, dump.sql.gz, database.sqlite, .mdb...). Un fichier SQLite est reconnu par "
         "ses octets de signature. Un dump telechargeable contient souvent toute la base — donnees "
         "et mots de passe. Severite : CRITIQUE.",
         "Hades tries to download database backups left in the web root (backup.sql, dump.sql.gz, "
         "database.sqlite, .mdb...). A SQLite file is recognised by its signature bytes. A "
         "downloadable dump often contains the whole database — data and passwords. Severity: "
         "CRITICAL."),

        ("sub", "7.11  Fuites par les frameworks", "7.11  Framework leaks"),
        ("body",
         "Certains frameworks exposent des pages de debogage qui affichent la configuration, dont "
         "les identifiants de base (ex. Spring Actuator /actuator/env, Rails). Hades les sonde et "
         "signale toute fuite d'identifiants. Severite : CRITIQUE.",
         "Some frameworks expose debug pages that print the configuration, including database "
         "credentials (e.g. Spring Actuator /actuator/env, Rails). Hades probes them and reports "
         "any credential leak. Severity: CRITICAL."),

        ("sub", "7.12  TLS sur les ports de base", "7.12  TLS on database ports"),
        ("body",
         "Hades verifie si la connexion a la base est chiffree (TLS). Un port ouvert sans TLS "
         "signifie que le trafic — identifiants compris — peut circuler en clair ; un certificat "
         "auto-signe est aussi signale. Severite : FAIBLE a MOYENNE.",
         "Hades checks whether the database connection is encrypted (TLS). An open port without "
         "TLS means traffic — credentials included — may travel in clear text; a self-signed "
         "certificate is also flagged. Severity: LOW to MEDIUM."),

        ("sub", "7.13  Injection via en-tetes HTTP et cookies",
         "7.13  Injection via HTTP headers and cookies"),
        ("body",
         "Les developpeurs oublient souvent que les EN-TETES (User-Agent, Referer, X-Forwarded-For) "
         "et les cookies finissent parfois dans une requete SQL (journalisation, statistiques). "
         "Hades injecte donc ses charges SQL aussi dans ces en-tetes et cookies, pas seulement dans "
         "les parametres d'URL — ce qui double la surface d'attaque. Severite : CRITIQUE si une "
         "erreur SQL en sort.",
         "Developers often forget that HEADERS (User-Agent, Referer, X-Forwarded-For) and cookies "
         "sometimes end up in a SQL query (logging, analytics). So Hades injects its SQL payloads "
         "into these headers and cookies too, not only URL parameters — doubling the attack "
         "surface. Severity: CRITICAL if a SQL error comes out."),

        ("sub", "7.14  Bypass d'authentification NoSQL",
         "7.14  NoSQL authentication bypass"),
        ("body",
         "Sur les applications MongoDB, un formulaire de connexion mal code peut etre trompe en "
         "envoyant un operateur au lieu d'un mot de passe : `{\"$ne\": \"\"}` signifie « different "
         "de vide », donc « n'importe quel mot de passe ». Hades soumet ce type de charge aux "
         "formulaires de login et detecte si une session s'ouvre — c'est un contournement complet "
         "de l'authentification. Severite : CRITIQUE.",
         "On MongoDB applications, a poorly coded login form can be tricked by sending an operator "
         "instead of a password: `{\"$ne\": \"\"}` means 'not equal to empty', i.e. 'any "
         "password'. Hades submits this kind of payload to login forms and detects whether a "
         "session opens — a full authentication bypass. Severity: CRITICAL."),

        ("sub", "7.15  Bases de donnees cloud (Firebase, Firestore, Supabase)",
         "7.15  Cloud databases (Firebase, Firestore, Supabase)"),
        ("body",
         "Beaucoup d'applis mobiles/web utilisent une base cloud dont l'adresse est ecrite dans le "
         "code. Hades la repere et teste si elle est lisible publiquement : une Firebase Realtime "
         "Database ouverte repond a l'adresse `/.json` avec TOUTES les donnees ; c'est l'une des "
         "fuites les plus frequentes du web moderne. Severite : CRITIQUE.",
         "Many mobile/web apps use a cloud database whose address is written in the code. Hades "
         "spots it and tests whether it is publicly readable: an open Firebase Realtime Database "
         "returns ALL the data at the `/.json` address — one of the most common leaks of the "
         "modern web. Severity: CRITICAL."),
    ]),

    ("8 · Comprendre le resultat  /  Understanding the output", [
        ("sub", "Le score d'exposition", "The exposure score"),
        ("body",
         "A la fin, Hades calcule un « DB Exposure Score » de 0 a 100 et une note : SECURE "
         "(0-15), AT RISK (16-40), EXPOSED (41-70), CRITICAL (71-100). Plus le score est haut, "
         "plus la base est exposee. Chaque categorie de probleme ajoute des points une seule fois.",
         "At the end, Hades computes a 'DB Exposure Score' from 0 to 100 and a grade: SECURE "
         "(0-15), AT RISK (16-40), EXPOSED (41-70), CRITICAL (71-100). The higher the score, the "
         "more exposed the database. Each category of problem adds points once."),
        ("sub", "Le panneau console", "The console panel"),
        ("body",
         "Un panneau dedie « Database Security Audit » affiche : la liste des trouvailles colorees "
         "par severite, la barre de score, un tableau recapitulatif (ports, problemes d'auth, "
         "points d'injection, fuites de donnees, interfaces), puis deux sections cles ci-dessous.",
         "A dedicated 'Database Security Audit' panel shows: the list of findings coloured by "
         "severity, the score bar, a summary table (ports, auth issues, injection points, data "
         "leaks, interfaces), then the two key sections below."),
        ("sub", "Loot — le butin extrait", "Loot — the extracted data"),
        ("body",
         "Cette section resume les DONNEES reellement recuperees pendant l'audit : echantillon de "
         "cles Redis, noms d'index Elasticsearch, bases CouchDB, types GraphQL, chaines de "
         "connexion et secrets fuites, identifiants par defaut. C'est la vision « ce qu'un "
         "attaquant repartirait avec ».",
         "This section summarises the DATA actually retrieved during the audit: a sample of Redis "
         "keys, Elasticsearch index names, CouchDB databases, GraphQL types, leaked connection "
         "strings and secrets, default credentials. It is the 'what an attacker would walk away "
         "with' view."),
        ("sub", "Attack path — le plan d'attaque", "Attack path — the exploitation plan"),
        ("body",
         "Hades transforme les failles exploitables en une liste ordonnee (de la plus grave a la "
         "moins grave) de commandes pretes a copier-coller : la ligne sqlmap pour chaque injection "
         "SQL, redis-cli pour Redis, curl pour Elasticsearch / CouchDB / fichiers de secrets. Un "
         "operateur peut reproduire l'acces etape par etape.",
         "Hades turns exploitable findings into an ordered list (most to least severe) of "
         "ready-to-copy commands: the sqlmap line for each SQL injection, redis-cli for Redis, "
         "curl for Elasticsearch / CouchDB / secret files. An operator can reproduce the access "
         "step by step."),
        ("sub", "Le rapport HTML", "The HTML report"),
        ("body",
         f"Avec {code('-o html')}, le rapport contient une section « Database Security » avec la "
         "jauge de score, le tableau des trouvailles, le plan d'attaque (commandes en vert) et le "
         "butin, plus une liste de remediation par moteur.",
         f"With {code('-o html')}, the report contains a 'Database Security' section with the "
         "score gauge, the findings table, the attack path (commands in green) and the loot, plus "
         "a per-engine remediation list."),
    ]),

    ("9 · Exploitation avec --exploit (sqlmap)  /  Exploitation with --exploit (sqlmap)", [
        ("body",
         "Hades ne reinvente pas l'exploitation : il lance le vrai outil de reference, sqlmap, "
         "contre les injections SQL confirmees (issues de l'arsenal d'injection ET de db_scan).",
         "Hades does not reinvent exploitation: it launches the real industry-standard tool, "
         "sqlmap, against confirmed SQL injections (from both the injection arsenal AND db_scan)."),
        ("sub", "Comment ca se passe", "How it works"),
        ("body",
         f"Apres le scan, si une SQLi est confirmee, Hades affiche un panneau d'avertissement, "
         "puis demande DEUX confirmations : lancer sqlmap sur ce parametre, et confirmer que vous "
         "etes autorise. Ensuite seulement il execute sqlmap. Sans ces confirmations (ou sans "
         f"{code('--exploit')}), rien n'est exploite.",
         "After the scan, if a SQLi is confirmed, Hades shows a warning panel, then asks for TWO "
         "confirmations: launch sqlmap on this parameter, and confirm you are authorised. Only "
         "then does it run sqlmap. Without those confirmations (or without "
         f"{code('--exploit')}), nothing is exploited."),
        ("sub", "Extraction active = preuve d'impact", "Active extraction = proof of impact"),
        ("body",
         f"Avec {code('--exploit')}, db_scan ne se contente plus de signaler : il EXTRAIT de "
         "vraies donnees pour prouver l'impact — valeurs reelles des cles Redis, documents "
         "Elasticsearch/CouchDB, et la banniere de la base via une injection SQL « in-band » "
         "(sans sqlmap). Tout est sauvegarde comme PREUVE dans le dossier "
         f"{code('loot/<hote>_<date>/')}.",
         f"With {code('--exploit')}, db_scan no longer just reports: it EXTRACTS real data to "
         "prove impact — actual Redis key values, Elasticsearch/CouchDB documents, and the "
         "database banner via an 'in-band' SQL injection (without sqlmap). Everything is saved as "
         f"EVIDENCE in the {code('loot/<host>_<date>/')} folder."),
        ("sub", "Reutilisation d'identifiants", "Credential reuse"),
        ("body",
         "Si Hades a trouve des identifiants de base (dans un .env ou une chaine de connexion), il "
         "les REJOUE contre les serveurs de base de donnees decouverts pour verifier s'ils "
         "fonctionnent vraiment — confirmant un acces total. Le mot de passe reste masque dans le "
         "rapport.",
         "If Hades found database credentials (in a .env or a connection string), it REPLAYS them "
         "against the discovered database servers to verify whether they actually work — "
         "confirming full access. The password stays masked in the report."),
        ("sub", "Rapport red-team (MITRE ATT&CK)", "Red-team report (MITRE ATT&CK)"),
        ("body",
         "Chaque etape du plan d'attaque est etiquetee avec une technique MITRE ATT&CK (ex. T1190, "
         "T1078) — le langage standard des equipes de securite — et pointe vers le fichier de "
         "preuve correspondant. Cela transforme le scan en un vrai compte-rendu d'engagement.",
         "Each attack-path step is tagged with a MITRE ATT&CK technique (e.g. T1190, T1078) — the "
         "standard language of security teams — and points to the matching evidence file. This "
         "turns the scan into a real engagement report."),
    ]),

    ("10 · Glossaire  /  Glossary", [
        ("body",
         "<b>Port</b> : porte numerotee d'un serveur par laquelle un service ecoute.<br/>"
         "<b>Banniere</b> : texte qu'un service renvoie en se presentant (nom, version).<br/>"
         "<b>Authentification</b> : verification d'identite (mot de passe, cle).<br/>"
         "<b>Injection SQL</b> : faire executer ses propres commandes a la base via un champ du "
         "site.<br/>"
         "<b>NoSQL</b> : bases sans langage SQL (MongoDB, Redis...).<br/>"
         "<b>RCE</b> : execution de code a distance = controle total du serveur.<br/>"
         "<b>Dump</b> : copie/sauvegarde complete d'une base.<br/>"
         "<b>TLS</b> : chiffrement des communications (le « s » de https).",
         "<b>Port</b>: a numbered door on a server where a service listens.<br/>"
         "<b>Banner</b>: text a service returns when introducing itself (name, version).<br/>"
         "<b>Authentication</b>: identity verification (password, key).<br/>"
         "<b>SQL injection</b>: making the database run your own commands via a site field.<br/>"
         "<b>NoSQL</b>: databases without the SQL language (MongoDB, Redis...).<br/>"
         "<b>RCE</b>: remote code execution = full control of the server.<br/>"
         "<b>Dump</b>: a complete copy/backup of a database.<br/>"
         "<b>TLS</b>: encryption of communications (the 's' in https)."),
    ]),

    ("11 · Liste de controle de remediation  /  Remediation checklist", [
        ("body",
         "• N'exposez jamais un port de base de donnees directement a Internet (VPN / liste "
         "blanche).<br/>"
         "• Exigez un mot de passe FORT et unique sur chaque base (jamais les valeurs par "
         "defaut).<br/>"
         "• Sortez les secrets de la racine web ; bloquez .env et fichiers de config au niveau du "
         "serveur.<br/>"
         "• Ne mettez jamais d'identifiants en dur dans le code front-end.<br/>"
         "• Retirez les interfaces d'admin (phpMyAdmin, Adminer...) de l'acces public.<br/>"
         "• Deplacez les dumps/sauvegardes hors de la racine web.<br/>"
         "• Utilisez des requetes parametrees contre l'injection SQL/NoSQL.<br/>"
         "• Desactivez l'introspection GraphQL en production.<br/>"
         "• Activez TLS pour les connexions a la base.<br/>"
         "• Apres toute fuite, changez immediatement le mot de passe concerne.",
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


def build_section(title: str, rows: list[tuple[str, str, str]], width: float):
    flow = [Paragraph(esc(title).replace("/", "&nbsp;/&nbsp;"), CAT)]
    half = (width) / 2
    data = [[Paragraph("FRANCAIS", HEADCELL), Paragraph("ENGLISH", HEADCELL)]]
    sub_rows: list[int] = []
    for kind, fr, en in rows:
        if kind == "sub":
            data.append([Paragraph(fr, SUBCELL), Paragraph(en, SUBCELL)])
            sub_rows.append(len(data) - 1)
        else:
            data.append([Paragraph(fr, CELL), Paragraph(en, CELL)])

    t = Table(data, colWidths=[half, half], repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), RED),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]
    for r in sub_rows:
        style.append(("BACKGROUND", (0, r), (-1, r), SUBBG))
    t.setStyle(TableStyle(style))
    flow.append(t)
    flow.append(Spacer(1, 8))
    return flow


def build():
    doc = BaseDocTemplate("Hades_Database_Security_Manual.pdf", pagesize=A4,
                          leftMargin=15 * mm, rightMargin=15 * mm,
                          topMargin=15 * mm, bottomMargin=16 * mm,
                          title="Hades — Database Security Manual (FR/EN)", author="Hades")
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="main")

    def footer(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(GREY)
        canvas.drawString(doc.leftMargin, 10 * mm,
                          "Hades — Database Security Manual · Manuel bilingue (FR/EN)")
        canvas.drawRightString(A4[0] - doc.rightMargin, 10 * mm, f"Page {d.page}")
        canvas.restoreState()

    doc.addPageTemplates([PageTemplate(id="main", frames=[frame], onPage=footer)])

    story: list = []
    # Cover
    story.append(Spacer(1, 42 * mm))
    story.append(Paragraph("HADES", H_TITLE))
    story.append(Paragraph("Database Security — Manuel complet (FR) / Complete manual (EN)", H_SUB))
    story.append(Paragraph("Le module db_scan explique a un debutant  ·  The db_scan module "
                           "explained for beginners", H_SUB))
    story.append(Spacer(1, 10 * mm))
    disc = ("<b>Pour tests de securite autorises uniquement / For authorised security testing "
            "only.</b><br/>Scanner ou exploiter une base sans autorisation ecrite est illegal. "
            "Ce manuel explique, en francais et en anglais, ce que verifie le module Database "
            "Security et comment l'utiliser.<br/>Scanning or exploiting a database without written "
            "permission is illegal. This manual explains, in French and English, what the "
            "Database Security module checks and how to use it.")
    story.append(Table([[Paragraph(disc, CELL)]], colWidths=[doc.width - 20 * mm],
                       style=TableStyle([("BOX", (0, 0), (-1, -1), 1, RED),
                                         ("BACKGROUND", (0, 0), (-1, -1), LIGHT),
                                         ("LEFTPADDING", (0, 0), (-1, -1), 10),
                                         ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                                         ("TOPPADDING", (0, 0), (-1, -1), 8),
                                         ("BOTTOMPADDING", (0, 0), (-1, -1), 8)])))
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph(f"Genere le / Generated {date.today().isoformat()}", H_SUB))
    story.append(PageBreak())

    # How to read
    story.append(Paragraph("Comment lire ce manuel / How to read this manual", H2))
    story.append(Paragraph(
        "Chaque section est presentee en DEUX colonnes : <b>le francais a gauche</b>, "
        "<b>l'anglais a droite</b>. Les lignes rose pale sont des sous-titres. Aucune connaissance "
        "prealable n'est requise.<br/><br/>"
        "Each section is shown in TWO columns: <b>French on the left</b>, <b>English on the "
        "right</b>. The pale-pink rows are sub-headings. No prior knowledge is required.", LEAD))
    story.append(Spacer(1, 4 * mm))

    for title, rows in SECTIONS:
        story.extend(build_section(title, rows, doc.width))

    doc.build(story)
    print("Hades_Database_Security_Manual.pdf written")


if __name__ == "__main__":
    build()
