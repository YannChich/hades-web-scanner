"""
graphql_detect — discover GraphQL endpoints and flag information-disclosure misconfigurations.

GraphQL APIs are a rich attack surface: if **introspection** is left enabled in production, the whole
schema (every type, field, argument and mutation) is downloadable by anyone — a map of the API for an
attacker. Verbose errors and "Did you mean …" field suggestions leak field names even with
introspection off, and a missing query-depth limit invites denial-of-service via deeply nested
queries.

This module probes a short list of conventional GraphQL paths (plus any `graphql`-looking URL the
crawl found), confirms which are real GraphQL endpoints (a `__typename` query that returns `data`, or
a GraphQL-shaped error), then reports:

* endpoint present → INFO,
* introspection enabled (schema types returned) → MEDIUM (schema disclosure),
* field suggestions in errors ("Did you mean") → LOW (field-name leak).

Read-only recon: it sends only benign, minimal queries and never a deeply-nested or mutating one, so
it is safe to run against an authorised target and is not gated behind `--exploit`.
"""
from __future__ import annotations

import json as _json
from urllib.parse import urlparse, urlunparse

import httpx
from loguru import logger

from scanner import evidence as ev
from scanner.engine import Finding, Severity, ScanEngine

MODULE = "graphql_detect"

# Conventional GraphQL mount points, most common first.
_PATHS: list[str] = [
    "/graphql", "/graphql/", "/api/graphql", "/v1/graphql", "/v2/graphql", "/query",
    "/gql", "/api/gql", "/graphiql", "/graphql/console", "/playground", "/index.php?graphql",
]

# A minimal, always-valid query to confirm the endpoint speaks GraphQL.
_PROBE_Q = "{__typename}"
# Standard, bounded introspection probe (types only — no deep recursion).
_INTROSPECT_Q = "query{__schema{queryType{name} types{name kind}}}"
# A deliberately wrong field to trigger "Did you mean" suggestions, if enabled.
_SUGGEST_Q = "{__typenamee}"

# GraphQL-shaped error fragments (proves a GraphQL engine even when the query is rejected).
_GQL_ERROR_HINTS = (
    "must provide query string", "cannot query field", "syntax error",
    "graphql", "no query string was present", "must provide an operation",
    "query is not valid", "getoperationast",
)


def _base(engine: ScanEngine) -> str:
    p = urlparse(engine.url)
    return urlunparse((p.scheme, p.netloc, "", "", "", ""))


def _candidates(engine: ScanEngine) -> list[str]:
    base = _base(engine)
    urls: list[str] = [base + p for p in _PATHS]
    seen = set(urls)
    try:
        for page in engine.get_crawl().pages:
            if "graphql" in page.lower() and page not in seen:
                seen.add(page)
                urls.append(page)
    except Exception:  # noqa: BLE001 — crawl optional
        pass
    return urls


def _post_query(engine: ScanEngine, url: str, query: str) -> "httpx.Response | None":
    try:
        return engine.request("POST", url, json={"query": query},
                              headers={"Accept": "application/json"})
    except httpx.HTTPError as exc:
        logger.debug(f"graphql_detect: POST {url} → {exc}")
        return None


def _as_json(resp: "httpx.Response | None") -> dict | None:
    if resp is None:
        return None
    ctype = resp.headers.get("content-type", "")
    if "json" not in ctype.lower() and not resp.text.lstrip().startswith("{"):
        return None
    try:
        data = resp.json()
    except (ValueError, _json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _is_graphql(resp: "httpx.Response | None", data: dict | None) -> bool:
    """True when the response looks like a GraphQL engine (valid data or a GraphQL-shaped error)."""
    if data is not None:
        if "data" in data and isinstance(data.get("data"), dict):
            return True
        if "errors" in data:
            blob = _json.dumps(data.get("errors", "")).lower()
            return any(h in blob for h in _GQL_ERROR_HINTS)
    if resp is not None:
        low = resp.text.lower()
        return any(h in low for h in _GQL_ERROR_HINTS)
    return False


def _probe_endpoint(engine: ScanEngine, url: str) -> list[Finding]:
    resp = _post_query(engine, url, _PROBE_Q)
    data = _as_json(resp)
    if not _is_graphql(resp, data):
        return []   # not a GraphQL endpoint

    findings: list[Finding] = [Finding(
        module=MODULE,
        title=f"GraphQL Endpoint Found: {urlparse(url).path or '/'}",
        description=(f"A GraphQL endpoint is exposed at {url}. GraphQL endpoints warrant extra review: "
                     "schema introspection, verbose errors and missing query-depth limits each expand "
                     "the attack surface."),
        severity=Severity.INFO,
        recommendation=("Ensure introspection is disabled in production, errors are generic, a query "
                        "depth/complexity limit is enforced, and rate limiting is in place."),
        raw={"endpoint": url, "confidence": "high",
             "evidence": ev.from_response(resp, indicator="responded to a GraphQL __typename query")},
    )]

    # Introspection enabled?
    intro = _post_query(engine, url, _INTROSPECT_Q)
    idata = _as_json(intro)
    schema = (idata or {}).get("data", {}).get("__schema") if isinstance(idata, dict) else None
    if isinstance(schema, dict) and schema.get("types"):
        type_count = len(schema.get("types") or [])
        findings.append(Finding(
            module=MODULE,
            title=f"GraphQL Introspection Enabled: {urlparse(url).path or '/'}",
            description=(f"Schema introspection is enabled at {url}: a standard introspection query "
                         f"returned the full schema ({type_count} types). An attacker can download every "
                         "type, field, argument and mutation — a complete map of the API."),
            severity=Severity.MEDIUM,
            recommendation=("Disable introspection in production (e.g. Apollo `introspection: false`, "
                            "graphql-php disable introspection, or a validation rule that rejects "
                            "`__schema`/`__type` queries)."),
            raw={"endpoint": url, "types": type_count, "confidence": "high", "verified": True,
                 "verification": "full schema returned by a standard introspection query",
                 "evidence": ev.from_response(intro, indicator=f"__schema returned {type_count} types")},
        ))

    # Field suggestions ("Did you mean …") leak field names even without introspection.
    sug = _post_query(engine, url, _SUGGEST_Q)
    if sug is not None and "did you mean" in sug.text.lower():
        findings.append(Finding(
            module=MODULE,
            title=f"GraphQL Field Suggestions Enabled: {urlparse(url).path or '/'}",
            description=(f"The endpoint {url} returns 'Did you mean …' field suggestions on invalid "
                         "queries. This leaks valid field names and lets an attacker reconstruct the "
                         "schema even when introspection is disabled."),
            severity=Severity.LOW,
            recommendation=("Disable field suggestions in production (e.g. graphql-js "
                            "`NoSchemaIntrospectionCustomRule` and a formatter that strips suggestions)."),
            raw={"endpoint": url, "confidence": "high",
                 "evidence": ev.from_response(sug, indicator="error contained 'Did you mean'")},
        ))

    return findings


def run(engine: ScanEngine) -> list[Finding]:
    findings: list[Finding] = []
    probed = 0
    for url in _candidates(engine):
        probed += 1
        result = _probe_endpoint(engine, url)
        if result:
            findings.extend(result)

    if not findings:
        return [Finding(MODULE, "GraphQL: No Endpoint Detected",
                        f"Probed {probed} conventional GraphQL path(s); none responded as a GraphQL "
                        "endpoint.",
                        Severity.INFO, "", {"paths_probed": probed, "confidence": "high"})]
    logger.info(f"graphql_detect: {len(findings)} finding(s) across the GraphQL surface")
    return findings
