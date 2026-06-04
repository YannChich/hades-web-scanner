"""
xss_detect — context-aware reflected XSS detection on URL parameters and form fields.

Rather than only checking "does the payload appear unencoded", this works the way modern
scanners do:
  1. Inject a harmless alphanumeric canary and find WHERE it is reflected — HTML text, an
     HTML attribute (single/double/unquoted), inside a <script> string, or an HTML comment.
  2. For each context, inject the minimal breakout sequence needed to escape it and check
     whether the breakout characters survive unencoded. A successful breakout is a real
     reflected-XSS (High); a reflection whose special characters are encoded is reported as
     Low (likely sanitised — verify the context).

Detects reflection/breakout only; it does not execute JS, test DOM/stored XSS, or bypass CSP.
Active probing is skipped in safe mode.
"""
from __future__ import annotations

import re
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx
from loguru import logger

from config import SAFE_MODE_RATE_DELAY
from scanner.crawler import Form
from scanner.engine import Finding, Severity, ScanEngine

MODULE = "xss_detect"

_ENCODED = ("&lt;", "&gt;", "&quot;", "&#x27;", "&#39;", "&amp;", "%3c", "%3e")

InjectFn = Callable[[str], "httpx.Response | None"]


# ---------------------------------------------------------------------------
# Context classification
# ---------------------------------------------------------------------------

def _enclosing_quote(segment: str) -> str:
    if segment.count('"') % 2 == 1:
        return '"'
    if segment.count("'") % 2 == 1:
        return "'"
    return ""


def _classify_context(html: str, canary: str) -> set[str]:
    """Return the reflection context(s) of *canary* in *html*."""
    contexts: set[str] = set()
    for m in re.finditer(re.escape(canary), html):
        before = html[:m.start()]
        if before.rfind("<!--") > before.rfind("-->"):
            contexts.add("comment")
        elif before.rfind("<script") > before.rfind("</script"):
            seg = before[before.rfind("<script"):]
            # strip the opening tag so its quotes don't skew the count
            seg = seg.split(">", 1)[1] if ">" in seg else seg
            contexts.add("js_string" if _enclosing_quote(seg) else "js")
        elif before.rfind("<") > before.rfind(">"):
            q = _enclosing_quote(before[before.rfind("<"):])
            contexts.add("attr_double" if q == '"' else "attr_single" if q == "'" else "attr_unquoted")
        else:
            contexts.add("html_text")
    return contexts


def _breakout(ctx: str, nonce: str) -> tuple[str, Callable[[str], bool]]:
    """Return (payload, success_check) that proves a breakout from *ctx*."""
    tag = f"<q{nonce}>"
    if ctx in ("html_text", "html"):
        return tag, lambda t: tag in t
    if ctx == "comment":
        return "-->" + tag, lambda t: ("-->" + tag) in t
    if ctx == "attr_double":
        return '">' + tag, lambda t: ('">' + tag) in t
    if ctx == "attr_single":
        return "'>" + tag, lambda t: ("'>" + tag) in t
    if ctx == "attr_unquoted":
        return f" onq{nonce}=1>{tag}", lambda t: tag in t
    if ctx == "js":
        payload = f";q{nonce}();"
        return payload, lambda t: re.search(r"<script[^>]*>[^<]*" + re.escape(payload), t) is not None
    if ctx == "js_string":
        payload = f"';q{nonce}='"
        return payload, lambda t: re.search(r"(?<!\\)';q" + re.escape(nonce), t) is not None
    return tag, lambda t: tag in t


_CTX_LABEL = {
    "html_text": "HTML text", "html": "HTML", "comment": "HTML comment",
    "attr_double": 'double-quoted attribute', "attr_single": "single-quoted attribute",
    "attr_unquoted": "unquoted attribute", "js": "inline <script>", "js_string": "JS string",
}


# ---------------------------------------------------------------------------
# Finding factory
# ---------------------------------------------------------------------------

def _finding(where: str, ctx: str, payload: str, severity: Severity, confidence: str,
             proof_url: str | None = None) -> Finding:
    if severity == Severity.LOW:
        title = f"Reflected Input (encoded): {where}"
        desc = (f"Input to {where} is reflected in the response but its special characters are "
                "encoded, so it is likely not exploitable. Verify the exact context manually.")
    else:
        title = f"Reflected XSS: {where} [{_CTX_LABEL.get(ctx, ctx)}]"
        desc = (f"Input to {where} is reflected in a {_CTX_LABEL.get(ctx, ctx)} context and a breakout "
                f"payload survived unencoded (payload: {payload!r}). This is an exploitable reflected XSS.")
        if proof_url:
            desc += ("\n\nThe clickable proof link opens the injected request — in a browser it may "
                     "execute the payload (e.g. pop an alert). Verify/exploit with dalfox:\n"
                     f'  dalfox url "{proof_url}"')
    raw = {"location": where, "context": ctx, "payload": payload, "confidence": confidence}
    if proof_url:
        raw["proof_url"] = proof_url
    return Finding(
        module=MODULE, title=title, description=desc,
        severity=severity,
        recommendation=("Context-encode all user input on output (HTML/attribute/JS/URL encoding as "
                        "appropriate), prefer auto-escaping templates, and add a strict Content-Security-Policy."),
        raw=raw,
    )


# ---------------------------------------------------------------------------
# Core test
# ---------------------------------------------------------------------------

def _probe(inject: InjectFn, where: str,
           proof: Callable[[str], str] | None = None) -> Finding | None:
    nonce = uuid.uuid4().hex[:10]
    canary = f"hx{nonce}"
    resp = inject(canary)
    if resp is None or canary not in resp.text:
        return None

    for ctx in _classify_context(resp.text, canary):
        payload, success = _breakout(ctx, nonce)
        r2 = inject(payload)
        if r2 is not None and success(r2.text):
            proof_url = proof(payload) if proof else None
            return _finding(where, ctx, payload, Severity.HIGH, "high", proof_url)

    # Reflected but no breakout achieved → likely encoded/sanitised.
    return _finding(where, "reflected", canary, Severity.LOW, "low")


# ---------------------------------------------------------------------------
# Injection helpers
# ---------------------------------------------------------------------------

def _inject_url_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


def _get(engine: ScanEngine, url: str) -> httpx.Response | None:
    try:
        return engine.request("GET", url)
    except httpx.HTTPError as exc:
        logger.debug(f"xss_detect: {url} → {exc}")
        return None


def _url_injector(engine: ScanEngine, url: str, param: str) -> InjectFn:
    return lambda payload: _get(engine, _inject_url_param(url, param, payload))


def _form_injector(engine: ScanEngine, form: Form, field: str) -> InjectFn:
    def inject(payload: str) -> httpx.Response | None:
        data = {**form.fields, field: payload}
        try:
            if form.method == "post":
                return engine.request("POST", form.action, data=data)
            return engine.request("GET", form.action, params=data)
        except httpx.HTTPError as exc:
            logger.debug(f"xss_detect: form {form.action} → {exc}")
            return None
    return inject


def _is_safe_mode(engine: ScanEngine) -> bool:
    try:
        return engine._rate_limiter._delay >= SAFE_MODE_RATE_DELAY
    except AttributeError:
        return False


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(engine: ScanEngine) -> list[Finding]:
    if _is_safe_mode(engine):
        logger.info("xss_detect: safe mode — skipping")
        return [Finding(MODULE, "XSS Scan Skipped (Safe Mode)",
                        "Active XSS probing was skipped because safe mode is enabled.",
                        Severity.INFO, "Re-run without safe mode on an authorised target.",
                        {"reason": "safe_mode", "confidence": "high"})]

    crawl = engine.get_crawl()
    candidate_urls = list(crawl.parametrised_urls)
    if urlparse(engine.url).query and engine.url not in candidate_urls:
        candidate_urls.insert(0, engine.url)

    seen: set[str] = set()
    url_work: list[tuple[str, str]] = []
    for url in candidate_urls:
        for param in parse_qs(urlparse(url).query, keep_blank_values=True):
            if param not in seen:
                seen.add(param)
                url_work.append((url, param))

    form_work: list[tuple[Form, str]] = []
    for form in crawl.forms:
        for field in form.fields:
            if field not in seen:
                seen.add(field)
                form_work.append((form, field))

    if not url_work and not form_work:
        return [Finding(MODULE, "XSS: No Injectable Parameters Found",
                        "No URL parameters or form inputs were discovered to test.",
                        Severity.INFO, "", {"scanned_url": engine.url, "confidence": "high"})]

    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=engine.threads) as pool:
        futures = []
        for url, param in url_work:
            proof = (lambda payload, u=url, p=param: _inject_url_param(u, p, payload))
            futures.append(pool.submit(_probe, _url_injector(engine, url, param),
                                       f"URL parameter '{param}'", proof))
        for form, field in form_work:
            # POST forms have no shareable GET proof URL.
            futures.append(pool.submit(_probe, _form_injector(engine, form, field),
                                       f"form field '{field}' ({form.method.upper()} {form.action})"))
        for future in as_completed(futures):
            result = future.result()
            if result:
                findings.append(result)

    if not findings:
        total = len(url_work) + len(form_work)
        return [Finding(MODULE, "XSS: No Reflection Detected",
                        f"Tested {total} input(s) with context-aware probes; no reflection was found.",
                        Severity.INFO, "", {"inputs_tested": total, "confidence": "high"})]
    return findings
