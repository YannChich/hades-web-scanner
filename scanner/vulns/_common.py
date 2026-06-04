"""
_common — shared plumbing for the active injection modules (cmd, ssti, lfi, open_redirect,
ssrf). It pulls injectable inputs from the shared crawl and exposes a single uniform
"injector" abstraction so each module only has to write its payloads and its verification.

An Injector knows how to send one payload (into a URL parameter or a form field) and, for
URL parameters, how to build the exact proof URL (used for the clickable verification link).
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx
from loguru import logger

from config import SAFE_MODE_RATE_DELAY
from scanner.engine import ScanEngine

InjectFn = Callable[[str], "httpx.Response | None"]
ProofFn = Callable[[str], str]


@dataclass
class Injector:
    label: str                 # human description, e.g. "URL parameter 'id'"
    param: str                 # the parameter/field name
    inject: InjectFn           # send a payload, return the response (or None)
    proof: ProofFn | None      # build the proof URL for a payload (None for POST forms)
    url: str | None = None     # base URL carrying the param (for sqlmap -u); None for forms


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_safe_mode(engine: ScanEngine) -> bool:
    try:
        return engine._rate_limiter._delay >= SAFE_MODE_RATE_DELAY
    except AttributeError:
        return False


def inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


def get(engine: ScanEngine, url: str, **kwargs) -> "httpx.Response | None":
    try:
        return engine.request("GET", url, **kwargs)
    except httpx.HTTPError as exc:
        logger.debug(f"inject: GET {url} → {exc}")
        return None


def timed_get(engine: ScanEngine, url: str, **kwargs) -> float | None:
    """Return the wall-clock seconds of a GET, or None on error."""
    start = time.monotonic()
    try:
        engine.request("GET", url, **kwargs)
    except httpx.HTTPError:
        return None
    return time.monotonic() - start


def similar(a: str, b: str, tol: float = 0.05) -> bool:
    la, lb = len(a), len(b)
    return abs(la - lb) / max(la, lb, 1) <= tol


# ---------------------------------------------------------------------------
# Injector enumeration (URL params + form fields, deduped by name)
# ---------------------------------------------------------------------------

def _form_inject(engine: ScanEngine, form, field: str) -> InjectFn:
    def inject(payload: str) -> "httpx.Response | None":
        data = {**form.fields, field: payload}
        try:
            if form.method == "post":
                return engine.request("POST", form.action, data=data)
            return engine.request("GET", form.action, params=data)
        except httpx.HTTPError as exc:
            logger.debug(f"inject: form {form.action} → {exc}")
            return None
    return inject


def iter_injectors(engine: ScanEngine) -> list[Injector]:
    """Every unique URL parameter and form field discovered by the shared crawl."""
    crawl = engine.get_crawl()
    candidate_urls = list(crawl.parametrised_urls)
    if urlparse(engine.url).query and engine.url not in candidate_urls:
        candidate_urls.insert(0, engine.url)

    injectors: list[Injector] = []
    seen: set[str] = set()

    for url in candidate_urls:
        for param in parse_qs(urlparse(url).query, keep_blank_values=True):
            if param in seen:
                continue
            seen.add(param)
            injectors.append(Injector(
                label=f"URL parameter '{param}'",
                param=param,
                inject=(lambda payload, u=url, p=param: get(engine, inject_param(u, p, payload))),
                proof=(lambda payload, u=url, p=param: inject_param(u, p, payload)),
                url=url,
            ))

    for form in crawl.forms:
        for field in form.fields:
            if field in seen:
                continue
            seen.add(field)
            injectors.append(Injector(
                label=f"form field '{field}' ({form.method.upper()} {form.action})",
                param=field,
                inject=_form_inject(engine, form, field),
                proof=None,
            ))

    return injectors
