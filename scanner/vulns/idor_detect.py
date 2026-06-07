"""
idor_detect — Insecure Direct Object Reference (IDOR) / Broken Object Level Authorization (BOLA).

Hades finds object-reference inputs (integer / UUID / hex ids in URL parameters and path segments
whose name looks like an object reference) and tests two access-control failures:

  * **Horizontal enumeration (IDOR):** tampering the id returns a *different but valid* object in
    the same page template — the app may be serving another user's record without an ownership check.
  * **Missing access control (BOLA):** when scanning with a session (``--login-url``), the same object
    is *also* returned to an anonymous client — it isn't protected by the login at all.

Read-only GETs only, volume-capped, skipped in safe mode. Each finding carries a clickable proof URL.
Confidence is deliberately ``medium`` (these need a human to confirm the objects are private/owned by
different users), matching Hades' "proof, not noise" stance.
"""
from __future__ import annotations

import difflib
import random
import re
import string
from dataclasses import dataclass
from typing import Callable
from urllib.parse import parse_qs, urlparse, urlunparse

import httpx
from loguru import logger

from scanner.engine import Finding, ScanEngine, Severity
from scanner.vulns._common import get, inject_param, is_safe_mode

MODULE = "idor_detect"

# Param / path-collection names that commonly carry an owned object reference (gate + confidence).
_ID_NAMES = {
    "id", "uid", "userid", "user_id", "user", "users", "account", "accountid", "accounts", "acct",
    "order", "orderid", "orders", "oid", "doc", "docid", "document", "documents", "file", "fileid",
    "files", "pid", "num", "number", "no", "invoice", "invoices", "key", "profile", "profiles",
    "customer", "customers", "cid", "item", "items", "record", "records", "rid", "ref", "object",
    "msg", "message", "messages", "ticket", "tickets", "report", "reports", "note", "notes",
    "comment", "comments", "group", "groups", "team", "teams", "project", "projects",
}

_INT_RE = re.compile(r"^\d{1,12}$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{16,64}$")

_MAX_LOCI = 12
_MAX_PROBES = 5


@dataclass
class _Ref:
    label: str
    base_url: str
    value: str
    build: Callable[[str], str]   # build a URL with a replacement reference value
    is_int: bool
    name_hint: bool               # the param/collection name looks like an object reference


def _rand(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text or "")[:6000]


def _ratio(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, _norm(a), _norm(b)).ratio()


def _looks_like_login(text: str) -> bool:
    t = (text or "").lower()
    return ('type="password"' in t or "type='password'" in t
            or ("sign in" in t and "password" in t) or ("log in" in t and "password" in t))


def _value_kind(value: str) -> tuple[bool, bool]:
    """(is_object_ref, is_integer) for a parameter/segment value."""
    if _INT_RE.match(value) and value != "0":
        return True, True
    if _UUID_RE.match(value) or _HEX_RE.match(value):
        return True, False
    return False, False


def _discover(engine: ScanEngine) -> list[_Ref]:
    crawl = engine.get_crawl()
    param_urls = list(crawl.parametrised_urls)
    if urlparse(engine.url).query:
        param_urls.insert(0, engine.url)
    refs: list[_Ref] = []
    seen: set[str] = set()

    # URL parameters carrying an object reference.
    for url in param_urls:
        for param, vals in parse_qs(urlparse(url).query, keep_blank_values=True).items():
            value = vals[0] if vals else ""
            ref_ok, is_int = _value_kind(value)
            if not ref_ok:
                continue
            key = f"param:{param}"
            if key in seen:
                continue
            seen.add(key)
            refs.append(_Ref(
                label=f"URL parameter '{param}'",
                base_url=url, value=value, is_int=is_int,
                name_hint=param.lower() in _ID_NAMES,
                build=(lambda v, u=url, p=param: inject_param(u, p, v)),
            ))

    # Numeric / UUID path segments (e.g. /users/123, /api/order/4567).
    for url in param_urls + list(crawl.internal_links):
        parsed = urlparse(url)
        parts = parsed.path.split("/")
        for i, seg in enumerate(parts):
            ref_ok, is_int = _value_kind(seg)
            if not ref_ok:
                continue
            collection = parts[i - 1] if i > 0 else ""
            key = f"path:{parsed.path}:{i}"
            if key in seen:
                continue
            seen.add(key)

            def _build(v: str, parts=parts, i=i, parsed=parsed) -> str:
                new = list(parts)
                new[i] = v
                return urlunparse(parsed._replace(path="/".join(new)))

            refs.append(_Ref(
                label=f"path segment after '/{collection}/'" if collection else "path segment",
                base_url=url, value=seg, is_int=is_int,
                name_hint=collection.lower() in _ID_NAMES,
                build=_build,
            ))
        if len(refs) >= _MAX_LOCI * 3:
            break

    # Prefer id-like references; only those are probed (keeps catalogue params out of the noise).
    refs.sort(key=lambda r: not r.name_hint)
    return [r for r in refs if r.name_hint][:_MAX_LOCI]


def _int_neighbours(value: str) -> list[str]:
    n = int(value)
    out: list[str] = []
    for c in (n + 1, n - 1, n + 2, 1, max(n // 2, 1)):
        if c >= 0 and str(c) != value and str(c) not in out:
            out.append(str(c))
    return out[:_MAX_PROBES]


def _check_missing_authz(engine: ScanEngine, ref: _Ref, base: httpx.Response, soft404: str):
    """When authenticated: is the same object also served to an anonymous client? (BOLA)"""
    if not getattr(engine, "authenticated", False):
        return None
    try:
        anon = engine.request_anonymous("GET", ref.base_url)
    except httpx.HTTPError:
        return None
    if anon.status_code != 200 or len(anon.text) < 200:
        return None
    if soft404 and _ratio(anon.text, soft404) > 0.9:
        return None
    if _looks_like_login(anon.text):
        return None                                  # anon hit the login wall → access IS controlled
    r = _ratio(anon.text, base.text)
    if r < 0.9:
        return None                                  # anon got something different → controlled
    return Finding(
        module=MODULE,
        title=f"Broken access control — object readable without a session ({ref.label})",
        description=(f"The object at {ref.base_url} is returned to an anonymous client almost "
                     f"identically to the authenticated response (similarity {r:.2f}); it is not "
                     f"protected by the login. Confirm the object should require authentication."),
        severity=Severity.HIGH,
        raw={"url": ref.base_url, "proof_url": ref.base_url, "param": ref.label,
             "confidence": "medium",
             "evidence": [f"authenticated vs anonymous response similarity {r:.2f} (same object)"]},
    )


def _check_enumeration(engine: ScanEngine, ref: _Ref, base: httpx.Response, soft404: str):
    """Tampering an integer id returns a different but valid object in the same template (IDOR)."""
    if not ref.is_int:
        return None
    base_login = _looks_like_login(base.text)
    for nv in _int_neighbours(ref.value):
        resp = get(engine, ref.build(nv))
        if resp is None or resp.status_code != 200 or len(resp.text) < 200:
            continue
        if soft404 and _ratio(resp.text, soft404) > 0.9:
            continue
        if _looks_like_login(resp.text) and not base_login:
            continue
        r = _ratio(resp.text, base.text)
        if 0.55 <= r < 0.985:                        # same page type, different data → other object
            return Finding(
                module=MODULE,
                title=f"Possible IDOR — {ref.label} exposes other objects (id {ref.value} → {nv})",
                description=(f"Changing the id to {nv} returns a different but valid object in the "
                             f"same template (similarity {r:.2f}); the app may lack an ownership "
                             f"check. Verify the two objects belong to different users."),
                severity=Severity.HIGH,
                raw={"url": ref.build(nv), "proof_url": ref.build(nv), "param": ref.label,
                     "confidence": "medium",
                     "evidence": [f"id {ref.value} vs {nv}: 200 OK, content similarity {r:.2f} "
                                  f"(distinct object, same page type)"]},
            )
    return None


def run(engine: ScanEngine) -> list[Finding]:
    if is_safe_mode(engine):
        logger.debug("idor_detect: safe mode — skipping active access-control probes")
        return []

    refs = _discover(engine)
    if not refs:
        return []

    # Soft-404 / catch-all baseline: a random path that should not exist.
    soft404 = ""
    sresp = get(engine, f"{engine.url}/hades_idor_{_rand()}")
    if sresp is not None:
        soft404 = sresp.text

    findings: list[Finding] = []
    seen_titles: set[str] = set()
    for ref in refs:
        base = get(engine, ref.base_url)
        if base is None or base.status_code != 200 or len(base.text) < 200:
            continue
        if soft404 and _ratio(base.text, soft404) > 0.9:
            continue                                 # the 'object' is really the catch-all page

        finding = (_check_missing_authz(engine, ref, base, soft404)
                   or _check_enumeration(engine, ref, base, soft404))
        if finding and finding.title not in seen_titles:
            seen_titles.add(finding.title)
            findings.append(finding)

    if findings:
        logger.info(f"idor_detect: {len(findings)} access-control finding(s)")
    return findings
