"""
idor_detect — Insecure Direct Object Reference (IDOR) / Broken Object Level Authorization (BOLA).

Hades finds object-reference inputs (integer / UUID / hex ids in URL parameters and path segments
whose name looks like an object reference) and tests two access-control failures:

  * **Horizontal enumeration (IDOR):** tampering the id returns a *different but valid* object — the
    app may be serving another user's record without an ownership check.
  * **Missing access control (BOLA):** when scanning with a session (``--login-url``), the same object
    is *also* returned to an anonymous client — it isn't protected by the login at all.

It is **JSON/API-aware** (compares object schemas + values, not just HTML text) and **calibrates to
each page's own variability** (a self-baseline "noise floor") so dynamic pages don't cause false
positives. Read-only GETs only, volume-capped, threaded, skipped in safe mode. Each finding carries a
clickable proof URL and a copy-paste ``curl`` PoC. Detection-only — nothing is modified.
"""
from __future__ import annotations

import difflib
import json
import random
import re
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Optional
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
    # APIs, commerce & bookings — high-value owned objects
    "payment", "payments", "paymentid", "transaction", "transactions", "tx", "booking", "bookings",
    "reservation", "reservations", "subscription", "subscriptions", "address", "addresses", "card",
    "cards", "cart", "cartid", "session", "sid", "post", "posts", "entry", "entries", "node",
}

_INT_RE = re.compile(r"^\d{1,12}$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{16,64}$")

_MAX_LOCI = 12
_MAX_PROBES = 5
_MAX_WORKERS = 8
_MIN_BODY = 64          # smaller than a real object; compact JSON objects are allowed separately


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


# ---------------------------------------------------------------------------
# Response comparison (JSON-aware) — the heart of the accuracy work
# ---------------------------------------------------------------------------

def _json_body(resp: "httpx.Response | None"):
    """Parse a response as JSON, or None if it isn't JSON."""
    if resp is None:
        return None
    body = resp.text or ""
    if "json" not in resp.headers.get("content-type", "").lower() and body.lstrip()[:1] not in ("{", "["):
        return None
    try:
        return json.loads(body)
    except (ValueError, TypeError):
        return None


def _flatten(obj, prefix: str = ""):
    """Yield (path, leaf_value) pairs so two JSON objects can be compared by shape and by values."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _flatten(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:60]):
            yield from _flatten(v, f"{prefix}[{i}]")
    else:
        yield (prefix, obj)


def _json_sim(a, b) -> tuple[float, float]:
    """(structure_similarity, value_similarity) of two parsed JSON bodies, each in 0..1."""
    fa, fb = dict(_flatten(a)), dict(_flatten(b))
    ka, kb = set(fa), set(fb)
    if not ka and not kb:
        return 1.0, 1.0
    structure = len(ka & kb) / max(len(ka | kb), 1)
    shared = ka & kb
    value = (sum(1 for k in shared if fa[k] == fb[k]) / len(shared)) if shared else 0.0
    return structure, value


def _same_object(a: "httpx.Response", b: "httpx.Response") -> bool:
    """Do two responses represent essentially the SAME object? (used for the BOLA check)."""
    ja, jb = _json_body(a), _json_body(b)
    if ja is not None and jb is not None:
        s, v = _json_sim(ja, jb)
        return s >= 0.7 and v >= 0.9
    return _ratio(a.text, b.text) >= 0.9


def _different_valid_object(base: "httpx.Response", other: "httpx.Response", noise: float) -> bool:
    """Is *other* a DIFFERENT but valid object of the same type as *base*? (the IDOR signal).

    JSON: same schema, different values. HTML: similar enough to be the same template, but more
    different than the page's own self-variation (*noise*) — so dynamic pages don't false-positive.
    """
    jb, jo = _json_body(base), _json_body(other)
    if jb is not None and jo is not None:
        s, v = _json_sim(jb, jo)
        return s >= 0.6 and v < 0.9
    upper = min(0.985, noise - 0.02) if noise < 1.0 else 0.985
    return 0.5 <= _ratio(base.text, other.text) < upper


def _value_kind(value: str) -> tuple[bool, bool]:
    """(is_object_ref, is_integer) for a parameter/segment value."""
    if _INT_RE.match(value) and value != "0":
        return True, True
    if _UUID_RE.match(value) or _HEX_RE.match(value):
        return True, False
    return False, False


def _meaningful(resp: "httpx.Response | None", soft404: str) -> bool:
    """A real object response: 200, with content, and not the catch-all/soft-404 page."""
    if resp is None or resp.status_code != 200:
        return False
    if _json_body(resp) is not None:
        return len((resp.text or "").strip()) >= 8          # any non-empty JSON object
    if len(resp.text) < _MIN_BODY:
        return False
    return not (soft404 and _ratio(resp.text, soft404) > 0.9)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def _discover(engine: ScanEngine) -> list[_Ref]:
    crawl = engine.get_crawl()
    param_urls = list(crawl.parametrised_urls)
    if urlparse(engine.url).query:
        param_urls.insert(0, engine.url)
    refs: list[_Ref] = []
    seen: set[str] = set()

    for url in param_urls:
        for param, vals in parse_qs(urlparse(url).query, keep_blank_values=True).items():
            value = vals[0] if vals else ""
            ref_ok, is_int = _value_kind(value)
            if not ref_ok or f"param:{param}" in seen:
                continue
            seen.add(f"param:{param}")
            refs.append(_Ref(
                label=f"URL parameter '{param}'", base_url=url, value=value, is_int=is_int,
                name_hint=param.lower() in _ID_NAMES,
                build=(lambda v, u=url, p=param: inject_param(u, p, v)),
            ))

    for url in param_urls + list(crawl.internal_links):
        parsed = urlparse(url)
        parts = parsed.path.split("/")
        for i, seg in enumerate(parts):
            ref_ok, is_int = _value_kind(seg)
            if not ref_ok or f"path:{parsed.path}:{i}" in seen:
                continue
            seen.add(f"path:{parsed.path}:{i}")
            collection = parts[i - 1] if i > 0 else ""

            def _build(v: str, parts=parts, i=i, parsed=parsed) -> str:
                new = list(parts)
                new[i] = v
                return urlunparse(parsed._replace(path="/".join(new)))

            refs.append(_Ref(
                label=f"path segment after '/{collection}/'" if collection else "path segment",
                base_url=url, value=seg, is_int=is_int,
                name_hint=collection.lower() in _ID_NAMES, build=_build,
            ))
        if len(refs) >= _MAX_LOCI * 3:
            break

    # Only id-like references are probed (keeps catalogue params out of the noise).
    refs.sort(key=lambda r: not r.name_hint)
    return [r for r in refs if r.name_hint][:_MAX_LOCI]


def _int_neighbours(value: str) -> list[str]:
    n = int(value)
    out: list[str] = []
    for c in (n + 1, n - 1, n + 2, 1, max(n // 2, 1)):
        if c >= 0 and str(c) != value and str(c) not in out:
            out.append(str(c))
    return out[:_MAX_PROBES]


def _ctype(resp: "httpx.Response") -> str:
    return (resp.headers.get("content-type", "").split(";")[0] or "?")


# ---------------------------------------------------------------------------
# The two checks
# ---------------------------------------------------------------------------

def _check_missing_authz(engine: ScanEngine, ref: _Ref, base: "httpx.Response", soft404: str):
    """When authenticated: is the same object also served to an anonymous client? (BOLA)."""
    if not getattr(engine, "authenticated", False):
        return None
    try:
        anon = engine.request_anonymous("GET", ref.base_url)
    except Exception:  # noqa: BLE001
        return None
    if not _meaningful(anon, soft404) or _looks_like_login(anon.text):
        return None                                  # anon hit the login wall → access IS controlled
    if not _same_object(anon, base):
        return None                                  # anon got something different → controlled
    return Finding(
        module=MODULE,
        title=f"Broken access control — object served without a session ({ref.label})",
        description=(f"The object at {ref.base_url} is returned to an anonymous client (no cookie or "
                     f"token), essentially identically to the authenticated response — it is not "
                     f"protected by the login. Confirm the object should require authentication."),
        severity=Severity.HIGH,
        poc=f'curl -sk "{ref.base_url}"   # returns the object with no session/token',
        raw={"url": ref.base_url, "proof_url": ref.base_url, "param": ref.label, "confidence": "high",
             "evidence": [
                 f"authenticated and anonymous requests return the same object [{_ctype(anon)}]",
                 f"anonymous response: {anon.status_code}, {len(anon.text)} bytes",
             ],
             "exploitation": [
                 {"step": 1, "description": "Re-fetch the object with no cookie/token to confirm unauthenticated access.",
                  "command": f'curl -sk "{ref.base_url}"'},
                 {"step": 2, "description": "Replay it from a clean browser/incognito to prove the access-control gap.",
                  "command": f'curl -sk -A "Mozilla/5.0" "{ref.base_url}"'}]},
    )


def _check_enumeration(engine: ScanEngine, ref: _Ref, base: "httpx.Response", soft404: str):
    """Tampering an integer id returns a different but valid object (IDOR)."""
    if not ref.is_int:
        return None
    base_login = _looks_like_login(base.text)
    noise = _self_noise(engine, ref, base)
    for nv in _int_neighbours(ref.value):
        resp = get(engine, ref.build(nv))
        if not _meaningful(resp, soft404):
            continue
        if _looks_like_login(resp.text) and not base_login:
            continue
        if _different_valid_object(base, resp, noise):
            is_json = _json_body(resp) is not None
            how = ("a different JSON object (same schema, different values)" if is_json
                   else "a different object in the same page template")
            return Finding(
                module=MODULE,
                title=f"Possible IDOR — {ref.label} exposes other objects (id {ref.value} → {nv})",
                description=(f"Changing the id from {ref.value} to {nv} returns {how}; the app may "
                            f"lack an ownership check. Verify the two objects belong to different users."),
                severity=Severity.HIGH,
                poc=f'curl -sk "{ref.build(nv)}"   # object {nv} (you are {ref.value})',
                raw={"url": ref.build(nv), "proof_url": ref.build(nv), "param": ref.label,
                     "confidence": "medium",
                     "evidence": [
                         f"id {ref.value} → {nv}: 200 OK [{_ctype(resp)}] — a distinct valid object",
                         ("JSON schema matches, values differ" if is_json
                          else f"page self-variation (noise) baseline {noise:.2f}"),
                     ],
                     "exploitation": [
                         {"step": 1, "description": f"Confirm the cross-object read (you are {ref.value}, this is {nv}).",
                          "command": f'curl -sk "{ref.build(nv)}"'},
                         {"step": 2, "description": f"Harvest the full range by fuzzing the {ref.label} value.",
                          "command": f'ffuf -w <(seq 1 1000) -u "{ref.build(nv)}"   # replace the id with FUZZ'}]},
            )
    return None


def _self_noise(engine: ScanEngine, ref: _Ref, base: "httpx.Response") -> float:
    """How much the *same* object's response varies between two fetches (1.0 = perfectly stable).

    JSON is compared structurally, so it needs no text-noise floor (returns 1.0). For HTML, a second
    fetch of the base URL measures the page's own churn (timestamps/tokens/ads) so dynamic pages
    aren't mistaken for "different objects".
    """
    if _json_body(base) is not None:
        return 1.0
    try:
        base2 = engine.request("GET", ref.base_url)
        return _ratio(base.text, base2.text)
    except Exception:  # noqa: BLE001 — mocks/streamed bodies can't be re-read; fall back to no floor
        return 1.0


def _check_locus(engine: ScanEngine, ref: _Ref, soft404: str) -> Optional[Finding]:
    base = get(engine, ref.base_url)
    if not _meaningful(base, soft404):
        return None
    return _check_missing_authz(engine, ref, base, soft404) or _check_enumeration(engine, ref, base, soft404)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

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

    # Warm the anonymous client once (single-threaded) so the per-locus threads never race to build it.
    if getattr(engine, "authenticated", False):
        try:
            engine.request_anonymous("GET", engine.url)
        except Exception:  # noqa: BLE001
            pass

    findings: list[Finding] = []
    seen_titles: set[str] = set()
    workers = max(1, min(getattr(engine, "threads", 4) or 4, len(refs), _MAX_WORKERS))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_check_locus, engine, ref, soft404) for ref in refs]
        for fut in as_completed(futures):
            try:
                finding = fut.result()
            except Exception as exc:  # noqa: BLE001 — one locus must never abort the module
                logger.debug(f"idor_detect: locus failed: {exc}")
                finding = None
            if finding and finding.title not in seen_titles:
                seen_titles.add(finding.title)
                findings.append(finding)

    if findings:
        logger.info(f"idor_detect: {len(findings)} access-control finding(s)")
    return findings
