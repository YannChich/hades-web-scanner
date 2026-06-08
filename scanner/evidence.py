"""
evidence — builds the standardised proof attached to every actionable finding.

Each finding stores a ``raw["evidence"]`` ``list[str]``: short, human-readable lines showing exactly
what Hades sent and what came back, so a reader can verify the finding at a glance without re-running
the scan. This module is the single source of that format (it mirrors how ``_common.py`` centralises
the injector plumbing). ``report_json`` already serialises ``raw["evidence"]``; ``console`` and
``report_html`` render it. The convention pre-dates this module (``idor_detect``, ``hephaestus_tls``)
— here it is generalised so every module produces consistent, structured evidence.

Lines look like::

    GET /admin?id=1 → 200 OK, 5.1 KB (text/html)
    matched: login form (action=/login) + 'Sign in' button
    differs from soft-404 baseline (Δ4.7 KB, distinct body)

Snippets are always sanitised (whitespace collapsed, control chars stripped, length capped) and should
only ever be the *proof itself* (e.g. a reflected payload echo) — never raw secret values.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urlsplit

if TYPE_CHECKING:
    import httpx

_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WS_RE = re.compile(r"\s+")

_SNIPPET_MAX = 160


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _sanitize(text: str, n: int = _SNIPPET_MAX) -> str:
    """Collapse whitespace, strip control characters and cap length — safe for a one-line snippet."""
    if not text:
        return ""
    cleaned = _WS_RE.sub(" ", _CTRL_RE.sub("", str(text))).strip()
    return cleaned[:n] + ("…" if len(cleaned) > n else "")


def _human_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.1f} MB"


def _path_of(url: Any) -> str:
    """The path+query of a URL, for a compact, readable request line."""
    parts = urlsplit(str(url))
    pq = parts.path or "/"
    if parts.query:
        pq += "?" + parts.query
    return pq


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

def request_line(resp: Any) -> str:
    """A single `METHOD path → status reason, size (ctype)` line from a live response.

    Fully defensive: works with a real ``httpx.Response`` and with lightweight stub objects that only
    expose ``text``/``status_code``. Any attribute that is missing (request, headers, content, reason)
    is simply omitted, so an evidence line is always producible.
    """
    method = path = ""
    try:
        req = resp.request
        method, path = req.method, _path_of(req.url)
    except Exception:           # noqa: BLE001 — no attached request / stub object
        method = path = ""

    ctype = ""
    try:
        ctype = resp.headers.get("content-type", "").split(";")[0].strip()
    except Exception:           # noqa: BLE001
        ctype = ""

    size = ""
    try:
        size = _human_size(len(resp.content))
    except Exception:           # noqa: BLE001 — fall back to text length for stubs
        try:
            size = _human_size(len(resp.text))
        except Exception:       # noqa: BLE001
            size = ""

    reason = (getattr(resp, "reason_phrase", "") or "").strip()
    status = getattr(resp, "status_code", "")

    head = f"{method} {path} → ".lstrip() if (method or path) else ""
    head += f"{status}"
    if reason:
        head += f" {reason}"
    if size:
        head += f", {size}"
    if ctype:
        head += f" ({ctype})"
    return head


def from_response(resp: "httpx.Response", *, indicator: str = "", snippet: str = "") -> list[str]:
    """Standard evidence list for a finding proven by an HTTP response."""
    lines: list[str] = [request_line(resp)]
    if indicator:
        lines.append(f"matched: {_sanitize(indicator)}")
    if snippet:
        lines.append(f"response: {_sanitize(snippet)}")
    return lines


def from_parts(method: str, path: str, status: int | str,
               size: Optional[int] = None, ctype: str = "", indicator: str = "") -> list[str]:
    """Evidence list for callers without a live ``Response`` (e.g. DNS, socket, parsed artifact)."""
    head = f"{method.upper()} {path} → {status}".strip()
    if size is not None:
        head += f", {_human_size(size)}"
    if ctype:
        head += f" ({ctype.split(';')[0].strip()})"
    lines = [head]
    if indicator:
        lines.append(f"matched: {_sanitize(indicator)}")
    return lines


def note(text: str) -> str:
    """A free-form, sanitised evidence line (for observations that aren't a request/response)."""
    return _sanitize(text, _SNIPPET_MAX)


def baseline_note(resp: "httpx.Response", baseline: Any) -> str:
    """One-line comparison of a response body against the shared soft-404 baseline.

    Returns '' when there is no usable baseline. The note makes the anti-false-positive reasoning
    visible in the evidence ('this is a real page, not the catch-all').
    """
    length = getattr(baseline, "length", None)
    if not length:
        return ""
    try:
        size = len(resp.content)
    except Exception:
        return ""
    delta = size - length
    tol = max(64, length // 20)
    if abs(delta) <= tol:
        return f"matches soft-404 baseline (~{_human_size(length)}) — likely not genuine"
    sign = "+" if delta > 0 else "−"
    return f"differs from soft-404 baseline (Δ{sign}{_human_size(abs(delta))}, distinct body)"


# ---------------------------------------------------------------------------
# Confidence + normalisation
# ---------------------------------------------------------------------------

def confidence_from(signals: int, *, active: bool = False) -> str:
    """Map the count of corroborating signals to a confidence tier.

    ``active=True`` means the finding was actively verified (payload reflected, time-delay observed,
    object served without a session…), worth one extra signal. 0 → low, 1 → medium, ≥2 → high.
    """
    score = max(0, int(signals)) + (1 if active else 0)
    if score >= 2:
        return "high"
    if score == 1:
        return "medium"
    return "low"


def as_list(value: Any) -> list[str]:
    """Coerce any stored evidence value into a clean ``list[str]`` (used to normalise the JSON report)."""
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    try:
        return [str(v) for v in value]
    except TypeError:
        return [str(value)]
