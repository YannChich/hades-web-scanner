"""
scope — allow/deny rules that keep a scan inside an authorised boundary.

A pentest engagement is scoped: only certain hosts (and sometimes only certain path prefixes)
are in bounds. ``ScopeRules`` turns ``--scope`` / ``--deny`` patterns into a single decision —
``in_scope(url)`` — enforced in the engine *before any request leaves*, so a link or redirect to
an out-of-scope host is blocked and logged rather than probed.

Pattern grammar (scheme optional, matching is case-insensitive):

    example.com                 host (and, implicitly, all of its paths)
    example.com/api             host + path prefix (only URLs under /api)
    *.example.com               the apex and every subdomain
    *.example.com/admin         subdomain wildcard + path prefix

Decision order (deny always wins):

    1. If the URL matches any ``deny`` pattern            → out of scope.
    2. If an ``allow`` list is given, the URL is in scope → only when it matches an allow
       pattern (the scan's own target host is auto-allowed so the base scan always runs).
    3. With no ``allow`` list, everything not denied is in scope.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx


class OutOfScopeError(httpx.RequestError):
    """Raised when a request targets a host/path outside the authorised scope.

    Subclasses ``httpx.RequestError`` (not Timeout/ConnectError) so it never trips the engine's
    circuit breaker; the engine catches it, logs it, and counts the blocked attempt.
    """


@dataclass(frozen=True)
class _Pattern:
    host: str          # lowercase; may start with "*." for a subdomain wildcard
    path: str          # "" or a normalised "/prefix"

    def matches(self, host: str, path: str) -> bool:
        return self._host_matches(host.lower()) and self._path_matches(path)

    def _host_matches(self, host: str) -> bool:
        if self.host.startswith("*."):
            apex = self.host[2:]
            return host == apex or host.endswith("." + apex)
        return host == self.host

    def _path_matches(self, path: str) -> bool:
        if not self.path:
            return True
        p = path or "/"
        return p == self.path or p.startswith(self.path.rstrip("/") + "/")


def _parse_pattern(raw: str) -> _Pattern | None:
    """Parse one 'host[/path]' pattern (a leading scheme is tolerated). None if blank."""
    raw = (raw or "").strip()
    if not raw:
        return None
    # Drop a scheme if present so 'https://example.com/api' and 'example.com/api' are equivalent.
    raw = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", raw)
    host, _, path = raw.partition("/")
    host = host.strip().lower().rstrip(".")
    path = ("/" + path.strip().strip("/")) if path.strip() else ""
    if not host:
        return None
    return _Pattern(host=host, path=path)


def _host_of(url: str) -> str:
    netloc = urlparse(url if "://" in url else f"http://{url}").netloc
    # Strip userinfo and keep host[:port] lowercased.
    return netloc.split("@")[-1].lower()


@dataclass
class ScopeRules:
    """Compiled scope decision for a scan. Build via :meth:`build`; query via :meth:`in_scope`."""
    allow: list[_Pattern] = field(default_factory=list)
    deny: list[_Pattern] = field(default_factory=list)
    target_host: str = ""
    blocked: int = 0           # count of requests refused (for the run summary)

    @classmethod
    def build(cls, target_url: str, allow: list[str] | None = None,
              deny: list[str] | None = None) -> "ScopeRules | None":
        """Return a ScopeRules, or None when no allow/deny rule is given (enforcement disabled)."""
        allow_pats = [p for p in (_parse_pattern(a) for a in (allow or [])) if p]
        deny_pats = [p for p in (_parse_pattern(d) for d in (deny or [])) if p]
        if not allow_pats and not deny_pats:
            return None
        return cls(allow=allow_pats, deny=deny_pats, target_host=_host_of(target_url))

    def in_scope(self, url: str) -> bool:
        """True when *url* may be requested under the current scope rules."""
        host = _host_of(url)
        path = urlparse(url if "://" in url else f"http://{url}").path or "/"

        if any(p.matches(host, path) for p in self.deny):
            return False
        if self.allow:
            if host == self.target_host:
                return True
            return any(p.matches(host, path) for p in self.allow)
        return True

    def check(self, url: str) -> None:
        """Raise :class:`OutOfScopeError` (and count it) when *url* is out of scope."""
        if not self.in_scope(url):
            self.blocked += 1
            raise OutOfScopeError(f"out of scope: {url}")

    def describe(self) -> str:
        """One-line human summary of the active rules (for the scan banner)."""
        parts = []
        if self.allow:
            parts.append("allow " + ", ".join(self._fmt(p) for p in self.allow))
        if self.deny:
            parts.append("deny " + ", ".join(self._fmt(p) for p in self.deny))
        return " · ".join(parts)

    @staticmethod
    def _fmt(p: _Pattern) -> str:
        return p.host + p.path
