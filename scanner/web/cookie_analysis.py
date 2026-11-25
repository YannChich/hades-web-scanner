"""
cookie_analysis — audits Set-Cookie headers for missing security attributes.

Checks every cookie for HttpOnly, Secure, and SameSite flags. Session cookies
(identified by name heuristic) are held to a stricter standard. Returns one
Finding per problematic attribute per cookie.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx
from loguru import logger

from scanner import evidence as ev
from scanner.engine import Finding, Severity, ScanEngine

MODULE = "cookie_analysis"

# Names or prefixes that strongly suggest a session / auth cookie
_SESSION_PATTERNS: list[str] = [
    "sess", "session", "auth", "token", "jwt", "access",
    "phpsessid", "jsessionid", "asp.net_sessionid", "sid",
    "_rails", "laravel_session", "django_session", "connect.sid",
]


@dataclass
class _Cookie:
    name: str
    raw: str                        # full Set-Cookie header value
    attrs: dict[str, str] = field(default_factory=dict)   # lowercased attr → value
    flags: set[str] = field(default_factory=set)          # flag-only attrs (no value)

    @property
    def is_session(self) -> bool:
        name_lower = self.name.lower()
        return any(p in name_lower for p in _SESSION_PATTERNS)

    def has_flag(self, name: str) -> bool:
        return name.lower() in self.flags or name.lower() in self.attrs

    def attr_value(self, name: str) -> str:
        return self.attrs.get(name.lower(), "")


def _parse_set_cookie(header_value: str) -> _Cookie:
    """Parse a raw Set-Cookie header into a _Cookie dataclass."""
    parts = [p.strip() for p in header_value.split(";")]
    # First part is name=value
    name = parts[0].split("=", 1)[0].strip() if parts else ""

    attrs: dict[str, str] = {}
    flags: set[str] = set()

    for part in parts[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
        else:
            flags.add(part.strip().lower())

    return _Cookie(name=name, raw=header_value, attrs=attrs, flags=flags)


def _collect_cookies(resp: httpx.Response) -> list[_Cookie]:
    """Extract all Set-Cookie headers from the response."""
    cookies: list[_Cookie] = []
    # httpx stores duplicate headers; iterate raw headers to catch all Set-Cookie lines
    for header_name, header_value in resp.headers.multi_items():
        if header_name.lower() == "set-cookie":
            cookies.append(_parse_set_cookie(header_value))
    return cookies


def _check_secure(cookie: _Cookie, is_https: bool) -> Finding | None:
    if cookie.has_flag("secure"):
        return None
    # Only flag if site is HTTPS — sending a Secure-less cookie over HTTP is expected
    if not is_https:
        return None
    # A session/auth cookie leaking over HTTP enables hijacking (High); a tracking/UI cookie
    # without Secure is a minor hardening gap (Low) — rating every cookie High over-reports.
    session = cookie.is_session
    return Finding(
        module=MODULE,
        title=f"{'Session ' if session else ''}Cookie Missing Secure Flag: {cookie.name}",
        description=(
            f"Cookie '{cookie.name}' does not have the Secure flag set. "
            "It will be transmitted over unencrypted HTTP connections if the user visits the "
            "HTTP version of the site, exposing it to network interception."
            + (" This is a session/auth cookie, so interception enables session hijacking." if session else "")
        ),
        severity=Severity.HIGH if session else Severity.LOW,
        recommendation=f"Add the Secure attribute to the '{cookie.name}' Set-Cookie header.",
        raw={"cookie": cookie.name, "issue": "missing_secure", "session": session, "raw": cookie.raw,
             "evidence": [f"Set-Cookie: {ev.note(cookie.raw)[:160]}", "no 'Secure' attribute present"]},
    )


def _check_httponly(cookie: _Cookie) -> Finding | None:
    if cookie.has_flag("httponly"):
        return None
    # Only flag session/auth cookies — tracking cookies without HttpOnly are less critical
    if not cookie.is_session:
        return None
    return Finding(
        module=MODULE,
        title=f"Session Cookie Missing HttpOnly Flag: {cookie.name}",
        description=(
            f"Session cookie '{cookie.name}' does not have the HttpOnly flag. "
            "It is accessible via JavaScript, making it vulnerable to theft through XSS attacks."
        ),
        severity=Severity.MEDIUM,
        recommendation=f"Add the HttpOnly attribute to the '{cookie.name}' Set-Cookie header.",
        raw={"cookie": cookie.name, "issue": "missing_httponly", "raw": cookie.raw,
             "evidence": [f"Set-Cookie: {ev.note(cookie.raw)[:160]}", "no 'HttpOnly' attribute present"]},
    )


def _check_samesite(cookie: _Cookie) -> Finding | None:
    samesite = cookie.attr_value("samesite")

    if not samesite:
        # Modern browsers default to SameSite=Lax, so an absent attribute is a hardening gap, not a
        # live CSRF hole — Low for ordinary cookies, Medium for session/auth cookies.
        session = cookie.is_session
        return Finding(
            module=MODULE,
            title=f"Cookie Missing SameSite Attribute: {cookie.name}",
            description=(
                f"Cookie '{cookie.name}' has no SameSite attribute. "
                "Browsers default to 'Lax' in modern versions, but explicit absence leaves "
                "the cookie potentially exposed to cross-site request forgery on older clients."
            ),
            severity=Severity.MEDIUM if session else Severity.LOW,
            recommendation=(
                f"Add 'SameSite=Strict' or 'SameSite=Lax' to the '{cookie.name}' cookie. "
                "Use 'SameSite=None; Secure' only if cross-site access is explicitly required."
            ),
            raw={"cookie": cookie.name, "issue": "missing_samesite", "session": session, "raw": cookie.raw,
                 "evidence": [f"Set-Cookie: {ev.note(cookie.raw)[:160]}", "no 'SameSite' attribute present"]},
        )

    if samesite.lower() == "none":
        if not cookie.has_flag("secure"):
            return Finding(
                module=MODULE,
                title=f"Cookie SameSite=None Without Secure: {cookie.name}",
                description=(
                    f"Cookie '{cookie.name}' is set to 'SameSite=None' but lacks the Secure flag. "
                    "Modern browsers will reject this cookie entirely per the SameSite=None spec."
                ),
                severity=Severity.MEDIUM,
                recommendation=(
                    f"Add the Secure flag alongside SameSite=None on '{cookie.name}', "
                    "or reconsider whether cross-site access is necessary."
                ),
                raw={"cookie": cookie.name, "issue": "samesite_none_without_secure", "raw": cookie.raw,
                     "evidence": [f"Set-Cookie: {ev.note(cookie.raw)[:160]}",
                                  "SameSite=None without the required 'Secure' flag"]},
            )

    return None


def _check_prefix(cookie: _Cookie) -> Finding | None:
    """A `__Host-`/`__Secure-` cookie prefix is a browser-enforced contract: if the cookie does not
    meet the prefix's requirements the browser silently REJECTS it, so the protection the developer
    thought they had is simply absent. Flag cookies that use a prefix but violate its rules."""
    low = cookie.name.lower()
    if low.startswith("__host-"):
        problems: list[str] = []
        if not cookie.has_flag("secure"):
            problems.append("missing Secure")
        if cookie.attr_value("path") != "/":
            problems.append("Path is not '/'")
        if cookie.attr_value("domain"):
            problems.append("Domain attribute present (must be absent)")
        if problems:
            return Finding(
                module=MODULE,
                title=f"__Host- Cookie Prefix Requirements Violated: {cookie.name}",
                description=(
                    f"Cookie '{cookie.name}' uses the '__Host-' prefix but violates its rules "
                    f"({', '.join(problems)}). Browsers REJECT a '__Host-' cookie unless it is Secure, "
                    "has Path=/, and has NO Domain attribute — so this cookie is silently dropped and "
                    "the intended protection is absent."),
                severity=Severity.MEDIUM,
                recommendation=(f"Serve '{cookie.name}' with Secure, Path=/ and no Domain attribute, "
                                "or drop the '__Host-' prefix if those constraints are not intended."),
                raw={"cookie": cookie.name, "issue": "host_prefix_violated", "problems": problems,
                     "raw": cookie.raw,
                     "evidence": [f"Set-Cookie: {ev.note(cookie.raw)[:160]}",
                                  f"__Host- prefix rules violated: {', '.join(problems)}"]},
            )
    elif low.startswith("__secure-"):
        if not cookie.has_flag("secure"):
            return Finding(
                module=MODULE,
                title=f"__Secure- Cookie Prefix Requirements Violated: {cookie.name}",
                description=(
                    f"Cookie '{cookie.name}' uses the '__Secure-' prefix but has no Secure flag. "
                    "Browsers REJECT a '__Secure-' cookie that is not marked Secure, so it is silently "
                    "dropped and provides no protection."),
                severity=Severity.MEDIUM,
                recommendation=f"Add the Secure flag to '{cookie.name}', or drop the '__Secure-' prefix.",
                raw={"cookie": cookie.name, "issue": "secure_prefix_violated", "raw": cookie.raw,
                     "evidence": [f"Set-Cookie: {ev.note(cookie.raw)[:160]}",
                                  "__Secure- prefix without the required 'Secure' flag"]},
            )
    return None


def run(engine: ScanEngine) -> list[Finding]:
    findings: list[Finding] = []

    try:
        resp = engine.get()
    except httpx.HTTPError as exc:
        logger.warning(f"cookie_analysis: request failed: {exc}")
        return []

    is_https = urlparse(engine.url).scheme == "https"
    cookies = _collect_cookies(resp)

    if not cookies:
        findings.append(Finding(
            module=MODULE,
            title="No Cookies Set",
            description="The server did not issue any Set-Cookie headers on the homepage response.",
            severity=Severity.INFO,
            recommendation="",
            raw={},
        ))
        return findings

    for cookie in cookies:
        for finding in (_check_secure(cookie, is_https), _check_httponly(cookie),
                        _check_samesite(cookie), _check_prefix(cookie)):
            if finding:
                findings.append(finding)

    if not findings:
        findings.append(Finding(
            module=MODULE,
            title="Cookie Security Attributes: OK",
            description=(
                f"All {len(cookies)} cookie(s) have appropriate security attributes set."
            ),
            severity=Severity.INFO,
            recommendation="",
            raw={"cookie_count": len(cookies)},
        ))

    return findings
