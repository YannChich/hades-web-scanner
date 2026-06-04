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
    return Finding(
        module=MODULE,
        title=f"Cookie Missing Secure Flag: {cookie.name}",
        description=(
            f"Cookie '{cookie.name}' does not have the Secure flag set. "
            "It will be transmitted over unencrypted HTTP connections if the user visits the "
            "HTTP version of the site, exposing it to network interception."
        ),
        severity=Severity.HIGH,
        recommendation=f"Add the Secure attribute to the '{cookie.name}' Set-Cookie header.",
        raw={"cookie": cookie.name, "issue": "missing_secure", "raw": cookie.raw},
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
        raw={"cookie": cookie.name, "issue": "missing_httponly", "raw": cookie.raw},
    )


def _check_samesite(cookie: _Cookie) -> Finding | None:
    samesite = cookie.attr_value("samesite")

    if not samesite:
        return Finding(
            module=MODULE,
            title=f"Cookie Missing SameSite Attribute: {cookie.name}",
            description=(
                f"Cookie '{cookie.name}' has no SameSite attribute. "
                "Browsers default to 'Lax' in modern versions, but explicit absence leaves "
                "the cookie potentially exposed to cross-site request forgery."
            ),
            severity=Severity.MEDIUM,
            recommendation=(
                f"Add 'SameSite=Strict' or 'SameSite=Lax' to the '{cookie.name}' cookie. "
                "Use 'SameSite=None; Secure' only if cross-site access is explicitly required."
            ),
            raw={"cookie": cookie.name, "issue": "missing_samesite", "raw": cookie.raw},
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
                raw={"cookie": cookie.name, "issue": "samesite_none_without_secure", "raw": cookie.raw},
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
        for check in (_check_secure, _check_httponly, _check_samesite):
            finding = check(cookie) if check is not _check_secure else check(cookie, is_https)
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
