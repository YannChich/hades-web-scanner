"""
tech_stack — Wappalyzer-style technology fingerprinting from headers, HTML, and cookies.

Detects server software, languages, frameworks, JS libraries, and CMS platforms.
Each detected technology is returned as an Info finding; version strings (when
extractable) are included in the raw payload for use by cve_mapping.py.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup
from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "tech_stack"


# ---------------------------------------------------------------------------
# Signature definitions
# ---------------------------------------------------------------------------

@dataclass
class _Sig:
    """A single fingerprint rule that produces one technology detection."""
    tech: str
    category: str
    # Each pattern is a regex; first capture group (if any) is the version.
    patterns: list[str] = field(default_factory=list)


# Header-based signatures: (header_name_lower, [_Sig, ...])
_HEADER_SIGS: list[tuple[str, _Sig]] = [
    ("server",        _Sig("Apache",        "Web Server",  [r"Apache(?:/([0-9.]+))?"])),
    ("server",        _Sig("Nginx",         "Web Server",  [r"nginx(?:/([0-9.]+))?"])),
    ("server",        _Sig("IIS",           "Web Server",  [r"Microsoft-IIS(?:/([0-9.]+))?"])),
    ("server",        _Sig("LiteSpeed",     "Web Server",  [r"LiteSpeed"])),
    ("server",        _Sig("Caddy",         "Web Server",  [r"Caddy"])),
    ("server",        _Sig("OpenResty",     "Web Server",  [r"openresty(?:/([0-9.]+))?"])),
    ("x-powered-by",  _Sig("PHP",           "Language",    [r"PHP(?:/([0-9.]+))?"])),
    ("x-powered-by",  _Sig("ASP.NET",       "Framework",   [r"ASP\.NET"])),
    ("x-powered-by",  _Sig("Express",       "Framework",   [r"Express"])),
    ("x-powered-by",  _Sig("Next.js",       "Framework",   [r"Next\.js"])),
    ("x-generator",   _Sig("WordPress",     "CMS",         [r"WordPress(?:\s([0-9.]+))?"])),
    ("x-generator",   _Sig("Drupal",        "CMS",         [r"Drupal\s?([0-9.]+)?"])),
    ("x-drupal-cache", _Sig("Drupal",       "CMS",         [])),
    ("x-wp-total",    _Sig("WordPress",     "CMS",         [])),
    ("x-shopify-stage", _Sig("Shopify",     "E-Commerce",  [])),
    ("x-wix-request-id", _Sig("Wix",       "CMS",         [])),
]

# HTML <meta> tag signatures: match generator/author content
_META_SIGS: list[_Sig] = [
    _Sig("WordPress",   "CMS",       [r"WordPress\s?([0-9.]+)?", r"wp-content"]),
    _Sig("Joomla",      "CMS",       [r"Joomla!\s?([0-9.]+)?"]),
    _Sig("Drupal",      "CMS",       [r"Drupal\s?([0-9.]+)?"]),
    _Sig("TYPO3",       "CMS",       [r"TYPO3\s?([0-9.]+)?"]),
    _Sig("Ghost",       "CMS",       [r"Ghost\s?([0-9.]+)?"]),
    _Sig("Squarespace", "CMS",       [r"Squarespace"]),
    _Sig("Wix",         "CMS",       [r"Wix\.com"]),
]

# <script src> JS library fingerprints
_SCRIPT_SIGS: list[_Sig] = [
    _Sig("jQuery",         "JS Library",  [r"jquery[.-]([0-9.]+(?:min)?)"]),
    _Sig("React",          "JS Framework",[r"react(?:\.production)?[.-]([0-9.]+)"]),
    _Sig("Vue.js",         "JS Framework",[r"vue(?:\.min)?[.-]([0-9.]+)"]),
    _Sig("Angular",        "JS Framework",[r"angular[.-]([0-9.]+)"]),
    _Sig("Bootstrap",      "CSS Framework",[r"bootstrap[.-]([0-9.]+)"]),
    _Sig("Backbone.js",    "JS Library",  [r"backbone[.-]([0-9.]+)"]),
    _Sig("Lodash",         "JS Library",  [r"lodash[.-]([0-9.]+)"]),
    _Sig("Moment.js",      "JS Library",  [r"moment[.-]([0-9.]+)"]),
    _Sig("Ember.js",       "JS Framework",[r"ember[.-]([0-9.]+)"]),
    _Sig("Alpine.js",      "JS Framework",[r"alpinejs[.-]([0-9.]+)"]),
    _Sig("HTMX",           "JS Library",  [r"htmx[.-]([0-9.]+)"]),
    _Sig("Svelte",         "JS Framework",[r"svelte[.-]([0-9.]+)"]),
    _Sig("Next.js",        "Framework",   [r"_next/static"]),
    _Sig("Nuxt.js",        "Framework",   [r"_nuxt/"]),
    _Sig("WordPress",      "CMS",         [r"/wp-content/", r"/wp-includes/"]),
    _Sig("Joomla",         "CMS",         [r"/components/com_", r"/media/jui/"]),
    _Sig("Drupal",         "CMS",         [r"/sites/default/files/", r"Drupal\.settings"]),
]

# Cookie name → technology
_COOKIE_SIGS: list[tuple[str, _Sig]] = [
    ("phpsessid",       _Sig("PHP",          "Language",  [])),
    ("jsessionid",      _Sig("Java / Servlet","Language", [])),
    ("asp.net_sessionid", _Sig("ASP.NET",    "Framework", [])),
    ("_rails",          _Sig("Ruby on Rails","Framework", [])),
    ("rack.session",    _Sig("Rack / Ruby",  "Framework", [])),
    ("laravel_session", _Sig("Laravel",      "Framework", [])),
    ("django_language", _Sig("Django",       "Framework", [])),
    ("csrftoken",       _Sig("Django",       "Framework", [])),
    ("wp-settings-",    _Sig("WordPress",    "CMS",       [])),
    ("wordpress_",      _Sig("WordPress",    "CMS",       [])),
    ("joomla_user_state", _Sig("Joomla",     "CMS",       [])),
    ("shopify_visit",   _Sig("Shopify",      "E-Commerce",[])),
]

# URL path patterns present in page HTML
_URL_SIGS: list[_Sig] = [
    _Sig("WordPress",  "CMS",        [r"/wp-content/", r"/wp-includes/", r"/wp-json/"]),
    _Sig("Joomla",     "CMS",        [r"/components/com_", r"/joomla/", r"/templates/system/"]),
    _Sig("Drupal",     "CMS",        [r"/sites/default/", r"/modules/", r"/core/misc/drupal"]),
    _Sig("Magento",    "E-Commerce", [r"/skin/frontend/", r"Mage\.Cookies"]),
    _Sig("PrestaShop", "E-Commerce", [r"/modules/ps_", r"prestashop"]),
    _Sig("OpenCart",   "E-Commerce", [r"route=common/home", r"/catalog/view/theme/"]),
]

# <link href> stylesheet signatures (CDN links expose version numbers)
_LINK_SIGS: list[_Sig] = [
    _Sig("Bootstrap",      "CSS Framework", [r"bootstrap[.-]([0-9.]+)"]),
    _Sig("Font Awesome",   "Icon Library",  [r"font-?awesome[.-]([0-9.]+)"]),
    _Sig("Bulma",          "CSS Framework", [r"bulma[.-]([0-9.]+)"]),
    _Sig("Tailwind CSS",   "CSS Framework", [r"tailwind[.-]([0-9.]+)"]),
    _Sig("Materialize",    "CSS Framework", [r"materialize[.-]([0-9.]+)"]),
    _Sig("Foundation",     "CSS Framework", [r"foundation[.-]([0-9.]+)"]),
]

# Inline JS variable signatures — many frameworks expose their version in JS globals
_JS_VAR_SIGS: list[_Sig] = [
    _Sig("WordPress",   "CMS",         [r'wp\.version\s*[=:]\s*["\']([0-9.]+)']),
    _Sig("jQuery",      "JS Library",  [r'jQuery\.fn\.jquery\s*[=:]\s*["\']([0-9.]+)',
                                        r'jquery:\s*["\']([0-9.]+)']),
    _Sig("React",       "JS Framework",[r'React\.version\s*[=:]\s*["\']([0-9.]+)',
                                        r'"react":\s*["\']([0-9.]+)']),
    _Sig("Vue.js",      "JS Framework",[r'Vue\.version\s*[=:]\s*["\']([0-9.]+)']),
    _Sig("Angular",     "JS Framework",[r'"@angular/core":\s*["\']([0-9.]+)',
                                        r'ng\.version\.full\s*[=:]\s*["\']([0-9.]+)']),
    _Sig("Lodash",      "JS Library",  [r'_\.VERSION\s*[=:]\s*["\']([0-9.]+)',
                                        r'"lodash":\s*["\']([0-9.]+)']),
    _Sig("Moment.js",   "JS Library",  [r'moment\.version\s*[=:]\s*["\']([0-9.]+)']),
    _Sig("Bootstrap",   "CSS Framework",[r'bootstrap\.Tooltip\.VERSION\s*[=:]\s*["\']([0-9.]+)',
                                         r'"bootstrap":\s*["\']([0-9.]+)']),
    _Sig("Next.js",     "Framework",   [r'"version":\s*["\']([0-9.]+)"[^}]*"next"']),
    _Sig("Nuxt.js",     "Framework",   [r'nuxt\.version\s*[=:]\s*["\']([0-9.]+)']),
]

# Extra header signatures for version-bearing headers
_EXTRA_HEADER_SIGS: list[tuple[str, _Sig]] = [
    ("x-aspnet-version",    _Sig("ASP.NET",        "Framework",  [r"([0-9.]+)"])),
    ("x-aspnetmvc-version", _Sig("ASP.NET MVC",    "Framework",  [r"([0-9.]+)"])),
    ("x-runtime",           _Sig("Ruby on Rails",  "Framework",  [r"([0-9.]+)"])),
    ("x-drupal-cache",      _Sig("Drupal",         "CMS",        [])),
    ("x-varnish",           _Sig("Varnish",        "Cache",      [])),
    ("x-cache",             _Sig("Varnish",        "Cache",      [r"varnish"])),
    ("via",                 _Sig("Varnish",        "Cache",      [r"varnish"])),
    ("x-magento-vary",      _Sig("Magento",        "E-Commerce", [])),
    ("x-turbo-charged-by",  _Sig("LiteSpeed",      "Web Server", [])),
    ("x-litespeed-cache",   _Sig("LiteSpeed",      "Web Server", [])),
    ("cf-ray",              _Sig("Cloudflare",     "CDN",        [])),
    ("x-amz-cf-id",         _Sig("AWS CloudFront", "CDN",        [])),
    ("x-akamai-transformed",_Sig("Akamai",         "CDN",        [])),
]

# HTML comment signatures (some CMSes embed version in comments)
_COMMENT_SIGS: list[_Sig] = [
    _Sig("WordPress",   "CMS",        [r"WordPress ([0-9.]+)"]),
    _Sig("Joomla",      "CMS",        [r"Joomla! ([0-9.]+)"]),
    _Sig("TYPO3",       "CMS",        [r"TYPO3 ([0-9.]+)"]),
    _Sig("Drupal",      "CMS",        [r"Drupal ([0-9.]+)"]),
    _Sig("OpenCart",    "E-Commerce", [r"OpenCart v\.?([0-9.]+)"]),
    _Sig("PrestaShop",  "E-Commerce", [r"PrestaShop ([0-9.]+)"]),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_version(value: str, patterns: list[str]) -> str:
    for pat in patterns:
        m = re.search(pat, value, re.IGNORECASE)
        if m:
            return m.group(1) if m.lastindex and m.group(1) else ""
    return ""


def _make_finding(tech: str, category: str, version: str, source: str) -> Finding:
    ver_str = f" {version}" if version else ""
    return Finding(
        module=MODULE,
        title=f"Technology Detected: {tech}{ver_str}",
        description=f"{tech}{ver_str} detected via {source}. Category: {category}.",
        severity=Severity.INFO,
        recommendation="",
        raw={"technology": tech, "version": version, "category": category, "source": source},
    )


# ---------------------------------------------------------------------------
# Detection passes
# ---------------------------------------------------------------------------

def _from_headers(headers: httpx.Headers, seen: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for header_name, sig in _HEADER_SIGS:
        if sig.tech in seen:
            continue
        value = headers.get(header_name, "")
        if not value:
            continue
        matched = not sig.patterns or any(
            re.search(p, value, re.IGNORECASE) for p in sig.patterns
        )
        if matched:
            version = _extract_version(value, sig.patterns)
            findings.append(_make_finding(sig.tech, sig.category, version, f"header:{header_name}"))
            seen.add(sig.tech)
    return findings


def _from_meta_tags(soup: BeautifulSoup, seen: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    meta_content = " ".join(
        tag.get("content", "")
        for tag in soup.find_all("meta", attrs={"name": re.compile(r"generator|author|framework", re.I)})
    )
    if not meta_content:
        return findings
    for sig in _META_SIGS:
        if sig.tech in seen:
            continue
        if any(re.search(p, meta_content, re.IGNORECASE) for p in sig.patterns):
            version = _extract_version(meta_content, sig.patterns)
            findings.append(_make_finding(sig.tech, sig.category, version, "meta:generator"))
            seen.add(sig.tech)
    return findings


def _from_scripts(soup: BeautifulSoup, seen: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    script_srcs = " ".join(
        tag.get("src", "") for tag in soup.find_all("script", src=True)
    )
    inline_scripts = " ".join(
        tag.string or "" for tag in soup.find_all("script", src=False)
    )
    haystack = script_srcs + " " + inline_scripts

    for sig in _SCRIPT_SIGS:
        if sig.tech in seen:
            continue
        if any(re.search(p, haystack, re.IGNORECASE) for p in sig.patterns):
            version = _extract_version(script_srcs, sig.patterns)
            findings.append(_make_finding(sig.tech, sig.category, version, "script:src"))
            seen.add(sig.tech)
    return findings


def _from_cookies(cookies: httpx.Cookies, seen: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    cookie_keys_lower = [k.lower() for k in cookies.keys()]
    for cookie_prefix, sig in _COOKIE_SIGS:
        if sig.tech in seen:
            continue
        if any(k.startswith(cookie_prefix) for k in cookie_keys_lower):
            findings.append(_make_finding(sig.tech, sig.category, "", "cookie"))
            seen.add(sig.tech)
    return findings


def _from_url_patterns(html: str, seen: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for sig in _URL_SIGS:
        if sig.tech in seen:
            continue
        if any(re.search(p, html, re.IGNORECASE) for p in sig.patterns):
            findings.append(_make_finding(sig.tech, sig.category, "", "url_pattern"))
            seen.add(sig.tech)
    return findings


def _from_link_tags(soup: BeautifulSoup, seen: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    link_hrefs = " ".join(
        tag.get("href", "") for tag in soup.find_all("link", href=True)
    )
    for sig in _LINK_SIGS:
        if sig.tech in seen:
            continue
        if any(re.search(p, link_hrefs, re.IGNORECASE) for p in sig.patterns):
            version = _extract_version(link_hrefs, sig.patterns)
            findings.append(_make_finding(sig.tech, sig.category, version, "link:href"))
            seen.add(sig.tech)
    return findings


def _from_js_vars(html: str, seen: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for sig in _JS_VAR_SIGS:
        if sig.tech in seen:
            continue
        if any(re.search(p, html, re.IGNORECASE) for p in sig.patterns):
            version = _extract_version(html, sig.patterns)
            findings.append(_make_finding(sig.tech, sig.category, version, "js:variable"))
            seen.add(sig.tech)
    return findings


def _from_extra_headers(headers: httpx.Headers, seen: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for header_name, sig in _EXTRA_HEADER_SIGS:
        if sig.tech in seen:
            continue
        value = headers.get(header_name, "")
        if not value:
            continue
        matched = not sig.patterns or any(re.search(p, value, re.IGNORECASE) for p in sig.patterns)
        if matched:
            version = _extract_version(value, sig.patterns)
            findings.append(_make_finding(sig.tech, sig.category, version, f"header:{header_name}"))
            seen.add(sig.tech)
    return findings


def _from_html_comments(html: str, seen: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    comments = " ".join(re.findall(r"<!--(.*?)-->", html, re.DOTALL))
    if not comments:
        return findings
    for sig in _COMMENT_SIGS:
        if sig.tech in seen:
            continue
        if any(re.search(p, comments, re.IGNORECASE) for p in sig.patterns):
            version = _extract_version(comments, sig.patterns)
            findings.append(_make_finding(sig.tech, sig.category, version, "html:comment"))
            seen.add(sig.tech)
    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(engine: ScanEngine) -> list[Finding]:
    try:
        resp = engine.get()
    except httpx.HTTPError as exc:
        logger.warning(f"tech_stack: request failed: {exc}")
        return []

    html = resp.text
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception as exc:
        logger.warning(f"tech_stack: HTML parse failed: {exc}")
        soup = BeautifulSoup("", "html.parser")

    seen: set[str] = set()
    findings: list[Finding] = []

    findings += _from_headers(resp.headers, seen)
    findings += _from_extra_headers(resp.headers, seen)
    findings += _from_cookies(resp.cookies, seen)
    findings += _from_meta_tags(soup, seen)
    findings += _from_scripts(soup, seen)
    findings += _from_link_tags(soup, seen)
    findings += _from_js_vars(html, seen)
    findings += _from_html_comments(html, seen)
    findings += _from_url_patterns(html, seen)

    return findings
