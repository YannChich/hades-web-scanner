"""
crawler — shared same-host crawler that runs once per scan and feeds multiple modules.

A single breadth-first crawl (bounded by depth and page count) collects everything the
active/vuln modules need: visited page bodies, internal/external links, URLs carrying
query parameters, HTML forms, and exposed e-mail addresses. The result is cached on the
ScanEngine (see ScanEngine.get_crawl) so parallel modules share one crawl instead of each
re-fetching the homepage.

All HTTP traffic flows through the engine, so the rate limiter, proxy, auth headers, and
cookies configured for the scan are respected. robots.txt Disallow rules are honoured
unless the scan was started with ignore_robots.
"""
from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse, urlunparse

import httpx
from bs4 import BeautifulSoup
from loguru import logger

from scanner.web.robots_txt import _parse_disallow

if TYPE_CHECKING:
    from scanner.engine import ScanEngine

# Links with these schemes are never fetched as pages.
_SKIP_SCHEMES = ("mailto:", "tel:", "javascript:", "data:", "ftp:")

# Conservative e-mail pattern — a dotted TLD of letters, anchored on word boundaries.
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")

# The regex above still matches non-addresses; these filters drop the common false positives.
# File-extension "TLDs" come from asset references like logo@2x.png or sprite@3x.svg.
_NON_EMAIL_TLDS: frozenset[str] = frozenset({
    "png", "jpg", "jpeg", "gif", "svg", "webp", "bmp", "ico", "avif",
    "css", "js", "mjs", "cjs", "ts", "json", "xml", "map", "html", "htm",
    "woff", "woff2", "ttf", "eot", "otf",
    "mp4", "webm", "mp3", "wav", "ogg", "pdf", "zip", "gz", "tar",
    "min", "scss", "less", "vue", "php",
})
# Placeholder / documentation / telemetry domains that are never a real exposed mailbox.
_PLACEHOLDER_EMAIL_DOMAINS: frozenset[str] = frozenset({
    "example.com", "example.org", "example.net", "domain.com", "domain.tld",
    "email.com", "yourdomain.com", "yoursite.com", "mydomain.com", "test.com",
    "sentry.io", "sentry.wixpress.com", "wixpress.com", "schema.org", "w3.org",
    "sentry-next.wixpress.com",
})


def _is_real_email(addr: str) -> bool:
    """Filter out asset references, telemetry DSNs and placeholder addresses the regex catches."""
    if addr.count("@") != 1:
        return False
    local, _, domain = addr.partition("@")
    domain = domain.lower().rstrip(".")
    if not local or "." not in domain:
        return False
    tld = domain.rsplit(".", 1)[-1]
    if tld in _NON_EMAIL_TLDS:
        return False
    # Retina/asset refs such as icon@2x.png leave a numeric "2x"-style host once the TLD is gone.
    if re.fullmatch(r"\d+x", domain.rsplit(".", 1)[0]):
        return False
    if domain in _PLACEHOLDER_EMAIL_DOMAINS or any(
            domain == d or domain.endswith("." + d) for d in _PLACEHOLDER_EMAIL_DOMAINS):
        return False
    return True


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Form:
    """An HTML form discovered during the crawl."""
    action: str
    method: str                       # "get" or "post"
    fields: dict[str, str]            # field name → realistic default value
    source_url: str = ""              # page the form was found on


@dataclass
class CrawlResult:
    """Everything the crawl gathered, shared across modules."""
    pages: dict[str, str] = field(default_factory=dict)            # url → html
    internal_links: set[str] = field(default_factory=set)
    external_links: set[str] = field(default_factory=set)
    parametrised_urls: list[str] = field(default_factory=list)     # internal, has query
    forms: list[Form] = field(default_factory=list)
    emails: set[str] = field(default_factory=set)


# ---------------------------------------------------------------------------
# Form extraction (shared with xss_detect, which used to own this)
# ---------------------------------------------------------------------------

def extract_forms(base_url: str, html: str) -> list[Form]:
    """Parse all same-host forms from *html*, filling realistic default values."""
    soup = BeautifulSoup(html, "html.parser")
    forms: list[Form] = []
    base_netloc = urlparse(base_url).netloc

    for form_tag in soup.find_all("form"):
        action = urljoin(base_url, form_tag.get("action") or "")
        method = (form_tag.get("method") or "get").lower()

        # Skip forms that submit off-host
        action_netloc = urlparse(action).netloc
        if action_netloc and action_netloc != base_netloc:
            continue

        fields: dict[str, str] = {}
        for inp in form_tag.find_all(["input", "textarea"]):
            name = inp.get("name")
            if not name:
                continue
            input_type = inp.get("type", "text").lower()
            if input_type in ("submit", "button", "image", "reset", "file"):
                continue
            if input_type == "email":
                fields[name] = "test@example.com"
            elif input_type == "number":
                fields[name] = "1"
            elif input_type == "hidden":
                fields[name] = inp.get("value", "")
            else:
                fields[name] = inp.get("value", "test")

        if fields:
            forms.append(Form(action=action, method=method, fields=fields, source_url=base_url))

    return forms


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalise(url: str) -> str:
    """Strip the fragment so #anchors don't create duplicate URLs."""
    return urlunparse(urlparse(url)._replace(fragment=""))


def _is_disallowed(path: str, disallow: list[str]) -> bool:
    """True if *path* falls under any robots.txt Disallow prefix."""
    for rule in disallow:
        if rule == "/":
            return True
        if rule and path.startswith(rule):
            return True
    return False


def _load_disallow(engine: "ScanEngine") -> list[str]:
    """Fetch and parse robots.txt Disallow rules; empty list if unavailable."""
    try:
        resp = engine.get("/robots.txt")
    except httpx.HTTPError as exc:
        logger.debug(f"crawler: robots.txt fetch failed: {exc}")
        return []
    if resp.status_code != 200:
        return []
    return _parse_disallow(resp.text)


def _collect_emails(html: str) -> set[str]:
    found: set[str] = set()
    soup = BeautifulSoup(html, "html.parser")
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.lower().startswith("mailto:"):
            addr = href[len("mailto:"):].split("?")[0].strip()
            if addr and _is_real_email(addr):
                found.add(addr)
    for match in _EMAIL_RE.finditer(html):
        addr = match.group(0)
        if _is_real_email(addr):
            found.add(addr)
    return found


# ---------------------------------------------------------------------------
# Crawl
# ---------------------------------------------------------------------------

def crawl(engine: "ScanEngine", max_depth: int = 2, max_pages: int = 50) -> CrawlResult:
    """
    Breadth-first crawl from engine.url, bounded by *max_depth* and *max_pages*.
    Stays on the start host. Honours robots.txt unless engine.ignore_robots.
    """
    result = CrawlResult()
    base_netloc = urlparse(engine.url).netloc

    disallow: list[str] = [] if engine.ignore_robots else _load_disallow(engine)
    if disallow:
        logger.debug(f"crawler: honouring {len(disallow)} robots.txt Disallow rule(s)")

    queue: deque[tuple[str, int]] = deque([(engine.url, 0)])
    visited: set[str] = set()
    seen_param_urls: set[str] = set()

    while queue and len(result.pages) < max_pages:
        url, depth = queue.popleft()
        url = _normalise(url)
        if url in visited:
            continue
        visited.add(url)

        try:
            resp = engine.request("GET", url)
        except httpx.HTTPError as exc:
            logger.debug(f"crawler: GET {url} failed: {exc}")
            continue

        ctype = resp.headers.get("content-type", "")
        if "html" not in ctype.lower():
            continue

        html = resp.text
        result.pages[url] = html
        result.emails |= _collect_emails(html)
        result.forms.extend(extract_forms(url, html))

        # Discover links on this page
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if not href or href.startswith("#"):
                continue
            if any(href.lower().startswith(s) for s in _SKIP_SCHEMES):
                continue

            absolute = _normalise(urljoin(url, href))
            parsed = urlparse(absolute)
            if parsed.scheme not in ("http", "https"):
                continue

            if parsed.netloc != base_netloc:
                result.external_links.add(absolute)
                continue

            # Internal link — honour robots.txt: a disallowed path is excluded
            # from the result entirely, so downstream modules never probe it.
            if _is_disallowed(parsed.path, disallow):
                continue

            result.internal_links.add(absolute)
            if parsed.query and absolute not in seen_param_urls:
                seen_param_urls.add(absolute)
                result.parametrised_urls.append(absolute)

            if depth < max_depth and absolute not in visited:
                queue.append((absolute, depth + 1))

    logger.debug(
        f"crawler: visited {len(result.pages)} page(s), "
        f"{len(result.internal_links)} internal / {len(result.external_links)} external link(s), "
        f"{len(result.parametrised_urls)} param URL(s), {len(result.forms)} form(s), "
        f"{len(result.emails)} email(s)"
    )
    return result
