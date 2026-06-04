"""
cms_detect — identifies the CMS platform powering the target.

Probes CMS-specific paths, headers, cookies, and HTML patterns for WordPress,
Joomla, Drupal, Magento, Shopify, Wix, and Squarespace. When a version is
extracted, calls cve_mapping.lookup() to append relevant CVE findings.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx
from bs4 import BeautifulSoup
from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "cms_detect"


# ---------------------------------------------------------------------------
# CMS fingerprint definitions
# ---------------------------------------------------------------------------

@dataclass
class _ProbeResult:
    detected: bool = False
    version: str = ""
    signals: list[str] = field(default_factory=list)


@dataclass
class _CmsSpec:
    name: str
    hosted: bool = False    # True for SaaS platforms (Shopify, Wix, Squarespace)


_CMS_SPECS: dict[str, _CmsSpec] = {
    "WordPress":   _CmsSpec("WordPress"),
    "Joomla":      _CmsSpec("Joomla"),
    "Drupal":      _CmsSpec("Drupal"),
    "Magento":     _CmsSpec("Magento"),
    "Shopify":     _CmsSpec("Shopify",     hosted=True),
    "Wix":         _CmsSpec("Wix",         hosted=True),
    "Squarespace": _CmsSpec("Squarespace", hosted=True),
    "Ghost":       _CmsSpec("Ghost"),
    "TYPO3":       _CmsSpec("TYPO3"),
    "PrestaShop":  _CmsSpec("PrestaShop"),
}


# ---------------------------------------------------------------------------
# Per-CMS detection logic
# ---------------------------------------------------------------------------

def _probe_path(engine: ScanEngine, path: str) -> httpx.Response | None:
    """GET a path; return Response on 2xx/3xx, None on error or 404."""
    try:
        resp = engine.get(path)
        return resp if resp.status_code < 400 else None
    except httpx.HTTPError:
        return None


def _meta_generator(soup: BeautifulSoup) -> str:
    tag = soup.find("meta", attrs={"name": re.compile(r"^generator$", re.I)})
    return tag.get("content", "") if tag else ""  # type: ignore[union-attr]


# -- WordPress ----------------------------------------------------------------

def _detect_wordpress(engine: ScanEngine, soup: BeautifulSoup, html: str, headers: httpx.Headers) -> _ProbeResult:
    result = _ProbeResult()
    version = ""

    generator = _meta_generator(soup)
    if re.search(r"WordPress", generator, re.I):
        result.signals.append("meta:generator")
        m = re.search(r"WordPress\s+([0-9.]+)", generator, re.I)
        if m:
            version = m.group(1)

    if re.search(r"/wp-content/|/wp-includes/", html):
        result.signals.append("html:wp-paths")

    if headers.get("x-wp-total") or headers.get("x-wp-totalpages"):
        result.signals.append("header:x-wp-total")

    if _probe_path(engine, "/wp-login.php"):
        result.signals.append("path:wp-login.php")

    # Version from readme if not yet found
    if not version:
        readme = _probe_path(engine, "/readme.html")
        if readme:
            m = re.search(r"Version\s+([0-9.]+)", readme.text, re.I)
            if m:
                version = m.group(1)
                result.signals.append("path:readme.html")

    if result.signals:
        result.detected = True
        result.version = version
    return result


# -- Joomla -------------------------------------------------------------------

def _detect_joomla(engine: ScanEngine, soup: BeautifulSoup, html: str, headers: httpx.Headers) -> _ProbeResult:
    result = _ProbeResult()
    version = ""

    generator = _meta_generator(soup)
    if re.search(r"Joomla", generator, re.I):
        result.signals.append("meta:generator")
        m = re.search(r"Joomla[!\s]+([0-9.]+)", generator, re.I)
        if m:
            version = m.group(1)

    if re.search(r"/media/jui/|/components/com_", html):
        result.signals.append("html:joomla-paths")

    if _probe_path(engine, "/administrator/"):
        result.signals.append("path:/administrator/")

    if not version:
        manifest = _probe_path(engine, "/administrator/manifests/files/joomla.xml")
        if manifest:
            m = re.search(r"<version>([0-9.]+)</version>", manifest.text)
            if m:
                version = m.group(1)
                result.signals.append("path:joomla.xml")

    if result.signals:
        result.detected = True
        result.version = version
    return result


# -- Drupal -------------------------------------------------------------------

def _detect_drupal(engine: ScanEngine, soup: BeautifulSoup, html: str, headers: httpx.Headers) -> _ProbeResult:
    result = _ProbeResult()
    version = ""

    if headers.get("x-generator", "").lower().startswith("drupal"):
        result.signals.append("header:x-generator")
        m = re.search(r"Drupal\s+([0-9.]+)", headers.get("x-generator", ""), re.I)
        if m:
            version = m.group(1)

    if headers.get("x-drupal-cache") or headers.get("x-drupal-dynamic-cache"):
        result.signals.append("header:x-drupal-cache")

    generator = _meta_generator(soup)
    if re.search(r"Drupal", generator, re.I):
        result.signals.append("meta:generator")
        m = re.search(r"Drupal\s+([0-9.]+)", generator, re.I)
        if m:
            version = m.group(1)

    if re.search(r"/sites/default/|Drupal\.settings", html):
        result.signals.append("html:drupal-paths")

    if not version:
        changelog = _probe_path(engine, "/CHANGELOG.txt")
        if changelog:
            m = re.search(r"Drupal\s+([0-9.]+)", changelog.text)
            if m:
                version = m.group(1)
                result.signals.append("path:CHANGELOG.txt")

    if result.signals:
        result.detected = True
        result.version = version
    return result


# -- Magento ------------------------------------------------------------------

def _detect_magento(engine: ScanEngine, soup: BeautifulSoup, html: str, headers: httpx.Headers) -> _ProbeResult:
    result = _ProbeResult()
    version = ""

    if re.search(r"Mage\.Cookies|/skin/frontend/|/mage/", html):
        result.signals.append("html:magento-patterns")

    if _probe_path(engine, "/magento_version"):
        ver_resp = _probe_path(engine, "/magento_version")
        if ver_resp:
            m = re.search(r"([0-9]+\.[0-9.]+)", ver_resp.text)
            if m:
                version = m.group(1)
                result.signals.append("path:magento_version")

    if result.signals:
        result.detected = True
        result.version = version
    return result


# -- Hosted platforms (header/HTML pattern only) ------------------------------

def _detect_shopify(engine: ScanEngine, soup: BeautifulSoup, html: str, headers: httpx.Headers) -> _ProbeResult:
    signals = []
    if headers.get("x-shopify-stage") or headers.get("x-shopid"):
        signals.append("header:x-shopify")
    if re.search(r"cdn\.shopify\.com|Shopify\.theme", html):
        signals.append("html:shopify-cdn")
    return _ProbeResult(detected=bool(signals), signals=signals)


def _detect_wix(engine: ScanEngine, soup: BeautifulSoup, html: str, headers: httpx.Headers) -> _ProbeResult:
    signals = []
    if headers.get("x-wix-request-id"):
        signals.append("header:x-wix-request-id")
    if re.search(r"static\.wixstatic\.com|wix-bolt", html):
        signals.append("html:wix-assets")
    return _ProbeResult(detected=bool(signals), signals=signals)


def _detect_squarespace(engine: ScanEngine, soup: BeautifulSoup, html: str, headers: httpx.Headers) -> _ProbeResult:
    signals = []
    if re.search(r"squarespace\.com|Squarespace", html, re.I):
        signals.append("html:squarespace-assets")
    generator = _meta_generator(soup)
    if re.search(r"Squarespace", generator, re.I):
        signals.append("meta:generator")
    return _ProbeResult(detected=bool(signals), signals=signals)


def _detect_ghost(engine: ScanEngine, soup: BeautifulSoup, html: str, headers: httpx.Headers) -> _ProbeResult:
    signals = []
    version = ""
    if re.search(r"/ghost/api/|ghost\.min\.js", html):
        signals.append("html:ghost-paths")
    generator = _meta_generator(soup)
    if re.search(r"Ghost", generator, re.I):
        signals.append("meta:generator")
        m = re.search(r"Ghost\s+([0-9.]+)", generator, re.I)
        if m:
            version = m.group(1)
    return _ProbeResult(detected=bool(signals), version=version, signals=signals)


def _detect_typo3(engine: ScanEngine, soup: BeautifulSoup, html: str, headers: httpx.Headers) -> _ProbeResult:
    signals = []
    version = ""
    if re.search(r"/typo3/|typo3temp", html, re.I):
        signals.append("html:typo3-paths")
    generator = _meta_generator(soup)
    if re.search(r"TYPO3", generator, re.I):
        signals.append("meta:generator")
        m = re.search(r"TYPO3\s+([0-9.]+)", generator, re.I)
        if m:
            version = m.group(1)
    return _ProbeResult(detected=bool(signals), version=version, signals=signals)


def _detect_prestashop(engine: ScanEngine, soup: BeautifulSoup, html: str, headers: httpx.Headers) -> _ProbeResult:
    signals = []
    version = ""
    if re.search(r"/modules/ps_|PrestaShop|prestashop", html, re.I):
        signals.append("html:prestashop-patterns")
    if headers.get("x-powered-by", "").lower().startswith("prestashop"):
        signals.append("header:x-powered-by")
        m = re.search(r"([0-9.]+)", headers.get("x-powered-by", ""))
        if m:
            version = m.group(1)
    return _ProbeResult(detected=bool(signals), version=version, signals=signals)


# Dispatch table
_DETECTORS = {
    "WordPress":   _detect_wordpress,
    "Joomla":      _detect_joomla,
    "Drupal":      _detect_drupal,
    "Magento":     _detect_magento,
    "Shopify":     _detect_shopify,
    "Wix":         _detect_wix,
    "Squarespace": _detect_squarespace,
    "Ghost":       _detect_ghost,
    "TYPO3":       _detect_typo3,
    "PrestaShop":  _detect_prestashop,
}


# ---------------------------------------------------------------------------
# Finding factory
# ---------------------------------------------------------------------------

def _cms_finding(name: str, version: str, signals: list[str], hosted: bool) -> Finding:
    ver_str = f" {version}" if version else " (version unknown)"
    signal_str = ", ".join(signals)
    rec = (
        f"This is a hosted platform ({name}); keep themes and apps up to date."
        if hosted else
        f"Keep {name} and all plugins/themes updated to the latest version. "
        "Remove unused plugins. Subscribe to the CMS security mailing list."
    )
    return Finding(
        module=MODULE,
        title=f"CMS Detected: {name}{ver_str}",
        description=f"{name}{ver_str} detected via: {signal_str}.",
        severity=Severity.HIGH,
        recommendation=rec,
        raw={"cms": name, "version": version, "signals": signals},
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(engine: ScanEngine) -> list[Finding]:
    # Lazy import to avoid circular dependency; cve_mapping may call back into engine
    from scanner.vulns import cve_mapping  # noqa: PLC0415

    findings: list[Finding] = []

    try:
        resp = engine.get()
    except httpx.HTTPError as exc:
        logger.warning(f"cms_detect: request failed: {exc}")
        return []

    html = resp.text
    headers = resp.headers

    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception as exc:
        logger.warning(f"cms_detect: HTML parse error: {exc}")
        soup = BeautifulSoup("", "html.parser")

    for cms_name, detector in _DETECTORS.items():
        spec = _CMS_SPECS[cms_name]
        try:
            result = detector(engine, soup, html, headers)
        except Exception as exc:
            logger.debug(f"cms_detect: {cms_name} probe error: {exc}")
            continue

        if not result.detected:
            continue

        findings.append(_cms_finding(cms_name, result.version, result.signals, spec.hosted))

        # Trigger CVE lookup if a version was extracted
        if result.version:
            try:
                cve_findings = cve_mapping.lookup(cms_name, result.version, engine)
                findings.extend(cve_findings)
            except Exception as exc:
                logger.debug(f"cms_detect: cve_mapping.lookup failed for {cms_name} {result.version}: {exc}")

        # Only report the first CMS detected — multiple matches indicate a detection error
        break

    return findings
