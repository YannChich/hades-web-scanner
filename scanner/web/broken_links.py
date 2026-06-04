"""
broken_links — classifies the HTTP status of every link the crawler discovered.

A naive "anything >= 400 is broken" check is misleading: a 403 is access control, not a
dead link, and a wall of 403s usually means a WAF/bot protection is blocking the scanner
rather than that the links are broken. This module separates the cases:

  • 404 / 410          → genuinely broken (removed) — Low internal, Info external
  • 5xx                → server error (often transient) — Info
  • 401 / 403          → access-controlled, NOT broken; collapsed into one advisory when many
                         (WAF/bot block) or reported individually when few
  • 429                → the scanner is being rate-limited — one advisory
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx
from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "broken_links"
_MAX_LINKS = 200
_WAF_COLLAPSE = 4          # this many 401/403s ⇒ treat as WAF/bot blocking, collapse


def _check(engine: ScanEngine, url: str) -> tuple[str, int]:
    """Return (url, status). HEAD first, GET fallback when HEAD is refused. 0 on error."""
    try:
        resp = engine.request("HEAD", url)
        if resp.status_code in (403, 405, 501):   # some servers mishandle HEAD
            resp = engine.request("GET", url)
        return url, resp.status_code
    except httpx.HTTPError as exc:
        logger.debug(f"broken_links: {url} → {exc}")
        return url, 0


def _link_finding(url: str, status: int, is_external: bool, kind: str) -> Finding:
    if kind == "broken":
        return Finding(
            MODULE, f"Broken {'External' if is_external else 'Internal'} Link [{status}]: {url}",
            f"The link {url} returned HTTP {status} (page removed/not found). "
            + ("It points to an external site the target does not control."
               if is_external else "Broken internal links harm usability and SEO."),
            Severity.INFO if is_external else Severity.LOW,
            "Remove or update the link to a valid destination.",
            {"url": url, "status_code": status, "external": is_external,
             "kind": "broken", "confidence": "high"})
    if kind == "server_error":
        return Finding(
            MODULE, f"Server Error on Link [{status}]: {url}",
            f"The link {url} returned HTTP {status}. This is a server-side error, possibly transient.",
            Severity.INFO, "Investigate the server error if it persists.",
            {"url": url, "status_code": status, "external": is_external,
             "kind": "server_error", "confidence": "medium"})
    # restricted (individual 401/403)
    return Finding(
        MODULE, f"Restricted Link [{status}]: {url}",
        f"The link {url} returned HTTP {status} — access is forbidden, not broken. The page likely "
        "exists but is protected (or the server blocked this automated request).",
        Severity.INFO if is_external else Severity.LOW,
        "Confirm the link is reachable for legitimate users; 403/401 indicates access control, not a dead link.",
        {"url": url, "status_code": status, "external": is_external,
         "kind": "restricted", "confidence": "medium"})


def run(engine: ScanEngine) -> list[Finding]:
    crawl = engine.get_crawl()
    external_set = set(crawl.external_links)

    seen: set[str] = set()
    links: list[str] = []
    for url in sorted(crawl.internal_links) + sorted(crawl.external_links):
        if url not in seen:
            seen.add(url)
            links.append(url)
    links = links[:_MAX_LINKS]

    if not links:
        return [Finding(MODULE, "Broken Links: No Links Crawled",
                        "The crawl did not discover any links to verify.",
                        Severity.INFO, "", {"confidence": "high"})]

    results: dict[str, int] = {}
    with ThreadPoolExecutor(max_workers=engine.threads) as pool:
        futures = {pool.submit(_check, engine, url): url for url in links}
        for future in as_completed(futures):
            url, status = future.result()
            if status:
                results[url] = status

    broken, server_err, forbidden, rate_limited = [], [], [], []
    for url, status in results.items():
        if status in (404, 410):
            broken.append((url, status))
        elif 500 <= status < 600:
            server_err.append((url, status))
        elif status in (401, 403):
            forbidden.append((url, status))
        elif status == 429:
            rate_limited.append(url)

    findings: list[Finding] = []

    for url, status in sorted(broken):
        findings.append(_link_finding(url, status, url in external_set, "broken"))
    for url, status in sorted(server_err):
        findings.append(_link_finding(url, status, url in external_set, "server_error"))

    # 401/403: collapse into one WAF/bot advisory when numerous, else report individually.
    if len(forbidden) >= _WAF_COLLAPSE:
        sample = ", ".join(u for u, _ in sorted(forbidden)[:5]) + (" …" if len(forbidden) > 5 else "")
        logger.info(f"broken_links: {len(forbidden)} links returned 401/403 — likely WAF/bot blocking")
        findings.append(Finding(
            MODULE, f"Access Blocked on {len(forbidden)} Links (Likely WAF/Bot Protection)",
            (f"{len(forbidden)} crawled links returned 401/403 to the scanner. This is almost certainly "
             "a WAF/bot protection blocking automated requests, not broken links — the pages likely work "
             f"in a normal browser. Affected: {sample}"),
            Severity.INFO,
            "Verify a sample manually in a browser. To scan behind the WAF, use an allowlisted IP or "
            "an authenticated/realistic session.",
            {"count": len(forbidden), "status_codes": sorted({s for _, s in forbidden}),
             "confidence": "high"}))
    else:
        for url, status in sorted(forbidden):
            findings.append(_link_finding(url, status, url in external_set, "restricted"))

    if rate_limited:
        findings.append(Finding(
            MODULE, f"Rate-Limited on {len(rate_limited)} Links (HTTP 429)",
            f"{len(rate_limited)} links returned HTTP 429 — the server is throttling the scanner, so "
            "results may be incomplete.",
            Severity.INFO, "Lower the thread count / increase the rate delay to scan more reliably.",
            {"count": len(rate_limited), "confidence": "high"}))

    if not findings:
        return [Finding(MODULE, "Broken Links: None Found",
                        f"Checked {len(links)} link(s); all responded healthily.",
                        Severity.INFO, "", {"links_checked": len(links), "confidence": "high"})]
    return findings
