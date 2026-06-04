"""
cve_mapping — queries the NVD API for CVEs matching detected software versions.

run(engine) re-runs tech_stack detection inline (since modules execute in parallel
and engine.findings is not populated yet) then queries NVD for each versioned component.

lookup(technology, version, engine) is the direct entry point used by cms_detect
when it identifies a CMS version during its own run.
"""
from __future__ import annotations

import os
import time
from typing import Any

import httpx
from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "cve_mapping"

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_TOP_N = 3          # max CVEs to report per technology
_RETRY_LIMIT = 3
_RETRY_DELAY = 6.0  # seconds — NVD rate limit: 5 req/30s without key

# ---------------------------------------------------------------------------
# CVSS score → Severity mapping
# ---------------------------------------------------------------------------

def _cvss_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


# ---------------------------------------------------------------------------
# NVD API client (separate from the scan engine — this is an external service)
# ---------------------------------------------------------------------------

def _nvd_headers() -> dict[str, str]:
    api_key = os.environ.get("NVD_API_KEY", "")
    if api_key:
        return {"apiKey": api_key}
    return {}


def _query_nvd(technology: str, version: str) -> list[dict[str, Any]]:
    """
    Query NVD for up to _TOP_N CVEs matching '{technology} {version}'.
    Returns raw vulnerability dicts from the API response.
    Raises httpx.HTTPError on persistent failure.
    """
    keyword = f"{technology} {version}"
    params: dict[str, Any] = {
        "keywordSearch": keyword,
        "resultsPerPage": _TOP_N,
        "startIndex": 0,
    }

    for attempt in range(1, _RETRY_LIMIT + 1):
        try:
            resp = httpx.get(
                _NVD_BASE,
                params=params,
                headers=_nvd_headers(),
                timeout=20.0,
            )

            if resp.status_code == 429 or resp.status_code == 403:
                wait = _RETRY_DELAY * attempt
                logger.debug(f"cve_mapping: NVD rate limit ({resp.status_code}), waiting {wait}s (attempt {attempt})")
                time.sleep(wait)
                continue

            resp.raise_for_status()
            data = resp.json()
            return data.get("vulnerabilities", [])

        except httpx.HTTPError as exc:
            if attempt == _RETRY_LIMIT:
                raise
            logger.debug(f"cve_mapping: NVD request failed (attempt {attempt}): {exc}")
            time.sleep(_RETRY_DELAY)

    return []


# ---------------------------------------------------------------------------
# CVE parsing
# ---------------------------------------------------------------------------

def _extract_cvss(metrics: dict[str, Any]) -> tuple[float, str]:
    """Return (base_score, vector_string) from the highest-version CVSS block available."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            score = float(data.get("baseScore", 0.0))
            vector = data.get("vectorString", "")
            return score, vector
    return 0.0, ""


def _parse_cve(vuln: dict[str, Any]) -> tuple[str, str, float, str] | None:
    """Return (cve_id, description, cvss_score, vector) or None if unparseable."""
    cve = vuln.get("cve", {})
    cve_id: str = cve.get("id", "")
    if not cve_id:
        return None

    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        "No description available.",
    )

    metrics = cve.get("metrics", {})
    score, vector = _extract_cvss(metrics)
    return cve_id, description, score, vector


# ---------------------------------------------------------------------------
# Finding factory
# ---------------------------------------------------------------------------

def _cve_finding(
    technology: str, version: str,
    cve_id: str, description: str,
    cvss_score: float, vector: str,
) -> Finding:
    severity = _cvss_to_severity(cvss_score)
    score_str = f"{cvss_score:.1f}" if cvss_score else "N/A"
    vector_str = f" ({vector})" if vector else ""
    return Finding(
        module=MODULE,
        title=f"CVE: {cve_id} — {technology} {version} (CVSS {score_str})",
        description=(
            f"{cve_id} affects {technology} {version}. CVSS: {score_str}{vector_str}.\n"
            f"{description[:400]}{'...' if len(description) > 400 else ''}"
        ),
        severity=severity,
        recommendation=(
            f"Update {technology} to the latest patched version. "
            f"Review the full advisory at https://nvd.nist.gov/vuln/detail/{cve_id}"
        ),
        raw={
            "cve_id": cve_id,
            "technology": technology,
            "version": version,
            "cvss_score": cvss_score,
            "cvss_vector": vector,
            "description": description,
        },
    )


# ---------------------------------------------------------------------------
# Core lookup (shared by run() and direct callers like cms_detect)
# ---------------------------------------------------------------------------

def lookup(technology: str, version: str, engine: ScanEngine) -> list[Finding]:  # noqa: ARG001
    """Query NVD for CVEs matching *technology* at *version*."""
    if not version:
        return []

    findings: list[Finding] = []

    try:
        vulns = _query_nvd(technology, version)
    except httpx.HTTPError as exc:
        logger.warning(f"cve_mapping: NVD query failed for {technology} {version}: {exc}")
        return [Finding(
            module=MODULE,
            title=f"CVE Lookup Failed: {technology} {version}",
            description=f"NVD API request failed: {exc}",
            severity=Severity.INFO,
            recommendation="Check NVD API availability or set NVD_API_KEY env var for higher rate limits.",
            raw={"technology": technology, "version": version, "error": str(exc)},
        )]

    for vuln in vulns[:_TOP_N]:
        parsed = _parse_cve(vuln)
        if parsed:
            cve_id, description, score, vector = parsed
            findings.append(_cve_finding(technology, version, cve_id, description, score, vector))

    return findings


# ---------------------------------------------------------------------------
# Standalone module entry point
# ---------------------------------------------------------------------------

def run(engine: ScanEngine) -> list[Finding]:
    # Re-run tech_stack detection inline to obtain versioned findings.
    # Modules execute in parallel so engine.findings is empty at this point.
    from scanner.recon.tech_stack import run as tech_run  # noqa: PLC0415

    try:
        tech_findings = tech_run(engine)
    except Exception as exc:
        logger.warning(f"cve_mapping: tech_stack re-run failed: {exc}")
        return [Finding(
            module=MODULE,
            title="CVE Mapping Skipped",
            description=f"Technology detection failed: {exc}",
            severity=Severity.INFO,
            recommendation="",
            raw={"error": str(exc)},
        )]

    # Collect unique (technology, version) pairs that have a version string
    versioned: dict[tuple[str, str], bool] = {}
    for f in tech_findings:
        tech = f.raw.get("technology", "")
        version = f.raw.get("version", "")
        if tech and version:
            versioned[(tech, version)] = True

    if not versioned:
        return [Finding(
            module=MODULE,
            title="CVE Mapping: No Versioned Technologies Detected",
            description=(
                "Tech stack detection found no components with extractable version numbers. "
                "CVE lookup requires a version to query NVD accurately."
            ),
            severity=Severity.INFO,
            recommendation="",
            raw={},
        )]

    findings: list[Finding] = []
    nvd_available = True

    for (technology, version) in versioned:
        if not nvd_available:
            break

        try:
            cve_findings = lookup(technology, version, engine)
            findings.extend(cve_findings)
            # If the lookup returned an API error finding, mark NVD as down
            if cve_findings and cve_findings[0].title.startswith("CVE Lookup Failed"):
                nvd_available = False
        except Exception as exc:
            logger.warning(f"cve_mapping: lookup error for {technology} {version}: {exc}")

        # Respect NVD rate limits between queries (5 req/30s without API key)
        if nvd_available and len(versioned) > 1:
            time.sleep(_RETRY_DELAY)

    if not nvd_available:
        findings.append(Finding(
            module=MODULE,
            title="CVE Lookup Skipped — NVD API Unavailable",
            description=(
                "The NVD API was unreachable or rate-limited. "
                "Remaining technology lookups were skipped."
            ),
            severity=Severity.INFO,
            recommendation=(
                "Set the NVD_API_KEY environment variable for a higher rate limit (50 req/30s). "
                "Re-run the scan when the API is available."
            ),
            raw={"nvd_available": False},
        ))

    return findings
