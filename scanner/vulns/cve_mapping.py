"""
cve_mapping — maps detected software versions to real CVEs (version-accurate).

Historically this module did an NVD full-text ``keywordSearch`` and reported the top results,
which produced false positives (CVEs that merely *mention* a product, or affect other versions).
It now reuses the accurate ``scanner.cve`` engine: each detected product is resolved to a CPE,
matched against NVD's four version-range bounds, classified (CONFIRMED / LIKELY / POSSIBLE),
enriched with CISA KEV / FIRST EPSS, and filtered to 2020+ — so a finding means the detected
version actually falls inside the CVE's affected range.

run(engine) re-runs tech_stack inline (modules execute in parallel, so engine.findings is empty)
and maps every versioned component. lookup(technology, version, engine) is the direct entry point
used by cms_detect when it identifies a CMS version.
"""
from __future__ import annotations

import time

from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "cve_mapping"

_MAX_PRODUCTS = 12     # bound NVD on-demand queries per scan (rate-limited without a key)
_NVD_DELAY = 1.5


def lookup(technology: str, version: str, engine: ScanEngine) -> list[Finding]:
    """Map *technology* at *version* to real CVEs via the version-accurate scanner.cve engine."""
    if not version:
        return []

    # Lazy imports: keep the CVE engine optional and avoid import cost on unrelated scans.
    from scanner.cve import nvd_parser, report
    from scanner.cve.cpe_matcher import candidates
    from scanner.cve.db import get_conn
    from scanner.cve.detector import _finalize, _match
    from scanner.cve.feed_downloader import has_full_nvd, query_nvd
    from scanner.cve.models import DetectedTech

    tech = DetectedTech(name=technology, version=version, source="tech_stack",
                        confidence=0.9, evidence=f"{technology} {version}")
    cands = candidates(tech)
    if not cands:
        return []   # product not in the CPE alias table → cannot map accurately (no guessing, no FP)

    offline = has_full_nvd()
    cve_findings = []
    conn = get_conn()
    try:
        for cand in cands:
            if not offline:
                data = query_nvd(virtual_match=cand.cpe_prefix)
                if data:
                    try:
                        nvd_parser.ingest(conn, data)
                    except Exception as exc:  # noqa: BLE001
                        logger.debug(f"cve_mapping: NVD ingest failed: {exc}")
                    time.sleep(_NVD_DELAY)
            cve_findings.extend(_match(conn, tech, cand))
        results, _ = _finalize(cve_findings)
    finally:
        conn.close()

    findings: list[Finding] = []
    for cf in results:
        f = report.to_finding(cf, engine.url)
        f.module = MODULE   # attribute to cve_mapping within the standard scan (not the cve panel)
        findings.append(f)
    return findings


def run(engine: ScanEngine) -> list[Finding]:
    from scanner.recon.tech_stack import run as tech_run  # noqa: PLC0415

    try:
        tech_findings = tech_run(engine)
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"cve_mapping: tech_stack re-run failed: {exc}")
        return [Finding(MODULE, "CVE Mapping Skipped", f"Technology detection failed: {exc}",
                        Severity.INFO, "", {"error": str(exc), "confidence": "high"})]

    # Unique (technology, version) pairs that carry a usable version string.
    versioned: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for f in tech_findings:
        tech = (f.raw or {}).get("technology", "")
        version = (f.raw or {}).get("version", "")
        if tech and version and (tech, version) not in seen:
            seen.add((tech, version))
            versioned.append((tech, version))

    if not versioned:
        return [Finding(
            MODULE, "CVE Mapping: No Versioned Technologies Detected",
            "Tech-stack detection found no components with an extractable version number; "
            "accurate CVE mapping requires a version.",
            Severity.INFO, "", {"confidence": "high"})]

    findings: list[Finding] = []
    for technology, version in versioned[:_MAX_PRODUCTS]:
        try:
            findings.extend(lookup(technology, version, engine))
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"cve_mapping: lookup error for {technology} {version}: {exc}")

    kev = sum(1 for f in findings if (f.raw or {}).get("kev"))
    findings.append(Finding(
        MODULE, f"CVE Mapping Summary: {len(findings)} CVE(s) across {len(versioned)} component(s)",
        f"{kev} in CISA KEV. Version-accurate matching (CPE + NVD version ranges, 2020+). "
        "For a full dedicated audit use menu option 8 (CVE Vulnerability Intelligence).",
        Severity.INFO, "", {"confidence": "high", "cve_category": "info"}))
    return findings
