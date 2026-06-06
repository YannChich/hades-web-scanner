"""
detector — CVE Vulnerability Intelligence orchestrator (the cve_scan profile / menu option 8).

Full mode, no flags: ensure the local CVE database exists and is fresh, collect technologies from
the target (Server header, tech_stack, cms_detect), resolve each to CPE candidates, pull matching
CVEs from NVD on demand (cached locally), version-match, enrich with CISA KEV / FIRST EPSS, classify
(CONFIRMED / LIKELY / POSSIBLE), score with the Hades CVE Priority Score, and emit Findings.
"""
from __future__ import annotations

import importlib
import json
import re
import time

from loguru import logger

from scanner.cve import nvd_parser, report
from scanner.cve.cpe_matcher import candidates
from scanner.cve.db import db_exists, get_conn
from scanner.cve.models import CveFinding, DetectedTech
from scanner.cve.prioritizer import priority_score, severity_from_score
from scanner.cve.version_matcher import affected_range_str, classify
from scanner.engine import Finding, Severity, ScanEngine
from scanner.severity import sort_by_severity

MODULE = "cve_vulnerability"

# Cap NVD queries per scan (rate-limited, no key) and limit unknown-version noise.
_MAX_PRODUCTS = 8
_NVD_DELAY = 1.5
_POSSIBLE_TOP = 10


def _info(title: str, desc: str) -> Finding:
    return Finding(module=MODULE, title=title, description=desc, severity=Severity.INFO,
                   recommendation="", raw={"cve_category": "info", "confidence": "high"})


def _collect_tech(engine: ScanEngine) -> list[DetectedTech]:
    """Discover technologies (with versions where possible) for CVE matching."""
    techs: dict[tuple[str, str], DetectedTech] = {}

    def add(name: str, version: str, type_: str, source: str, conf: float, evidence: str) -> None:
        name = (name or "").strip()
        if not name:
            return
        key = (name.lower(), version)
        techs.setdefault(key, DetectedTech(name=name, version=version, type=type_,
                                           source=source, confidence=conf, evidence=evidence))

    try:
        resp = engine.get()
        server = resp.headers.get("server", "")
        if server:
            m = re.match(r"([A-Za-z][\w\-]*)[/ ]?([\d][\d.]*)?", server)
            if m:
                add(m.group(1), m.group(2) or "", "web_server", "Server header",
                    0.9 if m.group(2) else 0.6, f"Server: {server}")
        powered = resp.headers.get("x-powered-by", "")
        if powered:
            m = re.match(r"([A-Za-z][\w\-.]*)[/ ]?([\d][\d.]*)?", powered)
            if m:
                add(m.group(1), m.group(2) or "", "language", "X-Powered-By header",
                    0.85 if m.group(2) else 0.5, f"X-Powered-By: {powered}")
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"cve: header tech collection failed: {exc}")

    for modpath in ("scanner.recon.tech_stack", "scanner.web.cms_detect"):
        try:
            for f in importlib.import_module(modpath).run(engine):
                r = f.raw or {}
                name = r.get("technology") or r.get("cms") or r.get("name") or ""
                if not name or r.get("confidence") == "high" and not name:
                    continue
                ver = r.get("version", "") or ""
                add(name, ver, r.get("category", ""), r.get("source", modpath.split(".")[-1]),
                    0.9 if ver else 0.6, f.title)
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"cve: {modpath} collection failed: {exc}")

    return list(techs.values())


def _build_cf(tech: DetectedTech, cand, match: dict, cve, intel, level: str) -> CveFinding:
    cvss = cve["cvss_score"] if cve else None
    vector = cve["cvss_vector"] if cve else ""
    cve_sev = cve["severity"] if cve else ""
    cwe = cve["cwe"] if cve else ""
    descr = cve["description"] if cve else ""
    kev = bool(intel["kev"]) if intel else False
    epss = intel["epss"] if intel else None
    pct = intel["epss_percentile"] if intel else None

    score = priority_score(cvss, epss, kev, internet_exposed=True, confidence=level)
    refs: list[str] = []
    if cve and cve["references_json"]:
        try:
            refs = json.loads(cve["references_json"])[:4]
        except ValueError:
            refs = []
    refs = [f"https://nvd.nist.gov/vuln/detail/{match['cve_id']}"] + refs
    if kev:
        refs.append("https://www.cisa.gov/known-exploited-vulnerabilities-catalog")

    return CveFinding(
        cve_id=match["cve_id"], vendor=cand.vendor, product=cand.product,
        detected_version=tech.version or "unknown", affected_range=affected_range_str(match),
        cvss_score=cvss, cvss_vector=vector, severity=cve_sev, cwe=cwe, epss=epss,
        epss_percentile=pct, kev=kev, confidence=level, priority_score=score,
        priority_severity=severity_from_score(score), evidence=tech.evidence,
        impact=(descr[:240] + "…") if len(descr) > 240 else descr,
        remediation=f"Upgrade {cand.product} to a patched version (see references).",
        references=refs[:6], description=descr)


def _match(conn, tech: DetectedTech, cand) -> list[CveFinding]:
    rows = conn.execute(
        "SELECT * FROM cpe_matches WHERE vendor=? AND product=? AND vulnerable=1",
        (cand.vendor, cand.product)).fetchall()
    out: list[CveFinding] = []
    seen: set[str] = set()
    for m in rows:
        md = dict(m)
        level = classify(tech.version, md, tech.confidence)
        if level is None or md["cve_id"] in seen:
            continue
        seen.add(md["cve_id"])
        cve = conn.execute("SELECT * FROM cves WHERE cve_id=?", (md["cve_id"],)).fetchone()
        intel = conn.execute("SELECT * FROM exploit_intel WHERE cve_id=?", (md["cve_id"],)).fetchone()
        out.append(_build_cf(tech, cand, md, cve, intel, level))
    return out


def _finalize(items: list[CveFinding]) -> tuple[list[CveFinding], list[tuple[str, int]]]:
    best: dict[str, CveFinding] = {}
    for cf in items:
        if cf.cve_id not in best or cf.priority_score > best[cf.cve_id].priority_score:
            best[cf.cve_id] = cf
    items = list(best.values())

    keep = [c for c in items if c.confidence in ("CONFIRMED", "LIKELY")]
    possible_by_prod: dict[str, list[CveFinding]] = {}
    for c in items:
        if c.confidence == "POSSIBLE":
            possible_by_prod.setdefault(c.product, []).append(c)

    notes: list[tuple[str, int]] = []
    for prod, lst in possible_by_prod.items():
        lst.sort(key=lambda c: (c.kev, c.epss or 0.0, c.cvss_score or 0.0), reverse=True)
        if len(lst) > _POSSIBLE_TOP:
            notes.append((prod, len(lst)))
        keep.extend(lst[:_POSSIBLE_TOP])
    keep.sort(key=lambda c: c.priority_score, reverse=True)
    return keep, notes


def run(engine: ScanEngine) -> list[Finding]:
    from scanner.cve.feed_downloader import query_nvd, update_vulndb_if_stale

    if not update_vulndb_if_stale(7) and not db_exists():
        return [_info("CVE Database Unavailable",
                      "Could not build or reach the local CVE database (KEV/EPSS feeds). "
                      "Check connectivity and re-run; the rest of Hades is unaffected.")]

    findings: list[Finding] = []
    conn = get_conn()
    try:
        techs = _collect_tech(engine)
        if not techs:
            findings.append(_info("CVE Intelligence: No Technologies Identified",
                                  "No products/versions could be fingerprinted on the target."))
            return findings

        cve_findings: list[CveFinding] = []
        queried: set[str] = set()
        for tech in techs:
            for cand in candidates(tech):
                if cand.cpe_prefix not in queried and len(queried) < _MAX_PRODUCTS:
                    queried.add(cand.cpe_prefix)
                    data = query_nvd(virtual_match=cand.cpe_prefix)
                    if data:
                        try:
                            nvd_parser.ingest(conn, data)
                        except Exception as exc:  # noqa: BLE001
                            logger.debug(f"cve: NVD ingest failed: {exc}")
                    time.sleep(_NVD_DELAY)
                cve_findings.extend(_match(conn, tech, cand))

        results, notes = _finalize(cve_findings)
        for prod, total in notes:
            findings.append(_info(
                f"CVE Intelligence: {prod} version unknown — {total} related CVEs",
                f"{prod} was detected but its version is unknown. {total} related CVEs exist in the "
                f"local database; showing the top {_POSSIBLE_TOP} by CISA KEV, EPSS and CVSS."))

        for cf in results:
            findings.append(report.to_finding(cf, engine.url))

        confirmed = sum(1 for c in results if c.confidence in ("CONFIRMED", "LIKELY"))
        findings.append(_info(
            f"CVE Intelligence Summary: {len(results)} CVE(s) across {len(techs)} technology(ies)",
            f"{confirmed} confirmed/likely; {sum(1 for c in results if c.kev)} in CISA KEV. "
            "Sources: local KEV/EPSS database + NVD 2.0 (free, no API key)."))
    finally:
        conn.close()

    return sort_by_severity(findings)


# Alias matching the spec's menu hook name.
def run_cve_vulnerability_full(engine: ScanEngine) -> list[Finding]:
    return run(engine)
