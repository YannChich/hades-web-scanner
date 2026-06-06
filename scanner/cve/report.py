"""report — turn CveFinding objects into Hades Findings and a Rich console panel."""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel

from scanner.cve.models import CveFinding
from scanner.engine import Finding, Severity
from scanner.severity import CONSOLE_STYLE

console = Console()

# CVE confidence -> the scorer's low/medium/high confidence weighting.
_SCORE_CONFIDENCE = {"CONFIRMED": "high", "LIKELY": "medium", "POSSIBLE": "low", "INFO": "low"}


def to_finding(cf: CveFinding, target: str) -> Finding:
    """Convert a CveFinding into a Hades Finding (severity = the priority-based severity)."""
    ver = f" {cf.detected_version}" if cf.detected_version else ""
    desc = (f"{cf.product}{ver} is affected by {cf.cve_id} (confidence: {cf.confidence}). "
            f"Affected: {cf.affected_range}. CVSS {cf.cvss_score if cf.cvss_score is not None else 'n/a'}"
            + (f", EPSS {cf.epss:.2f}" if cf.epss is not None else "")
            + (", listed in CISA KEV (actively exploited)" if cf.kev else "")
            + (f".\n\n{cf.impact}" if cf.impact else "."))
    return Finding(
        module="cve_vulnerability",
        title=f"{cf.cve_id}: {cf.product}{ver} ({cf.confidence})",
        description=desc,
        severity=Severity(cf.priority_severity),
        recommendation=cf.remediation,
        cwe=cf.cwe or "",
        owasp="A06:2021 Vulnerable and Outdated Components",
        mitre=["T1190"],
        cvss=cf.cvss_score,
        raw={
            "cve_id": cf.cve_id, "vendor": cf.vendor, "product": cf.product,
            "detected_version": cf.detected_version, "affected_range": cf.affected_range,
            "cvss_score": cf.cvss_score, "cvss_vector": cf.cvss_vector, "cve_severity": cf.severity,
            "cwe": cf.cwe, "epss": cf.epss, "epss_percentile": cf.epss_percentile, "kev": cf.kev,
            "cve_confidence": cf.confidence, "priority_score": cf.priority_score,
            "evidence": cf.evidence, "impact": cf.impact, "remediation": cf.remediation,
            "references": cf.references, "source_module": "cve_vulnerability",
            "confidence": _SCORE_CONFIDENCE.get(cf.confidence, "low"),
            "proof_url": cf.references[0] if cf.references else "",
        },
    )


def render_panel(findings) -> None:
    """Render the CVE Vulnerability Intelligence panel from the scan's Findings. No-op if none.

    Called from engine.run_scan (post-scan) like the other dedicated profile panels; reconstructs
    the display from each Finding's raw, so it stays decoupled from the detector internals.
    """
    cve = [f for f in findings if f.module == "cve_vulnerability"
           and (f.raw or {}).get("cve_category") != "info" and f.raw.get("cve_id")]
    if not cve:
        return

    body = []
    for f in sorted(cve, key=lambda x: x.raw.get("priority_score", 0), reverse=True)[:30]:
        r = f.raw
        style = CONSOLE_STYLE.get(f.severity.value, "white")
        kev = "[bold red]Yes[/bold red]" if r.get("kev") else "no"
        epss = f"{r['epss']:.2f}" if r.get("epss") is not None else "n/a"
        cvss = r.get("cvss_score") if r.get("cvss_score") is not None else "n/a"
        prod = f"{r.get('product', '')} {r.get('detected_version', '')}".strip()
        body.append(
            f"[{style}]{f.severity.value.upper():<8}[/] [bold]{r['cve_id']}[/]  {prod}"
            f"\n           score [bold]{r.get('priority_score', 0)}/100[/] · CVSS {cvss} · "
            f"EPSS {epss} · KEV {kev} · {r.get('cve_confidence', '')} · "
            f"affected {r.get('affected_range', '')}")

    crit = sum(1 for f in cve if f.severity.value == "critical")
    kevs = sum(1 for f in cve if f.raw.get("kev"))
    console.print()
    console.print(Panel(
        "\n".join(body),
        title="[bold red]CVE Vulnerability Intelligence[/bold red]",
        subtitle=f"[dim]{len(cve)} CVE(s) · {crit} critical · {kevs} in CISA KEV · "
                 "free local DB (KEV/EPSS) + NVD[/dim]",
        border_style="red", padding=(1, 2)))
