"""
report_md — emit scan findings as a Markdown report.

The HTML report is for reading, the JSON/SARIF reports are for tooling — but pentesters constantly
need to *paste* results somewhere: a GitHub/GitLab issue, a ticket, a Slack thread, a client email,
a repo's ``SECURITY_FINDINGS.md``. Markdown is the lingua franca for all of those, and it renders
with tables, headings and ``curl`` code blocks intact.

This module turns a finished scan into a single ``.md`` document:

* a header with the target, scan date, Hades version and the risk score + grade;
* a severity-count summary table and (when a retest ran) a diff line;
* one section per finding, newest-severity-first, carrying CWE / OWASP / MITRE / CVSS, the
  confidence + a ``✓ verified`` marker, the evidence lines, the recommendation and the PoC command.

It is a pure, dependency-free renderer: ``build_markdown`` returns the string (easy to unit-test) and
``generate_md`` writes it, degrading to ``None`` on any error so the reporting layer can never abort
a scan.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from loguru import logger

from config import HADES_VERSION
from scanner import evidence as ev
from scanner.output.scorer import calculate_score
from scanner.severity import SEVERITY_ORDER, severity_counts, sort_by_severity

if TYPE_CHECKING:
    from scanner.engine import Finding

# A small emoji per severity so a pasted report scans at a glance on GitHub.
_SEV_BADGE = {
    "critical": "🔴 Critical",
    "high":     "🟠 High",
    "medium":   "🟡 Medium",
    "low":      "🟢 Low",
    "info":     "🔵 Info",
}

_RETEST_LABEL = {
    "new":           "🆕 new",
    "still-present": "♻️ still present",
    "fixed":         "✅ fixed",
}


def _sev_value(f: "Finding") -> str:
    sev = f.severity
    return sev.value if hasattr(sev, "value") else str(sev)


def _md_escape(text: str) -> str:
    """Escape the pipe so a value never breaks a Markdown table cell."""
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


def _summary_table(counts: dict[str, int]) -> list[str]:
    lines = ["| Severity | Count |", "| --- | --- |"]
    for sev in SEVERITY_ORDER:
        lines.append(f"| {_SEV_BADGE[sev]} | {counts.get(sev, 0)} |")
    total = sum(counts.get(s, 0) for s in SEVERITY_ORDER)
    lines.append(f"| **Total** | **{total}** |")
    return lines


def _finding_section(f: "Finding", index: int) -> list[str]:
    sev = _sev_value(f)
    verified = " · ✓ verified" if bool(getattr(f, "verified", False)) else ""
    confidence = (f.raw or {}).get("confidence", "")

    out: list[str] = [f"### {index}. {_md_escape(f.title)}", ""]

    # A compact metadata table (only the columns that have a value).
    meta: list[tuple[str, str]] = [("Severity", _SEV_BADGE.get(sev, sev))]
    if confidence:
        meta.append(("Confidence", f"{confidence}{verified}"))
    elif verified:
        meta.append(("Confidence", verified.strip(" ·")))
    if f.module:
        meta.append(("Module", f"`{f.module}`"))
    if f.cwe:
        meta.append(("CWE", f.cwe))
    if f.owasp:
        meta.append(("OWASP", f.owasp))
    if f.mitre:
        meta.append(("MITRE ATT&CK", ", ".join(f.mitre)))
    if f.cvss is not None:
        meta.append(("CVSS", str(f.cvss)))
    retest = (f.raw or {}).get("retest")
    if retest in _RETEST_LABEL:
        meta.append(("Retest", _RETEST_LABEL[retest]))

    out.append("| Field | Value |")
    out.append("| --- | --- |")
    for label, value in meta:
        out.append(f"| {label} | {_md_escape(value)} |")
    out.append("")

    if f.description:
        out.append(_md_escape(f.description))
        out.append("")

    evidence = ev.as_list((f.raw or {}).get("evidence"))
    if evidence:
        out.append("**Evidence:**")
        out.append("")
        out.append("```")
        out.extend(str(line) for line in evidence[:12])
        out.append("```")
        out.append("")

    if f.verification:
        out.append(f"**Verification:** {_md_escape(f.verification)}")
        out.append("")

    if f.recommendation:
        out.append(f"**Recommendation:** {_md_escape(f.recommendation)}")
        out.append("")

    if f.poc:
        out.append("**Proof of concept:**")
        out.append("")
        out.append("```bash")
        out.append(str(f.poc))
        out.append("```")
        out.append("")

    if f.redteam_tools:
        out.append("**Relevant tools:** " + ", ".join(f"`{t}`" for t in f.redteam_tools))
        out.append("")

    return out


def build_markdown(findings: list["Finding"], url: str, score: int,
                   retest: dict | None = None) -> str:
    """Render a finished scan as a Markdown report string (pure — easy to unit-test)."""
    _, grade = calculate_score(findings)
    counts = severity_counts(findings)
    now = datetime.now(timezone.utc)

    lines: list[str] = [
        f"# Hades Security Report — {url}",
        "",
        f"- **Target:** {url}",
        f"- **Scan date:** {now.strftime('%Y-%m-%d %H:%M UTC')}",
        f"- **Hades version:** {HADES_VERSION}",
        f"- **Risk score:** {score}/100 (grade {grade})",
        "",
        "## Summary",
        "",
    ]
    lines.extend(_summary_table(counts))
    lines.append("")

    if isinstance(retest, dict) and not retest.get("baseline", False):
        n_new = len(retest.get("new", []))
        n_still = len(retest.get("still_present", []))
        n_fixed = len(retest.get("fixed", []))
        lines.append(
            f"**Retest diff vs previous scan:** {n_new} new · {n_still} still present · "
            f"{n_fixed} fixed."
        )
        lines.append("")

    actionable = [f for f in findings if _sev_value(f) != "info"]
    info = [f for f in findings if _sev_value(f) == "info"]

    lines.append("## Findings")
    lines.append("")
    if not actionable:
        lines.append("_No actionable (non-informational) findings were reported._")
        lines.append("")
    else:
        for i, f in enumerate(sort_by_severity(actionable), start=1):
            lines.extend(_finding_section(f, i))

    # Informational findings are bundled into a collapsed list so the report stays readable.
    if info:
        lines.append("<details>")
        lines.append(f"<summary><b>Informational ({len(info)})</b></summary>")
        lines.append("")
        for f in info:
            lines.append(f"- **{_md_escape(f.title)}** — `{f.module}`")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("_Generated by [Hades](https://github.com/YannChich/hades-web-scanner) — "
                 "authorised security testing only._")
    return "\n".join(lines) + "\n"


def generate_md(findings: list["Finding"], url: str, score: int, output_path: str = "reports",
                retest: dict | None = None) -> str | None:
    """Serialise findings to Markdown and write ``output_path/webscan_report_TIMESTAMP.md``.

    Returns the file path on success, None on error (never raises — reporting must not abort a scan).
    """
    try:
        doc = build_markdown(findings, url, score, retest=retest)
        os.makedirs(output_path, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        file_path = os.path.join(output_path, f"webscan_report_{timestamp}.md")
        with open(file_path, "w", encoding="utf-8") as fh:
            fh.write(doc)
        logger.info(f"Markdown report saved: {file_path}")
        return file_path
    except Exception as exc:  # noqa: BLE001 — reporting must never abort a scan
        logger.error(f"report_md: failed to write Markdown: {exc}")
        return None
