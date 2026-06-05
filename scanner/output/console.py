"""
console — Rich-formatted terminal output for WebScan.

Provides the ASCII banner, per-finding coloured lines, the findings table,
and the final summary panel with score, grade, and priority recommendations.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from scanner.severity import CONSOLE_STYLE as _SEVERITY_STYLE
from scanner.severity import SEVERITY_ORDER as _SEVERITY_ORDER

if TYPE_CHECKING:
    from scanner.engine import Finding

console = Console()

# ---------------------------------------------------------------------------
# Severity labels (fixed-width, terminal-only)
# ---------------------------------------------------------------------------

_SEVERITY_LABEL: dict[str, str] = {
    "critical": "CRITICAL",
    "high":     "HIGH    ",
    "medium":   "MEDIUM  ",
    "low":      "LOW     ",
    "info":     "INFO    ",
}

# Findings from these modules get a clickable "verify" link in the table so the
# user can Ctrl+click to open the exact URL in a browser and confirm it manually.
_VERIFIABLE_MODULES: set[str] = {"dir_scan", "sensitive_files", "admin_panel",
                                 "dir_listing", "backup_files", "robots_txt",
                                 "sqli_detect", "xss_detect", "command_injection",
                                 "ssti_detect", "lfi_detect", "open_redirect", "ssrf_detect"}


def _format_refs(finding: "Finding") -> str:
    """Compact one-line framework reference: ID · CVSS · CWE · OWASP code · ATT&CK."""
    parts: list[str] = [finding.finding_id] if finding.finding_id else []
    if finding.cvss is not None:
        parts.append(f"CVSS {finding.cvss:g}")
    if finding.cwe:
        parts.append(finding.cwe)
    if finding.owasp:
        parts.append(finding.owasp.split(" ")[0])  # just the "A03:2021" code
    parts.extend(finding.mitre)
    return " · ".join(parts)


def _verify_url(finding: "Finding", base_url: str) -> str | None:
    """Return the URL to verify for a verifiable finding, or None."""
    if finding.module not in _VERIFIABLE_MODULES:
        return None
    raw = finding.raw or {}
    # A proof URL (the exact injected request) takes priority over the plain URL.
    if raw.get("proof_url"):
        return str(raw["proof_url"])
    if raw.get("url"):
        return str(raw["url"])
    path = raw.get("path")
    if path:
        return base_url.rstrip("/") + "/" + str(path).lstrip("/")
    return None


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

_BANNER_ART = (
    "██   ██  █████  ██████  ███████ ███████\n"
    "██   ██ ██   ██ ██   ██ ██      ██     \n"
    "███████ ███████ ██   ██ █████   ███████\n"
    "██   ██ ██   ██ ██   ██ ██           ██\n"
    "██   ██ ██   ██ ██████  ███████ ███████"
)

_TAGLINE = "Ψ  Web Security Scanner  •  Kali-style recon & vulnerability detection  Ψ"
_LEGAL   = "[dim]⚠  For authorised testing only. Unauthorised scanning is illegal.[/dim]"


def print_banner() -> None:
    """Print the styled ASCII art HADES banner."""
    from rich import box
    from rich.align import Align

    banner_text = Text(_BANNER_ART, style="bold bright_red")
    console.print(Panel(
        Align.center(banner_text),
        box=box.DOUBLE,
        border_style="bold bright_red",
        title="[bold white]†  H A D E S  †[/bold white]",
        subtitle=f"[bold cyan]{_TAGLINE}[/bold cyan]",
        padding=(1, 6),
    ))
    console.print()
    console.print(Panel(_LEGAL, border_style="dim red", padding=(0, 2)))
    console.print()


# ---------------------------------------------------------------------------
# Single finding line
# ---------------------------------------------------------------------------

def print_finding(finding: Finding) -> None:
    """Print a single coloured finding line: [SEVERITY] module — title"""
    sev   = finding.severity.value
    style = _SEVERITY_STYLE.get(sev, "white")
    label = f"[{sev.upper():<8}]"
    line  = f"{label} {finding.module:<22} {finding.title}"
    console.print(line, style=style)


# ---------------------------------------------------------------------------
# Findings table (used after the scan completes)
# ---------------------------------------------------------------------------

def print_findings(findings: list[Finding], url: str) -> None:
    console.print()
    console.print(Rule(f"[bold white]Findings — {url}[/bold white]", style="dim"))
    console.print()

    if not findings:
        console.print("[dim]  No findings to display.[/dim]")
        return

    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold bright_white",
        expand=True,
        padding=(0, 1),
    )
    table.add_column("Severity",    style="bold", width=10, no_wrap=True)
    table.add_column("Module",      style="dim",  width=20, no_wrap=True)
    table.add_column("Title",       style="bold white", ratio=2, no_wrap=False)
    table.add_column("Description", ratio=3, no_wrap=False)

    has_verifiable = False
    for f in findings:
        sev   = f.severity.value
        style = _SEVERITY_STYLE.get(sev, "white")
        label = _SEVERITY_LABEL.get(sev, sev.upper())

        # Build the description, appending framework refs + a verify link.
        description = Text(f.description)
        refs = _format_refs(f)
        if refs:
            description.append(f"\n⟦ {refs} ⟧", style="dim")
        skills = getattr(f, "skill_refs", None)
        if skills:
            names = ", ".join(s["name"] for s in skills[:2])
            description.append(f"\n📘 playbook → {names}", style="magenta")
        tools = getattr(f, "redteam_tools", None)
        if tools:
            description.append(f"\n🛠 tools → {', '.join(tools)}", style="yellow")
        verify = _verify_url(f, url)
        if verify:
            has_verifiable = True
            description.append("\n🔗 verify → ", style="bold cyan")
            description.append(verify, style=f"link {verify} underline cyan")

        table.add_row(
            Text(label, style=style),
            f.module,
            f.title,
            description,
        )

    console.print(table)
    if has_verifiable:
        console.print(
            "\n[dim]See the [cyan]Verification Links[/cyan] table below to open or copy "
            "each URL and confirm the finding is real.[/dim]"
        )


# ---------------------------------------------------------------------------
# Verification links table (grouped list of all checkable URLs)
# ---------------------------------------------------------------------------

def print_verification_links(findings: list[Finding], url: str) -> None:
    """
    Print a grouped table of every verifiable URL (dir_scan + sensitive_files),
    sorted by severity. URLs are shown in full so they can be copy-pasted, and are
    also emitted as terminal hyperlinks for terminals that support Ctrl+click.
    """
    rows: list[tuple[Finding, str]] = []
    for f in findings:
        verify = _verify_url(f, url)
        if verify:
            rows.append((f, verify))

    if not rows:
        return

    rows.sort(key=lambda r: _SEVERITY_ORDER.index(r[0].severity.value))

    console.print()
    console.print(Rule("[bold white]Verification Links[/bold white]", style="dim"))
    console.print()

    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold bright_white",
        expand=True,
        padding=(0, 1),
    )
    table.add_column("#",      style="dim", width=3, justify="right", no_wrap=True)
    table.add_column("Sev",    width=9,  no_wrap=True)
    table.add_column("Module", style="dim", width=16, no_wrap=True)
    table.add_column("HTTP",   width=5,  justify="right", no_wrap=True)
    table.add_column("URL (Ctrl+click or copy-paste)", ratio=1, overflow="fold")

    for i, (f, verify) in enumerate(rows, 1):
        sev    = f.severity.value
        style  = _SEVERITY_STYLE.get(sev, "white")
        status = str(f.raw.get("status_code", "")) if f.raw else ""
        url_text = Text(verify, style=f"link {verify} underline cyan")
        table.add_row(str(i), Text(sev.upper(), style=style), f.module, status, url_text)

    console.print(table)
    console.print(
        f"\n[dim]{len(rows)} link(s). Ctrl+click to open (Windows Terminal / iTerm2), or "
        "copy-paste a URL into your browser to verify the finding manually.[/dim]"
    )


# ---------------------------------------------------------------------------
# Recommended playbooks (skills-library enrichment)
# ---------------------------------------------------------------------------

def print_playbooks(findings: list[Finding]) -> None:
    """Print the unique expert playbooks matched across all findings, if any."""
    from scanner.intel.skills_kb import distinct_skills  # avoid import at module load

    skills = distinct_skills(findings)
    if not skills:
        return

    console.print()
    console.print(Rule("[bold magenta]Recommended Playbooks[/bold magenta]", style="dim magenta"))
    console.print("[dim]  Matched from the cybersecurity skills library — open the path for the full procedure.[/dim]\n")

    table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold bright_white",
                  expand=True, padding=(0, 1))
    table.add_column("Playbook", style="bold magenta", width=42, no_wrap=True)
    table.add_column("ATT&CK", style="cyan", width=14, no_wrap=True)
    table.add_column("What it does", ratio=1)

    for s in skills:
        mitre = " ".join(s.get("mitre", [])[:2])
        desc = (s.get("description") or "").strip()
        table.add_row(s["name"], mitre, desc)

    console.print(table)
    console.print(f"\n[dim]{len(skills)} playbook(s) available under the skills library.[/dim]")


# ---------------------------------------------------------------------------
# Summary panel
# ---------------------------------------------------------------------------

def print_summary(findings: list[Finding], score: int) -> None:
    """
    Print the final summary: severity counts, score/grade panel,
    top 3 critical findings, and 3 priority recommendations.
    """
    from scanner.output.scorer import calculate_score  # avoid circular at module level

    _, grade = calculate_score(findings)

    # --- Severity counts ---
    counts: dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}
    for f in findings:
        counts[f.severity.value] += 1

    counts_table = Table(box=box.SIMPLE, show_header=True, header_style="bold bright_white",
                         padding=(0, 2))
    counts_table.add_column("Severity", style="bold")
    counts_table.add_column("Count",    justify="right")

    for sev in _SEVERITY_ORDER:
        style = _SEVERITY_STYLE[sev]
        # INFO findings are purely informational and do not affect the score.
        label = "INFO  (not scored)" if sev == "info" else sev.upper()
        counts_table.add_row(
            Text(label, style=style),
            str(counts[sev]),
        )
    counts_table.add_row(Text("TOTAL", style="bold white"), str(len(findings)))

    scored_count = sum(counts[s] for s in _SEVERITY_ORDER if s != "info")

    # --- Score / grade box ---
    grade_colour = {
        "A": "bold green", "B": "bold cyan",
        "C": "bold yellow", "D": "bold orange3", "F": "bold red",
    }.get(grade, "bold white")

    score_panel = Panel(
        Text(f"{score}/100\nGrade: {grade}", style=grade_colour, justify="center"),
        title="[bold white]Security Score[/bold white]",
        subtitle=f"[dim]{scored_count} scored · {counts['info']} info excluded[/dim]",
        border_style=grade_colour,
        padding=(1, 4),
    )

    console.print()
    console.print(Rule("[bold white]Scan Summary[/bold white]", style="dim"))
    console.print()
    console.print(Columns([counts_table, score_panel], equal=False, expand=False))
    console.print(
        "[dim]Score reflects actionable findings only — INFO items are context, "
        "not problems, and never lower the grade.[/dim]"
    )
    console.print()

    # --- Top 3 critical findings ---
    critical_findings = [
        f for f in findings
        if f.severity.value in ("critical", "high")
    ][:3]

    if critical_findings:
        console.print(Rule("[bold red]Top Critical Findings[/bold red]", style="dim red"))
        console.print()
        top_table = Table(box=box.SIMPLE_HEAD, show_header=True,
                          header_style="bold bright_white", expand=True, padding=(0, 1))
        top_table.add_column("#",       width=3,  no_wrap=True)
        top_table.add_column("Severity", width=10, no_wrap=True)
        top_table.add_column("Module",   width=20, no_wrap=True)
        top_table.add_column("Title",    ratio=1)

        for i, f in enumerate(critical_findings, 1):
            sev   = f.severity.value
            style = _SEVERITY_STYLE.get(sev, "white")
            top_table.add_row(
                str(i),
                Text(sev.upper(), style=style),
                f.module,
                f.title,
            )
        console.print(top_table)
        console.print()

    # --- 3 priority recommendations ---
    # Collect unique recommendations from Critical/High findings first, then Medium
    recs: list[str] = []
    seen_recs: set[str] = set()
    priority_order = sorted(
        findings,
        key=lambda f: _SEVERITY_ORDER.index(f.severity.value),
    )
    for f in priority_order:
        rec = (f.recommendation or "").strip()
        if rec and rec not in seen_recs:
            seen_recs.add(rec)
            recs.append(f"[bold]{f.module}:[/bold] {rec}")
        if len(recs) == 3:
            break

    if recs:
        console.print(Rule("[bold yellow]Priority Recommendations[/bold yellow]", style="dim yellow"))
        console.print()
        for i, rec in enumerate(recs, 1):
            console.print(f"  [bold yellow]{i}.[/bold yellow] {rec}")
        console.print()
