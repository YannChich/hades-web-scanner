"""
attack_path — synthesises confirmed findings into a single kill-chain attack path.

Generalises what db_security already does for databases to the whole scan: every actionable
finding becomes an ordered, copy-paste exploitation step, grouped by MITRE ATT&CK tactic in
attacker order (Reconnaissance → Initial Access → … → Impact). Each step reuses the framework
mapping (Axe 1: finding.mitre / poc) and the matched playbook (Axe 2: finding.skill_refs).

db_security findings are intentionally skipped here — they keep their own dedicated panel.
Pure hardening gaps (missing headers, cookie flags, clickjacking…) are not exploitation steps
and are left to the Recommendations section.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from rich import box
from rich.console import Console
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from scanner.severity import CONSOLE_STYLE as _SEV_STYLE
from scanner.severity import severity_rank

if TYPE_CHECKING:
    from scanner.engine import Finding

console = Console()

# Kill-chain phases in attacker order, with their ATT&CK tactic IDs.
PHASES: list[tuple[str, str]] = [
    ("Reconnaissance",       "TA0043"),
    ("Initial Access",       "TA0001"),
    ("Execution",            "TA0002"),
    ("Persistence",          "TA0003"),
    ("Privilege Escalation", "TA0004"),
    ("Credential Access",    "TA0006"),
    ("Discovery",            "TA0007"),
    ("Lateral Movement",     "TA0008"),
    ("Collection",           "TA0009"),
    ("Exfiltration",         "TA0010"),
    ("Impact",               "TA0040"),
]
_PHASE_ORDER: dict[str, int] = {name: i for i, (name, _) in enumerate(PHASES)}

# MITRE technique → kill-chain phase (covers the techniques Hades emits).
_TECHNIQUE_PHASE: dict[str, str] = {
    "T1595": "Reconnaissance", "T1589": "Reconnaissance", "T1590": "Reconnaissance",
    "T1591": "Reconnaissance", "T1589.002": "Reconnaissance", "T1592": "Reconnaissance",
    "T1190": "Initial Access", "T1133": "Initial Access",
    "T1078": "Initial Access", "T1078.001": "Initial Access",
    "T1059": "Execution", "T1059.007": "Execution",
    "T1505.003": "Persistence",
    "T1110": "Credential Access", "T1212": "Credential Access",
    "T1552": "Credential Access", "T1552.001": "Credential Access", "T1040": "Credential Access",
    "T1083": "Discovery", "T1046": "Discovery", "T1087": "Discovery",
    "T1530": "Collection", "T1213": "Collection",
}

# Modules whose findings are genuine attack steps (everything else is hardening/context).
_ATTACK_PATH_MODULES: set[str] = {
    "port_scan", "subdomain_scan", "js_recon", "git_dumper", "cloud_buckets",
    "sqli_detect", "xss_detect", "command_injection", "ssti_detect", "lfi_detect",
    "open_redirect", "ssrf_detect", "jwt_attacks", "auth_bypass", "bruteforce",
    "default_creds", "cve_mapping",
    "sensitive_files", "backup_files", "dir_scan", "dir_listing", "admin_panel",
    "llm_recon", "engage", "oob_detect",
}

# AI/LLM finding category → kill-chain phase (ATLAS techniques don't map to _TECHNIQUE_PHASE).
_AI_CATEGORY_PHASE: dict[str, str] = {
    "discovery": "Reconnaissance", "sdk": "Reconnaissance",
    "exposed_key": "Credential Access", "system_prompt_leak": "Credential Access",
    "exposed_server": "Initial Access", "exposed_ui": "Initial Access",
    "prompt_injection_surface": "Initial Access", "prompt_injection_confirmed": "Initial Access",
    "insecure_output": "Execution",
}
# Recon modules worth keeping even when their finding is INFO severity.
_KEEP_INFO_MODULES = {"port_scan", "git_dumper", "cloud_buckets", "js_recon"}
# Fallback phase when a finding carries no recognised technique.
_MODULE_PHASE: dict[str, str] = {
    "port_scan": "Discovery", "subdomain_scan": "Reconnaissance", "js_recon": "Reconnaissance",
}



# ---------------------------------------------------------------------------
# Step assembly
# ---------------------------------------------------------------------------

def _is_step(f: "Finding") -> bool:
    if f.module not in _ATTACK_PATH_MODULES:
        return False
    # The engagement summary is a roll-up, not an exploitation step.
    if f.module == "engage" and (f.raw or {}).get("engage_category") in ("result", "info"):
        return False
    if f.severity.value == "info":
        return f.module in _KEEP_INFO_MODULES
    return True


def _phase_for(f: "Finding") -> str:
    # AI findings route by their category (their ATLAS techniques aren't ATT&CK tactics).
    if f.module == "llm_recon":
        cat = (f.raw or {}).get("ai_category", "")
        if cat in _AI_CATEGORY_PHASE:
            return _AI_CATEGORY_PHASE[cat]
    for tech in f.mitre:
        if tech in _TECHNIQUE_PHASE:
            return _TECHNIQUE_PHASE[tech]
    return _MODULE_PHASE.get(f.module, "Initial Access")


def _command_for(f: "Finding", base_url: str) -> str:
    """Best copy-paste next step for a finding, or '' if none can be built."""
    r = f.raw or {}
    if r.get("sqlmap"):
        return str(r["sqlmap"])
    if r.get("exploit_cmd"):
        return str(r["exploit_cmd"])
    if f.module == "port_scan" and r.get("port"):
        host = r.get("ip") or r.get("hostname") or ""
        return f"nmap -sV -p {r['port']} {host}".strip()
    url = r.get("proof_url") or r.get("url")
    if not url and r.get("path") and base_url:
        url = base_url.rstrip("/") + "/" + str(r["path"]).lstrip("/")
    if url:
        return f'curl -sk "{url}"'
    return f.poc or ""


def build_attack_path(findings: list["Finding"], base_url: str = "") -> list[dict]:
    """
    Group actionable findings into ordered kill-chain phases.

    Returns a list of {phase, tactic, steps:[...]} in attacker order. Each step is
    {n, severity, id, module, title, mitre, command, evidence, playbook}. Empty list
    if nothing actionable was found.
    """
    steps: list[dict] = []
    for f in findings:
        if f.module == "db_security":      # has its own dedicated panel
            continue
        if not _is_step(f):
            continue
        steps.append({
            "phase":    _phase_for(f),
            "severity": f.severity.value,
            "id":       f.finding_id,
            "module":   f.module,
            "title":    f.title,
            "mitre":    list(f.mitre),
            "command":  _command_for(f, base_url),
            "evidence": (f.raw or {}).get("evidence_file", ""),
            "playbook": (f.skill_refs[0]["name"] if getattr(f, "skill_refs", None) else ""),
            "tools":    list(getattr(f, "redteam_tools", []) or []),
        })

    groups: list[dict] = []
    for phase, tactic in PHASES:
        phase_steps = [s for s in steps if s["phase"] == phase]
        if not phase_steps:
            continue
        phase_steps.sort(key=lambda s: severity_rank(s["severity"]))
        groups.append({"phase": phase, "tactic": tactic, "steps": phase_steps})

    n = 1
    for g in groups:
        for s in g["steps"]:
            s["n"] = n
            n += 1
    return groups


# ---------------------------------------------------------------------------
# Console rendering
# ---------------------------------------------------------------------------

def print_attack_path(findings: list["Finding"], base_url: str = "") -> None:
    """Print the kill-chain attack path. No-op if nothing actionable was found."""
    groups = build_attack_path(findings, base_url)
    if not groups:
        return

    total = sum(len(g["steps"]) for g in groups)
    console.print()
    console.print(Rule("[bold red]Attack Path — Kill Chain[/bold red]", style="dim red"))
    console.print(
        f"[dim]  {total} actionable step(s) across {len(groups)} ATT&CK phase(s), "
        "in attacker order. Commands are copy-paste; authorised targets only.[/dim]\n"
    )

    for g in groups:
        console.print(f"[bold cyan]▼ {g['phase']}[/bold cyan]  [dim]{g['tactic']}[/dim]")
        table = Table(box=box.SIMPLE, show_header=False, expand=True, padding=(0, 1), pad_edge=False)
        table.add_column(width=4, justify="right", no_wrap=True)     # step number
        table.add_column(width=10, no_wrap=True)                     # severity
        table.add_column(ratio=1)                                    # details

        for s in g["steps"]:
            style = _SEV_STYLE.get(s["severity"], "white")
            detail = Text()
            detail.append(s["title"], style="bold white")
            tags = " ".join(s["mitre"])
            meta = " · ".join(p for p in (s["id"], tags) if p)
            if meta:
                detail.append(f"\n{meta}", style="dim")
            if s["command"]:
                detail.append("\n$ ", style="bold green")
                detail.append(s["command"], style="green")
            if s["playbook"]:
                detail.append(f"\n📘 {s['playbook']}", style="magenta")
            if s["tools"]:
                detail.append(f"\n🛠 tools: {', '.join(s['tools'])}", style="yellow")
            if s["evidence"]:
                detail.append(f"\n⧉ evidence: {s['evidence']}", style="green")
            table.add_row(f"{s['n']}.", Text(s["severity"].upper(), style=style), detail)

        console.print(table)
    console.print()
