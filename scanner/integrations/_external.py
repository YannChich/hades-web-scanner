"""
_external — shared plumbing for the optional external-tool integrations.

Every integration uses these three helpers so they all behave the same way:
  * ``which()`` finds the tool on PATH (and the interpreter's Scripts dir, where pip drops Windows
    console-scripts that are often not on PATH);
  * ``run_tool()`` runs it with a hard timeout, capturing stdout/stderr and never raising;
  * ``missing_finding()`` emits the consistent INFO "install hint" when the tool is absent.

Hades shells out to the real, industry-standard tool — it never reimplements the engine. Active tools
are gated by safe mode in the calling module; OSINT tools query third parties, not the target.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from scanner.engine import Finding, Severity


def which(*names: str) -> str | None:
    """Path to the first installed tool among *names*, checking PATH then the interpreter's Scripts dir."""
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    scripts = Path(sys.executable).parent / "Scripts"
    for name in names:
        for candidate in (scripts / name, scripts / f"{name}.exe"):
            if candidate.exists():
                return str(candidate)
    return None


def run_tool(cmd: list[str], timeout: float, input_text: str | None = None) -> tuple[int, str, str]:
    """Run *cmd*, capturing output. Returns (returncode, stdout, stderr); (-1, "", reason) on failure."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              input=input_text, errors="replace")
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", f"timed out after {timeout:.0f}s"
    except (OSError, subprocess.SubprocessError) as exc:  # tool vanished / spawn error
        return -1, "", str(exc)


def missing_finding(module: str, tool: str, install_hint: str, what: str) -> Finding:
    """The consistent 'tool not installed' INFO finding (mirrors the sslyze/playwright hints)."""
    return Finding(
        module=module,
        title=f"{tool} Not Installed — {what} Skipped",
        description=(f"{tool} is not installed, so Hades skipped {what}. Install {tool} "
                     f"({install_hint}) to enable this integration; the rest of the scan is unaffected."),
        severity=Severity.INFO,
        recommendation="",
        raw={"tool": tool, "available": False, "confidence": "high"},
    )
