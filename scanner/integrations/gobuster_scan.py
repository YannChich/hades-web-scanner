"""
gobuster_scan — fast content/directory discovery via the real Gobuster, when installed.

Hades's built-in ``dir_scan`` is a threaded Python brute-forcer; this optional module shells out to
Gobuster (Go, much faster) to enumerate paths with Hades's wordlist, honouring the scan's proxy, cookies
and User-Agent. It reports the discovered content map as a single INFO finding (mirroring
``subdomain_scan``'s "Subdomains Discovered"); the dedicated modules (``dir_scan`` / ``sensitive_files`` /
``admin_panel``) keep ownership of classifying any sensitive path, so this never double-reports.

Optional: if Gobuster is absent, a single INFO hint is emitted. Active → skipped in safe mode.
Enumeration only — no exploitation.
"""
from __future__ import annotations

import re

from loguru import logger

from config import PROJECT_ROOT, WORDLIST_DIRS
from scanner.engine import Finding, Severity, ScanEngine
from scanner.integrations._external import missing_finding, run_tool, which

MODULE = "gobuster_scan"
_TIMEOUT = 280.0
_THREADS = "30"
_MAX_REPORTED = 60

# Gobuster `dir` line, e.g.  "/admin  (Status: 301) [Size: 234] [--> /admin/]"
_LINE = re.compile(r"^(/\S*)\s+\(Status:\s*(\d+)\)(?:\s*\[Size:\s*(\d+)\])?", re.MULTILINE)


def _wordlist(engine: ScanEngine) -> str:
    return str(engine.wordlist) if getattr(engine, "wordlist", None) else str(PROJECT_ROOT / WORDLIST_DIRS)


def _parse(out: str) -> list[tuple[str, int, int | None]]:
    """Parse gobuster `dir` stdout → [(path, status, size)]."""
    found: list[tuple[str, int, int | None]] = []
    for m in _LINE.finditer(out):
        found.append((m.group(1), int(m.group(2)), int(m.group(3)) if m.group(3) else None))
    return found


def run(engine: ScanEngine) -> list[Finding]:
    if engine.is_safe_mode():
        return [Finding(MODULE, "Gobuster Scan Skipped (Safe Mode)",
                        "Active content discovery was skipped because safe mode is enabled.",
                        Severity.INFO, "Re-run without safe mode on an authorised target.",
                        {"reason": "safe_mode", "confidence": "high"})]

    gobuster = which("gobuster")
    if not gobuster:
        return [missing_finding(MODULE, "Gobuster",
                                "https://github.com/OJ/gobuster — or `apt install gobuster`",
                                "fast content discovery")]

    wordlist = _wordlist(engine)
    cmd = [gobuster, "dir", "-u", engine.url, "-w", wordlist, "-q", "-t", _THREADS,
           "-k", "--no-error", "--timeout", "10s"]
    if getattr(engine, "proxy", None):
        cmd += ["--proxy", engine.proxy]
    if getattr(engine, "cookies", None):
        cmd += ["-c", engine.cookies]
    try:
        ua = engine._client.headers.get("User-Agent", "")
    except Exception:  # noqa: BLE001
        ua = ""
    if ua:
        cmd += ["-a", ua]

    code, out, err = run_tool(cmd, _TIMEOUT)
    if not out and err:
        return [Finding(MODULE, "Gobuster Scan Did Not Complete",
                        f"Gobuster produced no output for {engine.url} ({err}).",
                        Severity.INFO, "", {"error": err, "confidence": "high"})]

    paths = _parse(out)
    if not paths:
        return [Finding(MODULE, "Gobuster: No Additional Paths Found",
                        f"Gobuster enumerated {engine.url} with the directory wordlist and found no paths.",
                        Severity.INFO, "", {"url": engine.url, "confidence": "high"})]

    shown = ", ".join(f"{p} ({s})" for p, s, _ in sorted(paths)[:_MAX_REPORTED])
    more = " …" if len(paths) > _MAX_REPORTED else ""
    logger.info(f"gobuster_scan: {len(paths)} path(s) on {engine.url}")
    return [Finding(
        module=MODULE,
        title=f"Gobuster: {len(paths)} Path(s) Discovered",
        description=(f"Gobuster discovered {len(paths)} path(s) on {engine.url}: {shown}{more}. "
                     "Review them; the dedicated modules classify any sensitive ones."),
        severity=Severity.INFO,
        recommendation="Remove or protect any path that should not be publicly reachable.",
        raw={"url": engine.url, "count": len(paths),
             "paths": [{"path": p, "status": s, "size": z} for p, s, z in sorted(paths)][:200],
             "confidence": "high",
             "evidence": [f"gobuster dir -u {engine.url} -w {WORDLIST_DIRS} → {len(paths)} path(s)"]},
    )]
