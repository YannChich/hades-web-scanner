"""
reconng_scan — passive OSINT host enumeration via the real Recon-ng, when installed.

Recon-ng is a full reconnaissance framework backed by a per-workspace SQLite database. This integration
drives it non-interactively: it writes a resource script that installs/loads a couple of keyless
domains→hosts modules (HackerTarget, ThreatCrowd), runs them against the target domain, then reads the
discovered hosts straight out of the workspace's ``data.db``. It queries third parties, not the target,
so it is passive and runs in the passive + full profiles.

Optional: if Recon-ng is absent, a single INFO hint is emitted. Every step is defensive — a missing
module, an empty workspace or a schema change degrades to a calm INFO finding, never an error.
"""
from __future__ import annotations

import os
import re
import sqlite3
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine
from scanner.integrations._external import missing_finding, run_tool, which

MODULE = "reconng_scan"
_TIMEOUT = 240.0
_MAX_SHOWN = 40
# Keyless domains→hosts modules (marketplace-installed by the resource script if needed).
_RECON_MODULES = ("recon/domains-hosts/hackertarget", "recon/domains-hosts/threatcrowd")


def _domain(url: str) -> str:
    host = urlparse(url).hostname or ""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _workspace(domain: str) -> str:
    return ("hades_" + re.sub(r"[^a-z0-9]", "_", domain.lower()))[:32] or "hades"


def _resource_script(domain: str) -> str:
    """A recon-ng resource (batch) script: install/load each module, set SOURCE, run, then exit."""
    lines: list[str] = []
    for module in _RECON_MODULES:
        lines += [f"marketplace install {module}", f"modules load {module}",
                  f"options set SOURCE {domain}", "run", "back"]
    lines.append("exit")
    return "\n".join(lines) + "\n"


def _read_hosts(db_path: str) -> list[tuple[str, str]]:
    """Read (host, ip) rows from a recon-ng workspace data.db; empty list on any error."""
    rows: list[tuple[str, str]] = []
    try:
        con = sqlite3.connect(db_path)
        try:
            cur = con.execute("SELECT host, ip_address FROM hosts")
            for host, ip in cur.fetchall():
                if host:
                    rows.append((str(host).strip().lower(), str(ip).strip() if ip else ""))
        finally:
            con.close()
    except sqlite3.Error as exc:
        logger.debug(f"reconng_scan: cannot read {db_path}: {exc}")
    return sorted(set(rows))


def _build_findings(domain: str, hosts: list[tuple[str, str]]) -> list[Finding]:
    if not hosts:
        return [Finding(MODULE, f"Recon-ng: Nothing Found ({domain})",
                        f"Recon-ng enumerated {domain} but its workspace held no hosts.",
                        Severity.INFO, "", {"domain": domain, "confidence": "high"})]
    shown = ", ".join(f"{h}" + (f" ({ip})" if ip else "") for h, ip in hosts[:_MAX_SHOWN])
    more = " …" if len(hosts) > _MAX_SHOWN else ""
    return [Finding(
        MODULE, f"Recon-ng: {len(hosts)} Host(s) Discovered",
        f"Recon-ng discovered {len(hosts)} host(s) for {domain}: {shown}{more}.",
        Severity.INFO, "Review the externally-known hosts; restrict anything not meant to be public.",
        {"domain": domain, "count": len(hosts),
         "hosts": [{"host": h, "ip": ip} for h, ip in hosts][:200], "confidence": "high",
         "evidence": [f"recon-ng ({', '.join(_RECON_MODULES)}) → {len(hosts)} host(s) for {domain}"]})]


def run(engine: ScanEngine) -> list[Finding]:
    reconng = which("recon-ng")
    if not reconng:
        return [missing_finding(MODULE, "Recon-ng", "`pip install recon-ng`", "OSINT host enumeration")]

    domain = _domain(engine.url)
    if not domain:
        return [Finding(MODULE, "Recon-ng Skipped", "No domain found in the target URL.",
                        Severity.INFO, "", {"confidence": "high"})]

    workspace = _workspace(domain)
    rc_path = ""
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".rc", delete=False, encoding="utf-8") as rc:
            rc.write(_resource_script(domain))
            rc_path = rc.name
        run_tool([reconng, "-w", workspace, "-r", rc_path], _TIMEOUT)
    finally:
        if rc_path:
            try:
                os.unlink(rc_path)
            except OSError:
                pass

    db = Path.home() / ".recon-ng" / "workspaces" / workspace / "data.db"
    if not db.exists():
        return [Finding(MODULE, f"Recon-ng: No Workspace Data ({domain})",
                        "Recon-ng ran but produced no workspace database (modules may need API keys, or "
                        "the marketplace install failed).",
                        Severity.INFO, "", {"domain": domain, "confidence": "high"})]

    hosts = _read_hosts(str(db))
    logger.info(f"reconng_scan: {domain} → {len(hosts)} host(s)")
    return _build_findings(domain, hosts)
