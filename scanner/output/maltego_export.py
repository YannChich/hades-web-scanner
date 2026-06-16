"""
maltego_export — export a scan's discovered entities to a Maltego-importable CSV.

Maltego is a GUI link-analysis platform, not a command-line scanner, so the honest integration is the
other direction: Hades hands Maltego the entities it found — the domain, sub-domains/hosts, IP addresses
and e-mail addresses harvested across every module (subdomain_scan, theHarvester, Recon-ng, nmap,
email_exposure…) — as a connectivity CSV. The analyst imports it (Import ▸ Tables/CSV), maps the three
columns, and pivots from there.

Opt-in via ``--maltego``; writes ``reports/maltego_<host>_<timestamp>.csv``. Pure data export — no
network, no tool to install.
"""
from __future__ import annotations

import csv
import re
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

if TYPE_CHECKING:
    from scanner.engine import Finding


def _registrable(host: str) -> str:
    parts = (host or "").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def build_rows(target_url: str, findings: "list[Finding]") -> list[tuple[str, str, str]]:
    """Extract (EntityType, Value, LinkedTo) rows from a scan's findings — a star topology around the
    registrable domain. Deduplicated, Maltego entity-type names."""
    host = urlparse(target_url).hostname or ""
    domain = _registrable(host)
    rows: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(etype: str, value: Any, linked: str = "") -> None:
        val = str(value or "").strip()
        if not val:
            return
        key = (etype, val.lower())
        if key in seen:
            return
        seen.add(key)
        rows.append((etype, val, linked))

    if domain:
        add("Domain", domain)
    if host and host != domain:
        add("DNSName", host, domain)

    for finding in findings:
        raw = getattr(finding, "raw", None) or {}
        for sub in _as_list(raw.get("subdomains")):
            add("DNSName", sub, domain)
        add("DNSName", raw.get("subdomain"), domain)
        for hostent in _as_list(raw.get("hosts")):
            if isinstance(hostent, dict):
                add("DNSName", hostent.get("host"), domain)
                add("IPv4Address", hostent.get("ip"), hostent.get("host") or domain)
            else:
                add("DNSName", hostent, domain)
        for email in _as_list(raw.get("emails")):
            add("EmailAddress", email, domain)
        add("EmailAddress", raw.get("email"), domain)
        for ip in _as_list(raw.get("ips")):
            add("IPv4Address", ip, domain)
        if raw.get("ip"):
            add("IPv4Address", raw.get("ip"), raw.get("host") or host or domain)
    return rows


def export(target_url: str, findings: "list[Finding]", out_dir: str | Path) -> str:
    """Write the Maltego connectivity CSV and return its path."""
    rows = build_rows(target_url, findings)
    host = urlparse(target_url).hostname or "target"
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", host)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"maltego_{safe}_{stamp}.csv"
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["EntityType", "Value", "LinkedTo"])
        writer.writerows(rows)
    return str(path)
