"""
basic_info — collects surface-level target metadata:
IP, response time, server headers, content-type, page title, and OS fingerprint via TTL.
"""
from __future__ import annotations

import re
import socket
import subprocess
import time
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "basic_info"

# TTL thresholds → probable OS (packets lose 1 TTL per hop; allow ±10 slack)
_TTL_MAP: list[tuple[range, str]] = [
    (range(55, 70),  "Linux / macOS (TTL≈64)"),
    (range(118, 135), "Windows (TTL≈128)"),
    (range(245, 256), "Cisco / network device (TTL≈255)"),
]


def _info(title: str, description: str, raw: dict | None = None) -> Finding:
    return Finding(
        module=MODULE,
        title=title,
        description=description,
        severity=Severity.INFO,
        recommendation="",
        raw=raw or {},
    )


def _resolve_ip(hostname: str) -> list[str]:
    try:
        results = socket.getaddrinfo(hostname, None)
        return list({r[4][0] for r in results})
    except socket.gaierror as exc:
        logger.warning(f"basic_info: DNS resolution failed for {hostname}: {exc}")
        return []


def _ping_ttl(host: str) -> int | None:
    """Return the TTL from a single ping reply, or None if ping is unavailable."""
    try:
        out = subprocess.check_output(
            ["ping", "-n", "1", "-w", "2000", host],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
        # Windows: "TTL=64"  Linux: "ttl=64"
        match = re.search(r"ttl=(\d+)", out, re.IGNORECASE)
        if match:
            return int(match.group(1))
    except (subprocess.SubprocessError, OSError) as exc:
        logger.debug(f"basic_info: TTL probe failed: {exc}")
    return None


def _guess_os(ttl: int) -> str:
    for ttl_range, label in _TTL_MAP:
        if ttl in ttl_range:
            return label
    return f"Unknown (TTL={ttl})"


def run(engine: ScanEngine) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urlparse(engine.url)
    hostname = parsed.hostname or ""

    # --- IP resolution ---
    ips = _resolve_ip(hostname)
    if ips:
        findings.append(_info(
            "IP Address",
            f"{hostname} resolves to: {', '.join(ips)}",
            {"hostname": hostname, "ips": ips},
        ))

    # --- HTTP response + headers ---
    try:
        t0 = time.monotonic()
        resp = engine.get()
        elapsed_ms = int((time.monotonic() - t0) * 1000)

        findings.append(_info(
            "HTTP Response Time",
            f"Server responded in {elapsed_ms} ms  (status {resp.status_code})",
            {"response_time_ms": elapsed_ms, "status_code": resp.status_code},
        ))

        server = resp.headers.get("server", "")
        if server:
            findings.append(_info(
                "Server Header",
                f"Server: {server}",
                {"server": server},
            ))

        powered_by = resp.headers.get("x-powered-by", "")
        if powered_by:
            findings.append(_info(
                "X-Powered-By Header",
                f"X-Powered-By: {powered_by}",
                {"x_powered_by": powered_by},
            ))

        content_type = resp.headers.get("content-type", "")
        if content_type:
            findings.append(_info(
                "Content-Type",
                f"Content-Type: {content_type}",
                {"content_type": content_type},
            ))

        # --- Page title ---
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
            title_tag = soup.find("title")
            if title_tag and title_tag.string:
                title_text = title_tag.string.strip()
                findings.append(_info(
                    "Page Title",
                    f'<title>{title_text}</title>',
                    {"page_title": title_text},
                ))
        except Exception as exc:
            logger.warning(f"basic_info: HTML parsing failed: {exc}")

    except Exception as exc:
        logger.error(f"basic_info: HTTP request failed: {exc}")

    # --- OS fingerprint via TTL ---
    if ips:
        ttl = _ping_ttl(ips[0])
        if ttl is not None:
            os_guess = _guess_os(ttl)
            findings.append(_info(
                "OS Fingerprint (TTL)",
                f"Probable OS: {os_guess}",
                {"ttl": ttl, "os_guess": os_guess},
            ))

    return findings
