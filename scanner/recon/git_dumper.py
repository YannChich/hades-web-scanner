"""
git_dumper — extract intelligence from an exposed .git directory.

sensitive_files flags that /.git/ is reachable; this module goes further and pulls the
metadata a red team actually uses:

  * **/.git/config**     → remote URLs (sometimes with embedded credentials user:pass@)
  * **/.git/logs/HEAD**  → commit hashes + committer emails (phishing targets, history)
  * **/.git/index**      → the full list of tracked source files (best-effort binary parse)

With this, an attacker can reconstruct the source (e.g. git-dumper) and harvest secrets that
were ever committed. Read-only: it only fetches files the server already exposes.
"""
from __future__ import annotations

import re
import struct

import httpx
from loguru import logger

from scanner.engine import Finding, Severity, ScanEngine

MODULE = "git_dumper"

_REMOTE_URL_RE = re.compile(r"url\s*=\s*(\S+)", re.I)
_CREDS_IN_URL_RE = re.compile(r"https?://([^:@/\s]+):([^@/\s]+)@", re.I)
_EMAIL_RE = re.compile(r"<([^>]+@[^>]+)>")
_COMMIT_RE = re.compile(r"\b([0-9a-f]{40})\b")


def _get(engine: ScanEngine, path: str) -> "httpx.Response | None":
    try:
        return engine.request("GET", engine.url + path, timeout=8.0)
    except httpx.HTTPError:
        return None


def _git_exposed(engine: ScanEngine) -> bool:
    head = _get(engine, "/.git/HEAD")
    return head is not None and head.status_code == 200 and head.text.lstrip().startswith("ref:")


def _parse_index(data: bytes) -> list[str]:
    """Minimal git index (v2/3) parser → list of tracked file paths."""
    if data[:4] != b"DIRC" or len(data) < 12:
        return []
    try:
        _version, count = struct.unpack(">II", data[4:12])
    except struct.error:
        return []
    paths: list[str] = []
    off = 12
    for _ in range(min(count, 5000)):
        if off + 62 > len(data):
            break
        name_len = struct.unpack(">H", data[off + 60:off + 62])[0] & 0x0FFF
        start = off + 62
        if name_len and name_len < 0xFFF and start + name_len <= len(data):
            end = start + name_len
        else:  # name length not stored — read to NUL
            nul = data.find(b"\x00", start)
            if nul == -1:
                break
            end = nul
        paths.append(data[start:end].decode("utf-8", "replace"))
        total = 62 + (end - start)
        off += ((total // 8) + 1) * 8        # pad to multiple of 8 (keeps trailing NUL)
    return paths


def run(engine: ScanEngine) -> list[Finding]:
    if not _git_exposed(engine):
        return []
    logger.info("git_dumper: exposed .git confirmed — extracting metadata")

    remotes: list[str] = []
    leaked_creds: list[str] = []
    emails: set[str] = set()
    commits: list[str] = []
    files: list[str] = []

    cfg = _get(engine, "/.git/config")
    if cfg is not None and cfg.status_code == 200:
        for url in _REMOTE_URL_RE.findall(cfg.text):
            remotes.append(url)
            m = _CREDS_IN_URL_RE.search(url)
            if m:
                leaked_creds.append(f"{m.group(1)}:*** @ {url.split('@')[-1]}")

    logs = _get(engine, "/.git/logs/HEAD")
    if logs is not None and logs.status_code == 200:
        emails.update(_EMAIL_RE.findall(logs.text))
        commits = _COMMIT_RE.findall(logs.text)[:10]

    idx = _get(engine, "/.git/index")
    if idx is not None and idx.status_code == 200 and idx.content[:4] == b"DIRC":
        files = _parse_index(idx.content)

    desc = ["The exposed /.git/ directory leaks repository metadata."]
    if remotes:
        desc.append("Remote(s): " + ", ".join(remotes[:3]) + ".")
    if emails:
        desc.append(f"{len(emails)} committer email(s): " + ", ".join(sorted(emails)[:5]) + ".")
    if files:
        desc.append(f"{len(files)} tracked file(s), e.g. " + ", ".join(files[:8]) + ".")

    severity = Severity.CRITICAL if leaked_creds else Severity.HIGH
    if leaked_creds:
        desc.append("Credentials embedded in a remote URL: " + "; ".join(leaked_creds[:3]) + ".")

    proof: list[str] = ["GET /.git/HEAD → 200 (starts with 'ref:') — repository directory is exposed"]
    if remotes:
        proof.append(f"/.git/config remote(s): {', '.join(remotes[:2])}")
    if files:
        proof.append(f"/.git/index parsed → {len(files)} tracked file(s)")
    if emails:
        proof.append(f"/.git/logs/HEAD → {len(emails)} committer email(s)")
    if leaked_creds:
        proof.append(f"credentials embedded in remote URL: {leaked_creds[0]}")

    return [Finding(
        module=MODULE,
        title="Exposed .git — Repository Metadata Extracted",
        description=" ".join(desc) + " The full source/history can be reconstructed (git-dumper).",
        severity=severity,
        recommendation=(
            "Block all access to /.git/ at the web server and never deploy it to production. "
            "Rotate every secret ever committed and any credential found in remote URLs."
        ),
        raw={"remotes": remotes[:5], "leaked_credentials": leaked_creds[:5],
             "emails": sorted(emails)[:15], "commits": commits, "files": files[:100],
             "confidence": "high", "proof_url": engine.url + "/.git/config",
             "exploit_cmd": f"git-dumper {engine.url}/.git/ ./loot_src",
             "attack": "T1552.001 Credentials in Files", "evidence": proof,
             "exploitation": [
                 {"step": 1, "description": "Reconstruct the full source tree from the exposed .git.",
                  "command": f"git-dumper {engine.url}/.git/ ./loot_src"},
                 {"step": 2, "description": "Mine the commit history for committed secrets.",
                  "command": "cd loot_src && git log -p | grep -iE 'password|secret|api[_-]?key|token'"}]},
    )]
