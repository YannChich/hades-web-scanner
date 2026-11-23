"""
history — persist each scan and diff a re-run against the previous one (``--retest``).

Every finding is *fingerprinted* (module + normalised title) so the same issue matches
itself across runs. A ``--retest`` run loads the target's last snapshot, labels every current
finding ``new`` / ``still-present``, lists the previous issues that are now ``fixed``, then
records the current run. The whole layer is local and detection-only: nothing leaves the
machine, and snapshots live under ``reports/history/<host>.json``.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Optional
from urllib.parse import urlparse

from loguru import logger

from scanner.severity import severity_counts

if TYPE_CHECKING:
    from scanner.engine import Finding

# Where per-target history snapshots are stored (one JSON file per host).
HISTORY_DIR = "reports/history"
# Rolling window: keep at most this many runs per target so the file never grows unbounded.
MAX_RUNS = 30

# Retest status labels (shared by the console + HTML + JSON renderers).
STATUS_NEW = "new"
STATUS_STILL = "still-present"
STATUS_FIXED = "fixed"


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

def _slug_host(url: str) -> str:
    """Filesystem-safe host slug for a target URL, e.g. 'https://ex.com:8443/x' → 'ex.com_8443'."""
    netloc = urlparse(url if "://" in url else f"http://{url}").netloc or url
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", netloc).strip("_").lower()
    return slug or "target"


def history_path(url: str, base: str = HISTORY_DIR) -> Path:
    """Path to the history snapshot file for *url* (one file per host)."""
    return Path(base) / f"{_slug_host(url)}.json"


def _norm_title(title: str) -> str:
    return re.sub(r"\s+", " ", (title or "").strip().lower())


def fingerprint(finding: "Finding") -> str:
    """Stable cross-run identity of a finding: module + normalised title.

    Hades titles embed the location (parameter / path / header), so ``module|title`` already
    separates e.g. SQLi in ``id`` from SQLi in ``q``. A 12-hex-char SHA-1 digest keeps the
    collision probability negligible while staying deterministic across runs.
    """
    basis = f"{finding.module}|{_norm_title(finding.title)}"
    return hashlib.sha1(basis.encode("utf-8")).hexdigest()[:12]


def _entry(finding: "Finding") -> dict:
    """Minimal, serialisable record of a finding for the on-disk snapshot."""
    return {
        "fp": fingerprint(finding),
        "id": finding.finding_id,
        "module": finding.module,
        "title": finding.title,
        "severity": finding.severity.value,
    }


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def load_history(url: str, base: str = HISTORY_DIR) -> dict:
    """Read the target's history file ({target, host, runs:[...]}). Empty dict if absent/unreadable."""
    p = history_path(url, base)
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError) as exc:
        logger.warning(f"history: cannot read {p}: {exc}")
        return {}


def last_run(url: str, base: str = HISTORY_DIR) -> Optional[dict]:
    """The most recent recorded run for *url*, or None when there is no history yet."""
    runs = load_history(url, base).get("runs") or []
    return runs[-1] if runs else None


def save_run(findings: list["Finding"], url: str, score: int, grade: str,
             base: str = HISTORY_DIR) -> Optional[Path]:
    """Append the current run to the target's history (rolling window) and write it to disk."""
    hist = load_history(url, base)
    hist["target"] = url
    hist["host"] = _slug_host(url)
    runs = hist.get("runs")
    if not isinstance(runs, list):
        runs = []
    runs.append({
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "grade": grade,
        "counts": severity_counts(findings),
        "findings": [_entry(f) for f in findings],
    })
    hist["runs"] = runs[-MAX_RUNS:]

    p = history_path(url, base)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(hist, indent=2), encoding="utf-8")
        logger.info(f"history: recorded run for {url} → {p}")
        return p
    except OSError as exc:
        logger.error(f"history: cannot write {p}: {exc}")
        return None


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------

def diff(findings: list["Finding"], previous: Optional[dict]) -> dict:
    """Compare current *findings* against a *previous* run dict (or None for a baseline).

    Returns a report with the current findings split into ``new`` / ``still_present`` and the
    previous findings no longer present as ``fixed`` (minimal entry dicts). ``baseline`` is True
    when there is nothing to compare against yet.
    """
    prev_entries = {}
    for e in (previous or {}).get("findings", []):
        fp = e.get("fp")
        if fp:
            prev_entries[fp] = e

    cur_by_fp: dict[str, "Finding"] = {}
    for f in findings:
        cur_by_fp.setdefault(fingerprint(f), f)

    new = [f for fp, f in cur_by_fp.items() if fp not in prev_entries]
    still = [f for fp, f in cur_by_fp.items() if fp in prev_entries]
    fixed = [e for fp, e in prev_entries.items() if fp not in cur_by_fp]

    return {
        "baseline": previous is None,
        "previous_date": (previous or {}).get("scan_date"),
        "previous_score": (previous or {}).get("score"),
        "previous_grade": (previous or {}).get("grade"),
        "new": new,
        "still_present": still,
        "fixed": fixed,
    }


def tag_findings(findings: list["Finding"], previous: Optional[dict]) -> None:
    """Stamp each current finding's retest status into ``raw['retest']`` for the renderers.

    No-op on a baseline (no previous run): without a comparison, nothing is 'new' yet.
    """
    if previous is None:
        return
    prev_fps = {e.get("fp") for e in previous.get("findings", []) if e.get("fp")}
    for f in findings:
        if not isinstance(f.raw, dict):
            continue
        f.raw["retest"] = STATUS_STILL if fingerprint(f) in prev_fps else STATUS_NEW
