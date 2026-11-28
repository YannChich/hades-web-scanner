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


def _entry(finding: "Finding", now_iso: str, first_seen: Optional[str] = None) -> dict:
    """Minimal, serialisable record of a finding for the on-disk snapshot.

    ``first_seen`` carries forward the ISO timestamp from the first run an identical finding
    (same fingerprint) appeared in; ``last_seen`` is always this run. Together they let the
    retest panel show how long an issue has been outstanding.
    """
    return {
        "fp": fingerprint(finding),
        "id": finding.finding_id,
        "module": finding.module,
        "title": finding.title,
        "severity": finding.severity.value,
        "first_seen": first_seen or now_iso,
        "last_seen": now_iso,
    }


def _first_seen_map(previous: Optional[dict]) -> dict:
    """Map each previous finding's fingerprint to its recorded ``first_seen`` timestamp.

    Falls back to a run-level ``scan_date`` for snapshots written before first/last-seen
    tracking existed, so pre-existing history still yields a sensible age.
    """
    out: dict[str, str] = {}
    for e in (previous or {}).get("findings", []):
        fp = e.get("fp")
        if not fp:
            continue
        out[fp] = e.get("first_seen") or e.get("last_seen") or (previous or {}).get("scan_date")
    return out


def days_open(first_seen: Optional[str], ref: Optional[datetime] = None) -> Optional[int]:
    """Whole days between *first_seen* (ISO string) and *ref* (default: now). None if unparsable."""
    if not first_seen:
        return None
    try:
        start = datetime.fromisoformat(first_seen)
    except (TypeError, ValueError):
        return None
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    now = ref or datetime.now(timezone.utc)
    delta = now - start
    return max(0, delta.days)


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
    # Carry each finding's first_seen forward from the most recent prior run (if any), so a
    # still-present issue keeps the date it was first observed instead of resetting every scan.
    prior_first_seen = _first_seen_map(runs[-1] if runs else None)
    now_iso = datetime.now(timezone.utc).isoformat()
    runs.append({
        "scan_date": now_iso,
        "score": score,
        "grade": grade,
        "counts": severity_counts(findings),
        "findings": [_entry(f, now_iso, prior_first_seen.get(fingerprint(f))) for f in findings],
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
    first_seen = _first_seen_map(previous)
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    for f in findings:
        if not isinstance(f.raw, dict):
            continue
        fp = fingerprint(f)
        if fp in first_seen:
            f.raw["retest"] = STATUS_STILL
            seen = first_seen[fp] or now_iso
        else:
            f.raw["retest"] = STATUS_NEW
            seen = now_iso
        f.raw["first_seen"] = seen
        age = days_open(seen, now)
        if age is not None:
            f.raw["days_open"] = age
