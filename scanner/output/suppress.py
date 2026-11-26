"""
suppress — false-positive suppression via a ``.hadesignore`` file.

On a real engagement the same handful of findings get triaged as false positives (a WAF that always
echoes payloads, a deliberately-public backup, an accepted risk). Re-flagging them every scan is
noise that buries the findings that matter and skews the risk score. A ``.hadesignore`` file lets a
tester record those decisions once, in the repo, so later scans drop them *before* scoring and
reporting — the same idea as ``.gitignore`` or nuclei's ignore list.

Format — one rule per line, ``#`` comments and blank lines ignored. Each rule is ``type:value``:

* ``module:<name>``       — suppress every finding from that module (e.g. ``module:dir_listing``)
* ``id:<finding_id>``     — suppress one finding by its stable ID (e.g. ``id:SQLI-3F9A``)
* ``fingerprint:<hex>``   — suppress by cross-run fingerprint (``fp:`` is an accepted alias)
* ``title:<glob>``        — suppress findings whose title matches a glob (``title:*X-Frame*``)

A bare line with no ``type:`` prefix is matched against the finding ID *or* the fingerprint, so a
value copied straight out of a report just works. Matching is case-insensitive. Suppression never
raises: a malformed line is logged and skipped, an unreadable file yields no rules.
"""
from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

from loguru import logger

from scanner.output.history import fingerprint

if TYPE_CHECKING:
    from scanner.engine import Finding

DEFAULT_IGNORE_FILE = ".hadesignore"

_KINDS = {"module", "id", "fingerprint", "fp", "title", "any"}


@dataclass(frozen=True)
class Rule:
    kind: str   # one of: module, id, fingerprint, title, any
    value: str  # the (lower-cased) value to match

    def matches(self, f: "Finding") -> bool:
        v = self.value
        if self.kind == "module":
            return f.module.lower() == v
        if self.kind == "id":
            return (f.finding_id or "").lower() == v
        if self.kind in ("fingerprint", "fp"):
            return fingerprint(f).lower() == v
        if self.kind == "title":
            return fnmatch.fnmatch(f.title.lower(), v)
        if self.kind == "any":
            return (f.finding_id or "").lower() == v or fingerprint(f).lower() == v
        return False


def parse_rules(text: str) -> list[Rule]:
    """Parse ``.hadesignore`` text into rules (malformed lines are logged and skipped)."""
    rules: list[Rule] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if ":" in line:
            kind, _, value = line.partition(":")
            kind = kind.strip().lower()
            value = value.strip().lower()
            if kind not in _KINDS or not value:
                logger.warning(f".hadesignore line {lineno}: unrecognised rule '{raw.strip()}' — skipped")
                continue
            rules.append(Rule(kind, value))
        else:
            # Bare token → match the finding ID or the fingerprint.
            rules.append(Rule("any", line.lower()))
    return rules


def load_rules(path: str | None = None) -> list[Rule]:
    """Load rules from *path* (default ``./.hadesignore``). Returns [] when the file is absent."""
    target = path or DEFAULT_IGNORE_FILE
    if not os.path.isfile(target):
        if path:  # an explicitly-requested file that doesn't exist is worth a warning
            logger.warning(f".hadesignore: file not found: {target}")
        return []
    try:
        with open(target, encoding="utf-8") as fh:
            rules = parse_rules(fh.read())
        logger.info(f".hadesignore: loaded {len(rules)} rule(s) from {target}")
        return rules
    except OSError as exc:
        logger.warning(f".hadesignore: cannot read {target}: {exc}")
        return []


def apply(findings: list["Finding"], rules: list["Rule"]) -> tuple[list["Finding"], list["Finding"]]:
    """Split *findings* into (kept, suppressed) according to *rules*.

    A finding is suppressed when it matches at least one rule. With no rules, everything is kept.
    """
    if not rules:
        return list(findings), []
    kept: list["Finding"] = []
    suppressed: list["Finding"] = []
    for f in findings:
        if any(r.matches(f) for r in rules):
            suppressed.append(f)
        else:
            kept.append(f)
    return kept, suppressed
