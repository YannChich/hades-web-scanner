"""
alias_matcher — map a detected technology name to a normalised vendor/product/CPE prefix.

Aliases come from data/vulndb/aliases.json (and the `aliases` table when present). Exact,
case-insensitive matches first, then a couple of conservative fallbacks.
"""
from __future__ import annotations

import json
from functools import lru_cache

from scanner.cve.db import ALIASES_PATH


@lru_cache(maxsize=1)
def load_aliases() -> dict[str, dict]:
    """Load the alias table (name -> {vendor, product, cpe_prefix, type, requires?})."""
    try:
        data = json.loads(ALIASES_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {k.lower(): v for k, v in data.items()}


def normalize(name: str) -> dict | None:
    """Return the alias entry for *name*, or None. Case-insensitive."""
    if not name:
        return None
    aliases = load_aliases()
    key = name.strip().lower()
    if key in aliases:
        return aliases[key]
    # Conservative fallback: a known alias name contained as a whole word.
    for alias_name, entry in aliases.items():
        if alias_name in key.split():
            return entry
    return None
