"""
severity — the single source of truth for severity ordering and presentation.

Before this module the canonical order list (``["critical", … "info"]``) and the colour/style
maps were redefined in the engine, the scorer, every report renderer and each per-profile panel.
They now live here once, so ordering and colours stay consistent everywhere.

This module imports nothing from the rest of the package (it operates on the ``.value`` string
of a Severity), so it can be imported freely without creating cycles.
"""
from __future__ import annotations

from typing import Callable, Iterable, TypeVar

# Most-severe → least-severe. The canonical order used for sorting and counting.
SEVERITY_ORDER: list[str] = ["critical", "high", "medium", "low", "info"]

_RANK: dict[str, int] = {name: i for i, name in enumerate(SEVERITY_ORDER)}


def severity_rank(value: str) -> int:
    """Sort key for a severity string: critical=0 … info=4 (unknown sorts last)."""
    return _RANK.get(value, len(SEVERITY_ORDER))


_T = TypeVar("_T")


def sort_by_severity(items: Iterable[_T], key: Callable[[_T], str] = lambda f: f.severity.value) -> list[_T]:
    """Return *items* ordered most-severe first (by ``key`` → severity string)."""
    return sorted(items, key=lambda x: severity_rank(key(x)))


def severity_counts(items: Iterable, key: Callable = lambda f: f.severity.value) -> dict[str, int]:
    """Zero-initialised per-severity tally (keys follow SEVERITY_ORDER)."""
    counts = {name: 0 for name in SEVERITY_ORDER}
    for item in items:
        name = key(item)
        if name in counts:
            counts[name] += 1
    return counts


# Rich console / panel styles (terminal output).
CONSOLE_STYLE: dict[str, str] = {
    "critical": "bold red",
    "high":     "bold orange3",
    "medium":   "bold yellow",
    "low":      "bold green",
    "info":     "bold cyan",
}

# HTML report colours and row backgrounds.
HTML_COLOR: dict[str, str] = {
    "critical": "#ff2d55",
    "high":     "#ff6b35",
    "medium":   "#ffd700",
    "low":      "#34d399",
    "info":     "#60a5fa",
}

HTML_BG: dict[str, str] = {
    "critical": "rgba(255,45,85,0.08)",
    "high":     "rgba(255,107,53,0.08)",
    "medium":   "rgba(255,215,0,0.08)",
    "low":      "rgba(52,211,153,0.08)",
    "info":     "rgba(96,165,250,0.06)",
}
