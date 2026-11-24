"""
coverage — the scan's coverage ledger.

A finding list tells you what Hades *found*; it says nothing about what Hades *looked at*. The
coverage ledger closes that gap: for a given run it records which modules ran, which were skipped
(e.g. safe mode short-circuited them), which errored or timed out, and which modules in the catalog
were never attempted at all — plus the attack surface the shared crawl discovered (pages,
parametrised URLs, forms, parameters) and whether the input-probing modules that exercise that
surface actually ran.

This makes a scan *honest about its own limits*: a clean report over a surface that was barely
touched is very different from a clean report after every module ran. The ledger is a pure data
structure (see :func:`build_coverage`) so it renders identically in the console, HTML and JSON, and
is trivial to unit-test. ``from_engine`` is the thin adapter that reads it off a finished scan.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

from config import ALL_MODULES, MODULE_CATALOG

if TYPE_CHECKING:
    from scanner.crawler import CrawlResult
    from scanner.engine import Finding, ScanEngine


# Active modules that exercise the discovered input surface (parametrised URLs + forms). If one of
# these ran, the surface it iterates was probed — the ledger can say so truthfully.
INPUT_PROBING_MODULES: tuple[str, ...] = (
    "sqli_detect", "xss_detect", "command_injection", "ssti_detect",
    "lfi_detect", "open_redirect", "ssrf_detect", "idor_detect",
)

# Leaf module name → display category, derived once from the catalog.
_MODULE_CATEGORY: dict[str, str] = {
    path.split(".")[-1]: category
    for category, paths in MODULE_CATALOG.items()
    for path in paths
}

_ALL_LEAVES: set[str] = {p.split(".")[-1] for p in ALL_MODULES}


def _leaf(path: str) -> str:
    return path.rsplit(".", 1)[-1]


def _category(name: str) -> str:
    return _MODULE_CATEGORY.get(name, "Other")


def _is_skip_marker(title: str) -> bool:
    """True when a finding title is a module's own 'I did not really run' marker.

    Modules short-circuit cleanly in safe mode or when there is nothing to probe, emitting an INFO
    finding that says so ('… Skipped (Safe Mode)', '… No Injectable Inputs Found'). Those mean the
    module executed but did not actually test the target, so the ledger counts them as *skipped*."""
    t = title.lower()
    return ("skipped" in t) or ("no injectable inputs" in t) or ("no parametrised urls" in t)


def build_coverage(
    stats: list[dict],
    module_paths: list[str],
    findings: list["Finding"],
    crawl: Optional["CrawlResult"] = None,
    profile: str = "",
) -> dict[str, Any]:
    """Build the coverage ledger from a finished scan's raw inputs (pure function).

    ``stats`` are the per-module ``{name, status, count, seconds}`` dicts the engine records;
    ``module_paths`` is the exact module set attempted; ``findings`` is the final finding list (used
    to detect clean short-circuits); ``crawl`` is the shared crawl result if one ran.
    """
    attempted = [_leaf(p) for p in module_paths]

    # Which attempted modules short-circuited without really testing (safe-mode / no-input markers).
    skipped_names: set[str] = set()
    for f in findings:
        if _is_skip_marker(getattr(f, "title", "")):
            skipped_names.add(getattr(f, "module", ""))

    rows: list[dict] = []
    buckets = {"ran": [], "skipped": [], "errored": [], "timed_out": []}  # type: dict[str, list[str]]
    for st in stats:
        name = st.get("name", "")
        raw_status = st.get("status", "ok")
        if raw_status == "error":
            status = "errored"
        elif raw_status == "timeout":
            status = "timed_out"
        elif name in skipped_names and st.get("count", 0) <= 1:
            # Short-circuited cleanly (its only output is the skip marker itself).
            status = "skipped"
        else:
            status = "ran"
        buckets.setdefault(status, []).append(name)
        rows.append({
            "name":     name,
            "category": _category(name),
            "status":   status,
            "findings": int(st.get("count", 0)),
            "seconds":  round(float(st.get("seconds", 0.0)), 1),
        })

    rows.sort(key=lambda r: (r["category"], r["name"]))

    # Catalog modules that were never attempted this run = untested surface.
    attempted_set = set(attempted)
    not_run = sorted(n for n in _ALL_LEAVES if n not in attempted_set)

    # Attack surface the shared crawl discovered, and whether a probing module exercised it.
    probed_by = [n for n in INPUT_PROBING_MODULES if n in buckets["ran"]]
    surface: dict[str, Any] = {
        "crawled":            crawl is not None,
        "pages":              len(getattr(crawl, "pages", {}) or {}) if crawl else 0,
        "parametrised_urls":  len(getattr(crawl, "parametrised_urls", []) or []) if crawl else 0,
        "forms":              len(getattr(crawl, "forms", []) or []) if crawl else 0,
        "params":             _distinct_params(crawl),
        "probed_by":          probed_by,
        "probe_modules_total": len(INPUT_PROBING_MODULES),
    }

    counts = {
        "attempted": len(attempted),
        "ran":       len(buckets["ran"]),
        "skipped":   len(buckets["skipped"]),
        "errored":   len(buckets["errored"]),
        "timed_out": len(buckets["timed_out"]),
        "not_run":   len(not_run),
    }

    return {
        "profile":     profile,
        "counts":      counts,
        "modules":     {**buckets, "not_run": not_run},
        "module_rows": rows,
        "surface":     surface,
    }


def _distinct_params(crawl: Optional["CrawlResult"]) -> int:
    """Count distinct query-parameter names across the crawl's parametrised URLs + GET forms."""
    if crawl is None:
        return 0
    from urllib.parse import parse_qs, urlparse  # local import keeps module import cheap

    names: set[str] = set()
    for url in getattr(crawl, "parametrised_urls", []) or []:
        names.update(parse_qs(urlparse(url).query).keys())
    for form in getattr(crawl, "forms", []) or []:
        names.update((getattr(form, "fields", {}) or {}).keys())
    return len(names)


def from_engine(engine: "ScanEngine") -> dict[str, Any]:
    """Read the coverage ledger off a finished :class:`ScanEngine` (thin adapter)."""
    return build_coverage(
        stats=getattr(engine, "_run_stats", []) or [],
        module_paths=getattr(engine, "_module_paths", []) or [],
        findings=getattr(engine, "findings", []) or [],
        crawl=getattr(engine, "_crawl_result", None),
        profile=getattr(engine, "profile", "") or "",
    )
