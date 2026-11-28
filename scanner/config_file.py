"""
config_file — project-level defaults for Hades from a ``hades.toml`` file.

A pentester who scans the same target repeatedly shouldn't retype the same flags every run. A
``hades.toml`` in the working directory (or one passed with ``--config``) supplies default values
for CLI flags under a ``[hades]`` table, e.g.::

    [hades]
    profile = "full"
    no_open = true
    ignore_file = ".hadesignore"
    scope = ["*.example.com"]
    threads = 20

Precedence is the obvious one: an explicit CLI flag always wins over the config file, which in turn
wins over the built-in default. (This is achieved by feeding the config values to
``argparse.set_defaults`` before parsing, so a flag the user actually passes still overrides it.)

The parser is stdlib ``tomllib`` on Python 3.11+ and falls back to ``tomli`` on 3.10. The loader is
defensive: a missing file, a parse error or an unknown key never aborts a scan — it is logged and
ignored, so a typo in the config can't break the tool.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Optional

from loguru import logger

try:  # Python 3.11+
    import tomllib as _toml  # type: ignore
except ModuleNotFoundError:  # Python 3.10
    try:
        import tomli as _toml  # type: ignore
    except ModuleNotFoundError:  # pragma: no cover - only when neither is installed
        _toml = None  # type: ignore

DEFAULT_CONFIG_NAME = "hades.toml"
# The table the defaults live under. Top-level keys are also accepted as a convenience.
CONFIG_TABLE = "hades"


def find_config(explicit: Optional[str] = None) -> Optional[str]:
    """Resolve the config path: an explicit ``--config`` wins; otherwise ``./hades.toml`` if present.

    Returns None when there is nothing to load. An explicit path that does not exist is returned as
    given so the caller can surface a clear "not found" message rather than silently ignoring it.
    """
    if explicit:
        return explicit
    local = Path(DEFAULT_CONFIG_NAME)
    return str(local) if local.is_file() else None


def load_config(path: Optional[str]) -> dict[str, Any]:
    """Read the ``[hades]`` defaults table from *path*. Empty dict on any problem (never raises)."""
    if not path:
        return {}
    if _toml is None:  # pragma: no cover
        logger.warning("config: no TOML parser available (need Python 3.11+ or `tomli`); ignoring config")
        return {}
    p = Path(path)
    if not p.is_file():
        logger.warning(f"config: file not found: {path}")
        return {}
    try:
        data = _toml.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 — a bad config must never crash the scan
        logger.warning(f"config: cannot parse {path}: {exc}")
        return {}
    table = data.get(CONFIG_TABLE)
    if isinstance(table, dict):
        return table
    # Fall back to top-level keys (minus any nested tables) for a flat config.
    return {k: v for k, v in data.items() if not isinstance(v, dict)}


def select_defaults(config: dict[str, Any], valid_dests: Iterable[str]) -> dict[str, Any]:
    """Keep only the config keys that name a real CLI option; warn about the rest.

    Hyphens in keys are normalised to underscores so ``ignore-file`` and ``ignore_file`` both match
    the argparse dest. Returns a dict ready for ``argparse.set_defaults(**result)``.
    """
    valid = set(valid_dests)
    out: dict[str, Any] = {}
    for key, value in config.items():
        dest = str(key).replace("-", "_")
        if dest in valid:
            out[dest] = value
        else:
            logger.warning(f"config: ignoring unknown option '{key}'")
    return out
