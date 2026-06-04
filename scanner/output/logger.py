"""
logger — loguru configuration and structured logging helpers for WebScan.

Call setup_logging() once at application startup (main.py). All modules that
do `from loguru import logger` will automatically write to the configured sinks
because loguru uses a process-wide singleton.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from scanner.engine import Finding

# ---------------------------------------------------------------------------
# Loguru format strings
# ---------------------------------------------------------------------------

_FILE_FORMAT = (
    "{time:YYYY-MM-DD HH:mm:ss} | {level:<8} | {name} | {message}"
)

_CONSOLE_FORMAT = (
    "<dim>{time:HH:mm:ss}</dim> | "
    "<level>{level:<8}</level> | "
    "<cyan>{name}</cyan> | "
    "{message}"
)

_LOG_DIR = "logs"


def setup_logging(level: str = "DEBUG", console_level: str = "WARNING") -> str:
    """
    Configure loguru sinks:
      - File sink  : logs/webscan_TIMESTAMP.log  at *level* (default DEBUG)
      - Console sink: stderr at *console_level* (default WARNING, so scan
                      output isn't drowned by routine debug messages)

    Returns the log file path.
    """
    # Remove loguru's default stderr handler (id 0)
    logger.remove()

    # Console sink — only warnings and above so Rich scan output stays readable
    logger.add(
        sys.stderr,
        format=_CONSOLE_FORMAT,
        level=console_level,
        colorize=True,
    )

    # File sink — full debug detail
    os.makedirs(_LOG_DIR, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    log_path  = os.path.join(_LOG_DIR, f"webscan_{timestamp}.log")

    logger.add(
        log_path,
        format=_FILE_FORMAT,
        level=level,
        encoding="utf-8",
        rotation=None,      # single file per run
        enqueue=True,       # thread-safe writes from ThreadPoolExecutor workers
    )

    logger.debug(f"Logging initialised → {log_path}")
    return log_path


# ---------------------------------------------------------------------------
# Structured helpers
# ---------------------------------------------------------------------------

def log_finding(finding: Finding) -> None:
    """Log a single finding as it is discovered during scanning."""
    logger.bind(module=finding.module).info(
        "[{severity}] {title} | {description}",
        severity=finding.severity.value.upper(),
        title=finding.title,
        description=finding.description[:200],
    )


def log_request(
    method: str,
    url: str,
    status_code: int,
    response_time: float,
) -> None:
    """Log an outgoing HTTP request with its outcome."""
    logger.debug(
        "{method} {url} → {status} ({elapsed:.0f}ms)",
        method=method.upper(),
        url=url,
        status=status_code,
        elapsed=response_time * 1000,
    )


def log_error(module: str, error: BaseException) -> None:
    """Log an exception from a module without re-raising it."""
    logger.opt(exception=error).error(
        "[{module}] Unhandled exception: {error}",
        module=module,
        error=error,
    )
