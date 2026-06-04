"""
screenshot — captures a PNG of the target homepage with Playwright (headless Chromium).

The screenshot is saved under <project>/screenshots/ and reported as an Info finding with
the file path. Capture is self-healing: if the Chromium binary is missing (e.g. never
installed, or quarantined by antivirus) the module runs 'playwright install chromium'
once, automatically, and retries. If it still fails, it reports a clear Info finding and
never breaks the scan.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import threading
from datetime import datetime
from urllib.parse import urlparse

from loguru import logger

from config import PROJECT_ROOT
from scanner.engine import Finding, Severity, ScanEngine

MODULE = "screenshot"
_SHOT_DIR = PROJECT_ROOT / "screenshots"
_TIMEOUT_MS = 20000
_INSTALL_TIMEOUT = 600          # seconds for the one-time browser download

_install_lock = threading.Lock()
_install_attempted = False


def _output_path(url: str) -> str:
    host = urlparse(url).hostname or "target"
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", host)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    _SHOT_DIR.mkdir(parents=True, exist_ok=True)
    return str(_SHOT_DIR / f"{safe}_{stamp}.png")


def _browser_path() -> str | None:
    """Return Chromium's expected executable path, or None if Playwright is unusable."""
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            return p.chromium.executable_path
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"screenshot: cannot query Playwright: {exc}")
        return None


def _ensure_browser() -> bool:
    """Return True if Chromium is present, installing it once (thread-safe) if missing."""
    global _install_attempted
    path = _browser_path()
    if path is None:
        return False
    if os.path.exists(path):
        return True

    with _install_lock:
        if not _install_attempted:
            _install_attempted = True
            logger.warning("screenshot: Chromium missing — running a one-time "
                           "'playwright install chromium' (~150 MB download)…")
            try:
                subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"],
                               check=False, timeout=_INSTALL_TIMEOUT,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except (subprocess.SubprocessError, OSError) as exc:
                logger.warning(f"screenshot: auto-install failed: {exc}")

    new_path = _browser_path()
    return bool(new_path and os.path.exists(new_path))


def _capture(engine: ScanEngine, out_path: str) -> None:
    """Render the page and write a PNG. Raises on any Playwright/runtime failure."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
        try:
            context = browser.new_context(
                ignore_https_errors=True,
                user_agent=engine._client.headers.get("User-Agent", ""),
            )
            page = context.new_page()
            page.goto(engine.url, timeout=_TIMEOUT_MS, wait_until="domcontentloaded")
            page.screenshot(path=out_path, full_page=True)
        finally:
            browser.close()


def run(engine: ScanEngine) -> list[Finding]:
    if not _ensure_browser():
        return [Finding(
            module=MODULE, title="Screenshot: Browser Unavailable",
            description=("Chromium could not be installed automatically. Run "
                         "'py -m playwright install chromium' manually; if it persists, allow the "
                         "ms-playwright folder in your antivirus (it may quarantine chrome-headless-shell.exe)."),
            severity=Severity.INFO, recommendation="",
            raw={"error": "browser_unavailable", "confidence": "high"})]

    out_path = _output_path(engine.url)
    try:
        _capture(engine, out_path)
    except Exception as exc:  # noqa: BLE001 — capture is best-effort, never fail the scan
        logger.warning(f"screenshot: capture failed: {exc}")
        return [Finding(
            module=MODULE, title="Screenshot: Not Captured",
            description=f"The homepage screenshot could not be captured: {exc}",
            severity=Severity.INFO, recommendation="",
            raw={"error": str(exc), "confidence": "high"})]

    return [Finding(
        module=MODULE, title="Homepage Screenshot Captured",
        description=f"A screenshot of {engine.url} was saved to {out_path}.",
        severity=Severity.INFO, recommendation="",
        raw={"path": out_path, "url": engine.url, "confidence": "high"})]
