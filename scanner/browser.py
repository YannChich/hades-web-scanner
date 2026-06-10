"""
browser — shared headless-Chromium (Playwright) plumbing for the modules that need a real
browser (screenshot capture, browser-verified DOM/stored XSS).

Playwright is an *optional* dependency: every entry point degrades gracefully when it (or the
Chromium binary) is absent. ``ensure_chromium()`` is self-healing — if the browser is missing it
runs a one-time, thread-safe ``playwright install chromium`` and retries. ``launch_context()``
builds a context that inherits the scan's identity (User-Agent, cookies, Bearer token, proxy) so a
browser pass sees the same session the httpx client does.
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
from typing import TYPE_CHECKING, Any

from loguru import logger

if TYPE_CHECKING:
    from scanner.engine import ScanEngine

# Hardening flags so headless Chromium runs in CI/containers/locked-down hosts.
_LAUNCH_ARGS = ["--no-sandbox", "--disable-dev-shm-usage"]
_INSTALL_TIMEOUT = 600          # seconds for the one-time browser download

_install_lock = threading.Lock()
_install_attempted = False


# ---------------------------------------------------------------------------
# Availability / self-healing install
# ---------------------------------------------------------------------------

def _browser_path() -> str | None:
    """Return Chromium's expected executable path, or None if Playwright is unusable/absent."""
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            return p.chromium.executable_path
    except Exception as exc:  # noqa: BLE001 — Playwright not installed or broken
        logger.debug(f"browser: cannot query Playwright: {exc}")
        return None


def chromium_available() -> bool:
    """True if Playwright is importable AND the Chromium binary already exists on disk."""
    path = _browser_path()
    return bool(path and os.path.exists(path))


def ensure_chromium() -> bool:
    """Return True if Chromium is usable, installing it once (thread-safe) if missing."""
    global _install_attempted
    path = _browser_path()
    if path is None:
        return False                       # Playwright itself is not installed
    if os.path.exists(path):
        return True

    with _install_lock:
        if not _install_attempted:
            _install_attempted = True
            logger.warning("browser: Chromium missing — running a one-time "
                           "'playwright install chromium' (~150 MB download)…")
            try:
                subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"],
                               check=False, timeout=_INSTALL_TIMEOUT,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except (subprocess.SubprocessError, OSError) as exc:
                logger.warning(f"browser: auto-install failed: {exc}")

    new_path = _browser_path()
    return bool(new_path and os.path.exists(new_path))


# ---------------------------------------------------------------------------
# Context construction (inherits the scan's identity)
# ---------------------------------------------------------------------------

def _parse_cookie_header(cookie_header: str, url: str) -> list[dict[str, str]]:
    """Turn a "k=v; k2=v2" Cookie header into Playwright cookie dicts scoped to *url*."""
    cookies: list[dict[str, str]] = []
    for part in cookie_header.split(";"):
        name, sep, value = part.strip().partition("=")
        if name and sep:
            cookies.append({"name": name.strip(), "value": value.strip(), "url": url})
    return cookies


def launch_context(p: Any, engine: "ScanEngine") -> tuple[Any, Any]:
    """Launch headless Chromium and return (browser, context) carrying the scan's identity.

    The context inherits the engine's User-Agent, proxy, cookies and Bearer token so a browser
    pass operates with the same session (incl. authenticated scans) as the httpx client. The
    caller owns the lifecycle and must ``browser.close()``.
    """
    launch_kwargs: dict[str, Any] = {"headless": True, "args": list(_LAUNCH_ARGS)}
    if getattr(engine, "proxy", None):
        launch_kwargs["proxy"] = {"server": engine.proxy}
    browser = p.chromium.launch(**launch_kwargs)

    ua = ""
    try:
        ua = engine._client.headers.get("User-Agent", "")
    except Exception:  # noqa: BLE001 — UA is best-effort
        ua = ""
    context = browser.new_context(ignore_https_errors=True, user_agent=ua or None)

    cookie_header = getattr(engine, "cookies", "") or ""
    if cookie_header:
        try:
            context.add_cookies(_parse_cookie_header(cookie_header, engine.url))
        except Exception as exc:  # noqa: BLE001 — bad cookie string must not break the pass
            logger.debug(f"browser: could not seed cookies: {exc}")

    token = getattr(engine, "auth_token", "") or ""
    if token:
        try:
            context.set_extra_http_headers({"Authorization": f"Bearer {token}"})
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"browser: could not set auth header: {exc}")

    return browser, context
