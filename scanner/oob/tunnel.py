"""
tunnel — best-effort public tunnel so OOB callbacks reach a listener running behind NAT.

The out-of-band listener is only useful if the *target* can reach it. On a workstation behind a
home router that means a public address is required. If `cloudflared` (preferred — free, no account,
ephemeral "quick tunnels") or `ngrok` is installed, this spins up a tunnel to the local listener
port and returns the public URL to use for callbacks. Entirely optional and graceful: if no tunnel
tool is available it returns None and the caller falls back to the host's local IP.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import threading
import time

from loguru import logger

# cloudflared prints the assigned URL (to stderr/stdout) — match it as bytes (locale-safe).
_CF_URL_RE = re.compile(rb"https://[a-z0-9][a-z0-9.\-]*\.trycloudflare\.com")
# cloudflared logs this once the tunnel is actually established at Cloudflare's edge.
_CF_READY = (b"registered tunnel connection", b"connection registered")


class Tunnel:
    """A public tunnel to a local port. Best-effort; call start() then read .url, stop() to tear down."""

    def __init__(self) -> None:
        self.url: str | None = None
        self.tool: str | None = None
        self._proc: subprocess.Popen | None = None

    def start(self, local_port: int, timeout: float = 25.0) -> str | None:
        """Start a tunnel to http://localhost:<local_port>; return the public URL or None."""
        if shutil.which("cloudflared") and self._start_cloudflared(local_port, timeout):
            return self.url
        if shutil.which("ngrok") and self._start_ngrok(local_port, timeout):
            return self.url
        return None

    def _start_cloudflared(self, port: int, timeout: float) -> bool:
        try:
            self._proc = subprocess.Popen(
                ["cloudflared", "tunnel", "--no-autoupdate", "--url", f"http://localhost:{port}"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
        except OSError as exc:
            logger.debug(f"tunnel: cloudflared failed to launch: {exc}")
            return False

        state: dict[str, object] = {"url": None, "ready": False}

        def _reader() -> None:
            assert self._proc and self._proc.stdout
            for raw in self._proc.stdout:          # bytes — no locale decode (Windows-safe)
                if state["url"] is None:
                    m = _CF_URL_RE.search(raw)
                    if m:
                        state["url"] = m.group(0).decode("ascii")
                low = raw.lower()
                if any(sig in low for sig in _CF_READY):
                    state["ready"] = True
                    break

        threading.Thread(target=_reader, daemon=True).start()
        deadline = time.time() + timeout
        # Wait for the URL and, ideally, the edge-registration line (returns early once both seen).
        while time.time() < deadline and self._proc.poll() is None:
            if state["url"] and state["ready"]:
                break
            time.sleep(0.3)

        if state["url"]:
            self.url, self.tool = str(state["url"]), "cloudflared"
            extra = "" if state["ready"] else " (edge registration not confirmed in time — may need a few more seconds)"
            logger.info(f"tunnel: cloudflared quick tunnel up at {self.url}{extra}")
            return True
        self.stop()
        return False

    def _start_ngrok(self, port: int, timeout: float) -> bool:
        try:
            self._proc = subprocess.Popen(
                ["ngrok", "http", str(port), "--log=stdout"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            logger.debug(f"tunnel: ngrok failed to launch: {exc}")
            return False

        import httpx
        deadline = time.time() + timeout
        while time.time() < deadline and self._proc.poll() is None:
            try:
                data = httpx.get("http://127.0.0.1:4040/api/tunnels", timeout=2).json()
                for t in data.get("tunnels", []):
                    url = t.get("public_url", "")
                    if url.startswith("https"):
                        self.url, self.tool = url, "ngrok"
                        logger.info(f"tunnel: ngrok tunnel up at {self.url}")
                        return True
            except Exception:  # noqa: BLE001 — agent API not ready yet
                pass
            time.sleep(0.5)
        self.stop()
        return False

    def stop(self) -> None:
        if self._proc is not None:
            try:
                self._proc.terminate()
            except Exception:  # noqa: BLE001
                pass
            self._proc = None
