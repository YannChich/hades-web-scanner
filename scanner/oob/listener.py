"""
listener — a tiny self-hosted HTTP callback server for out-of-band (OAST) vulnerability detection.

Blind vulnerabilities (blind SSRF, blind OS command injection, stored/blind XSS, XXE) never reflect
anything in the HTTP response — the only proof is the SERVER reaching back out. This listener binds a
local HTTP server, hands out unique single-use callback URLs, and records every interaction keyed by
the token in the request path. The oob_detect module injects those URLs and then asks the listener
which tokens were hit, correlating each callback to the exact injection point and vulnerability class.

HTTP-only by design (no extra dependency); it catches the common HTTP-callback classes. The target
must be able to reach the listener's address — auto-detected as the host's primary IP, overridable
with --oob-host when the tester sits behind NAT (public IP / tunnel).
"""
from __future__ import annotations

import secrets
import socket
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


@dataclass
class Interaction:
    """A single recorded callback hit."""
    token: str
    method: str
    path: str
    source_ip: str
    user_agent: str
    at: float


def primary_ip() -> str:
    """Best-effort detection of the host's outbound IP (the address a target can reach back on)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


class _Handler(BaseHTTPRequestHandler):
    # The first path segment is the token: GET /<token>[/...]
    def _record(self) -> None:
        token = self.path.lstrip("/").split("/")[0].split("?")[0]
        if token:
            interaction = Interaction(
                token=token,
                method=self.command,
                path=self.path,
                source_ip=self.client_address[0],
                user_agent=self.headers.get("User-Agent", ""),
                at=time.time(),
            )
            with self.server.hit_lock:          # type: ignore[attr-defined]
                self.server.hits.setdefault(token, []).append(interaction)  # type: ignore[attr-defined]
        # A 1x1 gif keeps blind-XSS <img> beacons happy and reveals nothing.
        body = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
        try:
            self.send_response(200)
            self.send_header("Content-Type", "image/gif")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass

    do_GET = _record
    do_POST = _record
    do_HEAD = _record
    do_PUT = _record

    def log_message(self, *args) -> None:   # silence the default stderr logging
        return


class OOBListener:
    """Self-hosted OAST callback server. Start it, mint tokens/URLs, then read the hits."""

    def __init__(self, public_host: str | None = None, port: int = 0, bind: str = "0.0.0.0") -> None:
        self.public_host = public_host or primary_ip()
        self.bind = bind
        self.port = port
        self.hits: dict[str, list[Interaction]] = {}
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._counter = 0
        self._lock = threading.Lock()

    def start(self) -> None:
        self._server = ThreadingHTTPServer((self.bind, self.port), _Handler)
        self._server.hits = self.hits            # type: ignore[attr-defined]
        self._server.hit_lock = threading.Lock()  # type: ignore[attr-defined]
        self.port = self._server.server_address[1]   # resolve the real port if 0 was requested
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except OSError:
                pass

    @property
    def base_url(self) -> str:
        return f"http://{self.public_host}:{self.port}"

    def new_token(self) -> str:
        """Return a fresh, unique token (also unique per process run)."""
        with self._lock:
            self._counter += 1
            n = self._counter
        return f"{secrets.token_hex(4)}{n:03d}"

    def url_for(self, token: str) -> str:
        return f"{self.base_url}/{token}"

    def hits_for(self, token: str) -> list[Interaction]:
        return self.hits.get(token, [])

    def __enter__(self) -> "OOBListener":
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()
