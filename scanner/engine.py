"""
WebScan scan engine — module orchestration, threading, rate limiting, and result aggregation.
"""

import importlib
import time
import threading
from concurrent.futures import ThreadPoolExecutor, Future, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.crawler import CrawlResult

import httpx
from loguru import logger
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from config import (
    CRAWL_MAX_DEPTH,
    CRAWL_MAX_PAGES,
    DEFAULT_RATE_DELAY,
    DEFAULT_THREADS,
    DEFAULT_TIMEOUT,
    PROFILE_MODULES,
    USER_AGENT,
)
from scanner.output.console import print_findings, print_summary, print_verification_links
from scanner.output.scorer import score_findings
from scanner.output.report_json import generate_json
from scanner.output.report_html import generate_html
from scanner.output.report_pdf import generate_pdf

console = Console()


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    INFO     = "info"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


_SEVERITY_ORDER: list[str] = ["critical", "high", "medium", "low", "info"]


@dataclass
class Finding:
    module:         str
    title:          str
    description:    str
    severity:       Severity
    recommendation: str = ""
    raw:            dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """Thread-safe minimum-delay enforcer between outgoing requests."""

    def __init__(self, delay: float) -> None:
        self._delay = delay
        self._lock = threading.Lock()
        self._last: float = 0.0

    def acquire(self) -> None:
        with self._lock:
            wait = self._delay - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()


# ---------------------------------------------------------------------------
# Scan engine
# ---------------------------------------------------------------------------

class ScanEngine:
    """
    Orchestrates module loading, parallel execution, rate limiting,
    and result collection for a single scan run.
    """

    def __init__(
        self,
        url: str,
        profile: str = "full",
        threads: int = DEFAULT_THREADS,
        proxy: Optional[str] = None,
        ignore_robots: bool = False,
        wordlist: Optional[str] = None,
        cookies: Optional[str] = None,
        auth_token: Optional[str] = None,
        rate_delay: float = DEFAULT_RATE_DELAY,
        modules: Optional[list[str]] = None,
    ) -> None:
        self.url          = url.rstrip("/")
        self.profile      = profile
        self.threads      = threads
        # Explicit module list overrides the profile (e.g. single-module run).
        self.modules      = modules
        self.proxy        = proxy
        self.ignore_robots = ignore_robots
        self.wordlist     = wordlist
        self.cookies      = cookies
        self.auth_token   = auth_token

        self._rate_limiter = RateLimiter(rate_delay)
        self._client       = self._build_client()
        self.findings: list[Finding] = []

        # Shared crawl cache — populated lazily on first get_crawl() call and
        # reused by every module so parallel scans share a single crawl.
        self._crawl_result = None
        self._crawl_lock   = threading.Lock()

    # ------------------------------------------------------------------
    # HTTP helpers (all module traffic must flow through here)
    # ------------------------------------------------------------------

    def _build_client(self) -> httpx.Client:
        headers: dict[str, str] = {"User-Agent": USER_AGENT}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        if self.cookies:
            headers["Cookie"] = self.cookies

        mounts = (
            {"http://": httpx.HTTPTransport(proxy=self.proxy),
             "https://": httpx.HTTPTransport(proxy=self.proxy)}
            if self.proxy else None
        )

        return httpx.Client(
            headers=headers,
            mounts=mounts,
            follow_redirects=True,
            timeout=DEFAULT_TIMEOUT,
            verify=False,  # targets may have self-signed certs; caller controls this
        )

    def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Rate-limited HTTP request — every module must use this, never httpx directly."""
        self._rate_limiter.acquire()
        return self._client.request(method, url, **kwargs)

    def get(self, path: str = "", **kwargs) -> httpx.Response:
        target = f"{self.url}{path}" if path else self.url
        return self.request("GET", target, **kwargs)

    def head(self, path: str = "", **kwargs) -> httpx.Response:
        target = f"{self.url}{path}" if path else self.url
        return self.request("HEAD", target, **kwargs)

    # ------------------------------------------------------------------
    # Shared crawl (lazy, thread-safe — modules call this instead of crawling)
    # ------------------------------------------------------------------

    def get_crawl(
        self,
        max_depth: int = CRAWL_MAX_DEPTH,
        max_pages: int = CRAWL_MAX_PAGES,
    ) -> "CrawlResult":
        """
        Return the shared CrawlResult, running the crawl once on first call.
        Thread-safe: concurrent modules block until the first crawl completes,
        then all receive the same cached result.
        """
        if self._crawl_result is not None:
            return self._crawl_result
        with self._crawl_lock:
            if self._crawl_result is None:  # double-checked under lock
                from scanner.crawler import crawl  # local import avoids a cycle
                self._crawl_result = crawl(self, max_depth=max_depth, max_pages=max_pages)
        return self._crawl_result

    # ------------------------------------------------------------------
    # Module execution
    # ------------------------------------------------------------------

    def _run_module(self, module_path: str) -> list[Finding]:
        """Import module by dotted path and invoke its run(engine) function."""
        mod = importlib.import_module(module_path)
        return mod.run(self)  # type: ignore[attr-defined]

    def run_scan(self) -> list[Finding]:
        """Execute all modules for the chosen profile in parallel, collect findings."""
        module_paths: list[str] = (
            self.modules
            if self.modules
            else PROFILE_MODULES.get(self.profile, PROFILE_MODULES["full"])
        )
        findings: list[Finding] = []

        with Progress(
            SpinnerColumn(spinner_name="dots2"),
            TextColumn("[cyan]{task.description:<45}"),
            BarColumn(bar_width=30),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            task_id = progress.add_task(
                f"Scanning {self.url}",
                total=len(module_paths),
            )

            with ThreadPoolExecutor(max_workers=self.threads) as pool:
                future_to_mod: dict[Future[list[Finding]], str] = {
                    pool.submit(self._run_module, path): path
                    for path in module_paths
                }

                for future in as_completed(future_to_mod):
                    mod_path = future_to_mod[future]
                    mod_name = mod_path.split(".")[-1]

                    try:
                        result = future.result()
                        findings.extend(result)
                        progress.console.print(
                            f"  [green]+[/green] [dim]{mod_name:<30}[/dim] "
                            f"[cyan]{len(result)} finding(s)[/cyan]"
                        )
                    except Exception as exc:  # noqa: BLE001
                        logger.error(f"{mod_path} failed: {exc}")
                        progress.console.print(
                            f"  [red]x[/red] [dim]{mod_name:<30}[/dim] "
                            f"[red]{exc}[/red]"
                        )
                    finally:
                        progress.advance(task_id)

        self.findings = sorted(
            findings,
            key=lambda f: _SEVERITY_ORDER.index(f.severity.value),
        )
        return self.findings

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "ScanEngine":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Top-level entry called by main.py
# ---------------------------------------------------------------------------

def run_scan(
    url: str,
    profile: str = "full",
    output_format: Optional[str] = None,
    proxy: Optional[str] = None,
    threads: int = DEFAULT_THREADS,
    ignore_robots: bool = False,
    wordlist: Optional[str] = None,
    cookies: Optional[str] = None,
    auth_token: Optional[str] = None,
    modules: Optional[list[str]] = None,
    exploit: bool = False,
) -> None:
    """Instantiate the engine, run the scan, print results, and export a report if requested."""
    with ScanEngine(
        url=url,
        profile=profile,
        threads=threads,
        proxy=proxy,
        ignore_robots=ignore_robots,
        wordlist=wordlist,
        cookies=cookies,
        auth_token=auth_token,
        modules=modules,
    ) as engine:
        findings = engine.run_scan()

    print_findings(findings, url)
    print_verification_links(findings, url)
    score = score_findings(findings)
    print_summary(findings, score)

    # Dedicated Database Security Audit panel (no-op unless db_security ran).
    from scanner.db.db_security import render_panel  # local import avoids a cycle
    render_panel(findings)

    match output_format:
        case "json":
            generate_json(findings, url, score)
        case "html":
            generate_html(findings, url, score)
        case "pdf":
            generate_pdf(findings, url, score)

    # Opt-in exploitation: offer to launch sqlmap against confirmed SQL injections.
    from scanner.exploit import offer as offer_exploitation  # local import avoids a cycle
    offer_exploitation(findings, auto=exploit)
