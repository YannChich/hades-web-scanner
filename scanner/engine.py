"""
WebScan scan engine — module orchestration, threading, rate limiting, and result aggregation.
"""

import hashlib
import importlib
import random
import re
import string
import time
import threading
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
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
    CIRCUIT_BREAKER_COOLDOWN,
    CIRCUIT_BREAKER_FAILS,
    CRAWL_MAX_DEPTH,
    CRAWL_MAX_PAGES,
    DB_CATEGORY_REDTEAM_MAP,
    DEFAULT_RATE_DELAY,
    DEFAULT_THREADS,
    DEFAULT_TIMEOUT,
    FINDING_TAXONOMY,
    MAX_CONCURRENCY,
    MODULE_TIMEOUT,
    MODULE_REDTEAM_MAP,
    PROFILE_MODULES,
    SAFE_MODE_RATE_DELAY,
    SEVERITY_CVSS,
    USER_AGENT,
)
from scanner.severity import sort_by_severity
from scanner.output.console import (print_findings, print_playbooks, print_report_paths,
                                    print_summary, print_verification_links)
from scanner.output.logger import get_log_path
from scanner.output.scorer import score_findings
from scanner.output.report_json import generate_json
from scanner.output.report_html import generate_html

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


# Matches MITRE ATT&CK technique IDs, with optional sub-technique (e.g. T1078.001).
_MITRE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")

# Idempotent, genuinely-shared resources many modules fetch — cached once per scan (relative to url).
_CACHEABLE_PATHS = {"", "/robots.txt", "/sitemap.xml", "/sitemap_index.xml", "/favicon.ico"}

# Profiles for which an unreachable HTTP root means the scan can't proceed (so pre-flight may abort).
# Excludes db_scan/tls_scan/oob_scan/engage/cve_scan/ai_scan, whose target may have no HTTP root.
_WEB_CENTRIC_PROFILES = {"full", "quick", "passive", "cms"}


def _make_finding_id(module: str, title: str) -> str:
    """Stable, human-readable finding ID, e.g. 'SQLI-3F9A'.

    Deterministic: the same (module, title) always yields the same ID across runs,
    so reports can be diffed and findings cross-referenced. The prefix comes from
    the module name; the suffix is a short hash of module+title.
    """
    prefix = "".join(c for c in module.split("_")[0].upper() if c.isalnum())[:6] or "HADES"
    digest = hashlib.sha1(f"{module}|{title}".encode("utf-8")).hexdigest()[:4].upper()
    return f"{prefix}-{digest}"


@dataclass
class Finding:
    module:         str
    title:          str
    description:    str
    severity:       Severity
    recommendation: str = ""
    raw:            dict = field(default_factory=dict)
    # ── Framework mapping (auto-filled in __post_init__ from config.FINDING_TAXONOMY;
    #    a module may set any of these explicitly to override the default) ──
    cwe:        str = ""                              # e.g. "CWE-89"
    owasp:      str = ""                              # e.g. "A03:2021 Injection"
    mitre:      list[str] = field(default_factory=list)   # e.g. ["T1190"]
    cvss:       Optional[float] = None                # representative base score
    finding_id: str = ""                              # stable ID, e.g. "SQLI-3F9A"
    poc:        str = ""                              # reproducible proof (curl / HTTP request)
    # Matched expert playbooks from the skills library (filled by scanner.intel.skills_kb).
    skill_refs: list = field(default_factory=list)
    # Matched blue-team remediation playbook(s) — the defensive complement to skill_refs.
    remediation_refs: list = field(default_factory=list)
    # Relevant RedTeam-Tools entries by name (client-facing; details in the bundled PDF).
    redteam_tools: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        sev = self.severity.value if isinstance(self.severity, Severity) else str(self.severity)
        raw = self.raw if isinstance(self.raw, dict) else {}

        # Module-level framework defaults (never clobber an explicit value).
        tax = FINDING_TAXONOMY.get(self.module)
        if tax:
            self.cwe = self.cwe or str(tax.get("cwe", ""))
            self.owasp = self.owasp or str(tax.get("owasp", ""))
            if not self.mitre and tax.get("mitre"):
                self.mitre = list(tax["mitre"])  # type: ignore[arg-type]

        # ATT&CK technique from a raw["attack"] string (db_security per-category).
        if not self.mitre and raw.get("attack"):
            self.mitre = _MITRE_RE.findall(str(raw["attack"]))

        # Representative CVSS from severity (info → none) unless set explicitly.
        if self.cvss is None:
            self.cvss = SEVERITY_CVSS.get(sev)

        # Proof-of-concept: reuse a proof/verify URL when the module recorded one.
        if not self.poc:
            proof = raw.get("proof_url") or raw.get("url")
            if proof:
                self.poc = f"curl -sk \"{proof}\""

        # Relevant RedTeam-Tools by name (skip context-only INFO findings, like playbooks).
        if not self.redteam_tools and sev != "info":
            if self.module == "db_security":
                self.redteam_tools = list(DB_CATEGORY_REDTEAM_MAP.get(raw.get("db_category", ""), []))
            else:
                self.redteam_tools = list(MODULE_REDTEAM_MAP.get(self.module, []))

        # Every finding carries a confidence (low/medium/high) so the terminal table, the scorer
        # and the JSON report stay consistent even for modules that don't set one explicitly.
        self.raw = raw
        raw.setdefault("confidence",
                       "high" if sev in ("critical", "high") else "medium" if sev == "medium" else "low")

        # Stable identifier last, so it is always present.
        if not self.finding_id:
            self.finding_id = _make_finding_id(self.module, self.title)


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """Thread-safe concurrent token-bucket rate limiter.

    A plain global min-delay caps the whole scan at one request per ``delay`` and makes the thread
    pool useless (every thread queues on the same lock). This bucket instead sustains
    ``concurrency / delay`` requests per second and lets up to ``concurrency`` fire near-simultaneously,
    so threads actually parallelise. ``concurrency=1`` reproduces the old strictly-serial behaviour
    (used for safe/passive mode). ``_delay`` is kept for ``is_safe_mode()``.
    """

    def __init__(self, delay: float, concurrency: int = 1) -> None:
        self._delay = delay
        self._burst = max(1, concurrency)
        self._rate = (self._burst / delay) if delay > 0 else float("inf")   # tokens per second
        self._tokens = float(self._burst)
        self._updated = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(self._burst, self._tokens + (now - self._updated) * self._rate)
                self._updated = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait = (1.0 - self._tokens) / self._rate
            time.sleep(max(wait, 0.0))                # sleep OUTSIDE the lock so others can refill


# ---------------------------------------------------------------------------
# Soft-404 baseline (shared anti-false-positive fingerprint)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Soft404:
    """Fingerprint of how the target answers a request for a path that should not exist.

    A site that 200s every path (catch-all / SPA) or blanket-403s every path produces false
    positives in any path-probing module. This single baseline lets every such module reuse the
    same anti-noise check instead of re-deriving it. ``status`` is the bogus probe's status code;
    ``is_catch_all`` is True when that was a 200; ``length``/``digest``/``ctype`` fingerprint the
    bogus body. A neutral baseline (``status == 0``) means the probe could not be made.
    """
    status: int
    is_catch_all: bool
    is_blanket_403: bool
    length: int
    digest: str
    ctype: str


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
        login_url: Optional[str] = None,
        login_data: Optional[str] = None,
        login_check: Optional[str] = None,
        rate_delay: float = DEFAULT_RATE_DELAY,
        modules: Optional[list[str]] = None,
        exploit: bool = False,
        bruteforce: bool = False,
        oob_host: Optional[str] = None,
        oob_port: int = 0,
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
        # Authenticated scanning: establish a session so the crawler + every active module
        # operate logged in. login_data is form-encoded creds ("user=admin&password=secret").
        self.login_url    = login_url
        self.login_data   = login_data
        self.login_check  = login_check
        self.authenticated = False
        # Opt-in offensive mode: when True, modules may actively exploit/extract
        # (gated, authorised targets only). Mirrors the --exploit CLI flag.
        self.exploit      = exploit
        # Opt-in credential attacks (password spraying). Mirrors the --bruteforce CLI flag.
        self.bruteforce   = bruteforce
        # Out-of-band (OAST) callback address for the oob_scan profile (auto-detected if None).
        self.oob_host     = oob_host
        self.oob_port     = oob_port

        # Safe/passive mode stays strictly serial (one polite lane); otherwise allow the thread pool
        # to parallelise up to MAX_CONCURRENCY lanes so the scan isn't capped at one request/delay.
        concurrency = 1 if rate_delay >= SAFE_MODE_RATE_DELAY else max(1, min(threads, MAX_CONCURRENCY))
        self._rate_limiter = RateLimiter(rate_delay, concurrency)
        self._client       = self._build_client()
        self._anon_client: Optional[httpx.Client] = None   # lazy, for access-control checks
        self.findings: list[Finding] = []

        # Shared crawl cache — populated lazily on first get_crawl() call and
        # reused by every module so parallel scans share a single crawl.
        self._crawl_result = None
        self._crawl_lock   = threading.Lock()

        # Shared idempotent-GET cache — the homepage and a few well-known paths (robots/sitemap/
        # favicon) are fetched by ~12 modules each; cache them so each costs one request per scan.
        self._get_cache: dict[str, httpx.Response] = {}
        self._get_cache_lock = threading.Lock()

        # Shared soft-404 baseline — one probe of a certainly-nonexistent path, reused by every
        # path-probing module so they all apply the same anti-false-positive check (see soft404_baseline).
        self._soft404: Optional["Soft404"] = None
        self._soft404_lock = threading.Lock()

        # Circuit breaker — trips after CIRCUIT_BREAKER_FAILS consecutive request timeouts/connection
        # failures, then fast-fails requests for a cooldown so an unresponsive target can't make every
        # module grind to its time budget.
        self._breaker_lock = threading.Lock()
        self._fail_streak = 0
        self._breaker_open_until = 0.0
        self._breaker_announced = False

        # Establish an authenticated session before any module runs (best-effort).
        if self.login_url and self.login_data:
            self._establish_session()

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
            limits=httpx.Limits(max_connections=max(self.threads * 2, 20),
                                max_keepalive_connections=max(self.threads, 10)),
        )

    def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Rate-limited HTTP request — every module must use this, never httpx directly.

        Guarded by a circuit breaker: while it is open (the target looks unresponsive) requests
        fail fast instead of waiting on a timeout, so the scan finishes quickly rather than every
        module grinding to its budget. A successful request closes it again.
        """
        if self._breaker_open_until > time.monotonic():       # open → fail fast, no rate-limit wait
            raise httpx.ConnectError(f"circuit breaker open: {self.url} unresponsive")
        self._rate_limiter.acquire()
        try:
            resp = self._client.request(method, url, **kwargs)
        except (httpx.TimeoutException, httpx.ConnectError):
            with self._breaker_lock:
                self._fail_streak += 1
                if self._fail_streak >= CIRCUIT_BREAKER_FAILS and self._breaker_open_until <= time.monotonic():
                    self._breaker_open_until = time.monotonic() + CIRCUIT_BREAKER_COOLDOWN
                    if not self._breaker_announced:
                        self._breaker_announced = True
                        console.print(
                            f"[yellow]  ⚠ {self.url} is unresponsive "
                            f"({self._fail_streak} consecutive timeouts) — backing off; active probing "
                            f"will fail fast for ~{CIRCUIT_BREAKER_COOLDOWN:.0f}s.[/yellow]")
            raise
        if self._fail_streak:                                  # recovered → close the breaker
            with self._breaker_lock:
                self._fail_streak = 0
                self._breaker_open_until = 0.0
        return resp

    def get(self, path: str = "", **kwargs) -> httpx.Response:
        target = f"{self.url}{path}" if path else self.url
        # Plain GETs of genuinely-shared, idempotent resources are fetched once and reused for the
        # whole scan (the homepage alone is requested by ~12 modules). Anything with kwargs (custom
        # headers, no-redirect, timeouts) or a non-allowlisted path is never cached.
        if path in _CACHEABLE_PATHS and not kwargs:
            cached = self._get_cache.get(target)
            if cached is not None:
                return cached
            resp = self.request("GET", target)
            with self._get_cache_lock:
                self._get_cache.setdefault(target, resp)
            return self._get_cache[target]
        return self.request("GET", target, **kwargs)

    def head(self, path: str = "", **kwargs) -> httpx.Response:
        target = f"{self.url}{path}" if path else self.url
        return self.request("HEAD", target, **kwargs)

    def is_safe_mode(self) -> bool:
        """True when the scan runs in safe/passive mode (one polite request lane). Modules use this to
        skip destructive/active probing. Single source of truth — see SAFE_MODE_RATE_DELAY."""
        return self._rate_limiter._delay >= SAFE_MODE_RATE_DELAY

    def soft404_baseline(self) -> "Soft404":
        """Probe a random, certainly-nonexistent path once per scan and cache the fingerprint.

        Reused by path-probing modules (sensitive_files, backup_files, dir_scan, dir_listing,
        admin_panel…) so they all share one anti-false-positive baseline rather than each deriving
        their own. Returns a neutral ``Soft404`` (status 0) when the probe cannot be made (e.g. the
        circuit breaker is open or the host is unreachable).
        """
        if self._soft404 is not None:
            return self._soft404
        with self._soft404_lock:
            if self._soft404 is not None:
                return self._soft404
            rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=24))
            baseline = Soft404(0, False, False, 0, "", "")
            try:
                resp = self.request("GET", f"{self.url}/{rand}.html")
                body = resp.text
                baseline = Soft404(
                    status=resp.status_code,
                    is_catch_all=(resp.status_code == 200),
                    is_blanket_403=(resp.status_code == 403),
                    length=len(body),
                    digest=hashlib.md5(body.encode("utf-8", "ignore")).hexdigest(),
                    ctype=resp.headers.get("content-type", "").split(";")[0].strip(),
                )
            except httpx.HTTPError:
                pass
            self._soft404 = baseline
            return baseline

    def request_anonymous(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Rate-limited request with NO session cookie or auth header — used by access-control
        checks to tell whether an object is reachable without being logged in."""
        if self._anon_client is None:
            mounts = (
                {"http://": httpx.HTTPTransport(proxy=self.proxy),
                 "https://": httpx.HTTPTransport(proxy=self.proxy)}
                if self.proxy else None
            )
            self._anon_client = httpx.Client(
                headers={"User-Agent": USER_AGENT}, mounts=mounts,
                follow_redirects=True, timeout=DEFAULT_TIMEOUT, verify=False,
            )
        self._rate_limiter.acquire()
        return self._anon_client.request(method, url, **kwargs)

    def _establish_session(self) -> None:
        """Log in so the shared client carries the session for the crawler and every module.

        Best-effort and never fatal: GET the login page to pick up a CSRF cookie + hidden form
        fields, merge them with the supplied credentials, then POST. Cookies persist in self._client,
        so the crawl and all active modules run authenticated.
        """
        from urllib.parse import parse_qsl                 # local import
        from scanner.crawler import extract_forms          # local import avoids a cycle

        creds = dict(parse_qsl(self.login_data or "", keep_blank_values=True))
        login_url = self.login_url if self.login_url.startswith(("http://", "https://")) \
            else f"{self.url}/{self.login_url.lstrip('/')}"
        action, data = login_url, dict(creds)
        try:
            page = self.request("GET", login_url)
            forms = extract_forms(login_url, page.text)
            # Prefer the form whose fields cover the supplied creds (the real login form).
            form = next((f for f in forms if any(k in f.fields for k in creds)),
                        forms[0] if forms else None)
            if form is not None:
                data = {**form.fields, **creds}            # keep hidden CSRF tokens, override creds
                action = form.action or login_url
        except httpx.HTTPError as exc:
            logger.debug(f"login: GET {login_url} failed ({exc}); posting credentials directly")

        try:
            self.request("POST", action, data=data)
        except httpx.HTTPError as exc:
            logger.warning(f"login: POST {action} failed: {exc}")
            return

        ok = bool(self._client.cookies)
        if self.login_check:
            try:
                ok = self.login_check.lower() in self.request("GET", self.url).text.lower()
            except httpx.HTTPError:
                ok = False
        self.authenticated = ok
        logger.info(f"login: session {'established' if ok else 'NOT confirmed'} "
                    f"(cookies={len(self._client.cookies)}) via {action}")

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
        """Execute the profile's modules in parallel and collect findings.

        Each module gets a wall-clock budget (``MODULE_TIMEOUT``): a module that runs longer is
        *abandoned* — the scan stops waiting for it and shuts the pool down without blocking — so one
        slow or hung module can never stall the whole scan. Per-module timing/status is captured for
        the run summary.
        """
        module_paths: list[str] = (
            self.modules
            if self.modules
            else PROFILE_MODULES.get(self.profile, PROFILE_MODULES["full"])
        )

        # Pre-flight: for a web-centric profile run, confirm the HTTP root is reachable before
        # launching dozens of modules (and seed the shared GET cache with the homepage). A returned
        # response — even 4xx/5xx — means the host is up; only a connection-level failure aborts.
        if self.profile in _WEB_CENTRIC_PROFILES and not self.modules:
            try:
                self.get()
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                from rich.panel import Panel  # noqa: PLC0415
                console.print(Panel(
                    f"[bold]Target unreachable[/bold]  [cyan]{self.url}[/cyan]\n"
                    f"[dim]{exc}[/dim]\nThe HTTP root could not be reached — aborting the scan.",
                    title="[bold red]Pre-flight failed[/bold red]", border_style="red", padding=(1, 2)))
                logger.error(f"pre-flight: {self.url} unreachable: {exc}")
                self.findings = []
                return []

        findings: list[Finding] = []
        stats: list[dict] = []                          # {name, seconds, count, status}
        starts: dict[str, float] = {}                   # module path → when its thread began
        poll = min(2.0, max(0.1, MODULE_TIMEOUT / 5))

        def _runner(path: str) -> list[Finding]:
            starts[path] = time.monotonic()
            return self._run_module(path)

        with Progress(
            SpinnerColumn(spinner_name="dots2"),
            TextColumn("[cyan]{task.description:<45}"),
            BarColumn(bar_width=30),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            task_id = progress.add_task(f"Scanning {self.url}", total=len(module_paths))
            pool = ThreadPoolExecutor(max_workers=self.threads)
            try:
                fut_to_mod: dict[Future, str] = {pool.submit(_runner, p): p for p in module_paths}
                pending = set(fut_to_mod)
                while pending:
                    done, pending = wait(pending, timeout=poll, return_when=FIRST_COMPLETED)
                    for fut in done:
                        path = fut_to_mod[fut]
                        name = path.split(".")[-1]
                        elapsed = time.monotonic() - starts.get(path, time.monotonic())
                        try:
                            result = fut.result()
                            findings.extend(result)
                            stats.append({"name": name, "seconds": elapsed,
                                          "count": len(result), "status": "ok"})
                            progress.console.print(
                                f"  [green]+[/green] [dim]{name:<28}[/dim] "
                                f"[cyan]{len(result)} finding(s)[/cyan] [dim]{elapsed:.1f}s[/dim]")
                        except Exception as exc:  # noqa: BLE001 — one module must never abort the scan
                            logger.error(f"{path} failed: {exc}")
                            stats.append({"name": name, "seconds": elapsed, "count": 0,
                                          "status": "error"})
                            progress.console.print(
                                f"  [red]x[/red] [dim]{name:<28}[/dim] [red]{exc}[/red]")
                        progress.advance(task_id)
                    # Watchdog: abandon any module that has been RUNNING past its budget.
                    now = time.monotonic()
                    overdue = {f for f in pending
                               if (st := starts.get(fut_to_mod[f])) is not None and now - st > MODULE_TIMEOUT}
                    for fut in overdue:
                        name = fut_to_mod[fut].split(".")[-1]
                        fut.cancel()
                        stats.append({"name": name, "seconds": MODULE_TIMEOUT, "count": 0,
                                      "status": "timeout"})
                        logger.warning(f"{fut_to_mod[fut]} exceeded {MODULE_TIMEOUT:.0f}s — abandoned")
                        progress.console.print(
                            f"  [yellow]![/yellow] [dim]{name:<28}[/dim] "
                            f"[yellow]timed out (> {MODULE_TIMEOUT:.0f}s) — abandoned[/yellow]")
                        progress.advance(task_id)
                    pending -= overdue
            finally:
                pool.shutdown(wait=False, cancel_futures=True)

        self._run_stats = stats
        _print_run_summary(stats)
        self.findings = sort_by_severity(findings)
        return self.findings

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def close(self) -> None:
        self._client.close()
        if self._anon_client is not None:
            self._anon_client.close()

    def __enter__(self) -> "ScanEngine":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Top-level entry called by main.py
# ---------------------------------------------------------------------------

def _print_run_summary(stats: list[dict]) -> None:
    """A glance-able summary of the module run: status counts, total time/findings, the slowest
    modules, and anything that errored or timed out — so a full scan is observable at a glance."""
    if not stats:
        return
    ok = sum(1 for s in stats if s["status"] == "ok")
    errored = [s["name"] for s in stats if s["status"] == "error"]
    timed_out = [s["name"] for s in stats if s["status"] == "timeout"]
    total_time = sum(s["seconds"] for s in stats)
    total_findings = sum(s["count"] for s in stats)
    slowest = sorted((s for s in stats if s["status"] == "ok"),
                     key=lambda s: s["seconds"], reverse=True)[:3]

    line = f"[dim]Modules:[/dim] {len(stats)} run · [green]{ok} ok[/green]"
    if errored:
        line += f" · [red]{len(errored)} error[/red]"
    if timed_out:
        line += f" · [yellow]{len(timed_out)} timeout[/yellow]"
    line += f" · [cyan]{total_findings} finding(s)[/cyan] · [dim]{total_time:.1f}s total[/dim]"
    console.print()
    console.print(line)
    if slowest:
        console.print("  [dim]slowest:[/dim] "
                      + "  ·  ".join(f"{s['name']} [dim]{s['seconds']:.1f}s[/dim]" for s in slowest))
    if errored:
        console.print(f"  [red]errored:[/red] {', '.join(errored)}")
    if timed_out:
        console.print(f"  [yellow]timed out:[/yellow] {', '.join(timed_out)}")


def _open_in_browser(path: str) -> None:
    """Best-effort: open a report file in the default browser (never fails the scan)."""
    import webbrowser
    from pathlib import Path
    try:
        if webbrowser.open(Path(path).resolve().as_uri()):
            console.print(f"[dim]  🌐 Opened the HTML report in your browser.[/dim]")
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"could not open report in browser: {exc}")


def run_scan(
    url: str,
    profile: str = "full",
    proxy: Optional[str] = None,
    threads: int = DEFAULT_THREADS,
    ignore_robots: bool = False,
    wordlist: Optional[str] = None,
    cookies: Optional[str] = None,
    auth_token: Optional[str] = None,
    login_url: Optional[str] = None,
    login_data: Optional[str] = None,
    login_check: Optional[str] = None,
    modules: Optional[list[str]] = None,
    exploit: bool = False,
    bruteforce: bool = False,
    open_report: bool = True,
    oob_host: Optional[str] = None,
    oob_port: int = 0,
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
        login_url=login_url,
        login_data=login_data,
        login_check=login_check,
        modules=modules,
        exploit=exploit,
        bruteforce=bruteforce,
        oob_host=oob_host,
        oob_port=oob_port,
    ) as engine:
        if engine.authenticated:
            console.print("[dim]  🔓 Authenticated session established — scanning the logged-in surface.[/dim]")
        elif login_url:
            console.print("[yellow]  ⚠ Login not confirmed — continuing unauthenticated "
                          "(check --login-data / --login-check).[/yellow]")
        findings = engine.run_scan()

    # Knowledge-base enrichment: attach matching expert playbooks from the skills
    # library (optional — silently no-ops if the library isn't present).
    try:
        from scanner.intel.skills_kb import enrich as enrich_skills  # local import avoids a cycle
        n = enrich_skills(findings)
        if n:
            console.print(f"[dim]  📚 Enriched {n} finding(s) with expert playbooks from the skills library.[/dim]")
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"skills enrichment skipped: {exc}")

    print_findings(findings, url)
    print_verification_links(findings, url)
    score = score_findings(findings)
    print_summary(findings, score)
    print_playbooks(findings)

    # Unified kill-chain attack path (all modules except db_security, which has its own panel).
    from scanner.output.attack_path import print_attack_path  # local import avoids a cycle
    print_attack_path(findings, url)

    # Dedicated Database Security Audit panel (no-op unless db_security ran).
    from scanner.db.db_security import render_panel  # local import avoids a cycle
    render_panel(findings)

    # Dedicated AI/LLM Exposure panel (no-op unless llm_recon ran).
    from scanner.ai.llm_recon import render_panel as render_ai_panel
    render_ai_panel(findings)

    # Dedicated Active Engagement panel (no-op unless the engage profile ran).
    from scanner.offensive.engage import render_panel as render_engage_panel
    render_engage_panel(findings)

    # Dedicated CVE Vulnerability Intelligence panel (no-op unless cve_scan ran).
    from scanner.cve.report import render_panel as render_cve_panel
    render_cve_panel(findings)

    # Every scan always produces both reports: a rich, auto-opened HTML report (the detailed view)
    # and a machine-readable JSON report (for tooling / records).
    html_path = generate_html(findings, url, score)
    json_path = generate_json(findings, url, score)
    print_report_paths(html_path, json_path, log_path=str(get_log_path()))

    if open_report and html_path:
        _open_in_browser(html_path)

    # Opt-in exploitation: offer to launch sqlmap against confirmed SQL injections.
    from scanner.exploit import offer as offer_exploitation  # local import avoids a cycle
    offer_exploitation(findings, auto=exploit)
