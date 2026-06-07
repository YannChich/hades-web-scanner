"""
WebScan scan engine — module orchestration, threading, rate limiting, and result aggregation.
"""

import hashlib
import importlib
import re
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
    DB_CATEGORY_REDTEAM_MAP,
    DEFAULT_RATE_DELAY,
    DEFAULT_THREADS,
    DEFAULT_TIMEOUT,
    FINDING_TAXONOMY,
    MODULE_REDTEAM_MAP,
    PROFILE_MODULES,
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

        self._rate_limiter = RateLimiter(rate_delay)
        self._client       = self._build_client()
        self._anon_client: Optional[httpx.Client] = None   # lazy, for access-control checks
        self.findings: list[Finding] = []

        # Shared crawl cache — populated lazily on first get_crawl() call and
        # reused by every module so parallel scans share a single crawl.
        self._crawl_result = None
        self._crawl_lock   = threading.Lock()

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
