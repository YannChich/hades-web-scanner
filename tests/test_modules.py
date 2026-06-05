"""
WebScan unit tests.

All HTTP is intercepted via MockTransport — no real network calls are made.
Run with:  pytest tests/test_modules.py -v
"""
from __future__ import annotations

import sys
import os
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

# Ensure `import scanner.*` and `import config` resolve from webscan/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scanner.engine import Finding, Severity, ScanEngine
from scanner.output.scorer import calculate_score


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class MockTransport(httpx.BaseTransport):
    """Routes requests to a URL-keyed response dict."""

    def __init__(
        self,
        responses: dict[str, httpx.Response],
        default_status: int = 404,
    ) -> None:
        self._responses = responses
        self._default = default_status

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        # Exact match
        if url in self._responses:
            return self._responses[url]
        # Prefix match (catches injected query strings that share a base path)
        for key, resp in self._responses.items():
            if url.startswith(key):
                return resp
        return httpx.Response(self._default, text="")


def _make_finding(severity: Severity, module: str = "test", **raw) -> Finding:
    return Finding(
        module=module,
        title="Test finding",
        description="",
        severity=severity,
        raw=raw,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def base_url() -> str:
    return "https://example.com"


@pytest.fixture
def engine_factory(base_url: str):
    """
    Returns a factory: call it with a {url: Response} dict to get a
    ScanEngine whose HTTP client is fully mocked.
    """
    def _factory(responses: dict[str, httpx.Response]) -> ScanEngine:
        eng = ScanEngine(base_url, rate_delay=0)
        eng._client = httpx.Client(
            transport=MockTransport(responses),
            follow_redirects=True,
            verify=False,
        )
        return eng

    return _factory


# ---------------------------------------------------------------------------
# Finding taxonomy / framework-mapping tests (Axe 1)
# ---------------------------------------------------------------------------

class TestFindingTaxonomy:
    def test_autopopulates_framework_tags(self):
        f = Finding(module="sqli_detect", title="SQL Injection in 'id'",
                    description="", severity=Severity.CRITICAL)
        assert f.cwe == "CWE-89"
        assert f.owasp.startswith("A03:2021")
        assert "T1190" in f.mitre
        assert f.cvss == 9.8
        assert f.finding_id.startswith("SQLI-")

    def test_info_finding_has_no_cvss(self):
        f = Finding(module="basic_info", title="IP Address",
                    description="", severity=Severity.INFO)
        assert f.cvss is None

    def test_finding_id_is_stable_per_module_and_title(self):
        a = Finding(module="x", title="same title", description="d1", severity=Severity.LOW)
        b = Finding(module="x", title="same title", description="d2", severity=Severity.HIGH)
        c = Finding(module="x", title="other title", description="d1", severity=Severity.LOW)
        assert a.finding_id == b.finding_id      # ID ignores description/severity
        assert a.finding_id != c.finding_id      # ID changes with the title

    def test_explicit_values_are_not_overridden(self):
        f = Finding(module="sqli_detect", title="t", description="", severity=Severity.HIGH,
                    cwe="CWE-999", cvss=1.0, mitre=["T9999"], finding_id="CUSTOM-1")
        assert f.cwe == "CWE-999"
        assert f.cvss == 1.0
        assert f.mitre == ["T9999"]
        assert f.finding_id == "CUSTOM-1"

    def test_mitre_derived_from_raw_attack(self):
        # db_security stores its per-category ATT&CK technique in raw["attack"].
        f = Finding(module="db_security", title="Redis unauth", description="",
                    severity=Severity.CRITICAL,
                    raw={"attack": "T1190 Exploit Public-Facing Application"})
        assert "T1190" in f.mitre

    def test_poc_backfilled_from_proof_url(self):
        f = Finding(module="sqli_detect", title="t", description="", severity=Severity.CRITICAL,
                    raw={"proof_url": "https://t/?id=1'"})
        assert f.poc.startswith("curl ")
        assert "id=1" in f.poc

    def test_redteam_tools_filled_by_module(self):
        f = Finding(module="dir_scan", title="Found /admin", description="", severity=Severity.MEDIUM)
        assert "gobuster" in f.redteam_tools and "feroxbuster" in f.redteam_tools

    def test_redteam_tools_skipped_for_info(self):
        f = Finding(module="sqli_detect", title="no SQLi", description="", severity=Severity.INFO)
        assert f.redteam_tools == []

    def test_redteam_tools_by_db_category(self):
        f = Finding(module="db_security", title="Redis unauth", description="", severity=Severity.CRITICAL,
                    raw={"db_category": "unauth"})
        assert "crackmapexec" in f.redteam_tools

    def test_redteam_tools_not_overridden(self):
        f = Finding(module="dir_scan", title="t", description="", severity=Severity.LOW,
                    redteam_tools=["custom-tool"])
        assert f.redteam_tools == ["custom-tool"]


# ---------------------------------------------------------------------------
# Skills-library enrichment tests (Axe 2)
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_skills_repo(tmp_path, monkeypatch):
    """Build a minimal skills library on disk and point skills_kb at it."""
    import json as _json
    from scanner.intel import skills_kb

    repo = tmp_path / "skills-lib"
    (repo / "skills").mkdir(parents=True)

    def _add(name: str, mitre: list[str], tags: list[str]) -> None:
        d = repo / "skills" / name
        d.mkdir()
        fm = "---\nname: {n}\ntags:\n{t}\nmitre_attack:\n{m}\n---\n# {n}\n".format(
            n=name,
            t="\n".join(f"- {x}" for x in tags),
            m="\n".join(f"- {x}" for x in mitre),
        )
        (d / "SKILL.md").write_text(fm, encoding="utf-8")

    _add("exploiting-sql-injection-vulnerabilities", ["T1190", "T1078"], ["SQL-injection", "OWASP-A03"])
    _add("exploiting-sql-injection-with-sqlmap", ["T1190"], ["sqlmap"])
    _add("performing-second-order-sql-injection", ["T1190"], ["second-order"])
    _add("exploiting-nosql-injection-vulnerabilities", ["T1190"], ["NoSQL"])

    index = {"skills": [
        {"name": p.name, "description": f"Test skill {p.name}", "path": f"skills/{p.name}"}
        for p in sorted((repo / "skills").iterdir())
    ]}
    (repo / "index.json").write_text(_json.dumps(index), encoding="utf-8")

    monkeypatch.setenv("HADES_SKILLS_PATH", str(repo))
    for fn in (skills_kb.find_skills_repo, skills_kb._load_index, skills_kb._skill_detail):
        fn.cache_clear()
    yield repo
    for fn in (skills_kb.find_skills_repo, skills_kb._load_index, skills_kb._skill_detail):
        fn.cache_clear()


class TestSkillsEnrichment:
    def test_curated_module_match(self, fake_skills_repo):
        from scanner.intel.skills_kb import enrich
        f = Finding(module="sqli_detect", title="SQLi in id", description="", severity=Severity.CRITICAL)
        assert enrich([f]) == 1
        names = [s["name"] for s in f.skill_refs]
        assert "exploiting-sql-injection-vulnerabilities" in names
        assert "T1190" in f.skill_refs[0]["mitre"]   # parsed from SKILL.md frontmatter

    def test_db_category_routing(self, fake_skills_repo):
        from scanner.intel.skills_kb import enrich
        f = Finding(module="db_security", title="NoSQL bypass", description="",
                    severity=Severity.CRITICAL, raw={"db_category": "nosql"})
        enrich([f])
        assert [s["name"] for s in f.skill_refs] == ["exploiting-nosql-injection-vulnerabilities"]

    def test_info_module_not_enriched(self, fake_skills_repo):
        from scanner.intel.skills_kb import enrich
        f = Finding(module="basic_info", title="IP Address", description="", severity=Severity.INFO)
        enrich([f])
        assert f.skill_refs == []

    def test_info_severity_not_enriched(self, fake_skills_repo):
        # An INFO finding from an offensive module (e.g. "no SQLi found") gets no playbook.
        from scanner.intel.skills_kb import enrich
        f = Finding(module="sqli_detect", title="SQLi testing complete — none found",
                    description="", severity=Severity.INFO)
        enrich([f])
        assert f.skill_refs == []

    def test_graceful_noop_when_repo_absent(self, tmp_path, monkeypatch):
        from scanner.intel import skills_kb
        # Neutralise both the env override and the on-disk candidate paths so the
        # real library (if present in the workspace) is not discovered.
        monkeypatch.setenv("HADES_SKILLS_PATH", str(tmp_path / "does-not-exist"))
        monkeypatch.setattr(skills_kb, "SKILLS_REPO_CANDIDATES", [])
        for fn in (skills_kb.find_skills_repo, skills_kb._load_index, skills_kb._skill_detail):
            fn.cache_clear()
        f = Finding(module="sqli_detect", title="t", description="", severity=Severity.HIGH)
        assert skills_kb.enrich([f]) == 0
        assert f.skill_refs == []
        for fn in (skills_kb.find_skills_repo, skills_kb._load_index, skills_kb._skill_detail):
            fn.cache_clear()


# ---------------------------------------------------------------------------
# AI / LLM recon tests (Axe 4)
# ---------------------------------------------------------------------------

class _FakeCrawlEngine:
    def __init__(self, pages: dict[str, str]) -> None:
        from scanner.crawler import CrawlResult
        self.url = "https://t"
        self._cr = CrawlResult(pages=pages)
    def get_crawl(self):
        return self._cr


class TestLLMRecon:
    def test_exposed_anthropic_key(self):
        from scanner.ai import llm_recon
        eng = _FakeCrawlEngine({"https://t/app.js": "const K='sk-ant-ABCDEFGHIJKLMNOPQRSTUVWX';"})
        fs = llm_recon._check_exposed_keys(eng)
        assert fs and fs[0].raw["provider"] == "Anthropic"
        assert fs[0].severity is Severity.CRITICAL
        assert fs[0].owasp.startswith("LLM02:2025")
        assert "T1552.001" in fs[0].mitre

    def test_sdk_signature_detected(self):
        from scanner.ai import llm_recon
        eng = _FakeCrawlEngine({"https://t/": "<script src='https://api.openai.com/v1/x'></script>"})
        fs = llm_recon._check_sdk_signatures(eng)
        assert fs and "OpenAI" in fs[0].raw["providers"]

    def test_ai_finding_keeps_atlas_and_maps_to_phase(self):
        from scanner.output.attack_path import build_attack_path
        f = Finding(module="llm_recon", title="Prompt-Injection Surface", description="",
                    severity=Severity.MEDIUM, owasp="LLM01:2025 Prompt Injection",
                    mitre=["AML.T0051"], raw={"ai_category": "prompt_injection_surface",
                                              "proof_url": "https://t/chat"})
        assert f.mitre == ["AML.T0051"]                 # ATLAS tag preserved (Axe 1)
        assert "garak" in f.redteam_tools               # AI tools wired (Axe 4)
        groups = build_attack_path([f])
        assert groups[0]["phase"] == "Initial Access"   # routed by ai_category (Axe 3)

    def test_ai_scan_profile_registered(self):
        from config import PROFILE_MODULES
        assert PROFILE_MODULES["ai_scan"] == ["scanner.ai.llm_recon"]


# ---------------------------------------------------------------------------
# Active engagement (auto-pwn) tests
# ---------------------------------------------------------------------------

class TestEngage:
    def test_profile_registered(self):
        from config import PROFILE_MODULES
        assert PROFILE_MODULES["engage"] == ["scanner.offensive.engage"]

    def test_engage_finding_enriched(self):
        from scanner.offensive.engage import _f
        f = _f("RCE", "d", Severity.CRITICAL, "rec", "rce",
               cwe="CWE-78", owasp="A03:2021 Injection", mitre=["T1059"])
        assert f.cwe == "CWE-78"
        assert "nuclei" in f.redteam_tools            # from MODULE_REDTEAM_MAP['engage']
        assert f.raw["engage_category"] == "rce"

    def test_exploit_cmd_captures_rce(self):
        from scanner.vulns._common import Injector
        from scanner.offensive.engage import _exploit_cmd

        class _Resp:
            text = "result: uid=0(root) gid=0(root) groups=0(root)"
            status_code = 200

        inj = Injector(label="URL parameter 'q'", param="q",
                       inject=lambda p: _Resp(), proof=lambda p: "https://t/?q=" + p,
                       url="https://t/?q=1")
        res = _exploit_cmd(inj, None)            # loot=None → evidence skipped, no crash
        assert res is not None
        assert res.raw["engage_category"] == "rce"
        assert "T1059" in res.mitre

    def test_engage_rce_maps_to_execution_phase(self):
        from scanner.output.attack_path import build_attack_path
        f = Finding(module="engage", title="RCE Confirmed", description="", severity=Severity.CRITICAL,
                    cwe="CWE-78", owasp="A03:2021 Injection", mitre=["T1059"],
                    raw={"engage_category": "rce", "exploit_cmd": "curl x", "parameter": "q"})
        groups = build_attack_path([f])
        assert groups[0]["phase"] == "Execution"


# ---------------------------------------------------------------------------
# Attack-path / kill-chain tests (Axe 3)
# ---------------------------------------------------------------------------

class TestAttackPath:
    def test_groups_ordered_by_kill_chain(self):
        from scanner.output.attack_path import build_attack_path
        sqli = Finding(module="sqli_detect", title="SQLi in id", description="",
                       severity=Severity.CRITICAL,
                       raw={"sqlmap": "sqlmap -u 'https://t/?id=1' --batch --dbs", "proof_url": "https://t/?id=1'"})
        port = Finding(module="port_scan", title="Open port 3306", description="",
                       severity=Severity.LOW, raw={"port": 3306, "ip": "1.2.3.4"})
        groups = build_attack_path([port, sqli])
        phases = [g["phase"] for g in groups]
        assert phases.index("Initial Access") < phases.index("Discovery")  # attacker order
        # Steps are numbered globally across phases.
        nums = [s["n"] for g in groups for s in g["steps"]]
        assert nums == [1, 2]

    def test_command_prefers_specialised(self):
        from scanner.output.attack_path import build_attack_path
        sqli = Finding(module="sqli_detect", title="SQLi", description="", severity=Severity.CRITICAL,
                       raw={"sqlmap": "sqlmap -u X --dbs", "proof_url": "https://t/?id=1'"})
        port = Finding(module="port_scan", title="Open 3306", description="", severity=Severity.LOW,
                       raw={"port": 3306, "ip": "1.2.3.4"})
        steps = {s["module"]: s for g in build_attack_path([sqli, port]) for s in g["steps"]}
        assert steps["sqli_detect"]["command"].startswith("sqlmap")
        assert steps["port_scan"]["command"] == "nmap -sV -p 3306 1.2.3.4"

    def test_hardening_and_db_findings_excluded(self):
        from scanner.output.attack_path import build_attack_path
        headers = Finding(module="headers_check", title="Missing CSP", description="", severity=Severity.MEDIUM)
        db = Finding(module="db_security", title="Redis unauth", description="", severity=Severity.CRITICAL,
                     raw={"attack": "T1190 ...", "exploit_cmd": "redis-cli ..."})
        groups = build_attack_path([headers, db])
        modules = {s["module"] for g in groups for s in g["steps"]}
        assert "headers_check" not in modules   # hardening gap, not a step
        assert "db_security" not in modules      # has its own panel

    def test_playbook_crosslink_carried(self):
        from scanner.output.attack_path import build_attack_path
        f = Finding(module="lfi_detect", title="LFI in file", description="", severity=Severity.HIGH,
                    raw={"url": "https://t/?file=/etc/passwd"})
        f.skill_refs = [{"name": "performing-directory-traversal-testing", "mitre": ["T1083"]}]
        step = build_attack_path([f])[0]["steps"][0]
        assert step["playbook"] == "performing-directory-traversal-testing"
        assert step["command"].startswith("curl ")


# ---------------------------------------------------------------------------
# headers_check tests
# ---------------------------------------------------------------------------

class TestHeadersCheck:
    def test_missing_csp_is_medium(self, engine_factory, base_url):
        """Missing CSP is a hardening gap (defence-in-depth), not a Critical — it is Medium."""
        from scanner.web.headers_check import run

        # Provide all headers EXCEPT CSP
        eng = engine_factory({
            base_url: httpx.Response(200, text="<html></html>", headers={
                "strict-transport-security": "max-age=31536000",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
                "referrer-policy": "strict-origin-when-cross-origin",
                "permissions-policy": "camera=()",
            }),
        })

        findings = run(eng)

        assert not [f for f in findings if f.severity == Severity.CRITICAL]
        csp = [f for f in findings if "content-security-policy" in f.title.lower()
               and "missing" in f.title.lower()]
        assert csp and csp[0].severity == Severity.MEDIUM

    def test_csp_unsafe_inline_is_medium(self, engine_factory, base_url):
        """CSP with 'unsafe-inline' must produce a Medium weakness finding."""
        from scanner.web.headers_check import run

        eng = engine_factory({
            base_url: httpx.Response(200, text="<html></html>", headers={
                "content-security-policy": "default-src 'self'; script-src 'unsafe-inline'",
                "strict-transport-security": "max-age=31536000",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
                "referrer-policy": "strict-origin-when-cross-origin",
                "permissions-policy": "camera=()",
            }),
        })

        findings = run(eng)

        medium = [f for f in findings if f.severity == Severity.MEDIUM]
        assert any("unsafe-inline" in f.title.lower() for f in medium), (
            "Expected a Medium finding for 'unsafe-inline' in CSP"
        )

    def test_all_headers_present_no_critical(self, engine_factory, base_url):
        """A fully-configured response should produce no Critical or High findings."""
        from scanner.web.headers_check import run

        eng = engine_factory({
            base_url: httpx.Response(200, text="<html></html>", headers={
                "content-security-policy": "default-src 'self'",
                "strict-transport-security": "max-age=31536000; includeSubDomains",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
                "referrer-policy": "strict-origin-when-cross-origin",
                "permissions-policy": "camera=()",
            }),
        })

        findings = run(eng)

        severe = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert not severe, f"Unexpected severe findings: {[f.title for f in severe]}"

    def test_csp_missing_directives_flagged(self, engine_factory, base_url):
        """A minimal CSP still flags missing object-src / base-uri / frame-ancestors."""
        from scanner.web.headers_check import run

        eng = engine_factory({
            base_url: httpx.Response(200, text="<html></html>", headers={
                "content-security-policy": "default-src 'self'",
            }),
        })
        titles = " ".join(f.title.lower() for f in run(eng))
        assert "object-src" in titles and "base-uri" in titles and "frame-ancestors" in titles

    def test_hsts_missing_includesubdomains_and_preload(self, engine_factory, base_url):
        from scanner.web.headers_check import run

        eng = engine_factory({
            base_url: httpx.Response(200, text="<html></html>", headers={
                "content-security-policy": "default-src 'self'; object-src 'none'; "
                                           "base-uri 'none'; frame-ancestors 'none'",
                "strict-transport-security": "max-age=31536000",
            }),
        })
        titles = " ".join(f.title.lower() for f in run(eng))
        assert "includesubdomains" in titles and "preload" in titles

    def test_server_version_disclosure_is_low(self, engine_factory, base_url):
        from scanner.web.headers_check import run

        eng = engine_factory({
            base_url: httpx.Response(200, text="<html></html>", headers={
                "content-security-policy": "default-src 'self'",
                "server": "nginx/1.18.0",
                "x-powered-by": "PHP/8.1.2",
            }),
        })
        findings = run(eng)
        disclosure = [f for f in findings if "disclosure" in f.title.lower()]
        assert any("server" in f.raw.get("header", "") for f in disclosure)
        assert any(f.raw.get("header") == "x-powered-by" for f in disclosure)
        assert all(f.severity == Severity.LOW for f in disclosure)

    def test_xfo_covered_by_csp_frame_ancestors(self, engine_factory, base_url):
        """Missing X-Frame-Options is only Info when CSP frame-ancestors is set."""
        from scanner.web.headers_check import run

        eng = engine_factory({
            base_url: httpx.Response(200, text="<html></html>", headers={
                "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            }),
        })
        xfo = [f for f in run(eng) if f.raw.get("header") == "x-frame-options"]
        assert xfo and all(f.severity == Severity.INFO for f in xfo)


# ---------------------------------------------------------------------------
# ssl_check tests
# (test _check_expiry directly to avoid real TLS socket connections)
# ---------------------------------------------------------------------------

class TestSslCheck:
    def _make_cert(self, days_until_expiry: int) -> MagicMock:
        now = datetime.now(timezone.utc)
        cert = MagicMock()
        cert.not_valid_before_utc = now - timedelta(days=365)
        cert.not_valid_after_utc  = now + timedelta(days=days_until_expiry)
        return cert

    def test_expired_cert_is_critical(self):
        """A certificate expired 10 days ago must produce a Critical finding."""
        from scanner.recon.ssl_check import _check_expiry

        cert = self._make_cert(days_until_expiry=-10)
        findings = _check_expiry(cert, "example.com")

        assert any(f.severity == Severity.CRITICAL for f in findings), (
            "Expected Critical finding for expired certificate"
        )

    def test_expiring_in_3_days_is_high(self):
        """A certificate expiring in 3 days must produce a High finding."""
        from scanner.recon.ssl_check import _check_expiry

        cert = self._make_cert(days_until_expiry=3)
        findings = _check_expiry(cert, "example.com")

        assert any(f.severity == Severity.HIGH for f in findings), (
            "Expected High finding for certificate expiring in < 7 days"
        )

    def test_expiring_in_20_days_is_medium(self):
        """A certificate expiring in 20 days must produce a Medium finding."""
        from scanner.recon.ssl_check import _check_expiry

        cert = self._make_cert(days_until_expiry=20)
        findings = _check_expiry(cert, "example.com")

        assert any(f.severity == Severity.MEDIUM for f in findings), (
            "Expected Medium finding for certificate expiring in < 30 days"
        )

    def test_valid_cert_only_info(self):
        """A certificate with 180 days remaining must produce only Info findings."""
        from scanner.recon.ssl_check import _check_expiry

        cert = self._make_cert(days_until_expiry=180)
        findings = _check_expiry(cert, "example.com")

        non_info = [f for f in findings if f.severity != Severity.INFO]
        assert not non_info, f"Unexpected non-Info findings: {[f.title for f in non_info]}"

    def test_plain_http_is_high(self, engine_factory):
        """An http:// target must produce a High finding (no TLS)."""
        from scanner.recon.ssl_check import run

        eng = ScanEngine("http://example.com", rate_delay=0)
        findings = run(eng)

        assert any(f.severity == Severity.HIGH for f in findings)
        assert any("plain http" in f.title.lower() or "no tls" in f.title.lower()
                   for f in findings)


# ---------------------------------------------------------------------------
# sqli_detect tests
# ---------------------------------------------------------------------------

class TestSqliDetect:
    def test_sql_error_in_response_is_critical(self, base_url):
        """Injected parameter returning a MySQL error must produce a Critical finding."""
        from scanner.vulns.sqli_detect import run
        from scanner.crawler import CrawlResult

        sql_error_html = (
            '<html><body>'
            'You have an error in your SQL syntax near &quot;1&apos;&quot;'
            '</body></html>'
        )

        eng = ScanEngine(base_url, rate_delay=0)
        # The shared crawl yields a parametrised URL; any request returns a SQL error
        eng.get_crawl = MagicMock(return_value=CrawlResult(
            parametrised_urls=[f"{base_url}/search?id=1"],
        ))
        eng.request = MagicMock(return_value=httpx.Response(200, text=sql_error_html))

        findings = run(eng)

        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert critical, "Expected Critical finding for SQL error in response"
        assert any("sql" in f.title.lower() for f in critical)

    def test_no_params_returns_info(self, base_url):
        """No parametrised URLs from the crawl must return an Info finding, not Critical."""
        from scanner.vulns.sqli_detect import run
        from scanner.crawler import CrawlResult

        eng = ScanEngine(base_url, rate_delay=0)
        eng.get_crawl = MagicMock(return_value=CrawlResult())

        findings = run(eng)

        assert all(f.severity == Severity.INFO for f in findings)

    def test_safe_mode_skips_scan(self):
        """Safe mode (rate_delay >= SAFE_MODE_RATE_DELAY) must skip injection."""
        from scanner.vulns.sqli_detect import run
        from config import SAFE_MODE_RATE_DELAY

        eng = ScanEngine("https://example.com", rate_delay=SAFE_MODE_RATE_DELAY)
        eng.get = MagicMock(return_value=httpx.Response(200, text=""))

        findings = run(eng)

        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "safe mode" in findings[0].title.lower()

    def test_boolean_based_blind_detected(self, base_url):
        """TRUE≈baseline and FALSE≠baseline must be detected as boolean-based blind SQLi."""
        from scanner.vulns.sqli_detect import run
        from scanner.crawler import CrawlResult

        long_page = "<html>" + "A" * 600 + "record found</html>"
        short_page = "<html>no record</html>"

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                val = parse_qs(urlparse(str(req.url)).query).get("id", [""])[0]
                # No SQL error strings anywhere (so error-based must not fire).
                if "1=2" in val:           # FALSE condition → different page
                    return httpx.Response(200, text=short_page)
                return httpx.Response(200, text=long_page)   # baseline & TRUE

        eng = ScanEngine(base_url, rate_delay=0)
        eng.get_crawl = MagicMock(return_value=CrawlResult(parametrised_urls=[f"{base_url}/p?id=1"]))
        eng._client = httpx.Client(transport=_T(), follow_redirects=True, verify=False)

        findings = run(eng)
        crit = [f for f in findings if f.severity == Severity.CRITICAL]
        assert crit and crit[0].raw["technique"] == "boolean-based blind"

    def test_finding_includes_sqlmap_and_proof_link(self, base_url):
        from scanner.vulns.sqli_detect import _finding
        from scanner.output.console import _verify_url

        f = _finding(f"{base_url}/c?id=1", "id", "boolean-based blind", "1 AND 1=1", "")
        assert f.raw["sqlmap"].startswith('sqlmap -u "') and "--technique=B" in f.raw["sqlmap"]
        assert f.raw["proof_url"] and "id=" in f.raw["proof_url"]
        # The proof URL is what becomes the clickable link in the verification table.
        assert _verify_url(f, base_url) == f.raw["proof_url"]

    def test_time_based_blind_detected(self, base_url, monkeypatch):
        """A sleep payload whose delay scales with the requested time is time-based blind SQLi."""
        from scanner.vulns import sqli_detect
        from scanner.crawler import CrawlResult

        # Benign responses so error/boolean stages do not fire.
        eng = ScanEngine(base_url, rate_delay=0)
        eng.get_crawl = MagicMock(return_value=CrawlResult(parametrised_urls=[f"{base_url}/p?id=1"]))
        eng.request = MagicMock(return_value=httpx.Response(200, text="<html>same</html>"))

        def fake_timed(engine, url):
            from urllib.parse import unquote
            u = unquote(url)
            if "SLEEP(5)" in u or "0:0:5" in u or "pg_sleep(5)" in u:
                return 5.2
            if "SLEEP(2)" in u or "0:0:2" in u or "pg_sleep(2)" in u:
                return 2.1
            return 0.1

        monkeypatch.setattr(sqli_detect, "_timed_get", fake_timed)
        findings = sqli_detect.run(eng)
        crit = [f for f in findings if f.severity == Severity.CRITICAL]
        assert crit and crit[0].raw["technique"] == "time-based blind"


# ---------------------------------------------------------------------------
# xss_detect tests (context-aware)
# ---------------------------------------------------------------------------

class TestXssDetect:
    def _eng(self, base_url, transport):
        from scanner.crawler import CrawlResult
        eng = ScanEngine(base_url, rate_delay=0)
        eng.get_crawl = MagicMock(return_value=CrawlResult(parametrised_urls=[f"{base_url}/s?q=hi"]))
        eng._client = httpx.Client(transport=transport, follow_redirects=True, verify=False)
        return eng

    def test_html_context_breakout_is_high(self, base_url):
        from scanner.vulns.xss_detect import run

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                val = parse_qs(urlparse(str(req.url)).query).get("q", [""])[0]
                return httpx.Response(200, text=f"<html><body>Results for: {val}</body></html>")

        findings = run(self._eng(base_url, _T()))
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert high and high[0].raw["context"] == "html_text"

    def test_encoded_reflection_is_low(self, base_url):
        from scanner.vulns.xss_detect import run
        import html as htmllib

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                val = parse_qs(urlparse(str(req.url)).query).get("q", [""])[0]
                return httpx.Response(200, text=f"<html>Results: {htmllib.escape(val)}</html>")

        findings = run(self._eng(base_url, _T()))
        assert findings and all(f.severity != Severity.HIGH for f in findings)
        assert any(f.severity == Severity.LOW for f in findings)

    def test_no_reflection_is_info(self, base_url):
        from scanner.vulns.xss_detect import run

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                return httpx.Response(200, text="<html>static page, no echo</html>")

        findings = run(self._eng(base_url, _T()))
        assert len(findings) == 1 and findings[0].severity == Severity.INFO


# ---------------------------------------------------------------------------
# Injection arsenal tests (command_injection, ssti, lfi, open_redirect, ssrf)
# ---------------------------------------------------------------------------

def _inj_engine(base_url, transport, param_url):
    from scanner.crawler import CrawlResult
    eng = ScanEngine(base_url, rate_delay=0)
    eng.get_crawl = MagicMock(return_value=CrawlResult(parametrised_urls=[param_url]))
    eng._client = httpx.Client(transport=transport, follow_redirects=False, verify=False)
    return eng


class TestCommandInjection:
    def test_output_based_is_critical(self, base_url):
        from scanner.vulns.command_injection import run

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                q = parse_qs(urlparse(str(req.url)).query).get("q", [""])[0]
                if "id" in q or "whoami" in q:
                    return httpx.Response(200, text="uid=0(root) gid=0(root) groups=0(root)")
                return httpx.Response(200, text="<html>normal</html>")

        eng = _inj_engine(base_url, _T(), f"{base_url}/c?q=1")
        crit = [f for f in run(eng) if f.severity == Severity.CRITICAL]
        assert crit and crit[0].raw["technique"] == "output-based"
        assert crit[0].raw["commix"].startswith("commix -u")

    def test_time_based_is_critical(self, base_url, monkeypatch):
        from scanner.vulns import command_injection
        from scanner.crawler import CrawlResult

        eng = ScanEngine(base_url, rate_delay=0)
        eng.get_crawl = MagicMock(return_value=CrawlResult(parametrised_urls=[f"{base_url}/c?q=1"]))
        eng.request = MagicMock(return_value=httpx.Response(200, text="benign"))  # output stage fails

        def fake_timed(engine, url, **k):
            from urllib.parse import unquote_plus
            u = unquote_plus(url)
            if "sleep 5" in u or "timeout /t 5" in u or "ping -n 5" in u:
                return 5.2
            if "sleep 2" in u or "timeout /t 2" in u or "ping -n 2" in u:
                return 2.1
            return 0.1

        monkeypatch.setattr(command_injection, "timed_get", fake_timed)
        crit = [f for f in command_injection.run(eng) if f.severity == Severity.CRITICAL]
        assert crit and crit[0].raw["technique"] == "time-based"

    def test_safe_mode_skips(self):
        from scanner.vulns.command_injection import run
        from config import SAFE_MODE_RATE_DELAY
        eng = ScanEngine("https://example.com", rate_delay=SAFE_MODE_RATE_DELAY)
        findings = run(eng)
        assert len(findings) == 1 and "safe mode" in findings[0].title.lower()


class TestSSTI:
    def test_evaluated_expression_is_critical(self, base_url):
        from scanner.vulns.ssti_detect import run, _PRODUCT, _EXPR

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                q = parse_qs(urlparse(str(req.url)).query).get("q", [""])[0]
                if _EXPR in q:                       # server evaluates → returns product only
                    return httpx.Response(200, text=f"<html>result: {_PRODUCT}</html>")
                return httpx.Response(200, text="<html>x</html>")

        eng = _inj_engine(base_url, _T(), f"{base_url}/t?q=1")
        assert any(f.severity == Severity.CRITICAL for f in run(eng))

    def test_echoed_expression_not_flagged(self, base_url):
        from scanner.vulns.ssti_detect import run

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                q = parse_qs(urlparse(str(req.url)).query).get("q", [""])[0]
                return httpx.Response(200, text=f"<html>you said: {q}</html>")  # literal echo

        eng = _inj_engine(base_url, _T(), f"{base_url}/t?q=1")
        assert not [f for f in run(eng) if f.severity == Severity.CRITICAL]


class TestLFI:
    def test_passwd_read_is_high(self, base_url):
        from scanner.vulns.lfi_detect import run

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                q = parse_qs(urlparse(str(req.url)).query).get("file", [""])[0]
                if "etc/passwd" in q:
                    return httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:")
                return httpx.Response(200, text="<html>page</html>")

        eng = _inj_engine(base_url, _T(), f"{base_url}/p?file=home")
        high = [f for f in run(eng) if f.severity == Severity.HIGH]
        assert high and high[0].raw["signal"].startswith("root:")

    def test_no_lfi_is_info(self, base_url):
        from scanner.vulns.lfi_detect import run

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                return httpx.Response(200, text="<html>nothing here</html>")

        eng = _inj_engine(base_url, _T(), f"{base_url}/p?file=home")
        assert all(f.severity == Severity.INFO for f in run(eng))


class TestOpenRedirect:
    def test_open_redirect_is_medium(self, base_url):
        from scanner.vulns.open_redirect import run

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                val = parse_qs(urlparse(str(req.url)).query).get("u", [""])[0]
                if val.startswith("https://hades-"):
                    return httpx.Response(302, headers={"location": val})
                return httpx.Response(200, text="ok")

        eng = _inj_engine(base_url, _T(), f"{base_url}/r?u=1")
        med = [f for f in run(eng) if f.severity == Severity.MEDIUM]
        assert med and med[0].raw["mechanism"] == "Location header"

    def test_same_host_redirect_not_flagged(self, base_url):
        from scanner.vulns.open_redirect import run

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                return httpx.Response(302, headers={"location": "/dashboard"})  # internal only

        eng = _inj_engine(base_url, _T(), f"{base_url}/r?u=1")
        assert not [f for f in run(eng) if f.severity in (Severity.MEDIUM, Severity.HIGH)]


class TestSSRF:
    def test_metadata_read_is_medium(self, base_url):
        from scanner.vulns.ssrf_detect import run

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                val = parse_qs(urlparse(str(req.url)).query).get("url", [""])[0]
                if "169.254.169.254" in val:
                    return httpx.Response(200, text="ami-id: ami-123\ninstance-id: i-456\nlocal-ipv4: 10.0.0.5")
                return httpx.Response(200, text="<html>ok</html>")

        eng = _inj_engine(base_url, _T(), f"{base_url}/fetch?url=http://a")
        med = [f for f in run(eng) if f.severity == Severity.MEDIUM]
        assert med and "metadata" in med[0].raw["signal"].lower()

    def test_no_ssrf_is_info(self, base_url):
        from scanner.vulns.ssrf_detect import run

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                return httpx.Response(200, text="<html>ok</html>")

        eng = _inj_engine(base_url, _T(), f"{base_url}/fetch?url=http://a")
        assert all(f.severity == Severity.INFO for f in run(eng))


# ---------------------------------------------------------------------------
# robots_txt tests
# ---------------------------------------------------------------------------

class TestRobotsTxt:
    def test_login_logout_not_mislabeled_as_log(self, engine_factory, base_url):
        """The /log → /login substring bug must be fixed: login/logout are login pages."""
        from scanner.web.robots_txt import run

        robots = "User-agent: *\nDisallow: /user/login/\nDisallow: /user/logout/\n"
        eng = engine_factory({f"{base_url}/robots.txt": httpx.Response(200, text=robots)})
        findings = run(eng)
        login = [f for f in findings if f.raw.get("path") == "/user/login/"]
        assert login and login[0].raw["label"] == "Login/logout page"
        # And it must NOT be labelled a log directory anywhere.
        assert not any(f.raw.get("label") == "Log directory" for f in findings)

    def test_accessible_admin_is_escalated(self, engine_factory, base_url):
        """A disallowed /admin that is actually reachable (200) is escalated to Medium."""
        from scanner.web.robots_txt import run

        eng = engine_factory({
            f"{base_url}/robots.txt": httpx.Response(200, text="User-agent: *\nDisallow: /admin\n"),
            f"{base_url}/admin": httpx.Response(200, text="admin login"),
        })
        findings = run(eng)
        admin = [f for f in findings if f.raw.get("path") == "/admin"]
        assert admin and admin[0].severity == Severity.MEDIUM  # LOW base → escalated
        assert "accessible" in admin[0].description.lower()

    def test_stale_entry_is_downgraded(self, engine_factory, base_url):
        """A disallowed path returning 404 is a stale entry (Low)."""
        from scanner.web.robots_txt import run

        eng = engine_factory({
            f"{base_url}/robots.txt": httpx.Response(200, text="User-agent: *\nDisallow: /admin\n"),
        })  # /admin → 404 default
        findings = run(eng)
        admin = [f for f in findings if f.raw.get("path") == "/admin"]
        assert admin and admin[0].severity == Severity.LOW
        assert "stale" in admin[0].description.lower()

    def test_wildcard_extension_leak(self, engine_factory, base_url):
        from scanner.web.robots_txt import run

        eng = engine_factory({
            f"{base_url}/robots.txt": httpx.Response(200, text="User-agent: *\nDisallow: /*.sql$\n"),
        })
        findings = run(eng)
        assert any(f.severity == Severity.MEDIUM and "sql" in f.title.lower() for f in findings)

    def test_sitemaps_surfaced(self, engine_factory, base_url):
        from scanner.web.robots_txt import run

        robots = "User-agent: *\nDisallow: /x\nSitemap: https://example.com/sitemap.xml\n"
        eng = engine_factory({f"{base_url}/robots.txt": httpx.Response(200, text=robots)})
        findings = run(eng)
        assert any("sitemap" in f.title.lower() for f in findings)

    def test_missing_robots_is_info(self, engine_factory, base_url):
        from scanner.web.robots_txt import run

        eng = engine_factory({f"{base_url}/robots.txt": httpx.Response(404, text="")})
        findings = run(eng)
        assert findings and all(f.severity == Severity.INFO for f in findings)

    def test_non_sensitive_disallow_no_medium(self, engine_factory, base_url):
        from scanner.web.robots_txt import run

        eng = engine_factory({
            f"{base_url}/robots.txt": httpx.Response(200, text="User-agent: *\nDisallow: /search\nDisallow: /print\n"),
        })
        findings = run(eng)
        assert not [f for f in findings if f.severity in (Severity.MEDIUM, Severity.HIGH)]


# ---------------------------------------------------------------------------
# sensitive_files tests (soft-404 / catch-all false-positive suppression)
# ---------------------------------------------------------------------------

class TestSensitiveFiles:
    def test_catchall_spa_produces_no_false_positives(self, base_url):
        """A server that 200s every path with the same HTML must yield no Critical."""
        from scanner.web.sensitive_files import run

        spa = "<html><body><div id=app>SPA</div></body></html>"

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                return httpx.Response(200, text=spa,
                                      headers={"content-type": "text/html; charset=utf-8"})

        eng = ScanEngine(base_url, rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=True, verify=False)

        findings = run(eng)
        assert not [f for f in findings if f.severity == Severity.CRITICAL], (
            "Catch-all SPA server must not produce Critical sensitive-file findings"
        )

    def test_genuine_exposed_file_still_detected(self, base_url):
        """A real .env (text/plain, key=value) on a 404-ing server stays Critical."""
        from scanner.web.sensitive_files import run

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                if request.url.path == "/.env":
                    return httpx.Response(
                        200, text="APP_KEY=base64:xx\nDB_PASSWORD=s3cret\n",
                        headers={"content-type": "text/plain"},
                    )
                return httpx.Response(404, text="Not Found")

        eng = ScanEngine(base_url, rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=True, verify=False)

        findings = run(eng)
        env = [f for f in findings if f.raw.get("path") == "/.env"]
        assert env and env[0].severity == Severity.CRITICAL

    def test_blanket_403_collapses_to_single_info(self, base_url):
        """A server that 403s every path must yield one INFO finding, no Medium spam."""
        from scanner.web.sensitive_files import run

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                return httpx.Response(403, text="Forbidden")

        eng = ScanEngine(base_url, rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=True, verify=False)

        findings = run(eng)
        assert not [f for f in findings if f.severity == Severity.MEDIUM]
        info = [f for f in findings if f.severity == Severity.INFO]
        assert len(info) == 1 and "deny rule" in info[0].title.lower()

    def test_individual_403_reported_when_not_blanket(self, base_url):
        """A couple of specific 403s on a 404-ing server are reported individually."""
        from scanner.web.sensitive_files import run

        protected = {"/.htpasswd", "/.htaccess"}

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                if request.url.path in protected:
                    return httpx.Response(403, text="Forbidden")
                return httpx.Response(404, text="Not Found")

        eng = ScanEngine(base_url, rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=True, verify=False)

        findings = run(eng)
        medium_paths = {f.raw.get("path") for f in findings if f.severity == Severity.MEDIUM}
        assert medium_paths == protected

    def test_exposed_git_escalates_to_critical(self, base_url):
        """A readable /.git/ produces a dedicated 'source code downloadable' Critical."""
        from scanner.web.sensitive_files import run

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                p = request.url.path
                if p == "/.git/HEAD":
                    return httpx.Response(200, text="ref: refs/heads/main\n",
                                          headers={"content-type": "text/plain"})
                if p == "/.git/config":
                    return httpx.Response(200, text="[core]\n\trepositoryformatversion = 0\n",
                                          headers={"content-type": "text/plain"})
                return httpx.Response(404, text="Not Found")

        eng = ScanEngine(base_url, rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=True, verify=False)

        findings = run(eng)
        assert any("exposed .git" in f.title.lower() and f.severity == Severity.CRITICAL
                   for f in findings)


# ---------------------------------------------------------------------------
# admin_panel tests (catch-all / SPA false-positive suppression)
# ---------------------------------------------------------------------------

class TestAdminPanel:
    def test_catchall_spa_yields_no_panels(self, base_url):
        """A server that 200s every path with the same shell must find no admin panels."""
        from scanner.web.admin_panel import run

        shell = "<!doctype html><html><body><div id=__next>Not found</div></body></html>"

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                return httpx.Response(200, text=shell,
                                      headers={"content-type": "text/html"})

        eng = ScanEngine(base_url, rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)

        assert run(eng) == []

    def test_genuine_panels_still_detected(self, base_url):
        """Distinct /admin and /login pages on a 404-ing server stay flagged."""
        from scanner.web.admin_panel import run

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                p = request.url.path
                if p == "/":
                    return httpx.Response(200, text="<html>home</html>")
                if p in ("/admin", "/login"):
                    return httpx.Response(
                        200, text="<html><form><input type=password></form></html>")
                return httpx.Response(404, text="nope")

        eng = ScanEngine(base_url, rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)

        paths = {f.raw["path"] for f in run(eng)}
        assert "/admin" in paths and "/login" in paths

    def test_generic_200_without_login_is_ignored(self, base_url):
        """A 200 page with no login form is not an admin panel — skip it (dir_scan's job)."""
        from scanner.web.admin_panel import run

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                if request.url.path == "/manage":
                    return httpx.Response(200, text="<html><body>Welcome to our blog</body></html>")
                return httpx.Response(404, text="nope")

        eng = ScanEngine(base_url, rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)
        assert run(eng) == []

    def test_http_basic_auth_is_medium(self, base_url):
        """A 401 with WWW-Authenticate on an admin path is a Medium finding."""
        from scanner.web.admin_panel import run

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                if request.url.path == "/admin":
                    return httpx.Response(401, headers={"www-authenticate": 'Basic realm="Admin"'})
                return httpx.Response(404, text="nope")

        eng = ScanEngine(base_url, rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)

        findings = run(eng)
        assert any(f.severity == Severity.MEDIUM and f.raw["path"] == "/admin"
                   and f.raw["status_code"] == 401 for f in findings)

    def test_redirect_to_login_is_medium(self, base_url):
        """A 302 to a login page flags the admin path as existing (Medium)."""
        from scanner.web.admin_panel import run

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                if request.url.path == "/dashboard":
                    return httpx.Response(302, headers={"location": "https://example.com/login"})
                return httpx.Response(404, text="nope")

        eng = ScanEngine(base_url, rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)

        findings = run(eng)
        assert any(f.severity == Severity.MEDIUM and f.raw["path"] == "/dashboard"
                   for f in findings)


# ---------------------------------------------------------------------------
# sitemap tests
# ---------------------------------------------------------------------------

class TestSitemap:
    def test_sitemap_found_and_sensitive_path(self, engine_factory, base_url):
        from scanner.web.sitemap import run

        xml = ('<?xml version="1.0"?><urlset>'
               '<url><loc>https://example.com/</loc></url>'
               '<url><loc>https://example.com/admin/login</loc></url>'
               '</urlset>')
        eng = engine_factory({
            f"{base_url}/sitemap.xml": httpx.Response(
                200, text=xml, headers={"content-type": "application/xml"}),
        })
        findings = run(eng)
        assert any(f.title.startswith("Sitemap Found") for f in findings)
        assert any("/admin" in f.title and f.severity == Severity.LOW for f in findings)

    def test_sitemap_absent_is_info(self, engine_factory, base_url):
        from scanner.web.sitemap import run

        eng = engine_factory({base_url: httpx.Response(404, text="")})
        findings = run(eng)
        assert len(findings) == 1 and findings[0].title == "Sitemap Not Found"


# ---------------------------------------------------------------------------
# redirect_chain tests
# ---------------------------------------------------------------------------

class TestRedirectChain:
    def _eng(self, start, transport):
        eng = ScanEngine(start, rate_delay=0)
        eng._client = httpx.Client(transport=transport, follow_redirects=False, verify=False)
        return eng

    def test_https_to_http_downgrade_is_medium(self):
        from scanner.web.redirect_chain import run

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                if req.url.scheme == "https" and req.url.path in ("", "/"):
                    return httpx.Response(302, headers={"location": "http://example.com/x"})
                return httpx.Response(200, text="ok")

        findings = run(self._eng("https://example.com", _T()))
        assert any(f.severity == Severity.MEDIUM and "downgrade" in f.title.lower() for f in findings)

    def test_offdomain_redirect_is_low(self):
        from scanner.web.redirect_chain import run

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                if req.url.host == "example.com":
                    return httpx.Response(301, headers={"location": "https://other-site.org/"})
                return httpx.Response(200, text="ok")

        findings = run(self._eng("https://example.com", _T()))
        assert any(f.severity == Severity.LOW and "domain" in f.title.lower() for f in findings)

    def test_no_redirect_is_info(self):
        from scanner.web.redirect_chain import run

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                return httpx.Response(200, text="ok")

        findings = run(self._eng("https://example.com", _T()))
        assert len(findings) == 1 and findings[0].severity == Severity.INFO


# ---------------------------------------------------------------------------
# favicon_hash tests
# ---------------------------------------------------------------------------

class TestFaviconHash:
    def test_favicon_hash_computed(self, engine_factory, base_url):
        from scanner.web.favicon_hash import run

        eng = engine_factory({
            base_url: httpx.Response(200, text="<html></html>"),
            f"{base_url}/favicon.ico": httpx.Response(
                200, content=b"\x00\x00\x01\x00icondata", headers={"content-type": "image/x-icon"}),
        })
        findings = run(eng)
        assert findings[0].title.startswith("Favicon Hash:")
        assert isinstance(findings[0].raw["favicon_hash"], int)

    def test_html_soft404_is_not_a_favicon(self, engine_factory, base_url):
        from scanner.web.favicon_hash import run

        # Homepage only; /favicon.ico falls through to the HTML page (soft-404).
        eng = engine_factory({base_url: httpx.Response(200, text="<html><body>x</body></html>")})
        findings = run(eng)
        assert findings[0].title == "Favicon Not Found"


# ---------------------------------------------------------------------------
# dir_scan tests
# ---------------------------------------------------------------------------

class TestDirScan:
    def _engine(self, base_url, transport, monkeypatch, paths):
        from scanner.web import dir_scan
        monkeypatch.setattr(dir_scan, "_load_wordlist", lambda eng: list(paths))
        eng = ScanEngine(base_url, rate_delay=0)
        eng._client = httpx.Client(transport=transport, follow_redirects=False, verify=False)
        return eng

    def test_excluded_paths_filtered(self, base_url, tmp_path):
        """Paths owned by other modules (.env, robots.txt, .git) are filtered out."""
        from scanner.web.dir_scan import _load_wordlist

        wl = tmp_path / "wl.txt"
        wl.write_text("admin\n.env\nrobots.txt\nbackup\n.git\nsitemap.xml\n", encoding="utf-8")
        eng = ScanEngine(base_url, rate_delay=0)
        eng.wordlist = str(wl)

        paths = _load_wordlist(eng)
        assert "/admin" in paths and "/backup" in paths
        for excluded in ("/.env", "/robots.txt", "/.git", "/sitemap.xml"):
            assert excluded not in paths

    def test_open_directory_listing_is_high(self, base_url, monkeypatch):
        from scanner.web.dir_scan import run

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                if request.url.path == "/uploads":
                    return httpx.Response(200, text="<html><title>Index of /uploads</title>"
                                                    "<a href='..'>Parent Directory</a></html>")
                return httpx.Response(404, text="nf")

        eng = self._engine(base_url, _T(), monkeypatch, ["/uploads", "/admin"])
        findings = run(eng)
        assert any(f.severity == Severity.HIGH and "listing" in f.title.lower() for f in findings)

    def test_listing_detected_even_on_wildcard_server(self, base_url, monkeypatch):
        """On a catch-all 200 server, a genuine listing is still HIGH; the rest suppressed."""
        from scanner.web.dir_scan import run

        spa = "<html><body>not found</body></html>"

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                if request.url.path == "/uploads":
                    return httpx.Response(200, text="<title>Index of /uploads</title>")
                return httpx.Response(200, text=spa)  # wildcard

        eng = self._engine(base_url, _T(), monkeypatch, ["/uploads", "/admin"])
        findings = run(eng)
        assert any(f.severity == Severity.HIGH and f.raw["path"] == "/uploads" for f in findings)
        assert not any(f.raw.get("path") == "/admin" for f in findings)

    def test_blanket_403_collapses(self, base_url, monkeypatch):
        from scanner.web.dir_scan import run

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                return httpx.Response(403, text="Forbidden")

        eng = self._engine(base_url, _T(), monkeypatch, ["/admin", "/backup", "/api"])
        findings = run(eng)
        assert not [f for f in findings if f.severity == Severity.LOW]
        info = [f for f in findings if f.severity == Severity.INFO]
        assert len(info) == 1 and "deny rule" in info[0].title.lower()

    def test_401_is_low_and_present(self, base_url, monkeypatch):
        from scanner.web.dir_scan import run

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                if request.url.path == "/manager":
                    return httpx.Response(401, text="Auth required")
                return httpx.Response(404, text="nf")

        eng = self._engine(base_url, _T(), monkeypatch, ["/manager"])
        findings = run(eng)
        assert any(f.severity == Severity.LOW and f.raw["path"] == "/manager"
                   and f.raw["status_code"] == 401 for f in findings)

    def test_blanket_5xx_collapses(self, base_url, monkeypatch):
        """A server that 500s every path (incl. random baseline) collapses to one INFO."""
        from scanner.web.dir_scan import run

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                return httpx.Response(500, text="Internal Server Error")

        eng = self._engine(base_url, _T(), monkeypatch, ["/admin", "/api", "/config"])
        findings = run(eng)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "every unknown path" in findings[0].title.lower()
        assert "error_paths" in findings[0].raw


# ---------------------------------------------------------------------------
# http_methods tests
# ---------------------------------------------------------------------------

class TestHttpMethods:
    def _eng(self, transport, profile="full"):
        eng = ScanEngine("https://example.com", profile=profile, rate_delay=0)
        eng._client = httpx.Client(transport=transport, follow_redirects=False, verify=False)
        return eng

    def test_confirmed_put_upload_is_critical(self):
        from scanner.web.http_methods import run

        class _T(httpx.BaseTransport):
            def __init__(self):
                self.store: dict[str, bytes] = {}

            def handle_request(self, req):
                if req.method == "OPTIONS":
                    return httpx.Response(200, headers={"allow": "GET,POST,PUT,DELETE,OPTIONS"})
                if req.method == "PUT":
                    self.store[req.url.path] = req.content
                    return httpx.Response(201)
                if req.method == "GET":
                    if req.url.path in self.store:
                        return httpx.Response(200, content=self.store[req.url.path])
                    return httpx.Response(404)
                if req.method == "DELETE":
                    self.store.pop(req.url.path, None)
                    return httpx.Response(204)
                return httpx.Response(200)

        findings = run(self._eng(_T()))
        crit = [f for f in findings if f.severity == Severity.CRITICAL]
        assert crit and crit[0].raw["method"] == "PUT" and crit[0].raw["verified"] is True

    def test_advertised_put_not_exploitable_is_low(self):
        from scanner.web.http_methods import run

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                if req.method == "OPTIONS":
                    return httpx.Response(200, headers={"allow": "GET,PUT,DELETE,OPTIONS"})
                if req.method == "PUT":
                    return httpx.Response(403)        # advertised but blocked
                return httpx.Response(200, text="home")

        findings = run(self._eng(_T()))
        put = [f for f in findings if f.raw.get("method") == "PUT"]
        assert put and put[0].severity == Severity.LOW       # NOT high/critical
        # DELETE is advertised-only → Medium, never tested
        delete = [f for f in findings if f.raw.get("method") == "DELETE"]
        assert delete and delete[0].severity == Severity.MEDIUM

    def test_trace_xst_confirmed_is_medium(self):
        from scanner.web.http_methods import run

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                if req.method == "OPTIONS":
                    return httpx.Response(200, headers={"allow": "GET,OPTIONS,TRACE"})
                if req.method == "TRACE":
                    echo = req.headers.get("x-hades-trace", "")
                    return httpx.Response(200, text=f"TRACE / HTTP/1.1\nX-Hades-Trace: {echo}")
                return httpx.Response(200)

        findings = run(self._eng(_T()))
        trace = [f for f in findings if f.raw.get("method") == "TRACE"]
        assert trace and trace[0].severity == Severity.MEDIUM and trace[0].raw["verified"] is True

    def test_passive_profile_skips_put_upload(self):
        from scanner.web.http_methods import run

        calls = {"put": 0}

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                if req.method == "OPTIONS":
                    return httpx.Response(200, headers={"allow": "GET,PUT,OPTIONS"})
                if req.method == "PUT":
                    calls["put"] += 1
                    return httpx.Response(201)
                return httpx.Response(200)

        findings = run(self._eng(_T(), profile="passive"))
        assert calls["put"] == 0                              # no active write in passive mode
        put = [f for f in findings if f.raw.get("method") == "PUT"]
        assert put and put[0].severity == Severity.LOW and put[0].raw["confidence"] == "low"

    def test_no_dangerous_methods_is_info(self):
        from scanner.web.http_methods import run

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                if req.method == "OPTIONS":
                    return httpx.Response(200, headers={"allow": "GET,POST,HEAD,OPTIONS"})
                if req.method == "PUT":
                    return httpx.Response(405)
                if req.method == "TRACE":
                    return httpx.Response(405)
                return httpx.Response(200)

        findings = run(self._eng(_T()))
        assert not [f for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL, Severity.MEDIUM)]


# ---------------------------------------------------------------------------
# broken_links tests
# ---------------------------------------------------------------------------

class TestBrokenLinks:
    def _eng(self, base_url, internal, transport):
        from scanner.crawler import CrawlResult
        from unittest.mock import MagicMock
        eng = ScanEngine(base_url, rate_delay=0)
        eng.get_crawl = MagicMock(return_value=CrawlResult(internal_links=set(internal)))
        eng._client = httpx.Client(transport=transport, follow_redirects=True, verify=False)
        return eng

    def test_404_is_broken_low(self, base_url):
        from scanner.web.broken_links import run

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                return httpx.Response(404 if req.url.path == "/gone" else 200)

        eng = self._eng(base_url, [f"{base_url}/gone", f"{base_url}/ok"], _T())
        findings = run(eng)
        broken = [f for f in findings if f.raw.get("kind") == "broken"]
        assert broken and broken[0].severity == Severity.LOW and broken[0].raw["status_code"] == 404

    def test_many_403_collapse_to_waf_advisory(self, base_url):
        from scanner.web.broken_links import run

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                return httpx.Response(403)  # WAF blocks everything

        links = [f"{base_url}/p{i}" for i in range(6)]
        findings = self._run(base_url, links, _T())
        assert len(findings) == 1
        assert "waf" in findings[0].title.lower() or "blocked" in findings[0].title.lower()
        assert findings[0].severity == Severity.INFO
        assert not [f for f in findings if f.raw.get("kind") == "broken"]

    def test_few_403_reported_individually(self, base_url):
        from scanner.web.broken_links import run

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                return httpx.Response(403 if req.url.path == "/secret" else 200)

        findings = self._run(base_url, [f"{base_url}/secret", f"{base_url}/ok"], _T())
        restricted = [f for f in findings if f.raw.get("kind") == "restricted"]
        assert restricted and "restricted" in restricted[0].title.lower()

    def test_5xx_is_server_error_info(self, base_url):
        from scanner.web.broken_links import run

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                return httpx.Response(503 if req.url.path == "/down" else 200)

        findings = self._run(base_url, [f"{base_url}/down"], _T())
        srv = [f for f in findings if f.raw.get("kind") == "server_error"]
        assert srv and srv[0].severity == Severity.INFO

    def _run(self, base_url, links, transport):
        from scanner.web.broken_links import run
        return run(self._eng(base_url, links, transport))


# ---------------------------------------------------------------------------
# port_scan tests
# ---------------------------------------------------------------------------

class TestPortScan:
    def test_open_db_port_is_high(self, base_url, monkeypatch):
        from scanner.recon import port_scan
        monkeypatch.setattr(port_scan, "_resolve", lambda host: "203.0.113.5")
        monkeypatch.setattr(port_scan, "_is_accept_all", lambda ip, timeout=1.5: False)
        # MySQL (3306) open with a banner, HTTPS (443) open, everything else closed
        monkeypatch.setattr(port_scan, "_probe_port",
                            lambda ip, port, timeout=1.5:
                            (True, "5.7.40-MySQL") if port == 3306 else
                            (True, "") if port == 443 else (False, ""))

        findings = port_scan.run(ScanEngine(base_url, rate_delay=0))
        mysql = [f for f in findings if f.raw.get("port") == 3306]
        https = [f for f in findings if f.raw.get("port") == 443]
        assert mysql and mysql[0].severity == Severity.HIGH
        assert mysql[0].raw["banner"] == "5.7.40-MySQL"
        assert https and https[0].severity == Severity.INFO

    def test_accept_all_host_collapses(self, base_url, monkeypatch):
        from scanner.recon import port_scan
        monkeypatch.setattr(port_scan, "_resolve", lambda host: "45.223.20.44")
        monkeypatch.setattr(port_scan, "_is_accept_all", lambda ip, timeout=1.5: True)
        # Even if probes would say "open", accept-all must short-circuit.
        monkeypatch.setattr(port_scan, "_probe_port", lambda ip, port, timeout=1.5: (True, ""))

        findings = port_scan.run(ScanEngine(base_url, rate_delay=0))
        assert len(findings) == 1
        assert findings[0].raw.get("accept_all") is True
        assert findings[0].severity == Severity.INFO

    def test_no_open_ports_is_info(self, base_url, monkeypatch):
        from scanner.recon import port_scan
        monkeypatch.setattr(port_scan, "_resolve", lambda host: "203.0.113.5")
        monkeypatch.setattr(port_scan, "_is_accept_all", lambda ip, timeout=1.5: False)
        monkeypatch.setattr(port_scan, "_probe_port", lambda ip, port, timeout=1.5: (False, ""))

        findings = port_scan.run(ScanEngine(base_url, rate_delay=0))
        assert len(findings) == 1 and findings[0].severity == Severity.INFO

    def test_resolution_failure_is_info(self, base_url, monkeypatch):
        from scanner.recon import port_scan
        monkeypatch.setattr(port_scan, "_resolve", lambda host: None)
        findings = port_scan.run(ScanEngine(base_url, rate_delay=0))
        assert len(findings) == 1 and "resolution failed" in findings[0].title.lower()


# ---------------------------------------------------------------------------
# subdomain_scan tests
# ---------------------------------------------------------------------------

class TestSubdomainScan:
    def _patch(self, monkeypatch, labels, resolve, crtsh=None, fetch=None):
        from scanner.web import subdomain_scan
        monkeypatch.setattr(subdomain_scan, "_load_labels", lambda: labels)
        monkeypatch.setattr(subdomain_scan, "_resolve", resolve)
        monkeypatch.setattr(subdomain_scan, "_crtsh", crtsh or (lambda d: set()))
        monkeypatch.setattr(subdomain_scan, "_fetch_body", fetch or (lambda eng, host: None))
        return subdomain_scan

    def test_sensitive_subdomain_flagged(self, monkeypatch):
        def fake_resolve(host):
            return {"203.0.113.10"} if host.startswith(("www.", "staging.", "blog.")) else None
        mod = self._patch(monkeypatch, ["www", "staging", "blog"], fake_resolve)
        findings = mod.run(ScanEngine("https://example.com", rate_delay=0))
        assert any(f.title.startswith("Subdomains Discovered") for f in findings)
        assert any(f.severity == Severity.LOW and "staging" in f.raw.get("subdomain", "")
                   for f in findings)

    def test_wildcard_dns_suppresses_false_positives(self, monkeypatch):
        mod = self._patch(monkeypatch, ["a", "b", "c"], lambda host: {"203.0.113.99"})
        findings = mod.run(ScanEngine("https://example.com", rate_delay=0))
        assert len(findings) == 1 and "none found" in findings[0].title.lower()

    def test_crtsh_passive_discovery(self, monkeypatch):
        def fake_resolve(host):
            return {"203.0.113.5"} if host in ("www.example.com", "api.example.com") else None
        mod = self._patch(monkeypatch, ["www"], fake_resolve,
                          crtsh=lambda d: {"api.example.com"})
        findings = mod.run(ScanEngine("https://example.com", rate_delay=0))
        disc = [f for f in findings if f.title.startswith("Subdomains Discovered")]
        assert disc and "api.example.com" in disc[0].raw["subdomains"]

    def test_subdomain_takeover_detected(self, monkeypatch):
        def fake_resolve(host):
            return {"203.0.113.7"} if host == "shop.example.com" else None
        mod = self._patch(monkeypatch, ["shop"], fake_resolve,
                          fetch=lambda eng, host: "<html>NoSuchBucket</html>")
        findings = mod.run(ScanEngine("https://example.com", rate_delay=0))
        takeover = [f for f in findings if "takeover" in f.title.lower()]
        assert takeover and takeover[0].severity == Severity.HIGH
        assert takeover[0].raw["service"] == "AWS S3"


# ---------------------------------------------------------------------------
# dir_listing tests
# ---------------------------------------------------------------------------

class TestDirListing:
    def test_open_listing_is_high(self, base_url, monkeypatch):
        from scanner.web import dir_listing
        monkeypatch.setattr(dir_listing, "_candidates", lambda eng: ["/uploads/"])

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                if request.url.path == "/uploads/":
                    return httpx.Response(200, text="<html><title>Index of /uploads</title>"
                                                    "<a href='secret.zip'>secret.zip</a></html>")
                return httpx.Response(404, text="nf")

        eng = ScanEngine(base_url, rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)
        findings = dir_listing.run(eng)
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert high and "secret.zip" in high[0].raw.get("entries", [])

    def test_no_listing_is_info(self, base_url, monkeypatch):
        from scanner.web import dir_listing
        monkeypatch.setattr(dir_listing, "_candidates", lambda eng: ["/uploads/"])

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                return httpx.Response(200, text="<html>normal page</html>")

        eng = ScanEngine(base_url, rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)
        findings = dir_listing.run(eng)
        assert len(findings) == 1 and findings[0].severity == Severity.INFO


# ---------------------------------------------------------------------------
# clickjacking tests
# ---------------------------------------------------------------------------

class TestClickjacking:
    def test_framable_login_page_is_high(self, engine_factory, base_url):
        from scanner.web.clickjacking import run
        eng = engine_factory({
            base_url: httpx.Response(200, text="<html><form><input type=password></form></html>"),
        })
        findings = run(eng)
        assert findings[0].severity == Severity.HIGH and "framable" in findings[0].title.lower()

    def test_xfo_deny_is_protected(self, engine_factory, base_url):
        from scanner.web.clickjacking import run
        eng = engine_factory({
            base_url: httpx.Response(200, text="<html></html>", headers={"x-frame-options": "DENY"}),
        })
        findings = run(eng)
        assert findings[0].severity == Severity.INFO and findings[0].raw["protected"] is True

    def test_csp_frame_ancestors_none_is_protected(self, engine_factory, base_url):
        from scanner.web.clickjacking import run
        eng = engine_factory({
            base_url: httpx.Response(200, text="<html></html>",
                                     headers={"content-security-policy": "frame-ancestors 'none'"}),
        })
        assert run(eng)[0].raw["protected"] is True


# ---------------------------------------------------------------------------
# backup_files tests
# ---------------------------------------------------------------------------

class TestBackupFiles:
    def test_zip_archive_is_critical(self, base_url, monkeypatch):
        from scanner.web import backup_files
        monkeypatch.setattr(backup_files, "_candidates", lambda eng: ["/backup.zip"])

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                if request.url.path == "/backup.zip":
                    return httpx.Response(200, content=b"PK\x03\x04rest-of-zip",
                                          headers={"content-type": "application/zip"})
                return httpx.Response(404, text="nf")

        eng = ScanEngine(base_url, rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=True, verify=False)
        findings = backup_files.run(eng)
        assert any(f.severity == Severity.CRITICAL and f.raw["path"] == "/backup.zip" for f in findings)

    def test_html_soft404_not_flagged(self, base_url, monkeypatch):
        from scanner.web import backup_files
        monkeypatch.setattr(backup_files, "_candidates", lambda eng: ["/backup.zip"])

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                return httpx.Response(200, text="<!doctype html><html>not found</html>",
                                      headers={"content-type": "text/html"})

        eng = ScanEngine(base_url, rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=True, verify=False)
        findings = backup_files.run(eng)
        assert not [f for f in findings if f.severity == Severity.CRITICAL]


# ---------------------------------------------------------------------------
# default_creds tests
# ---------------------------------------------------------------------------

class TestDefaultCreds:
    def test_phpmyadmin_detected_advisory(self, engine_factory, base_url):
        from scanner.web import dir_listing  # noqa: F401 - ensure package import path
        from scanner.vulns.default_creds import run

        eng = engine_factory({
            f"{base_url}/phpmyadmin/": httpx.Response(
                200, text="<html><title>phpMyAdmin</title></html>"),
        })
        findings = run(eng)
        assert any(f.severity == Severity.MEDIUM and "phpmyadmin" in f.title.lower() for f in findings)

    def test_nothing_detected_is_info(self, engine_factory, base_url):
        from scanner.vulns.default_creds import run
        eng = engine_factory({base_url: httpx.Response(200, text="<html>plain</html>")})
        findings = run(eng)
        assert len(findings) == 1 and findings[0].severity == Severity.INFO


# ---------------------------------------------------------------------------
# blacklist_check tests
# ---------------------------------------------------------------------------

class TestBlacklistCheck:
    def test_listed_ip_is_flagged(self, base_url, monkeypatch):
        from scanner.web import blacklist_check
        monkeypatch.setattr(blacklist_check, "_resolve", lambda h: "203.0.113.7")
        # Listed on two IP DNSBLs, clean elsewhere.
        monkeypatch.setattr(blacklist_check, "_is_listed",
                            lambda q: q.startswith("7.113.0.203.") and "spamhaus" in q or "spamcop" in q)

        findings = blacklist_check.run(ScanEngine(base_url, rate_delay=0))
        assert findings[0].severity in (Severity.MEDIUM, Severity.HIGH)
        assert "blocklist" in findings[0].title.lower()

    def test_clean_ip_is_info(self, base_url, monkeypatch):
        from scanner.web import blacklist_check
        monkeypatch.setattr(blacklist_check, "_resolve", lambda h: "203.0.113.7")
        monkeypatch.setattr(blacklist_check, "_is_listed", lambda q: False)

        findings = blacklist_check.run(ScanEngine(base_url, rate_delay=0))
        assert len(findings) == 1 and "clean" in findings[0].title.lower()


# ---------------------------------------------------------------------------
# screenshot tests
# ---------------------------------------------------------------------------

class TestScreenshot:
    def test_capture_success(self, base_url, monkeypatch):
        from scanner.web import screenshot
        monkeypatch.setattr(screenshot, "_ensure_browser", lambda: True)
        monkeypatch.setattr(screenshot, "_capture", lambda eng, path: None)

        findings = screenshot.run(ScanEngine(base_url, rate_delay=0))
        assert findings[0].severity == Severity.INFO and "captured" in findings[0].title.lower()

    def test_capture_failure_is_graceful(self, base_url, monkeypatch):
        from scanner.web import screenshot
        monkeypatch.setattr(screenshot, "_ensure_browser", lambda: True)

        def boom(eng, path):
            raise RuntimeError("page navigation timed out")

        monkeypatch.setattr(screenshot, "_capture", boom)
        findings = screenshot.run(ScanEngine(base_url, rate_delay=0))
        assert findings[0].severity == Severity.INFO and "not captured" in findings[0].title.lower()

    def test_browser_unavailable_is_graceful(self, base_url, monkeypatch):
        """If the browser can't be installed, the scan still continues with a clear note."""
        from scanner.web import screenshot
        monkeypatch.setattr(screenshot, "_ensure_browser", lambda: False)

        findings = screenshot.run(ScanEngine(base_url, rate_delay=0))
        assert findings[0].severity == Severity.INFO
        assert "playwright install" in findings[0].description.lower()
        assert "antivirus" in findings[0].description.lower()

    def test_autoinstall_runs_once_when_missing(self, monkeypatch, tmp_path):
        """_ensure_browser installs once when the binary is missing, then re-checks."""
        from scanner.web import screenshot

        screenshot._install_attempted = False
        missing = str(tmp_path / "nope.exe")
        present = str(tmp_path / "ok.exe")
        (tmp_path / "ok.exe").write_text("x")
        calls = {"install": 0, "path": 0}

        def fake_path():
            calls["path"] += 1
            # First call (pre-install) → missing; after install → present
            return missing if calls["install"] == 0 else present

        def fake_install(*a, **k):
            calls["install"] += 1

        monkeypatch.setattr(screenshot, "_browser_path", fake_path)
        monkeypatch.setattr(screenshot.subprocess, "run", fake_install)
        assert screenshot._ensure_browser() is True
        assert calls["install"] == 1


# ---------------------------------------------------------------------------
# exploit (sqlmap launcher) tests — sqlmap is always mocked, never really run
# ---------------------------------------------------------------------------

class TestExploit:
    def _sqli(self):
        return Finding("sqli_detect", "SQLi", "", Severity.CRITICAL, "",
                       {"url": "http://t/c?id=1", "parameter": "id",
                        "sqlmap_args": ["-u", "http://t/c?id=1", "-p", "id", "--batch", "--dbs"]})

    def test_no_sqli_is_noop(self, monkeypatch):
        from scanner import exploit
        ran = {"n": 0}
        monkeypatch.setattr(exploit.subprocess, "run", lambda *a, **k: ran.__setitem__("n", ran["n"] + 1))
        exploit.offer([_make_finding(Severity.HIGH, module="headers_check")], auto=True)
        assert ran["n"] == 0

    def test_sqlmap_missing_does_not_run(self, monkeypatch):
        from scanner import exploit
        # Force "not found" regardless of whether sqlmap is installed on this machine.
        monkeypatch.setattr(exploit, "_sqlmap_path", lambda: None)
        ran = {"n": 0}
        monkeypatch.setattr(exploit.subprocess, "run", lambda *a, **k: ran.__setitem__("n", 1))
        exploit.offer([self._sqli()], auto=True)
        assert ran["n"] == 0

    def test_auto_runs_sqlmap_with_resolved_path(self, monkeypatch):
        from scanner import exploit
        monkeypatch.setattr(exploit.shutil, "which",
                            lambda name: "C:/tools/sqlmap.exe" if name == "sqlmap" else None)
        captured = {}
        monkeypatch.setattr(exploit.subprocess, "run", lambda args, **k: captured.update(args=args))
        exploit.offer([self._sqli()], auto=True)
        assert captured["args"][0] == "C:/tools/sqlmap.exe"
        assert "--dbs" in captured["args"] and "id" in captured["args"]


# ---------------------------------------------------------------------------
# db_security tests (db_scan profile)
# ---------------------------------------------------------------------------

class _All404(httpx.BaseTransport):
    def handle_request(self, request):
        return httpx.Response(404, text="nope")


class TestDbSecurity:
    def _engine(self, transport=None, params=None):
        from scanner.crawler import CrawlResult
        eng = ScanEngine("http://db.test", rate_delay=0)
        eng.get_crawl = MagicMock(return_value=CrawlResult(parametrised_urls=params or []))
        eng._client = httpx.Client(transport=transport or _All404(), follow_redirects=True, verify=False)
        return eng

    def test_open_port_3306_mysql_detected(self, monkeypatch):
        from scanner.db import db_security
        monkeypatch.setattr(db_security, "_resolve", lambda h: "203.0.113.5")
        monkeypatch.setattr(db_security, "_is_accept_all", lambda ip, timeout=1.5: False)
        monkeypatch.setattr(db_security, "_probe_port",
                            lambda ip, port, timeout=1.5: (True, "5.7.40-0ubuntu0.18") if port == 3306 else (False, ""))
        monkeypatch.setattr(db_security, "_check_tls", lambda *a: [])

        findings = db_security.run(self._engine())
        mysql = [f for f in findings if f.raw.get("engine") == "MySQL/MariaDB"
                 and f.raw.get("db_category") == "open_port"]
        assert mysql and mysql[0].raw["version"] == "5.7.40"

    def test_redis_unauthenticated_is_critical(self, monkeypatch):
        from scanner.db import db_security
        monkeypatch.setattr(db_security, "_resolve", lambda h: "203.0.113.6")
        monkeypatch.setattr(db_security, "_is_accept_all", lambda ip, timeout=1.5: False)
        monkeypatch.setattr(db_security, "_probe_port",
                            lambda ip, port, timeout=1.5: (True, "") if port == 6379 else (False, ""))
        monkeypatch.setattr(db_security, "_check_tls", lambda *a: [])

        def fake_tcp(host, port, payload, timeout=3.0, read=4096):
            if b"PING" in payload:
                return b"+PONG\r\n"
            if b"INFO" in payload:
                return b"redis_version:7.0.5\r\n"
            return b""

        monkeypatch.setattr(db_security, "_tcp_send_recv", fake_tcp)
        findings = db_security.run(self._engine())
        crit = [f for f in findings if f.severity == Severity.CRITICAL and f.raw.get("engine") == "Redis"]
        assert crit and crit[0].raw["db_category"] == "unauth"

    def test_sql_error_is_critical_and_exploitable(self, monkeypatch):
        from scanner.db import db_security
        from scanner.exploit import _sqli_targets
        monkeypatch.setattr(db_security, "_resolve", lambda h: None)  # skip port scan

        class _Err(httpx.BaseTransport):
            def handle_request(self, request):
                return httpx.Response(200, text="You have an error in your SQL syntax near '1'")

        eng = self._engine(transport=_Err(), params=["http://db.test/p?id=1"])
        findings = db_security.run(eng)
        crit = [f for f in findings if f.severity == Severity.CRITICAL and f.raw.get("db_category") == "sqli"]
        assert crit and crit[0].raw["engine"] == "MySQL"
        # The SQLi must carry a sqlmap command so --exploit can attack it.
        assert crit[0].raw["sqlmap_args"][:2] == ["-u", "http://db.test/p?id=1"]
        assert crit[0] in _sqli_targets(findings)

    def test_accept_all_host_skips_port_scan(self, monkeypatch):
        from scanner.db import db_security
        monkeypatch.setattr(db_security, "_resolve", lambda h: "203.0.113.9")
        monkeypatch.setattr(db_security, "_is_accept_all", lambda ip, timeout=1.5: True)
        # If the scan were not skipped this would mark every port open:
        monkeypatch.setattr(db_security, "_probe_port", lambda ip, port, timeout=1.5: (True, ""))

        findings = db_security.run(self._engine())
        assert not [f for f in findings if f.raw.get("db_category") == "open_port"]
        assert any("answers all ports" in f.title.lower() for f in findings)

    def test_connection_string_leak_is_critical_and_redacted(self):
        from scanner.db import db_security
        from scanner.crawler import CrawlResult
        eng = ScanEngine("http://app.test", rate_delay=0)
        eng.get_crawl = MagicMock(return_value=CrawlResult(
            pages={"http://app.test/main.js": "const uri='mongodb://admin:s3cretPW@10.0.0.5:27017/prod';"}))

        findings = db_security._check_connstrings(eng)
        assert findings and findings[0].severity == Severity.CRITICAL
        assert findings[0].raw["has_credentials"] is True
        assert "***" in findings[0].raw["snippet"] and "s3cretPW" not in findings[0].raw["snippet"]

    def test_graphql_introspection_is_high(self):
        from scanner.db import db_security

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                if request.method == "POST" and request.url.path == "/graphql":
                    return httpx.Response(200, json={"data": {"__schema": {
                        "types": [{"name": "User"}, {"name": "Secret"}, {"name": "__Type"}]}}})
                return httpx.Response(404)

        eng = ScanEngine("http://api.test", rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)
        findings = db_security._check_graphql(eng)
        assert findings and findings[0].severity == Severity.HIGH
        assert "User" in findings[0].raw["types"] and "__Type" not in findings[0].raw["types"]

    def test_redis_config_reachable_is_rce(self, monkeypatch):
        from scanner.db import db_security

        def fake_tcp(host, port, payload, timeout=3.0, read=4096):
            if b"PING" in payload:
                return b"+PONG\r\n"
            if b"INFO" in payload:
                return b"redis_version:7.0.5\r\n"
            if b"DBSIZE" in payload:
                return b":42\r\n"
            if b"KEYS" in payload:
                return b"*2\r\n$4\r\nuser\r\n$7\r\nsession\r\n"
            if b"CONFIG" in payload:
                return b"*2\r\n$3\r\ndir\r\n$11\r\n/var/lib/db\r\n"
            return b""

        monkeypatch.setattr(db_security, "_tcp_send_recv", fake_tcp)
        findings = db_security._check_redis("203.0.113.6", 6379)
        assert any(f.severity == Severity.CRITICAL and "remote code execution" in f.title.lower()
                   for f in findings)
        unauth = [f for f in findings if "Unauthenticated Redis" in f.title]
        assert unauth and unauth[0].raw["keys_count"] == "42"
        assert "user" in unauth[0].raw["sample_keys"]

    def test_secret_env_file_is_critical_and_redacted(self):
        from scanner.db import db_security

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                if request.url.path == "/.env":
                    return httpx.Response(
                        200, text="APP_ENV=prod\nDB_HOST=10.0.0.5\nDB_PASSWORD=SuperS3cret\n",
                        headers={"content-type": "text/plain"})
                return httpx.Response(404, text="nf")

        eng = ScanEngine("http://app.test", rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)
        findings = db_security._check_secret_files(eng, catch_all=False)
        assert findings and findings[0].severity == Severity.CRITICAL
        assert findings[0].raw["db_category"] == "creds_leak"
        assert "SuperS3cret" not in findings[0].raw["secret_match"]
        assert "***" in findings[0].raw["secret_match"]

    def test_secret_file_html_page_is_ignored(self):
        from scanner.db import db_security

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                # SPA returns 200 HTML for everything, including /.env — must NOT flag.
                return httpx.Response(200, text="<!doctype html><html>app</html>",
                                      headers={"content-type": "text/html"})

        eng = ScanEngine("http://spa.test", rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)
        assert db_security._check_secret_files(eng, catch_all=False) == []

    def test_playbook_and_loot_built_from_findings(self):
        from scanner.db import db_security as d
        findings = [
            d._f("SQL Injection (error-based): id (MySQL)", "x", Severity.CRITICAL, "r", "sqli",
                 sqlmap='sqlmap -u "http://t/p?id=1" -p id --batch --dbs', parameter="id"),
            d._f("Unauthenticated Redis Access: h:6379", "x", Severity.CRITICAL, "r", "unauth",
                 exploit_cmd="redis-cli -h h -p 6379", sample_keys=["user", "token"], keys_count="9"),
            d._f("Database Port Open: 3306/tcp", "x", Severity.LOW, "r", "open_port"),  # no command
        ]
        plan = d.build_playbook(findings)
        assert len(plan) == 2 and plan[0]["severity"] == "critical"
        assert any("sqlmap" in s["command"] for s in plan)
        loot = d.collect_loot(findings)
        assert any("Redis keys" in item for item in loot)

    # --- Offensive red-team layer -------------------------------------------------

    def test_attack_tag_attached_to_finding(self):
        from scanner.db import db_security as d
        f = d._f("Unauthenticated Redis", "x", Severity.CRITICAL, "r", "unauth", host="h", port=6379)
        assert f.raw.get("attack", "").startswith("T1190")

    def test_header_sqli_via_user_agent(self):
        from scanner.db import db_security as d

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                ua = request.headers.get("user-agent", "")
                if "'" in ua:
                    return httpx.Response(200, text="You have an error in your SQL syntax near ''")
                return httpx.Response(200, text="<html>ok</html>")

        eng = ScanEngine("http://hdr.test", rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=True, verify=False)
        findings = d._check_injection_headers(eng, safe=False)
        assert findings and findings[0].severity == Severity.CRITICAL
        assert findings[0].raw["parameter"] == "User-Agent"
        # Safe mode skips header injection entirely.
        assert d._check_injection_headers(eng, safe=True) == []

    def test_header_sqli_negative(self):
        from scanner.db import db_security as d

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                return httpx.Response(200, text="<html>nothing reflected</html>")

        eng = ScanEngine("http://hdr.test", rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=True, verify=False)
        assert d._check_injection_headers(eng, safe=False) == []

    def test_nosql_authbypass_on_login_form(self):
        from scanner.db import db_security as d
        from scanner.crawler import CrawlResult, Form

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                if b'"$ne"' in request.content:
                    return httpx.Response(200, text="<html>welcome admin</html>",
                                          headers={"set-cookie": "session=abc123; Path=/"})
                return httpx.Response(200, text="<html>invalid login</html>")

        form = Form(action="http://app.test/login", method="post",
                    fields={"username": "x", "password": "y"}, source_url="http://app.test/login")
        eng = ScanEngine("http://app.test", rate_delay=0)
        eng.get_crawl = MagicMock(return_value=CrawlResult(forms=[form]))
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)
        findings = d._check_nosql_authbypass(eng, safe=False)
        assert findings and findings[0].raw["db_category"] == "authbypass"
        assert findings[0].severity == Severity.CRITICAL

    def test_cloud_db_firebase_open(self):
        from scanner.db import db_security as d
        from scanner.crawler import CrawlResult

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                if request.url.host == "myproj.firebaseio.com":
                    return httpx.Response(200, text='{"users":{"1":{"email":"a@b.c"}}}')
                return httpx.Response(404)

        eng = ScanEngine("http://site.test", rate_delay=0)
        eng.get_crawl = MagicMock(return_value=CrawlResult(
            pages={"http://site.test/app.js": "var c={databaseURL:'https://myproj.firebaseio.com'}"}))
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)
        findings = d._check_cloud_db(eng)
        assert findings and findings[0].severity == Severity.CRITICAL
        assert findings[0].raw["project"] == "myproj" and findings[0].raw["db_category"] == "cloud_db"

    def test_cloud_db_firebase_locked_is_silent(self):
        from scanner.db import db_security as d
        from scanner.crawler import CrawlResult

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                if request.url.host == "locked.firebaseio.com":
                    return httpx.Response(401, text='{"error":"Permission denied"}')
                return httpx.Response(404)

        eng = ScanEngine("http://site.test", rate_delay=0)
        eng.get_crawl = MagicMock(return_value=CrawlResult(
            pages={"http://site.test/x.js": "databaseURL:'https://locked.firebaseio.com'"}))
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)
        assert d._check_cloud_db(eng) == []

    def test_credential_reuse_success_is_critical(self, monkeypatch):
        from scanner.db import db_security as d
        monkeypatch.setattr(d, "_harvest_credentials",
                            lambda eng: [("mysql", "root", "leakedpw", "10.0.0.9", 3306)])
        monkeypatch.setattr(d, "_try_db_login", lambda *a: True)
        findings = d._exploit_cred_reuse(self._engine())
        assert findings and findings[0].raw["db_category"] == "cred_reuse"
        assert "leakedpw" not in findings[0].description  # password masked

    def test_active_extraction_gated_by_exploit(self, monkeypatch, tmp_path):
        from scanner.db import db_security as d
        monkeypatch.setattr(d, "_resolve", lambda h: "203.0.113.7")
        monkeypatch.setattr(d, "_is_accept_all", lambda ip, timeout=1.5: False)
        monkeypatch.setattr(d, "_probe_port",
                            lambda ip, port, timeout=1.5: (True, "") if port == 6379 else (False, ""))
        monkeypatch.setattr(d, "_check_tls", lambda *a: [])
        monkeypatch.setattr(d, "_loot_dir", lambda eng: tmp_path)

        def fake_tcp(host, port, payload, timeout=3.0, read=4096):
            if b"PING" in payload:
                return b"+PONG\r\n"
            if b"INFO" in payload:
                return b"redis_version:7.0\r\n"
            if b"DBSIZE" in payload:
                return b":3\r\n"
            if b"KEYS" in payload:
                return b"*1\r\n$4\r\nuser\r\n"
            if b"TYPE" in payload:
                return b"+string\r\n"
            if b"GET" in payload:
                return b"$5\r\nadmin\r\n"
            return b""

        monkeypatch.setattr(d, "_tcp_send_recv", fake_tcp)

        passive = self._engine()
        passive.exploit = False
        assert not [x for x in d.run(passive) if x.raw.get("db_category") == "extraction"]

        offensive = self._engine()
        offensive.exploit = True
        ext = [x for x in d.run(offensive) if x.raw.get("db_category") == "extraction"]
        assert ext and ext[0].raw.get("evidence_file")
        assert (tmp_path / "redis_203.0.113.7_6379.txt").exists()

    def test_nosql_not_flagged_on_sql_param(self):
        # A SQL-injectable param must NOT be double-reported as NoSQL (false positive).
        from scanner.db import db_security as d
        base_url = "http://t.test"

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                val = parse_qs(urlparse(str(req.url)).query).get("id", [""])[0]
                if val != "1":  # operator payload breaks the SQL query → SQL error
                    return httpx.Response(200, text="You have an error in your SQL syntax near '{'")
                return httpx.Response(200, text="<html>row 1</html>")

        eng = ScanEngine(base_url, rate_delay=0)
        from scanner.crawler import CrawlResult
        eng.get_crawl = MagicMock(return_value=CrawlResult(parametrised_urls=[f"{base_url}/p?id=1"]))
        eng._client = httpx.Client(transport=_T(), follow_redirects=True, verify=False)
        assert d._check_nosql(eng, safe=False) == []

    def test_nosql_authbypass_skips_aspnet_viewstate(self):
        # ASP.NET WebForms (MSSQL stack) must be skipped — a Mongo bypass is impossible there.
        from scanner.db import db_security as d
        from scanner.crawler import CrawlResult, Form

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                # Even if it 'looked' successful, the ViewState skip must prevent a finding.
                return httpx.Response(200, text="<html>welcome</html>",
                                      headers={"set-cookie": "ASP.NET_SessionId=xyz"})

        form = Form(action="http://aspnet.test/login.aspx", method="post",
                    fields={"__VIEWSTATE": "abc", "txtUser": "x", "txtPassword": "y"},
                    source_url="http://aspnet.test/login.aspx")
        eng = ScanEngine("http://aspnet.test", rate_delay=0)
        eng.get_crawl = MagicMock(return_value=CrawlResult(forms=[form]))
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)
        assert d._check_nosql_authbypass(eng, safe=False) == []

    def test_nosql_authbypass_no_failuretransition_is_silent(self):
        # Both baseline and attempt render the same login page → no bypass, no finding.
        from scanner.db import db_security as d
        from scanner.crawler import CrawlResult, Form

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                return httpx.Response(200, text="<html><form>Please log in</form></html>",
                                      headers={"set-cookie": "session=new"})

        form = Form(action="http://app.test/login", method="post",
                    fields={"username": "x", "password": "y"}, source_url="http://app.test/login")
        eng = ScanEngine("http://app.test", rate_delay=0)
        eng.get_crawl = MagicMock(return_value=CrawlResult(forms=[form]))
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)
        assert d._check_nosql_authbypass(eng, safe=False) == []


# ---------------------------------------------------------------------------
# crawler tests
# ---------------------------------------------------------------------------

def _html(body: str) -> httpx.Response:
    return httpx.Response(200, text=f"<html><body>{body}</body></html>",
                          headers={"content-type": "text/html"})


class TestCrawler:
    def _site(self, base_url: str) -> dict[str, httpx.Response]:
        return {
            base_url: _html(
                '<a href="/products?id=1">P</a>'
                '<a href="/contact">C</a>'
                '<a href="https://external.com/page">E</a>'
            ),
            f"{base_url}/products?id=1": _html('<a href="/products?id=2">P2</a>'),
            f"{base_url}/products?id=2": _html("end"),
            f"{base_url}/contact": _html(
                '<form action="/submit" method="post">'
                '<input name="email" type="email"><input name="msg"></form>'
                '<a href="mailto:info@example.com">mail</a> '
                'reach us at sales@example.com'
            ),
        }

    def test_collects_params_forms_emails_links(self, engine_factory, base_url):
        from scanner.crawler import crawl

        eng = engine_factory(self._site(base_url))
        result = crawl(eng, max_depth=2, max_pages=50)

        # Parametrised URLs found at depth 0 AND depth 1
        assert f"{base_url}/products?id=1" in result.parametrised_urls
        assert f"{base_url}/products?id=2" in result.parametrised_urls
        # Form extracted from the contact page
        assert any(f.method == "post" and "msg" in f.fields for f in result.forms)
        # Both mailto and free-text emails captured
        assert "info@example.com" in result.emails
        assert "sales@example.com" in result.emails
        # External link separated from internal ones
        assert "https://external.com/page" in result.external_links

    def test_max_pages_is_respected(self, engine_factory, base_url):
        from scanner.crawler import crawl

        eng = engine_factory(self._site(base_url))
        result = crawl(eng, max_depth=2, max_pages=1)
        assert len(result.pages) == 1

    def test_robots_disallow_excludes_path(self, engine_factory, base_url):
        from scanner.crawler import crawl

        site = self._site(base_url)
        site[f"{base_url}/robots.txt"] = httpx.Response(
            200, text="User-agent: *\nDisallow: /products\n"
        )
        eng = engine_factory(site)  # ignore_robots defaults to False
        result = crawl(eng, max_depth=2, max_pages=50)

        assert not any("/products" in u for u in result.parametrised_urls)
        assert not any("/products" in u for u in result.internal_links)

    def test_ignore_robots_includes_path(self, engine_factory, base_url):
        from scanner.crawler import crawl

        site = self._site(base_url)
        site[f"{base_url}/robots.txt"] = httpx.Response(
            200, text="User-agent: *\nDisallow: /products\n"
        )
        eng = engine_factory(site)
        eng.ignore_robots = True
        result = crawl(eng, max_depth=2, max_pages=50)

        assert f"{base_url}/products?id=1" in result.parametrised_urls


# ---------------------------------------------------------------------------
# scorer tests
# ---------------------------------------------------------------------------

class TestScorer:
    def test_no_findings_is_100(self):
        score, grade = calculate_score([])
        assert score == 100
        assert grade == "A"

    def test_single_critical_uses_config_penalty(self):
        """A lone critical deducts exactly SEVERITY_PENALTY['critical'] (config-driven)."""
        from config import SEVERITY_PENALTY

        score, _ = calculate_score([_make_finding(Severity.CRITICAL)])
        assert score == round(100 - SEVERITY_PENALTY["critical"])

    def test_info_findings_do_not_change_score(self):
        score, _ = calculate_score([_make_finding(Severity.INFO)] * 5)
        assert score == 100

    def test_diminishing_returns_within_module(self):
        """Findings in one module penalise less than the same findings spread out."""
        same_module = [_make_finding(Severity.CRITICAL, module="m") for _ in range(3)]
        spread      = [_make_finding(Severity.CRITICAL, module=f"m{i}") for i in range(3)]

        same_score, _   = calculate_score(same_module)
        spread_score, _ = calculate_score(spread)
        assert same_score > spread_score

    def test_five_criticals_not_mechanically_zero(self):
        """Five criticals in one module no longer collapse the score to 0."""
        findings = [_make_finding(Severity.CRITICAL, module="noisy") for _ in range(5)]
        score, _ = calculate_score(findings)
        assert score > 0

    def test_low_confidence_penalised_less(self):
        high = calculate_score([_make_finding(Severity.HIGH, confidence="high")])[0]
        low  = calculate_score([_make_finding(Severity.HIGH, confidence="low")])[0]
        assert low > high  # lower confidence ⇒ smaller penalty ⇒ higher score

    @pytest.mark.parametrize("findings,expected_grade", [
        ([], "A"),
        ([_make_finding(Severity.CRITICAL, module="a")], "B"),                       # 75
        ([_make_finding(Severity.CRITICAL, module="a"),
          _make_finding(Severity.LOW, module="b")], "C"),                            # 73
        ([_make_finding(Severity.CRITICAL, module="a"),
          _make_finding(Severity.CRITICAL, module="b")], "D"),                       # 50
        ([_make_finding(Severity.CRITICAL, module=f"m{i}") for i in range(3)], "F"), # 25
    ])
    def test_grade_boundaries(self, findings, expected_grade):
        _, grade = calculate_score(findings)
        assert grade == expected_grade

    def test_signatures_stable(self):
        from scanner.output.scorer import score_findings

        findings = [_make_finding(Severity.HIGH)]
        score, grade = calculate_score(findings)
        assert isinstance(score, int) and isinstance(grade, str)
        assert isinstance(score_findings(findings), int)


# ---------------------------------------------------------------------------
# js_recon tests
# ---------------------------------------------------------------------------

class TestJsRecon:
    def test_leaked_aws_key_and_endpoints(self):
        from scanner.recon import js_recon
        from scanner.crawler import CrawlResult
        base = "http://js.test"
        html = '<html><head><script src="/bundle.js"></script></head></html>'
        js = ('var cfg={awsKey:"AKIAZ7Q4RXBN2VWPL3KD"};'
              'fetch("/api/internal/users");axios.get("/admin/config");')

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                if req.url.path == "/bundle.js":
                    return httpx.Response(200, text=js,
                                          headers={"content-type": "application/javascript"})
                return httpx.Response(404, text="nf")

        eng = ScanEngine(base, rate_delay=0)
        eng.get_crawl = MagicMock(return_value=CrawlResult(pages={base: html}))
        eng._client = httpx.Client(transport=_T(), follow_redirects=True, verify=False)
        findings = js_recon.run(eng)
        assert any(f.raw.get("type") == "AWS Access Key ID" and f.severity == Severity.CRITICAL
                   for f in findings)
        # Secret is redacted, never shown in full.
        assert all("AKIAZ7Q4RXBN2VWPL3KD" not in f.description for f in findings)
        eps = next((f for f in findings if f.raw.get("endpoints")), None)
        assert eps and "/api/internal/users" in eps.raw["endpoints"]

    def test_example_placeholder_is_ignored(self):
        from scanner.recon import js_recon
        from scanner.crawler import CrawlResult
        base = "http://js.test"
        # The classic AWS *example* key must be filtered as a placeholder.
        html = '<html><script>var k="AKIAIOSFODNN7EXAMPLE";</script></html>'
        eng = ScanEngine(base, rate_delay=0)
        eng.get_crawl = MagicMock(return_value=CrawlResult(pages={base: html}))
        eng._client = httpx.Client(transport=_All404(), follow_redirects=True, verify=False)
        assert not [f for f in js_recon.run(eng) if f.raw.get("type") == "AWS Access Key ID"]


# ---------------------------------------------------------------------------
# cloud_buckets tests
# ---------------------------------------------------------------------------

class TestCloudBuckets:
    def test_open_s3_bucket_is_critical(self):
        from scanner.recon import cloud_buckets
        from scanner.crawler import CrawlResult

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                if req.url.host == "buckettest.s3.amazonaws.com":
                    return httpx.Response(200, text="<ListBucketResult><Contents><Key>"
                                                    "dump.sql</Key></Contents></ListBucketResult>")
                return httpx.Response(404, text="<Error><Code>NoSuchBucket</Code></Error>")

        eng = ScanEngine("http://buckettest.com", rate_delay=0)
        eng.get_crawl = MagicMock(return_value=CrawlResult(pages={}))
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)
        findings = cloud_buckets.run(eng)
        hit = [f for f in findings if f.severity == Severity.CRITICAL]
        assert hit and hit[0].raw["bucket"] == "buckettest" and hit[0].raw["provider"] == "Amazon S3"
        assert "dump.sql" in hit[0].raw["objects"]

    def test_private_bucket_is_low(self):
        from scanner.recon import cloud_buckets
        from scanner.crawler import CrawlResult

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                if req.url.host == "buckettest.s3.amazonaws.com":
                    return httpx.Response(403, text="<Error><Code>AccessDenied</Code></Error>")
                return httpx.Response(404, text="<Error><Code>NoSuchBucket</Code></Error>")

        eng = ScanEngine("http://buckettest.com", rate_delay=0)
        eng.get_crawl = MagicMock(return_value=CrawlResult(pages={}))
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)
        findings = cloud_buckets.run(eng)
        assert any(f.severity == Severity.LOW and f.raw.get("bucket") == "buckettest" for f in findings)

    def test_no_bucket_is_silent(self):
        from scanner.recon import cloud_buckets
        from scanner.crawler import CrawlResult

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                return httpx.Response(404, text="<Error><Code>NoSuchBucket</Code></Error>")

        eng = ScanEngine("http://buckettest.com", rate_delay=0)
        eng.get_crawl = MagicMock(return_value=CrawlResult(pages={}))
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)
        assert cloud_buckets.run(eng) == []


# ---------------------------------------------------------------------------
# jwt_attacks tests
# ---------------------------------------------------------------------------

def _make_jwt(payload: dict, secret: str = "secret", alg: str = "HS256") -> str:
    import base64, hmac, hashlib, json as _json

    def b64(d):
        return base64.urlsafe_b64encode(_json.dumps(d).encode()).rstrip(b"=").decode()
    signing = f'{b64({"alg": alg, "typ": "JWT"})}.{b64(payload)}'
    if alg == "none":
        return signing + "."
    h = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]
    sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), signing.encode(), h).digest()).rstrip(b"=").decode()
    return f"{signing}.{sig}"


class TestJwtAttacks:
    def test_weak_hmac_secret_cracked(self):
        from scanner.vulns import jwt_attacks
        from scanner.crawler import CrawlResult
        tok = _make_jwt({"user": "bob", "role": "admin"}, secret="secret")
        eng = ScanEngine("http://jwt.test", rate_delay=0)
        eng.get_crawl = MagicMock(return_value=CrawlResult(pages={"http://jwt.test/a.js": f'var t="{tok}";'}))
        eng._client = httpx.Client(transport=_All404(), follow_redirects=True, verify=False)
        findings = jwt_attacks.run(eng)
        assert any(f.raw.get("secret") == "secret" and f.severity == Severity.CRITICAL for f in findings)

    def test_alg_none_is_critical(self):
        from scanner.vulns import jwt_attacks
        from scanner.crawler import CrawlResult
        tok = _make_jwt({"role": "admin"}, alg="none")
        eng = ScanEngine("http://jwt.test", rate_delay=0)
        eng.get_crawl = MagicMock(return_value=CrawlResult(pages={"http://jwt.test/a.js": f'token="{tok}"'}))
        eng._client = httpx.Client(transport=_All404(), follow_redirects=True, verify=False)
        findings = jwt_attacks.run(eng)
        assert any(f.raw.get("alg") == "none" and f.severity == Severity.CRITICAL for f in findings)

    def test_strong_secret_not_cracked(self):
        from scanner.vulns import jwt_attacks
        from scanner.crawler import CrawlResult
        tok = _make_jwt({"role": "admin"}, secret="b7f3c1a9e6d4f8821094aa55cc77ee33longrandom")
        eng = ScanEngine("http://jwt.test", rate_delay=0)
        eng.get_crawl = MagicMock(return_value=CrawlResult(pages={"http://jwt.test/a.js": f'"{tok}"'}))
        eng._client = httpx.Client(transport=_All404(), follow_redirects=True, verify=False)
        assert not [f for f in jwt_attacks.run(eng) if f.raw.get("secret")]


# ---------------------------------------------------------------------------
# auth_bypass tests
# ---------------------------------------------------------------------------

class TestAuthBypass:
    def test_path_mutation_bypass_is_high(self):
        from scanner.vulns import auth_bypass

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                p = req.url.path
                if p == "/admin":
                    return httpx.Response(403, text="Forbidden 403")
                if p == "/admin/":
                    return httpx.Response(200, text="<html>Admin dashboard - secret control panel</html>")
                return httpx.Response(404, text="nf")

        eng = ScanEngine("http://ab.test", rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)
        findings = auth_bypass.run(eng)
        assert findings and findings[0].severity == Severity.HIGH and findings[0].raw["path"] == "/admin"

    def test_no_bypass_is_silent(self):
        from scanner.vulns import auth_bypass

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                if req.url.path.startswith("/admin"):
                    return httpx.Response(403, text="Forbidden")
                return httpx.Response(404, text="nf")

        eng = ScanEngine("http://ab.test", rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)
        assert auth_bypass.run(eng) == []


# ---------------------------------------------------------------------------
# bruteforce tests (opt-in)
# ---------------------------------------------------------------------------

class TestBruteforce:
    def test_disabled_by_default(self):
        from scanner.vulns import bruteforce
        from scanner.crawler import CrawlResult, Form
        form = Form(action="http://bf.test/login", method="post",
                    fields={"username": "x", "password": "y"}, source_url="http://bf.test/login")
        eng = ScanEngine("http://bf.test", rate_delay=0)   # bruteforce defaults to False
        eng.get_crawl = MagicMock(return_value=CrawlResult(forms=[form]))
        eng._client = httpx.Client(transport=_All404(), follow_redirects=False, verify=False)
        assert bruteforce.run(eng) == []

    def test_form_spray_finds_admin_admin(self):
        from scanner.vulns import bruteforce
        from scanner.crawler import CrawlResult, Form

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                vals = parse_qs(req.content.decode())
                u, p = vals.get("username", [""])[0], vals.get("password", [""])[0]
                if u == "admin" and p == "admin":
                    return httpx.Response(200, text="<html>welcome to your dashboard</html>")
                return httpx.Response(200, text="<html>invalid credentials</html>")

        form = Form(action="http://bf.test/login", method="post",
                    fields={"username": "x", "password": "y"}, source_url="http://bf.test/login")
        eng = ScanEngine("http://bf.test", rate_delay=0, bruteforce=True)
        eng.get_crawl = MagicMock(return_value=CrawlResult(forms=[form]))
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)
        findings = bruteforce.run(eng)
        assert findings and findings[0].severity == Severity.CRITICAL
        assert findings[0].raw["username"] == "admin" and findings[0].raw["password"] == "admin"

    def test_basic_auth_spray(self):
        import base64 as _b64
        from scanner.vulns import bruteforce
        from scanner.crawler import CrawlResult

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                if req.url.path != "/admin":
                    return httpx.Response(404, text="nf")
                auth = req.headers.get("authorization")
                if auth and _b64.b64decode(auth.split()[1]).decode() == "admin:admin":
                    return httpx.Response(200, text="ok")
                return httpx.Response(401, headers={"www-authenticate": 'Basic realm="x"'})

        eng = ScanEngine("http://bf.test", rate_delay=0, bruteforce=True)
        eng.get_crawl = MagicMock(return_value=CrawlResult())
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)
        findings = bruteforce.run(eng)
        assert any(f.raw.get("kind") == "HTTP Basic-Auth" and f.raw["password"] == "admin"
                   for f in findings)


# ---------------------------------------------------------------------------
# git_dumper tests
# ---------------------------------------------------------------------------

class TestGitDumper:
    def _index_blob(self) -> bytes:
        import struct
        name = b"app.py"
        entry = b"\x00" * 60 + struct.pack(">H", len(name)) + name
        total = 62 + len(name)
        entry += b"\x00" * (((total // 8) + 1) * 8 - total)
        return b"DIRC" + struct.pack(">II", 2, 1) + entry

    def test_exposed_git_extracts_creds_and_files(self):
        from scanner.recon import git_dumper
        blob = self._index_blob()

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                p = req.url.path
                if p == "/.git/HEAD":
                    return httpx.Response(200, text="ref: refs/heads/main\n")
                if p == "/.git/config":
                    return httpx.Response(200, text='[remote "origin"]\n\turl = '
                                          'https://deploy:s3cretpw@github.com/acme/app.git\n')
                if p == "/.git/logs/HEAD":
                    return httpx.Response(200, text=("0"*40 + " " + "a"*40 +
                                          " Joe <joe@acme.com> 1620000000 +0000\tcommit: init\n"))
                if p == "/.git/index":
                    return httpx.Response(200, content=blob)
                return httpx.Response(404, text="nf")

        eng = ScanEngine("http://gd.test", rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)
        findings = git_dumper.run(eng)
        assert findings and findings[0].severity == Severity.CRITICAL
        assert findings[0].raw["leaked_credentials"]
        assert "app.py" in findings[0].raw["files"]
        assert "joe@acme.com" in findings[0].raw["emails"]

    def test_no_git_is_silent(self):
        from scanner.recon import git_dumper
        eng = ScanEngine("http://gd.test", rate_delay=0)
        eng._client = httpx.Client(transport=_All404(), follow_redirects=False, verify=False)
        assert git_dumper.run(eng) == []


# ---------------------------------------------------------------------------
# wayback tests
# ---------------------------------------------------------------------------

class TestWayback:
    def test_archived_urls_and_params(self):
        from scanner.recon import wayback

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                if req.url.host == "web.archive.org":
                    body = '[["original"],["http://t.test/p?id=1&q=2"],'\
                           '["http://t.test/admin/backup.sql"]]'
                    return httpx.Response(200, text=body)
                return httpx.Response(404)

        eng = ScanEngine("http://t.test", rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)
        findings = wayback.run(eng)
        info = next((f for f in findings if f.severity == Severity.INFO), None)
        assert info and "id" in info.raw["parameters"] and "q" in info.raw["parameters"]
        assert any(f.severity == Severity.MEDIUM and
                   any("backup.sql" in p for p in f.raw["paths"]) for f in findings)

    def test_no_archive_is_silent(self):
        from scanner.recon import wayback

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                return httpx.Response(200, text='[["original"]]')   # header only, no URLs

        eng = ScanEngine("http://t.test", rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)
        assert wayback.run(eng) == []
