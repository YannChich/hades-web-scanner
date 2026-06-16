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


@pytest.fixture(autouse=True)
def _no_real_browser(monkeypatch):
    """Safety net: unit tests must never launch a real headless browser (or trigger a Chromium
    install). Stub xss_detect's optional DOM/stored-XSS browser pass off by default — every test that
    drives xss_detect.run over a form would otherwise reach it. Tests that exercise the pure browser
    helpers call monkeypatch.undo() or re-patch as needed."""
    from scanner.vulns import dom_xss
    monkeypatch.setattr(dom_xss, "candidates", lambda engine: [])
    monkeypatch.setattr(dom_xss, "verify", lambda engine, pages, params=None: [])


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
    for fn in (skills_kb.find_skills_repo, skills_kb._load_index,
               skills_kb._skill_detail, skills_kb._skill_meta):
        fn.cache_clear()
    yield repo
    for fn in (skills_kb.find_skills_repo, skills_kb._load_index,
               skills_kb._skill_detail, skills_kb._skill_meta):
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

    def test_graceful_noop_when_repo_and_bundle_absent(self, tmp_path, monkeypatch):
        from scanner.intel import skills_kb
        # Neutralise the env override, the on-disk candidate paths, AND the bundled JSON,
        # so nothing is discovered at all.
        monkeypatch.setenv("HADES_SKILLS_PATH", str(tmp_path / "does-not-exist"))
        monkeypatch.setattr(skills_kb, "SKILLS_REPO_CANDIDATES", [])
        monkeypatch.setattr(skills_kb, "_load_bundle", lambda: {})
        for fn in (skills_kb.find_skills_repo, skills_kb._load_index,
                   skills_kb._skill_detail, skills_kb._skill_meta):
            fn.cache_clear()
        f = Finding(module="sqli_detect", title="t", description="", severity=Severity.HIGH)
        assert skills_kb.enrich([f]) == 0
        assert f.skill_refs == []
        for fn in (skills_kb.find_skills_repo, skills_kb._load_index,
                   skills_kb._skill_detail, skills_kb._skill_meta):
            fn.cache_clear()

    def test_bundle_fallback_when_repo_absent(self, tmp_path, monkeypatch):
        """No external library, but the shipped bundle still resolves playbooks (GitHub links)."""
        from scanner.intel import skills_kb
        monkeypatch.setenv("HADES_SKILLS_PATH", str(tmp_path / "nope"))
        monkeypatch.setattr(skills_kb, "SKILLS_REPO_CANDIDATES", [])
        for fn in (skills_kb.find_skills_repo, skills_kb._load_index,
                   skills_kb._skill_detail, skills_kb._load_bundle, skills_kb._skill_meta):
            fn.cache_clear()
        f = Finding(module="sqli_detect", title="SQLi", description="", severity=Severity.CRITICAL)
        assert skills_kb.enrich([f]) == 1                       # works via the bundle
        ref = f.skill_refs[0]
        assert ref["name"] == "exploiting-sql-injection-vulnerabilities"
        assert ref["href"].startswith("https://github.com/")   # links upstream, not a local file
        for fn in (skills_kb.find_skills_repo, skills_kb._load_index,
                   skills_kb._skill_detail, skills_kb._load_bundle):
            fn.cache_clear()


class TestPlaybookQuality:
    @staticmethod
    def _bundle():
        import json
        from pathlib import Path
        p = Path(__file__).resolve().parent.parent / "scanner" / "intel" / "playbooks.json"
        return json.loads(p.read_text(encoding="utf-8"))

    def test_descriptions_are_complete_and_engaging(self):
        """The playbook teasers actually shown next to findings (curated offensive + remediation
        maps) must each be a complete, non-truncated sentence. The wider 754-skill bundle is a
        reference catalogue and is not held to this editorial bar."""
        import config
        by_name = {s["name"]: s for s in self._bundle()}
        surfaced: set[str] = set()
        for mapping in (config.MODULE_SKILL_MAP, config.DB_CATEGORY_SKILL_MAP,
                        config.MODULE_REMEDIATION_MAP):
            for names in mapping.values():
                surfaced.update(names)
        dangling = {"to", "using", "that", "by", "where", "including", "and", "the", "with",
                    "for", "of", "a", "in", "on", "from", "as"}
        for name in sorted(surfaced):
            assert name in by_name, f"{name}: surfaced playbook missing from bundle"
            d = by_name[name]["description"].strip()
            assert d.endswith("."), f"{name}: description not a full sentence"
            assert len(d) >= 40, f"{name}: description too short"
            assert d.rstrip(".").split()[-1].lower() not in dangling, f"{name}: truncated"

    def test_mapped_skills_all_resolve_in_bundle(self):
        import config
        names = {s["name"] for s in self._bundle()}
        mapped = set()
        for v in config.MODULE_SKILL_MAP.values():
            mapped |= set(v)
        for v in config.DB_CATEGORY_SKILL_MAP.values():
            mapped |= set(v)
        assert mapped <= names, f"mapped but missing from bundle: {sorted(mapped - names)}"

    def test_no_defensive_playbook_attached_to_findings(self):
        """Offensive findings must never link a pure blue-team (remediation/hardening) playbook."""
        import config
        mapped = set()
        for v in config.MODULE_SKILL_MAP.values():
            mapped |= set(v)
        for v in config.DB_CATEGORY_SKILL_MAP.values():
            mapped |= set(v)
        assert "implementing-llm-guardrails-for-security" not in mapped
        assert "analyzing-cloud-storage-access-patterns" not in mapped
        for name in mapped:
            assert not name.startswith(("remediating-", "implementing-", "hardening-",
                                        "deploying-", "building-")), f"defensive playbook mapped: {name}"


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

    def test_more_key_providers_detected(self):
        from scanner.ai import llm_recon
        b = "Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op0Qr1St2Uv3Wx4Yz5"        # 40 high-entropy chars
        page = f"GROQ='gsk_{b}{b[:5]}'; XAI='xai-{b}{b[:22]}'; LS='lsv2_{b}'"
        eng = _FakeCrawlEngine({"https://t/app.js": page})
        provs = {f.raw["provider"] for f in llm_recon._check_exposed_keys(eng)}
        assert {"Groq", "xAI Grok", "LangSmith"} <= provs

    def test_low_entropy_key_is_not_flagged(self):
        from scanner.ai import llm_recon
        eng = _FakeCrawlEngine({"https://t/x.js": "key='sk-" + "a" * 40 + "'"})   # placeholder
        assert llm_recon._check_exposed_keys(eng) == []

    def test_ai_plugin_manifest_is_excessive_agency(self):
        from scanner.ai import llm_recon

        class _T(httpx.BaseTransport):
            def handle_request(self, req: httpx.Request) -> httpx.Response:
                if req.url.path == "/.well-known/ai-plugin.json":
                    return httpx.Response(200, json={"schema_version": "v1", "api": {"url": "/openapi.json"}})
                return httpx.Response(404, text="nf")

        eng = ScanEngine("http://t.test", rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)
        fs = llm_recon._check_ai_manifests(eng)
        assert fs and fs[0].raw["ai_category"] == "excessive_agency"
        assert fs[0].owasp.startswith("LLM06:2025")

    def test_active_injection_leak_jailbreak_output(self):
        """Under --exploit, the full offensive suite confirms injection, leak, jailbreak and XSS output."""
        import json as _json
        from scanner.ai import llm_recon

        class _T(httpx.BaseTransport):
            def handle_request(self, req: httpx.Request) -> httpx.Response:
                if req.method == "GET":
                    if req.url.path == "/api/chat":
                        return httpx.Response(200, json={"status": "ready"})
                    return httpx.Response(404, text="nf")
                body = _json.loads(req.content or b"{}")
                if "messages" in body:
                    prompt = body["messages"][-1].get("content", "")
                else:
                    prompt = next((body[k] for k in
                                   ("message", "prompt", "input", "query", "text", "question", "content")
                                   if k in body), "")
                p = prompt.lower()
                if "token: hades7531" in p:
                    ans = "Sure thing: HADES7531"
                elif "system prompt" in p:
                    ans = "You are a helpful banking assistant. Never reveal secrets. HADES7531"
                elif "dan" in p:
                    ans = "HADES7531-JB"
                elif "repeat the following" in p:
                    ans = "<b>HADES7531</b><img src=x onerror=alert(HADES7531)>"
                else:
                    ans = "hi"
                return httpx.Response(200, json={"choices": [{"message": {"content": ans}}]})

        eng = ScanEngine("http://t.test", rate_delay=0)
        eng.exploit = True
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)
        fs = llm_recon._check_prompt_injection(eng, active=True, loot=None)
        cats = {f.raw["ai_category"] for f in fs}
        assert {"prompt_injection_surface", "prompt_injection_confirmed", "system_prompt_leak",
                "jailbreak_confirmed", "output_handling"} <= cats
        leak = next(f for f in fs if f.raw["ai_category"] == "system_prompt_leak")
        assert leak.owasp.startswith("LLM07:2025") and "AML.T0057" in leak.mitre

    def test_run_emits_exposure_score_and_panel(self):
        from unittest.mock import MagicMock
        from scanner.ai import llm_recon
        from scanner.crawler import CrawlResult

        class _T(httpx.BaseTransport):
            def handle_request(self, req: httpx.Request) -> httpx.Response:
                return httpx.Response(404, text="nf")

        b = "Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op0Qr1"
        eng = ScanEngine("http://nonexistent.invalid", rate_delay=0)
        eng.get_crawl = MagicMock(return_value=CrawlResult(pages={"http://x/app.js": f"K='sk-ant-{b}'"}))
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)
        fs = llm_recon.run(eng)
        cats = {f.raw.get("ai_category") for f in fs}
        assert "exposed_key" in cats and "score" in cats
        score_f = next(f for f in fs if f.raw.get("ai_category") == "score")
        assert 0 < score_f.raw["score"] <= 100
        llm_recon.render_panel(fs)                  # must not raise

    # --- Axis 1: more providers + GCP service account ---
    def test_more_key_providers_v2_and_gcp_sa(self):
        from scanner.ai import llm_recon
        hex64 = "0123456789abcdef" * 4
        page = ('OR="sk-or-v1-' + hex64 + '"; FW="fw_Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op0"; '
                '{"type": "service_account", "project_id": "p", '
                '"private_key": "-----BEGIN PRIVATE KEY-----MIIE..."}')
        eng = _FakeCrawlEngine({"https://t/app.js": page})
        provs = {f.raw["provider"] for f in llm_recon._check_exposed_keys(eng)}
        assert "OpenRouter" in provs and "Fireworks AI" in provs
        assert any("service account" in p.lower() for p in provs)

    # --- Axis 1: unauthenticated vector database ---
    def test_vector_db_unauth_detected(self, monkeypatch):
        from scanner.ai import llm_recon
        monkeypatch.setattr(llm_recon.socket, "gethostbyname", lambda h: "127.0.0.1")
        monkeypatch.setattr(llm_recon, "_probe_port", lambda ip, port, timeout=1.2: port == 6333)

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                if req.url.port == 6333 and req.url.path == "/collections":
                    return httpx.Response(200, json={"result": {"collections": [{"name": "docs"}]}})
                return httpx.Response(404, text="nf")
        eng = ScanEngine("http://t.test", rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)
        fs = llm_recon._check_vector_dbs(eng, active=False, loot=None)
        assert fs and fs[0].raw["ai_category"] == "exposed_vector_db" and "Qdrant" in fs[0].title
        assert fs[0].raw.get("evidence") and fs[0].raw.get("exploitation")

    # --- Axis 2: MCP tools/list enumeration (excessive agency) ---
    def test_mcp_tools_enumerated(self):
        from scanner.ai import llm_recon

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                if req.url.path == "/mcp" and req.method == "POST":
                    return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1,
                                                     "result": {"tools": [{"name": "read_file"},
                                                                          {"name": "run_sql"}]}})
                return httpx.Response(404, text="nf")
        eng = ScanEngine("http://t.test", rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=False, verify=False)
        fs = llm_recon._check_mcp_tools(eng, active=False, loot=None)
        assert fs and fs[0].raw["ai_category"] == "excessive_agency"
        assert "read_file" in fs[0].raw["tools"] and fs[0].raw.get("exploitation")

    # --- Axis 3: exposed AI engine → known CVE ---
    def test_ai_cve_correlation(self):
        from scanner.ai.llm_recon import _check_ai_cves
        from scanner.engine import Finding, Severity
        exposed = Finding(module="llm_recon", title="Unauthenticated Ollama Server Exposed",
                          description="", severity=Severity.CRITICAL,
                          raw={"ai_category": "exposed_server", "engine_name": "Ollama",
                               "url": "http://t:11434"})
        cves = _check_ai_cves([exposed])
        assert cves and cves[0].raw["cve_id"] == "CVE-2024-37032" and cves[0].raw["ai_category"] == "ai_cve"
        assert not _check_ai_cves([Finding(module="llm_recon", title="x", description="",
                                           severity=Severity.LOW, raw={"ai_category": "discovery"})])

    def test_exposed_key_carries_evidence_and_exploitation(self):
        from scanner.ai import llm_recon
        eng = _FakeCrawlEngine({"https://t/app.js": "const K='sk-ant-ABCDEFGHIJKLMNOPQRSTUVWX';"})
        f = llm_recon._check_exposed_keys(eng)[0]
        assert f.raw.get("evidence")
        steps = f.raw.get("exploitation")
        assert isinstance(steps, list) and any("rotate" in s["description"].lower() for s in steps)


# ---------------------------------------------------------------------------
# SSRF accuracy — a reflected payload must NOT be a false positive
# ---------------------------------------------------------------------------

# Acuforum-style login page: reflects the injected URL in a RetURL param and carries
# Dreamweaver "InstanceBegin" template comments — both tripped the old loose heuristics.
_REFLECTED_PAGE = (
    '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">\n'
    '<html><!-- InstanceBegin template="/Templates/Main.dwt.asp" -->\n'
    '<head><!-- InstanceBeginEditable name="doctitle" --><title>acuforum login</title>\n'
    '<!-- InstanceEndEditable --></head><body>\n'
    '<a href="./Login.asp?RetURL=http%3A%2F%2F169%2E254%2E169%2E254%2Flatest%2Fmeta%2Ddata%2F">login</a>\n'
    '</body><!-- InstanceEnd --></html>'
)
_REAL_AWS_META = "ami-id\nami-launch-index\nhostname\ninstance-id\nlocal-ipv4\npublic-keys/\n"


def _resp(text: str, status: int = 200):
    return type("_R", (), {"text": text, "status_code": status})()


class TestSSRFAccuracy:
    def test_ssrf_detect_ignores_reflected_payload(self):
        from scanner.vulns._common import Injector
        from scanner.vulns.ssrf_detect import _test
        inj = Injector(label="URL parameter 'RetURL'", param="RetURL",
                       inject=lambda p: _resp(_REFLECTED_PAGE),
                       proof=lambda p: "https://t/?RetURL=" + p, url="https://t/?RetURL=1")
        assert _test(inj) is None       # a reflected URL is NOT SSRF

    def test_ssrf_detect_flags_real_metadata(self):
        from scanner.vulns._common import Injector
        from scanner.vulns.ssrf_detect import _test, _PAYLOADS
        aws_payload = _PAYLOADS[0][0]
        inj = Injector(label="URL parameter 'url'", param="url",
                       inject=lambda p: _resp(_REAL_AWS_META if p == aws_payload else "", 200),
                       proof=lambda p: "https://t/?url=" + p, url="https://t/?url=1")
        f = _test(inj)
        assert f is not None and "AWS" in f.raw["signal"]

    def test_engage_ssrf_ignores_reflected_page(self):
        from scanner.vulns._common import Injector
        from scanner.offensive.engage import _exploit_ssrf
        inj = Injector(label="URL parameter 'RetURL'", param="RetURL",
                       inject=lambda p: _resp(_REFLECTED_PAGE),
                       proof=lambda p: "https://t/?RetURL=" + p, url="https://t/?RetURL=1")
        assert _exploit_ssrf(inj, None) is None

    def test_engage_ssrf_proves_on_real_metadata(self):
        from scanner.vulns._common import Injector
        from scanner.offensive.engage import _exploit_ssrf
        inj = Injector(label="URL parameter 'url'", param="url",
                       inject=lambda p: _resp("ami-id\ninstance-id\nlocal-ipv4\niam/security-credentials/role"),
                       proof=lambda p: "https://t/?url=" + p, url="https://t/?url=1")
        res = _exploit_ssrf(inj, None)
        assert res is not None and res.raw["engage_category"] == "ssrf_read"


# ---------------------------------------------------------------------------
# CVE Vulnerability Intelligence tests (menu option 8 / cve_scan)
# ---------------------------------------------------------------------------

_MOCK_KEV = {"vulnerabilities": [{
    "cveID": "CVE-2021-23017", "vendorProject": "nginx", "product": "nginx",
    "vulnerabilityName": "nginx DNS Resolver Off-by-One", "dateAdded": "2022-02-10",
    "dueDate": "2022-03-03", "requiredAction": "Apply updates.", "shortDescription": "nginx resolver bug."}]}

_MOCK_EPSS = "#model_version:v2024\ncve,epss,percentile\nCVE-2021-23017,0.91,0.99\nCVE-0000-0001,0.02,0.10\n"

_MOCK_NVD = {"vulnerabilities": [{"cve": {
    "id": "CVE-2021-23017", "published": "2021-05-25T00:00:00", "lastModified": "2021-06-01T00:00:00",
    "descriptions": [{"lang": "en", "value": "off-by-one in the nginx resolver"}],
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N"}, "baseSeverity": "CRITICAL"}]},
    "weaknesses": [{"description": [{"value": "CWE-787"}]}],
    "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23017"}],
    "configurations": [{"nodes": [{"cpeMatch": [{
        "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", "vulnerable": True,
        "versionStartIncluding": "0.6.18", "versionEndExcluding": "1.21.0"}]}]}]}}]}


class TestCVE:
    def test_profile_registered_and_menu(self):
        from config import PROFILE_MODULES
        assert PROFILE_MODULES["cve_scan"] == ["scanner.cve.detector"]

    def test_db_schema_created(self, tmp_path):
        from scanner.cve.db import get_conn
        conn = get_conn(tmp_path / "v.sqlite")
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"cves", "cpe_matches", "cpe_dictionary", "exploit_intel", "aliases", "sync_state"} <= tables
        conn.close()

    def test_kev_parser_ingest(self, tmp_path):
        from scanner.cve import kev_parser
        from scanner.cve.db import get_conn
        conn = get_conn(tmp_path / "v.sqlite")
        assert kev_parser.ingest(conn, _MOCK_KEV) == 1
        row = conn.execute("SELECT kev, kev_product FROM exploit_intel WHERE cve_id='CVE-2021-23017'").fetchone()
        assert row["kev"] == 1 and row["kev_product"] == "nginx"
        conn.close()

    def test_epss_parser(self, tmp_path):
        from scanner.cve import epss_parser
        from scanner.cve.db import get_conn
        assert epss_parser.parse(_MOCK_EPSS) == [("CVE-2021-23017", 0.91, 0.99), ("CVE-0000-0001", 0.02, 0.10)]
        conn = get_conn(tmp_path / "v.sqlite")
        epss_parser.ingest(conn, _MOCK_EPSS)
        assert conn.execute("SELECT epss FROM exploit_intel WHERE cve_id='CVE-2021-23017'").fetchone()["epss"] == 0.91
        conn.close()

    def test_nvd_parser(self, tmp_path):
        from scanner.cve import nvd_parser
        from scanner.cve.db import get_conn
        cve_row, matches = nvd_parser.parse_vulnerability(_MOCK_NVD["vulnerabilities"][0])
        assert cve_row["cvss_score"] == 9.8 and cve_row["cwe"] == "CWE-787"
        assert matches[0]["vendor"] == "nginx" and matches[0]["version_end_excluding"] == "1.21.0"
        conn = get_conn(tmp_path / "v.sqlite")
        assert nvd_parser.ingest(conn, _MOCK_NVD) == 1
        assert conn.execute("SELECT COUNT(*) FROM cpe_matches WHERE vendor='nginx'").fetchone()[0] == 1
        conn.close()

    def test_alias_and_cpe_matching(self):
        from scanner.cve.alias_matcher import normalize
        from scanner.cve.cpe_matcher import candidates
        from scanner.cve.models import DetectedTech
        assert normalize("nginx")["cpe_prefix"] == "cpe:2.3:a:nginx:nginx"
        cands = candidates(DetectedTech(name="nginx", version="1.18.0", source="Server header"))
        assert cands and cands[0].product == "nginx"
        # nginx is indexed in NVD under both `nginx:nginx` and (post-F5-acquisition) `f5:nginx`;
        # candidates() must emit the alternate vendor or most modern nginx CVEs are missed.
        vendors = {c.vendor for c in cands}
        assert {"nginx", "f5"} <= vendors

    def test_expanded_alias_coverage(self):
        """Newly-mapped web/service products must resolve to their NVD-verified CPEs."""
        from scanner.cve.cpe_matcher import candidates
        from scanner.cve.models import DetectedTech
        expect = {
            "OpenSSH": "openbsd:openssh", "PrestaShop": "prestashop:prestashop",
            "Symfony": "sensiolabs:symfony", "OpenCart": "opencart:opencart",
            "Jenkins": "jenkins:jenkins", "MariaDB": "mariadb:mariadb",
            "Varnish": "varnish-cache:varnish", "Exim": "exim:exim", "vsftpd": "beasts:vsftpd",
        }
        for name, prefix in expect.items():
            cands = candidates(DetectedTech(name=name, source="banner", evidence=name))
            assert cands and any(c.cpe_prefix == f"cpe:2.3:a:{prefix}" for c in cands), name

    def test_apache_http_vs_tomcat_ambiguity(self):
        from scanner.cve.cpe_matcher import candidates
        from scanner.cve.models import DetectedTech
        http = candidates(DetectedTech(name="Apache", type="web_server", source="Server header"))
        assert http and http[0].product == "http_server"
        tomcat = candidates(DetectedTech(name="Apache Tomcat", source="header"))
        assert tomcat and tomcat[0].product == "tomcat"
        # bare 'apache' whose evidence mentions tomcat must NOT be matched as http_server
        ambiguous = candidates(DetectedTech(name="Apache", source="Server: Apache-Coyote tomcat"))
        assert ambiguous == []

    def test_version_compare_and_range(self):
        from scanner.cve.version_matcher import version_compare, in_affected_range, version_known
        assert version_compare("1.18.0", "1.21.0") < 0
        assert version_compare("1.0.0", "1.0.0-rc1") > 0          # release > pre-release
        assert version_compare("2.0", "2.0.0") == 0
        assert not version_known("") and version_known("1.2.3")
        m = {"version_start_including": "0.6.18", "version_end_excluding": "1.21.0"}
        assert in_affected_range("1.18.0", m) is True
        assert in_affected_range("1.21.0", m) is False           # excluded upper bound
        assert in_affected_range("0.5", m) is False

    def test_classify_levels(self):
        from scanner.cve.version_matcher import classify
        m = {"version_end_excluding": "1.21.0"}
        assert classify("1.18.0", m, 0.9) == "CONFIRMED"
        assert classify("1.18.0", m, 0.6) == "LIKELY"
        assert classify("", m, 0.9) == "POSSIBLE"                # unknown version
        assert classify("2.0.0", m, 0.9) is None                 # not in range -> skip

    def test_priority_scoring(self):
        from scanner.cve.prioritizer import priority_score, severity_from_score
        hi = priority_score(9.8, 0.91, kev=True, internet_exposed=True, confidence="CONFIRMED")
        lo = priority_score(9.8, 0.91, kev=True, internet_exposed=True, confidence="POSSIBLE")
        assert hi >= 90 and severity_from_score(hi) == "critical"
        assert lo < hi                                            # confidence multiplier bites
        assert severity_from_score(5) == "info" and severity_from_score(45) == "medium"

    def test_unknown_version_top10_noise_control(self):
        from scanner.cve.detector import _finalize
        from scanner.cve.models import CveFinding
        items = [CveFinding(cve_id=f"CVE-2020-{i:04d}", vendor="nginx", product="nginx",
                            detected_version="unknown", affected_range="all", cvss_score=5.0,
                            cvss_vector="", severity="medium", cwe="", epss=0.1 * (i % 9),
                            epss_percentile=0.5, kev=(i == 3), confidence="POSSIBLE",
                            priority_score=10 + i, priority_severity="low", evidence="", impact="",
                            remediation="") for i in range(25)]
        kept, notes = _finalize(items)
        assert len(kept) == 10                                   # capped to top 10
        assert notes and notes[0] == ("nginx", 25)
        assert any(c.kev for c in kept)                          # the KEV one survives the cut

    def test_report_to_finding(self):
        from scanner.cve.report import to_finding
        from scanner.cve.models import CveFinding
        from scanner.engine import Severity
        cf = CveFinding(cve_id="CVE-2021-23017", vendor="nginx", product="nginx",
                        detected_version="1.18.0", affected_range="< 1.21.0", cvss_score=9.8,
                        cvss_vector="CVSS:3.1", severity="critical", cwe="CWE-787", epss=0.91,
                        epss_percentile=0.99, kev=True, confidence="CONFIRMED", priority_score=97,
                        priority_severity="critical", evidence="Server: nginx/1.18.0",
                        impact="off-by-one", remediation="upgrade", references=["https://nvd"])
        f = to_finding(cf, "https://t")
        assert f.module == "cve_vulnerability" and f.severity is Severity.CRITICAL
        assert f.raw["cve_id"] == "CVE-2021-23017" and f.raw["kev"] is True
        assert f.raw["priority_score"] == 97 and f.cwe == "CWE-787"
        assert f.raw["confidence"] == "high"                     # mapped for the scorer

    def test_update_if_missing_and_stale(self, tmp_path, monkeypatch):
        from scanner.cve import db as cvedb, feed_downloader as fd
        monkeypatch.setattr(cvedb, "DB_PATH", tmp_path / "v.sqlite")
        built = {"n": 0}
        monkeypatch.setattr(fd, "build_database", lambda: (built.__setitem__("n", built["n"] + 1) or True))
        assert fd.update_vulndb_if_missing() is True and built["n"] == 1     # missing -> build
        monkeypatch.setattr(fd, "db_age_days", lambda *a: 10.0)
        monkeypatch.setattr(fd, "db_exists", lambda *a: True)
        assert fd.update_vulndb_if_stale(7) is True and built["n"] == 2      # stale -> build again

    def test_detector_end_to_end(self, tmp_path, monkeypatch):
        from scanner.cve import db as cvedb, feed_downloader as fd, detector
        from scanner.cve.db import get_conn
        from scanner.cve.kev_parser import ingest as kev_ingest
        from scanner.cve.epss_parser import ingest as epss_ingest
        from scanner.cve.nvd_parser import ingest as nvd_ingest
        from scanner.engine import ScanEngine

        db_file = tmp_path / "v.sqlite"
        monkeypatch.setattr(cvedb, "DB_PATH", db_file)
        seed = get_conn(db_file)
        nvd_ingest(seed, _MOCK_NVD); kev_ingest(seed, _MOCK_KEV); epss_ingest(seed, _MOCK_EPSS)
        seed.close()
        monkeypatch.setattr(fd, "update_vulndb_if_stale", lambda *a, **k: True)
        monkeypatch.setattr(fd, "query_nvd", lambda *a, **k: {})   # rely on the seeded data

        class _ServerTransport(httpx.BaseTransport):   # fresh response per request
            def handle_request(self, request: httpx.Request) -> httpx.Response:
                return httpx.Response(200, text="<html></html>",
                                      headers={"server": "nginx/1.18.0", "content-type": "text/html"})

        eng = ScanEngine("https://target.test", rate_delay=0)
        eng._client = httpx.Client(transport=_ServerTransport(), follow_redirects=True, verify=False)
        findings = detector.run(eng)
        cves = [f for f in findings if f.module == "cve_vulnerability" and f.raw.get("cve_id")]
        assert any(f.raw["cve_id"] == "CVE-2021-23017" and f.raw["kev"] for f in cves)
        assert any(f.raw["cve_confidence"] == "CONFIRMED" for f in cves)

    def test_service_banner_parsing(self):
        from scanner.cve.detector import _parse_banner
        assert ("OpenSSH", "8.2p1") in _parse_banner("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")
        assert ("ProFTPD", "1.3.5") in _parse_banner("220 ProFTPD 1.3.5 Server ready")
        assert ("vsftpd", "3.0.3") in _parse_banner("220 (vsFTPd 3.0.3)")
        assert any(n == "Exim" and v == "4.94" for n, v in _parse_banner("220 mail ESMTP Exim 4.94"))
        assert ("Postfix", "") in _parse_banner("220 mail.example.com ESMTP Postfix")
        assert _parse_banner("HTTP/1.1 200 OK") == []        # no false product from a protocol token

    def test_nvd_date_windows(self):
        from datetime import datetime, timezone
        from scanner.cve.feed_downloader import _date_windows, _nvd_date
        d = datetime(2024, 1, 1, tzinfo=timezone.utc)
        assert _nvd_date(d) == "2024-01-01T00:00:00.000+00:00"
        # a > 110-day span must be split into multiple NVD-legal windows (each < 120 days)
        wins = _date_windows(datetime(2023, 1, 1, tzinfo=timezone.utc),
                             datetime(2024, 1, 1, tzinfo=timezone.utc))
        assert len(wins) >= 3 and all(isinstance(a, str) and isinstance(b, str) for a, b in wins)

    @staticmethod
    def _mk_nvd_vuln(i: int) -> dict:
        return {"cve": {
            "id": f"CVE-9999-{1000 + i}", "published": "2024-01-01T00:00:00",
            "lastModified": "2024-02-01T00:00:00",
            "descriptions": [{"lang": "en", "value": f"test vuln {i}"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "vectorString": "CVSS:3.1/AV:N"},
                                           "baseSeverity": "HIGH"}]},
            "weaknesses": [{"description": [{"value": "CWE-79"}]}],
            "references": [{"url": "https://nvd.nist.gov/vuln/detail/x"}],
            "configurations": [{"nodes": [{"cpeMatch": [{
                "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", "vulnerable": True,
                "versionStartIncluding": "0.1.0", "versionEndExcluding": "1.21.0"}]}]}]}}

    def test_full_corpus_pagination_then_offline_match(self, tmp_path, monkeypatch):
        """Bulk-load paginates the whole corpus locally, then the detector matches with no network."""
        from scanner.cve import db as cvedb, feed_downloader as fd, detector
        from scanner.cve.models import DetectedTech
        from scanner.engine import ScanEngine

        monkeypatch.setattr(cvedb, "DB_PATH", tmp_path / "v.sqlite")
        monkeypatch.setattr(fd, "_nvd_delay", lambda: 0)            # no real sleeping
        corpus = [self._mk_nvd_vuln(i) for i in range(3)]

        def fake_get(_client, params):                              # 2 CVEs per page
            start = params["startIndex"]
            page = corpus[start:start + 2]
            return {"totalResults": len(corpus), "resultsPerPage": len(page),
                    "startIndex": start, "vulnerabilities": page}
        monkeypatch.setattr(fd, "_nvd_get", fake_get)

        ingested = fd.build_full_nvd()
        assert ingested == 3
        assert fd.nvd_corpus_size() == 3 and fd.has_full_nvd() is True

        # Detector must now run fully offline — query_nvd is forbidden.
        monkeypatch.setattr(fd, "update_vulndb_if_stale", lambda *a, **k: True)
        def _boom(*a, **k):
            raise AssertionError("query_nvd must not be called when the full corpus is present")
        monkeypatch.setattr(fd, "query_nvd", _boom)
        monkeypatch.setattr(detector, "_collect_tech", lambda eng: [
            DetectedTech(name="nginx", version="1.18.0", type="web_server",
                         source="Server header", confidence=0.9, evidence="Server: nginx/1.18.0")])

        findings = detector.run(ScanEngine("https://target.test", rate_delay=0))
        cves = [f for f in findings if f.raw.get("cve_id")]
        assert cves and all(c.raw["cve_id"].startswith("CVE-9999-") for c in cves)
        assert any("offline" in f.description for f in findings if "Summary" in f.title)

    @staticmethod
    def _nginx_vuln(cve_id: str) -> dict:
        return {"cve": {
            "id": cve_id, "published": "2021-01-01T00:00:00", "lastModified": "2021-02-01T00:00:00",
            "descriptions": [{"lang": "en", "value": "x"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "vectorString": "CVSS:3.1/AV:N"},
                                           "baseSeverity": "HIGH"}]},
            "weaknesses": [], "references": [],
            "configurations": [{"nodes": [{"cpeMatch": [{
                "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", "vulnerable": True,
                "versionEndExcluding": "1.21.0"}]}]}]}}

    def test_cve_year_filter_excludes_pre_2020(self, tmp_path, monkeypatch):
        from scanner.cve import db as cvedb, detector, feed_downloader as fd
        from scanner.cve.db import get_conn, set_sync_state
        from scanner.cve.nvd_parser import ingest as nvd_ingest
        from scanner.cve.models import DetectedTech
        from scanner.engine import ScanEngine

        assert detector._cve_year("CVE-2019-1111") == 2019 and detector._cve_year("CVE-7C51") == 0
        db_file = tmp_path / "v.sqlite"
        monkeypatch.setattr(cvedb, "DB_PATH", db_file)
        seed = get_conn(db_file)
        nvd_ingest(seed, {"vulnerabilities": [self._nginx_vuln("CVE-2019-1111")]})
        nvd_ingest(seed, {"vulnerabilities": [self._nginx_vuln("CVE-2021-2222")]})
        set_sync_state(seed, "nvd_full", 2)
        seed.close()
        monkeypatch.setattr(fd, "update_vulndb_if_stale", lambda *a, **k: True)
        monkeypatch.setattr(fd, "query_nvd", lambda *a, **k: {})
        monkeypatch.setattr(detector, "_collect_tech", lambda eng: [
            DetectedTech(name="nginx", version="1.18.0", type="web_server",
                         source="hdr", confidence=0.9, evidence="x")])

        findings = detector.run(ScanEngine("https://target.test", rate_delay=0))
        ids = {f.raw["cve_id"] for f in findings if f.raw.get("cve_id")}
        assert "CVE-2021-2222" in ids and "CVE-2019-1111" not in ids

    def test_html_badge_links(self):
        from scanner.output import report_html as rh
        assert rh._cwe_url("CWE-79") == "https://cwe.mitre.org/data/definitions/79.html"
        assert rh._mitre_url("T1190") == "https://attack.mitre.org/techniques/T1190/"
        assert rh._mitre_url("T1059.001") == "https://attack.mitre.org/techniques/T1059/001/"
        assert rh._owasp_url("A06:2021 Vulnerable and Outdated Components").endswith(
            "A06_2021-Vulnerable_and_Outdated_Components/")
        assert rh._cve_url("CVE-2021-23017") == "https://nvd.nist.gov/vuln/detail/CVE-2021-23017"
        assert rh._cve_url("CVE-7C51") == ""        # internal Hades id -> not a CVE link
        assert rh._cvss_url(_FakeF("CVSS:3.1/AV:N/AC:L")).startswith(
            "https://www.first.org/cvss/calculator/3.1#")
        # A rendered CVE finding wraps its badges in <a href> links.
        from scanner.engine import Finding, Severity
        f = Finding(module="cve_vulnerability", title="CVE-2021-23017", description="d",
                    severity=Severity.HIGH, recommendation="", cwe="CWE-787",
                    owasp="A06:2021 Vulnerable and Outdated Components", mitre=["T1190"],
                    cvss=9.8, raw={"cve_id": "CVE-2021-23017", "cvss_vector": "CVSS:3.1/AV:N"})
        html_out = rh._refs_html(f, "#ff0000")
        assert 'href="https://nvd.nist.gov/vuln/detail/CVE-2021-23017"' in html_out
        assert "cwe.mitre.org/data/definitions/787.html" in html_out
        assert "attack.mitre.org/techniques/T1190/" in html_out


class _FakeF:
    def __init__(self, vector: str) -> None:
        self.raw = {"cvss_vector": vector}


# ---------------------------------------------------------------------------
# Out-of-band / blind-vuln (OAST) tests
# ---------------------------------------------------------------------------

class TestOOB:
    def test_profile_registered(self):
        from config import PROFILE_MODULES
        assert PROFILE_MODULES["oob_scan"] == ["scanner.oob.oob_detect"]

    def test_listener_records_callback(self):
        import time
        from scanner.oob.listener import OOBListener
        lis = OOBListener(public_host="127.0.0.1", bind="127.0.0.1")
        lis.start()
        try:
            tok = lis.new_token()
            httpx.get(lis.url_for(tok), timeout=2)
            time.sleep(0.2)
            hits = lis.hits_for(tok)
            assert hits and hits[0].source_ip == "127.0.0.1"
        finally:
            lis.stop()

    def test_tunnel_returns_none_without_tools(self, monkeypatch):
        from scanner.oob import tunnel as tmod
        monkeypatch.setattr(tmod.shutil, "which", lambda name: None)   # no cloudflared/ngrok
        t = tmod.Tunnel()
        assert t.start(12345, timeout=1.0) is None

    def test_detects_blind_ssrf_via_callback(self):
        """A target that fetches the injected URL (blind SSRF) triggers an OAST callback."""
        from urllib.parse import parse_qs, urlparse
        from scanner.engine import ScanEngine
        from scanner.oob import oob_detect

        class _SSRFTarget(httpx.BaseTransport):
            def handle_request(self, request: httpx.Request) -> httpx.Response:
                val = (parse_qs(urlparse(str(request.url)).query).get("cmd") or [""])[0]
                # Simulate SSRF: the server fetches a bare URL supplied in the parameter.
                if val.startswith("http://127.0.0.1"):
                    try:
                        httpx.get(val, timeout=2)
                    except Exception:
                        pass
                return httpx.Response(200, text="ok")

        eng = ScanEngine("http://target.test/vuln?cmd=1", rate_delay=0,
                         oob_host="127.0.0.1", oob_port=0)
        eng._client = httpx.Client(transport=_SSRFTarget(), follow_redirects=True, verify=False)
        eng.oob_wait = 0.6
        findings = oob_detect.run(eng)
        ssrf = [f for f in findings if f.raw.get("oob_category") == "ssrf"]
        assert ssrf, "blind SSRF should be confirmed via the out-of-band callback"
        assert ssrf[0].severity is Severity.HIGH
        assert ssrf[0].raw.get("source_ip")


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

    def test_engage_end_to_end_rce(self, monkeypatch, tmp_path):
        """Full chain: mock a command-injection endpoint, run engage --exploit, assert RCE + evidence."""
        from scanner.engine import ScanEngine
        from scanner.offensive import engage

        # The injectable parameter lives on the target URL itself, so iter_injectors picks
        # it up without depending on link crawling. The endpoint reflects command output.
        rce_out = "uid=0(root) gid=0(root) groups=0(root)"
        responses = {
            "https://example.com/run": httpx.Response(200, text=rce_out,
                                                      headers={"content-type": "text/html"}),
        }
        eng = ScanEngine("https://example.com/run?cmd=ls", rate_delay=0, exploit=True)
        eng._client = httpx.Client(transport=MockTransport(responses), follow_redirects=True, verify=False)
        # Keep evidence writes inside the test's tmp dir (no project loot/ pollution).
        monkeypatch.setattr(engage, "_loot_dir", lambda e: tmp_path)

        findings = engage.run(eng)

        # Detection confirmed the command injection…
        assert any(f.module == "command_injection" and f.severity is Severity.CRITICAL
                   for f in findings)
        # …and engage actively proved RCE and wrote evidence.
        rce = [f for f in findings if f.module == "engage" and f.raw.get("engage_category") == "rce"]
        assert rce, "engage should have proven RCE"
        assert rce[0].raw.get("evidence_file"), "evidence file should be written"
        assert (tmp_path / "rce_cmd.txt").exists()
        result = next(f for f in findings if f.raw.get("engage_category") == "result")
        assert result.raw["footholds"] >= 1

    def test_engage_exploit_clean_target_creates_no_loot(self, monkeypatch):
        """--exploit on a target with nothing exploitable must not create a loot dir."""
        from scanner.engine import ScanEngine
        from scanner.offensive import engage

        def _fail_loot(_e):
            raise AssertionError("loot dir must not be created when nothing is exploitable")

        monkeypatch.setattr(engage, "_loot_dir", _fail_loot)
        eng = ScanEngine("https://example.com/run?cmd=ls", rate_delay=0, exploit=True)
        eng._client = httpx.Client(transport=MockTransport({}, default_status=404),
                                   follow_redirects=True, verify=False)
        findings = engage.run(eng)                       # must not raise
        result = next(f for f in findings if f.raw.get("engage_category") == "result")
        assert result.raw["footholds"] == 0
        assert result.severity is Severity.INFO


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

        # The DB error must be INTRODUCED by a breaking payload — the clean baseline is error-free,
        # otherwise a page that always prints that text would be a false positive.
        class _T(httpx.BaseTransport):
            def handle_request(self, request: httpx.Request) -> httpx.Response:
                q = str(request.url)
                if "%27" in q or "%22" in q or "'" in q or '"' in q:
                    return httpx.Response(200, text=sql_error_html)
                return httpx.Response(200, text="<html><body>ok, record found</body></html>")

        eng = ScanEngine(base_url, rate_delay=0)
        eng.get_crawl = MagicMock(return_value=CrawlResult(
            parametrised_urls=[f"{base_url}/search?id=1"],
        ))
        eng._client = httpx.Client(transport=_T(), follow_redirects=True, verify=False)

        findings = run(eng)

        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert critical, "Expected Critical finding for SQL error in response"
        assert any("sql" in f.title.lower() for f in critical)

    def test_preexisting_sql_error_text_is_not_false_positive(self, base_url):
        """A page that always prints SQL-error-like text (clean baseline included) is not SQLi."""
        from scanner.vulns.sqli_detect import run
        from scanner.crawler import CrawlResult

        err = "<html>You have an error in your SQL syntax near the manual</html>"

        class _T(httpx.BaseTransport):
            def handle_request(self, request: httpx.Request) -> httpx.Response:
                return httpx.Response(200, text=err)     # identical for baseline AND injected

        eng = ScanEngine(base_url, rate_delay=0)
        eng.get_crawl = MagicMock(return_value=CrawlResult(parametrised_urls=[f"{base_url}/p?id=1"]))
        eng._client = httpx.Client(transport=_T(), follow_redirects=True, verify=False)
        findings = run(eng)
        assert not any(f.raw.get("technique") == "error-based" for f in findings)

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

    def test_waf_block_page_reflecting_payload_is_not_xss(self, base_url):
        """A CloudFront/WAF 403 block page that echoes the payload must not be reported as XSS."""
        from scanner.vulns.xss_detect import run

        block = ("<html><head><title>ERROR: The request could not be satisfied</title></head>"
                 "<body><h1>403 ERROR</h1>Request blocked. Generated by cloudfront</body></html>")

        class _T(httpx.BaseTransport):
            def handle_request(self, req):                 # reflects nothing useful, always blocked
                val = parse_qs(urlparse(str(req.url)).query).get("q", [""])[0]
                return httpx.Response(403, text=block + f"<!--{val}-->")

        findings = run(self._eng(base_url, _T()))
        assert not any(f.severity == Severity.HIGH for f in findings)

    def test_js_string_reflection_outside_script_is_not_high(self, base_url):
        """The js-string breakout must land inside <script>; a bare reflection in HTML isn't execution."""
        from scanner.vulns.xss_detect import run

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                val = parse_qs(urlparse(str(req.url)).query).get("q", [""])[0]
                esc = val.replace("'", "\\'")              # script string is correctly escaped
                return httpx.Response(200, text=f"<script>var ref='{esc}';</script><div>{val}</div>")

        findings = run(self._eng(base_url, _T()))
        assert not any(f.severity == Severity.HIGH and f.raw.get("context") == "js_string"
                       for f in findings)

    def test_stored_xss_via_form_is_high(self, base_url, monkeypatch):
        """Value not echoed in the POST response but rendered unescaped on a display page → Stored XSS."""
        from scanner.vulns.xss_detect import run
        from scanner.vulns import dom_xss
        from scanner.crawler import CrawlResult, Form
        monkeypatch.setattr(dom_xss, "candidates", lambda e: [])   # this test covers the httpx pass only

        class _T(httpx.BaseTransport):
            def __init__(self):
                self.store: list[str] = []

            def handle_request(self, req):
                if req.method == "POST":
                    msg = parse_qs(req.content.decode()).get("message", [""])[0]
                    self.store.append(msg)
                    return httpx.Response(200, text="<html>posted, thanks</html>",
                                         headers={"content-type": "text/html"})
                items = "".join(f"<blockquote>{m}</blockquote>" for m in self.store)
                return httpx.Response(200, text=f"<html><body>{items}</body></html>",
                                     headers={"content-type": "text/html"})

        form = Form(action=f"{base_url}/post", method="post",
                    fields={"message": "test"}, source_url=base_url)
        eng = ScanEngine(base_url, rate_delay=0)
        eng.get_crawl = MagicMock(return_value=CrawlResult(forms=[form]))
        eng._client = httpx.Client(transport=_T(), follow_redirects=True, verify=False)

        findings = run(eng)
        stored = [f for f in findings if f.severity == Severity.HIGH and f.title.startswith("Stored XSS")]
        assert stored, [f.title for f in findings]
        assert stored[0].raw.get("evidence")

    def test_stored_encoded_value_is_low(self, base_url, monkeypatch):
        """A stored value echoed *escaped* on the display page is LOW, never a HIGH stored XSS."""
        from scanner.vulns.xss_detect import run
        from scanner.vulns import dom_xss
        from scanner.crawler import CrawlResult, Form
        import html as htmllib
        monkeypatch.setattr(dom_xss, "candidates", lambda e: [])   # this test covers the httpx pass only

        class _T(httpx.BaseTransport):
            def __init__(self):
                self.store: list[str] = []

            def handle_request(self, req):
                if req.method == "POST":
                    self.store.append(parse_qs(req.content.decode()).get("message", [""])[0])
                    return httpx.Response(200, text="<html>ok</html>",
                                         headers={"content-type": "text/html"})
                items = "".join(f"<blockquote>{htmllib.escape(m)}</blockquote>" for m in self.store)
                return httpx.Response(200, text=f"<html><body>{items}</body></html>",
                                     headers={"content-type": "text/html"})

        form = Form(action=f"{base_url}/post", method="post",
                    fields={"message": "test"}, source_url=base_url)
        eng = ScanEngine(base_url, rate_delay=0)
        eng.get_crawl = MagicMock(return_value=CrawlResult(forms=[form]))
        eng._client = httpx.Client(transport=_T(), follow_redirects=True, verify=False)

        findings = run(eng)
        assert not any(f.title.startswith("Stored XSS:") and f.severity == Severity.HIGH for f in findings)
        assert any(f.severity == Severity.LOW for f in findings)


# ---------------------------------------------------------------------------
# dom_xss tests (browser-verified DOM/stored XSS — pure logic, no real browser)
# ---------------------------------------------------------------------------

class _FakePage:
    def __init__(self, hits):
        self._hits = hits

    def evaluate(self, expr):
        return self._hits


class TestDomXss:
    def test_payload_carries_token(self):
        from scanner.vulns import dom_xss
        p = dom_xss._payload("deadbeefcafe")
        assert "deadbeefcafe" in p and "onerror" in p and "__hadesxss" in p

    def test_fired_token_distinguishes_hook_and_alert(self):
        from scanner.vulns import dom_xss
        assert dom_xss._fired_token(_FakePage(["tok1"]), "tok1") == "dom-hook"
        assert dom_xss._fired_token(_FakePage(["ALERT:tok2"]), "tok2") == "alert"
        assert dom_xss._fired_token(_FakePage(["other"]), "tok3") == ""
        assert dom_xss._fired_token(_FakePage([]), "tok4") == ""

    def test_candidates_prioritise_textish_form_pages(self, monkeypatch):
        from scanner.vulns import dom_xss
        from scanner.crawler import CrawlResult, Form
        monkeypatch.undo()                                  # exercise the real candidates()
        f_text = Form(action="http://app.test/post", method="post",
                      fields={"message": "x"}, source_url="http://app.test/board")
        f_plain = Form(action="http://app.test/sub", method="post",
                       fields={"id": "1"}, source_url="http://app.test/other")
        eng = ScanEngine("http://app.test", rate_delay=0)
        eng.get_crawl = MagicMock(return_value=CrawlResult(forms=[f_plain, f_text]))
        cands = dom_xss.candidates(eng)
        assert cands[0] == "http://app.test/board"          # textish form page first
        assert "http://app.test" in cands                   # the target itself
        assert cands[-1] == "http://app.test/other"         # non-textish form page last

    def test_to_finding_is_high_with_evidence_and_chain(self):
        from scanner.vulns import dom_xss
        hit = dom_xss.DomXssHit(url="http://app.test/level2/frame", field="message",
                                payload='"><img src=x onerror=...>', trigger="dom-hook", token="abc123")
        f = dom_xss.to_finding(hit)
        assert f.module == "xss_detect" and f.severity == Severity.HIGH
        assert "browser-verified" in f.title.lower()
        assert f.raw.get("evidence") and f.raw.get("exploitation")
        assert f.raw["trigger"] == "dom-hook"

    def test_fragment_payload_quoting_avoids_attribute_clash(self):
        """In a single-quoted attribute the token must be double-quoted (and vice-versa)."""
        from scanner.vulns import dom_xss
        sq_tmpl = "x' onerror='{cb}"                        # single-quoted onerror
        p = dom_xss._det_payload(sq_tmpl, '"', "TOKZ")
        assert 'window.__hadesxss("TOKZ")' in p             # token double-quoted → no early close
        assert dom_xss._poc_payload(sq_tmpl) == "x' onerror='alert(document.domain)"

    def test_to_finding_fragment_vector(self):
        from scanner.vulns import dom_xss
        poc = "https://t/level3/frame#x' onerror='alert(document.domain)"
        hit = dom_xss.DomXssHit(url="https://t/level3/frame", field="URL fragment (#)",
                                payload="x' onerror='...", trigger="dom-hook", token="tk",
                                vector="fragment", poc=poc)
        f = dom_xss.to_finding(hit)
        assert f.severity == Severity.HIGH and "URL fragment" in f.title
        assert f.raw["vector"] == "fragment"
        assert f.raw["exploitation"][0]["command"] == poc        # repro is the full hash URL

    def test_set_param_replaces_query_value(self):
        from scanner.vulns import dom_xss
        out = dom_xss._set_param("http://t/level4/frame?timer=3", "timer", "');PWN//")
        assert "timer=" in out and "3" not in out.split("timer=")[1][:3]

    def test_field_templates_cover_event_handler_breakout(self):
        """A form field can feed an event handler, so the templates must include a JS-string breakout."""
        from scanner.vulns import dom_xss
        payloads = [dom_xss._det_payload(t, q, "TOK") for t, q in dom_xss._FIELD_TEMPLATES]
        assert any(p.startswith("');") for p in payloads)          # single-quoted JS string close
        assert any("<img" in p for p in payloads)                  # innerHTML / attribute breakout

    def test_input_name_extracts_quoted_name(self):
        from scanner.vulns import xss_detect
        assert xss_detect._input_name("form field 'timer' (GET https://x)") == "timer"
        assert xss_detect._input_name("URL parameter 'timer'") == "timer"
        assert xss_detect._input_name("URL fragment (#)") is None

    def test_to_finding_param_vector_is_reflected_xss(self):
        from scanner.vulns import dom_xss
        poc = "http://t/level4/frame?timer=%27%29%3Balert(document.domain)%3B%2F%2F"
        hit = dom_xss.DomXssHit(url="http://t/level4/frame", field="URL parameter 'timer'",
                                payload="');...//", trigger="dom-hook", token="tk",
                                vector="param", poc=poc)
        f = dom_xss.to_finding(hit)
        assert f.severity == Severity.HIGH
        assert f.title.startswith("Reflected XSS (browser-verified)")   # reflected, not DOM-based
        assert "timer" in f.title and f.raw["vector"] == "param"
        assert f.raw["exploitation"][0]["command"] == poc

    def test_run_emits_info_hint_when_browser_unavailable(self, base_url, monkeypatch):
        """With forms present but no browser, xss_detect surfaces a single INFO install hint."""
        from scanner.vulns.xss_detect import run
        from scanner.vulns import dom_xss
        from scanner import browser
        from scanner.crawler import CrawlResult, Form
        monkeypatch.setattr(browser, "ensure_chromium", lambda: False)
        monkeypatch.setattr(dom_xss, "candidates", lambda e: ["http://hint.test/board"])

        class _T(httpx.BaseTransport):
            def handle_request(self, req):
                return httpx.Response(200, text="<html>nothing reflected</html>",
                                     headers={"content-type": "text/html"})

        form = Form(action=f"{base_url}/post", method="post",
                    fields={"message": "test"}, source_url=base_url)
        eng = ScanEngine(base_url, rate_delay=0)
        eng.get_crawl = MagicMock(return_value=CrawlResult(forms=[form]))
        eng._client = httpx.Client(transport=_T(), follow_redirects=True, verify=False)

        findings = run(eng)
        assert any(f.severity == Severity.INFO and "no browser" in f.title.lower() for f in findings)


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

    def test_low_value_disclosure_is_not_critical(self, base_url):
        """An exposed package.json is dependency disclosure (LOW), not a CRITICAL secret leak."""
        from scanner.web.sensitive_files import run

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                if request.url.path == "/package.json":
                    return httpx.Response(200, text='{"name":"app","dependencies":{"x":"1"}}',
                                          headers={"content-type": "application/json"})
                return httpx.Response(404, text="Not Found")

        eng = ScanEngine(base_url, rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=True, verify=False)
        pkg = [f for f in run(eng) if f.raw.get("path") == "/package.json"]
        assert pkg and pkg[0].severity == Severity.LOW

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

    def test_empty_htaccess_downgraded_to_low(self, base_url):
        """A /.htaccess that 200s with an empty body must be LOW, never a CRITICAL exposure."""
        from scanner.web.sensitive_files import run

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                if request.url.path == "/.htaccess":
                    return httpx.Response(200, text="", headers={"content-type": "text/plain"})
                return httpx.Response(404, text="Not Found")

        eng = ScanEngine(base_url, rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=True, verify=False)

        findings = run(eng)
        ht = [f for f in findings if f.raw.get("path") == "/.htaccess"]
        assert ht, "the empty /.htaccess should still surface as a (low) breadcrumb"
        assert all(f.severity == Severity.LOW for f in ht)
        assert not [f for f in ht if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert "empty body" in ht[0].title.lower()
        assert ht[0].raw.get("confidence") == "low"
        assert ht[0].raw.get("validation") == "LOW"

    def test_htaccess_with_rules_confirmed(self, base_url):
        """A /.htaccess whose body matches Apache directives is a confirmed HIGH exposure."""
        from scanner.web.sensitive_files import run

        body = "RewriteEngine On\nRewriteRule ^old$ /new [R=301,L]\n"

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                if request.url.path == "/.htaccess":
                    return httpx.Response(200, text=body, headers={"content-type": "text/plain"})
                return httpx.Response(404, text="Not Found")

        eng = ScanEngine(base_url, rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=True, verify=False)

        findings = run(eng)
        ht = [f for f in findings if f.raw.get("path") == "/.htaccess"]
        assert ht and ht[0].severity == Severity.HIGH
        assert ht[0].raw.get("confidence") == "high"
        assert ht[0].raw.get("validation") == "CONFIRMED"
        assert "exposed" in ht[0].title.lower()

    def test_signature_mismatch_needs_manual(self, base_url):
        """A wp-config.php 200 whose body lacks the expected signature is LOW needs-manual, not CRITICAL."""
        from scanner.web.sensitive_files import run

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                if request.url.path == "/wp-config.php":
                    return httpx.Response(200, text="placeholder, not php config",
                                          headers={"content-type": "text/plain"})
                return httpx.Response(404, text="Not Found")

        eng = ScanEngine(base_url, rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=True, verify=False)

        findings = run(eng)
        wp = [f for f in findings if f.raw.get("path") == "/wp-config.php"]
        assert wp, "an ambiguous 200 should surface as a low breadcrumb"
        assert all(f.severity == Severity.LOW for f in wp)
        assert not [f for f in findings if f.severity == Severity.CRITICAL]
        assert wp[0].raw.get("confidence") == "low"
        assert wp[0].raw.get("validation") == "NEEDS_MANUAL_VALIDATION"
        assert "manual validation" in wp[0].title.lower()


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

    def test_specialist_owned_paths_excluded(self, base_url, tmp_path):
        """The expanded wordlist's sensitive-file / backup / VCS-internal / key / dump paths are deferred
        to the dedicated content-validating modules, not probed as generic MEDIUM dir_scan paths."""
        from scanner.web.dir_scan import _load_wordlist

        specialist = [".git/config", ".git/HEAD", ".aws/credentials", ".ssh/id_rsa",
                      "config.php", "settings.php", "secrets.json", "credentials.json",
                      "backup.sql", "dump.sql", "server.key", "private.key",
                      "site.zip", "backup.tar.gz", "debug.log", "db.sqlite3", "adminer.php"]
        benign = ["admin", "api", "css", "js", "login", "cart", "dashboard"]
        wl = tmp_path / "wl.txt"
        wl.write_text("\n".join(specialist + benign) + "\n", encoding="utf-8")
        eng = ScanEngine(base_url, rate_delay=0)
        eng.wordlist = str(wl)

        paths = _load_wordlist(eng)
        for s in specialist:
            assert ("/" + s) not in paths, f"{s} should be excluded (owned by a dedicated module)"
        for b in benign:
            assert ("/" + b) in paths, f"{b} should be kept (benign directory)"

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
    def _patch(self, monkeypatch, labels, resolve, crtsh=None, fetch=None, cname=None):
        from scanner.web import subdomain_scan
        monkeypatch.setattr(subdomain_scan, "_load_labels", lambda: labels)
        monkeypatch.setattr(subdomain_scan, "_resolve", resolve)
        monkeypatch.setattr(subdomain_scan, "_crtsh", crtsh or (lambda d: set()))
        monkeypatch.setattr(subdomain_scan, "_fetch_body", fetch or (lambda eng, host: None))
        monkeypatch.setattr(subdomain_scan, "_cname_targets", cname or (lambda host: set()))
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

    def test_rotating_wildcard_suppressed(self, monkeypatch):
        """A CDN wildcard that rotates IPs must still suppress guessed labels (no false sensitives)."""
        import threading
        calls = {"n": 0}
        lock = threading.Lock()

        def fake_resolve(host):
            with lock:
                i = calls["n"]
                calls["n"] += 1
            # First 3 calls are the wildcard probes; alternate the two rotating IPs so the union
            # covers both. Everything afterwards lands on one of them -> must be suppressed.
            return {"1.1.1.1"} if i % 2 == 0 else {"2.2.2.2"}

        mod = self._patch(monkeypatch, ["dev", "admin"], fake_resolve)
        findings = mod.run(ScanEngine("https://example.com", rate_delay=0))
        assert not any(f.severity == Severity.LOW for f in findings)
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
        """Fingerprint + DNS pointing at the service (CNAME → *.amazonaws.com) → High takeover."""
        def fake_resolve(host):
            return {"203.0.113.7"} if host == "shop.example.com" else None
        mod = self._patch(monkeypatch, ["shop"], fake_resolve,
                          fetch=lambda eng, host: "<html>NoSuchBucket</html>",
                          cname=lambda host: ({"shop.example.com.s3.amazonaws.com"}
                                              if host == "shop.example.com" else set()))
        findings = mod.run(ScanEngine("https://example.com", rate_delay=0))
        takeover = [f for f in findings if "takeover" in f.title.lower()]
        assert takeover and takeover[0].severity == Severity.HIGH
        assert takeover[0].raw["service"] == "AWS S3"
        assert takeover[0].raw.get("evidence")

    def test_generic_404_without_dns_correlation_is_not_takeover(self, monkeypatch):
        """An App Engine *.appspot.com 404 (the apac.appspot.com false positive) must NOT be flagged:
        the page carries a generic 'not found on this server' string but DNS points at Google, not Unbounce."""
        def fake_resolve(host):
            return {"142.250.75.116"} if host.startswith("apac.") else None
        mod = self._patch(monkeypatch, ["apac"], fake_resolve,
                          fetch=lambda eng, host: ("<h1>Error: Not Found</h1>The requested URL was not "
                                                   "found on this server."),
                          cname=lambda host: set())          # resolves to Google A records, no service CNAME
        findings = mod.run(ScanEngine("https://appspot.com", rate_delay=0))
        assert not any("takeover" in f.title.lower() for f in findings)

    def test_takeover_requires_dns_correlation_unbounce(self, monkeypatch):
        """A real dangling Unbounce sub (CNAME → *.unbouncepages.com + its 404) IS reported — but Medium,
        because the fingerprint is a generic 404 (verify-manually rather than High)."""
        def fake_resolve(host):
            return {"1.2.3.4"} if host.startswith("promo.") else None
        mod = self._patch(monkeypatch, ["promo"], fake_resolve,
                          fetch=lambda eng, host: "The requested URL was not found on this server.",
                          cname=lambda host: ({"abc123.unbouncepages.com"}
                                              if host.startswith("promo.") else set()))
        findings = mod.run(ScanEngine("https://victim.com", rate_delay=0))
        takeover = [f for f in findings if "takeover" in f.title.lower()]
        assert takeover and takeover[0].raw["service"] == "Unbounce"
        assert takeover[0].severity == Severity.MEDIUM      # generic fingerprint → verify, not High
        assert takeover[0].raw.get("evidence")


# ---------------------------------------------------------------------------
# cookie_analysis severity calibration
# ---------------------------------------------------------------------------

class TestCookieAnalysis:
    @staticmethod
    def _run(set_cookies, scheme="https"):
        import scanner.web.cookie_analysis as ca

        class _T(httpx.BaseTransport):
            def handle_request(self, request: httpx.Request) -> httpx.Response:
                headers = [("content-type", "text/html")] + [("set-cookie", c) for c in set_cookies]
                return httpx.Response(200, text="<html></html>", headers=headers)

        eng = ScanEngine(f"{scheme}://t.test", rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=True, verify=False)
        return ca.run(eng)

    def test_session_cookie_missing_secure_is_high(self):
        f = [x for x in self._run(["sessionid=abc; Path=/"]) if x.raw.get("issue") == "missing_secure"]
        assert f and f[0].severity == Severity.HIGH

    def test_tracking_cookie_missing_secure_is_low(self):
        f = [x for x in self._run(["_ga=GA1.2.3; Path=/"]) if x.raw.get("issue") == "missing_secure"]
        assert f and f[0].severity == Severity.LOW    # non-session cookie -> not High

    def test_missing_samesite_calibrated_by_session(self):
        out = self._run(["sessionid=abc; Secure", "_ga=GA1; Secure"])
        sev = {x.raw["cookie"]: x.severity for x in out if x.raw.get("issue") == "missing_samesite"}
        assert sev.get("sessionid") == Severity.MEDIUM and sev.get("_ga") == Severity.LOW


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

    def test_framable_finding_carries_evidence(self, engine_factory, base_url):
        """A framable verdict must ship a non-empty evidence proof block."""
        from scanner.web.clickjacking import run
        eng = engine_factory({
            base_url: httpx.Response(200, text="<html><form><input type=password></form></html>"),
        })
        assert run(eng)[0].raw.get("evidence")


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

    def test_image_response_not_flagged(self, base_url, monkeypatch):
        """An image served for a backup path (asset / soft-404) must not be flagged as a backup."""
        from scanner.web import backup_files
        monkeypatch.setattr(backup_files, "_candidates", lambda eng: ["/backup.zip"])

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                if request.url.path == "/backup.zip":
                    return httpx.Response(200, content=b"\x89PNG\r\n\x1a\nnotazip",
                                          headers={"content-type": "image/png"})
                return httpx.Response(404, text="nf")

        eng = ScanEngine(base_url, rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=True, verify=False)
        assert not [f for f in backup_files.run(eng) if f.severity == Severity.CRITICAL]


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

    def test_dnsbl_error_codes_are_not_listings(self, monkeypatch):
        import socket
        from scanner.web import blacklist_check

        answers = {"a.bl": "127.0.0.2",            # genuine listing
                   "b.bl": "127.255.255.254",      # Spamhaus "public resolver" error code
                   "c.bl": "127.255.255.252",      # config-error code
                   "d.bl": "9.9.9.9"}              # not a 127.x answer

        def fake_resolve(query: str) -> str:
            if query in answers:
                return answers[query]
            raise OSError("NXDOMAIN")
        monkeypatch.setattr(socket, "gethostbyname", fake_resolve)

        assert blacklist_check._is_listed("a.bl") is True
        assert blacklist_check._is_listed("b.bl") is False   # error code, not a real listing
        assert blacklist_check._is_listed("c.bl") is False
        assert blacklist_check._is_listed("d.bl") is False
        assert blacklist_check._is_listed("missing.bl") is False


# ---------------------------------------------------------------------------
# screenshot tests
# ---------------------------------------------------------------------------

class TestScreenshot:
    def test_capture_success(self, base_url, monkeypatch):
        from scanner.web import screenshot
        from scanner import browser
        monkeypatch.setattr(browser, "ensure_chromium", lambda: True)
        monkeypatch.setattr(screenshot, "_capture", lambda eng, path: None)

        findings = screenshot.run(ScanEngine(base_url, rate_delay=0))
        assert findings[0].severity == Severity.INFO and "captured" in findings[0].title.lower()

    def test_capture_failure_is_graceful(self, base_url, monkeypatch):
        from scanner.web import screenshot
        from scanner import browser
        monkeypatch.setattr(browser, "ensure_chromium", lambda: True)

        def boom(eng, path):
            raise RuntimeError("page navigation timed out")

        monkeypatch.setattr(screenshot, "_capture", boom)
        findings = screenshot.run(ScanEngine(base_url, rate_delay=0))
        assert findings[0].severity == Severity.INFO and "not captured" in findings[0].title.lower()

    def test_browser_unavailable_is_graceful(self, base_url, monkeypatch):
        """If the browser can't be installed, the scan still continues with a clear note."""
        from scanner.web import screenshot
        from scanner import browser
        monkeypatch.setattr(browser, "ensure_chromium", lambda: False)

        findings = screenshot.run(ScanEngine(base_url, rate_delay=0))
        assert findings[0].severity == Severity.INFO
        assert "playwright install" in findings[0].description.lower()
        assert "antivirus" in findings[0].description.lower()

    def test_autoinstall_runs_once_when_missing(self, monkeypatch, tmp_path):
        """ensure_chromium installs once when the binary is missing, then re-checks."""
        from scanner import browser

        browser._install_attempted = False
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

        monkeypatch.setattr(browser, "_browser_path", fake_path)
        monkeypatch.setattr(browser.subprocess, "run", fake_install)
        assert browser.ensure_chromium() is True
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

    # --- Axis 1: broadened engine coverage ---
    def test_modern_mongodb_op_msg_detected(self, monkeypatch):
        from scanner.db import db_security
        reply = (b"\x01" * 16 + b" databases sizeOnDisk "
                 + b"\x02name\x00\x05\x00\x00\x00prod\x00"
                 + b"\x02name\x00\x06\x00\x00\x00users\x00")
        monkeypatch.setattr(db_security, "_tcp_send_recv",
                            lambda host, port, payload, timeout=3.0, read=4096: reply)
        m = db_security._check_mongodb("10.0.0.2", 27017)
        assert m and m[0].raw["db_category"] == "unauth" and m[0].raw["databases"] == ["prod", "users"]
        assert m[0].raw.get("evidence") and m[0].raw.get("exploitation")

    def test_clickhouse_unauth_detected(self):
        from scanner.db import db_security

        class _CH(httpx.BaseTransport):
            def handle_request(self, request):
                return httpx.Response(200, text="default\nsystem\nshop\n",
                                      headers={"x-clickhouse-server-display-name": "ch01",
                                               "content-type": "text/plain"})
        ch = db_security._check_clickhouse(self._engine(transport=_CH()), "10.0.0.1", 8123)
        assert ch and ch[0].raw["db_category"] == "unauth" and "ClickHouse" in ch[0].title
        assert ch[0].raw.get("evidence") and ch[0].raw.get("exploitation")

    def test_zookeeper_four_letter_word_unauth(self, monkeypatch):
        from scanner.db import db_security
        monkeypatch.setattr(db_security, "_tcp_send_recv",
                            lambda host, port, payload, timeout=3.0, read=4096:
                            b"Zookeeper version: 3.4.10-39d3a4f\nClients:\n /10.0.0.5:52810")
        z = db_security._check_zookeeper("10.0.0.3", 2181)
        assert z and z[0].raw["engine"] == "Zookeeper" and z[0].raw.get("evidence")

    # --- Axis 3: version → CVE correlation ---
    def test_cve_correlation_fires_on_vulnerable_version_only(self):
        from scanner.db.db_security import _check_versions, _OpenPort
        vuln = _check_versions("1.2.3.4", [_OpenPort(6379, "Redis", "redis_version:6.0.5", "6.0.5")])
        assert vuln and vuln[0].raw["cve_id"] == "CVE-2022-0543" and vuln[0].raw["db_category"] == "cve"
        patched = _check_versions("1.2.3.4", [_OpenPort(6379, "Redis", "redis_version:7.2.0", "7.2.0")])
        assert not patched

    # --- Axis 3: every actionable finding is evidence-grade + carries a kill-chain ---
    def test_redis_finding_has_evidence_and_exploitation(self, monkeypatch):
        from scanner.db import db_security

        def fake_tcp(host, port, payload, timeout=3.0, read=4096):
            if b"PING" in payload:
                return b"+PONG\r\n"
            if b"INFO" in payload:
                return b"redis_version:7.0.5\r\n"
            if b"DBSIZE" in payload:
                return b":42\r\n"
            if b"KEYS" in payload:
                return b"*1\r\nsession:abc\r\n"
            return b""
        monkeypatch.setattr(db_security, "_tcp_send_recv", fake_tcp)
        r = db_security._check_redis("10.0.0.9", 6379)
        assert r and r[0].raw.get("evidence")
        steps = r[0].raw.get("exploitation")
        assert isinstance(steps, list) and any("redis-cli" in s["command"] for s in steps)

    def test_build_playbook_expands_multistep_chain(self):
        from scanner.db.db_security import build_playbook
        from scanner.engine import Finding, Severity
        f = Finding(module="db_security", title="Redis unauth", description="", severity=Severity.CRITICAL,
                    raw={"db_category": "unauth", "exploitation": [
                        {"step": 1, "description": "connect", "command": "redis-cli -h h -p 6379"},
                        {"step": 2, "description": "dump", "command": "KEYS *"}]})
        plan = build_playbook([f])
        assert plan and len(plan[0]["steps"]) == 2 and plan[0]["command"].startswith("redis-cli")

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
# nmap_scan integration tests
# ---------------------------------------------------------------------------

_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2p1"/></port>
      <port protocol="tcp" portid="6379"><state state="open"/>
        <service name="redis" product="Redis key-value store" version="6.0.16"/></port>
      <port protocol="tcp" portid="443"><state state="closed"/>
        <service name="https"/></port>
    </ports>
    <os><osmatch name="Linux 5.4"/></os>
  </host>
</nmaprun>"""


class TestNmapScan:
    def test_parse_open_ports_and_os(self):
        from scanner.integrations import nmap_scan
        ports, os_guess = nmap_scan._parse(_NMAP_XML)
        by_port = {p[0]: p for p in ports}
        assert set(by_port) == {22, 6379}                       # the closed 443 is excluded
        assert by_port[22][2] == "ssh" and "OpenSSH" in by_port[22][3]
        assert os_guess == "Linux 5.4"

    def test_missing_nmap_is_graceful_info(self, monkeypatch):
        from scanner.integrations import nmap_scan
        monkeypatch.setattr(nmap_scan, "which", lambda *a: None)
        findings = nmap_scan.run(ScanEngine("http://host.test", rate_delay=0))
        assert len(findings) == 1 and findings[0].severity == Severity.INFO
        assert "not installed" in findings[0].title.lower()

    def test_safe_mode_skips(self):
        from scanner.integrations import nmap_scan
        from config import SAFE_MODE_RATE_DELAY
        findings = nmap_scan.run(ScanEngine("http://host.test", rate_delay=SAFE_MODE_RATE_DELAY))
        assert findings[0].severity == Severity.INFO and "safe mode" in findings[0].title.lower()

    def test_run_emits_severity_rated_findings(self, monkeypatch):
        from scanner.integrations import nmap_scan
        monkeypatch.setattr(nmap_scan, "which", lambda *a: "/usr/bin/nmap")
        monkeypatch.setattr(nmap_scan, "run_tool", lambda cmd, timeout: (0, _NMAP_XML, ""))
        findings = nmap_scan.run(ScanEngine("http://host.test", rate_delay=0))
        redis = [f for f in findings if f.raw.get("port") == 6379]
        ssh = [f for f in findings if f.raw.get("port") == 22]
        assert redis and redis[0].severity == Severity.HIGH and "6.0.16" in redis[0].title
        assert ssh and ssh[0].severity == Severity.LOW
        assert any("OS Fingerprint" in f.title for f in findings)
        assert redis[0].raw.get("evidence")


# ---------------------------------------------------------------------------
# gobuster_scan integration tests
# ---------------------------------------------------------------------------

_GOBUSTER_OUT = """/admin                (Status: 301) [Size: 234] [--> /admin/]
/images               (Status: 200) [Size: 1234]
/.git                 (Status: 200) [Size: 92]
/server-status        (Status: 403) [Size: 300]
"""


class TestGobusterScan:
    def test_parse_paths(self):
        from scanner.integrations import gobuster_scan
        paths = gobuster_scan._parse(_GOBUSTER_OUT)
        by = {p: (s, z) for p, s, z in paths}
        assert by["/admin"][0] == 301 and by["/images"] == (200, 1234)
        assert "/server-status" in by and len(paths) == 4

    def test_missing_gobuster_is_graceful_info(self, monkeypatch):
        from scanner.integrations import gobuster_scan
        monkeypatch.setattr(gobuster_scan, "which", lambda *a: None)
        findings = gobuster_scan.run(ScanEngine("http://t.test", rate_delay=0))
        assert len(findings) == 1 and "not installed" in findings[0].title.lower()

    def test_safe_mode_skips(self):
        from scanner.integrations import gobuster_scan
        from config import SAFE_MODE_RATE_DELAY
        findings = gobuster_scan.run(ScanEngine("http://t.test", rate_delay=SAFE_MODE_RATE_DELAY))
        assert "safe mode" in findings[0].title.lower()

    def test_run_summarises_discovered_paths(self, monkeypatch):
        from scanner.integrations import gobuster_scan
        monkeypatch.setattr(gobuster_scan, "which", lambda *a: "/usr/bin/gobuster")
        monkeypatch.setattr(gobuster_scan, "run_tool", lambda cmd, timeout: (0, _GOBUSTER_OUT, ""))
        findings = gobuster_scan.run(ScanEngine("http://t.test", rate_delay=0))
        assert len(findings) == 1 and findings[0].raw["count"] == 4
        assert any(p["path"] == "/admin" for p in findings[0].raw["paths"])
        assert findings[0].raw.get("evidence")


# ---------------------------------------------------------------------------
# theharvester_scan integration tests
# ---------------------------------------------------------------------------

class TestTheHarvesterScan:
    def test_parse_extracts_emails_hosts_ips(self):
        from scanner.integrations import theharvester_scan as th
        data = {"emails": ["a@x.com", "a@x.com", " b@x.com "],
                "hosts": ["www.x.com:1.2.3.4", "API.x.com", ""],
                "ips": ["1.2.3.4", "1.2.3.4"]}
        emails, hosts, ips = th._parse(data)
        assert emails == ["a@x.com", "b@x.com"]
        assert hosts == ["api.x.com", "www.x.com"]           # lowercased, ip stripped, deduped
        assert ips == ["1.2.3.4"]

    def test_domain_extraction(self):
        from scanner.integrations import theharvester_scan as th
        assert th._domain("https://www.example.co/path") == "example.co"

    def test_build_findings_emails_are_low_hosts_info(self):
        from scanner.integrations import theharvester_scan as th
        findings = th._build_findings("x.com", ["a@x.com"], ["api.x.com"], ["1.2.3.4"])
        emails = [f for f in findings if "E-mail" in f.title]
        assert emails and emails[0].severity == Severity.LOW and emails[0].raw.get("evidence")
        assert any(f.severity == Severity.INFO and "Host" in f.title for f in findings)

    def test_missing_theharvester_is_graceful_info(self, monkeypatch):
        from scanner.integrations import theharvester_scan as th
        monkeypatch.setattr(th, "which", lambda *a: None)
        findings = th.run(ScanEngine("http://x.com", rate_delay=0))
        assert len(findings) == 1 and "not installed" in findings[0].title.lower()


# ---------------------------------------------------------------------------
# reconng_scan integration tests
# ---------------------------------------------------------------------------

class TestReconngScan:
    def test_read_hosts_from_workspace_db(self, tmp_path):
        import sqlite3
        from scanner.integrations import reconng_scan as r
        db = tmp_path / "data.db"
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE hosts (host TEXT, ip_address TEXT)")
        con.executemany("INSERT INTO hosts VALUES (?, ?)",
                        [("WWW.x.com", "1.2.3.4"), ("api.x.com", None), ("www.x.com", "1.2.3.4")])
        con.commit()
        con.close()
        hosts = r._read_hosts(str(db))
        assert ("www.x.com", "1.2.3.4") in hosts and ("api.x.com", "") in hosts
        assert len(hosts) == 2                               # deduped + lowercased

    def test_resource_script_sets_source_and_modules(self):
        from scanner.integrations import reconng_scan as r
        script = r._resource_script("example.com")
        assert "options set SOURCE example.com" in script
        assert "modules load recon/domains-hosts/hackertarget" in script
        assert script.strip().endswith("exit")

    def test_build_findings_summary(self):
        from scanner.integrations import reconng_scan as r
        findings = r._build_findings("x.com", [("api.x.com", "1.2.3.4"), ("www.x.com", "")])
        assert findings[0].severity == Severity.INFO and findings[0].raw["count"] == 2
        assert findings[0].raw.get("evidence")

    def test_missing_reconng_is_graceful_info(self, monkeypatch):
        from scanner.integrations import reconng_scan as r
        monkeypatch.setattr(r, "which", lambda *a: None)
        findings = r.run(ScanEngine("http://x.com", rate_delay=0))
        assert len(findings) == 1 and "not installed" in findings[0].title.lower()


# ---------------------------------------------------------------------------
# maltego_export tests
# ---------------------------------------------------------------------------

class TestMaltegoExport:
    def _findings(self):
        return [
            Finding("subdomain_scan", "x", "", Severity.INFO, "", {"subdomains": ["api.x.com", "www.x.com"]}),
            Finding("theharvester_scan", "x", "", Severity.LOW, "", {"emails": ["a@x.com"]}),
            Finding("nmap_scan", "x", "", Severity.HIGH, "", {"host": "x.com", "ip": "1.2.3.4"}),
            Finding("reconng_scan", "x", "", Severity.INFO, "", {"hosts": [{"host": "vpn.x.com", "ip": "5.6.7.8"}]}),
        ]

    def test_build_rows_extracts_entities(self):
        from scanner.output import maltego_export as mx
        rows = mx.build_rows("https://www.x.com", self._findings())
        types = {(t, v) for t, v, _ in rows}
        assert ("Domain", "x.com") in types
        assert ("DNSName", "api.x.com") in types and ("DNSName", "vpn.x.com") in types
        assert ("EmailAddress", "a@x.com") in types
        assert ("IPv4Address", "1.2.3.4") in types and ("IPv4Address", "5.6.7.8") in types

    def test_build_rows_deduplicates(self):
        from scanner.output import maltego_export as mx
        dup = [Finding("a", "x", "", Severity.INFO, "", {"subdomains": ["api.x.com"]}),
               Finding("b", "x", "", Severity.INFO, "", {"subdomains": ["API.x.com"]})]
        rows = [r for r in mx.build_rows("https://x.com", dup) if r[0] == "DNSName"]
        assert len(rows) == 1                                # case-insensitive dedupe

    def test_export_writes_csv(self, tmp_path):
        import csv
        from scanner.output import maltego_export as mx
        path = mx.export("https://x.com", self._findings(), tmp_path)
        with open(path, newline="", encoding="utf-8") as fh:
            rows = list(csv.reader(fh))
        assert rows[0] == ["EntityType", "Value", "LinkedTo"]
        assert any(r[0] == "DNSName" and r[1] == "api.x.com" for r in rows)


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
                '<a href="mailto:info@acme-corp.com">mail</a> '
                'reach us at sales@acme-corp.com '
                '<img src="/logo@2x.png"> placeholder you@example.com'
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
        assert "info@acme-corp.com" in result.emails
        assert "sales@acme-corp.com" in result.emails
        # Asset references and RFC-2606 placeholders are filtered out (not real exposures)
        assert "logo@2x.png" not in result.emails
        assert "you@example.com" not in result.emails
        # External link separated from internal ones
        assert "https://external.com/page" in result.external_links

    def test_email_filtering(self):
        from scanner.crawler import _is_real_email
        assert _is_real_email("info@acme-corp.com")
        assert _is_real_email("a.b+c@sub.example.io")
        assert not _is_real_email("logo@2x.png")              # retina asset reference
        assert not _is_real_email("sprite@3x.svg")
        assert not _is_real_email("app@bundle.min.js")
        assert not _is_real_email("you@example.com")          # RFC-2606 placeholder
        assert not _is_real_email("deadbeef@o12.ingest.sentry.io")   # Sentry DSN
        assert not _is_real_email("notanemail")

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

    def test_critical_findings_carry_evidence(self):
        """Both CRITICAL JWT findings must ship a non-empty evidence proof block."""
        from scanner.vulns import jwt_attacks
        from scanner.crawler import CrawlResult
        none_tok = _make_jwt({"role": "admin"}, alg="none")
        weak_tok = _make_jwt({"role": "admin"}, secret="secret")
        eng = ScanEngine("http://jwt.test", rate_delay=0)
        eng.get_crawl = MagicMock(return_value=CrawlResult(
            pages={"http://jwt.test/a.js": f'a="{none_tok}"; b="{weak_tok}"'}))
        eng._client = httpx.Client(transport=_All404(), follow_redirects=True, verify=False)
        crit = [f for f in jwt_attacks.run(eng) if f.severity == Severity.CRITICAL]
        assert len(crit) == 2
        assert all(f.raw.get("evidence") for f in crit)


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

    def test_homepage_routing_is_not_a_bypass(self):
        """A path mutation that just routes to the generic homepage (200) is not a real bypass."""
        from scanner.vulns import auth_bypass

        home = "<html><body>Welcome home — lots of normal marketing content here.</body></html>"

        class _T(httpx.BaseTransport):
            def handle_request(self, req: httpx.Request) -> httpx.Response:
                p = req.url.path
                if p == "/admin":
                    return httpx.Response(403, text="Forbidden")
                if p == "/" or p.lower().startswith("/admin"):
                    return httpx.Response(200, text=home)     # mutations route to the homepage
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


# ---------------------------------------------------------------------------
# CORS severity calibration
# ---------------------------------------------------------------------------

class TestCorsCheck:
    @staticmethod
    def _run(base_url: str, acao_mode: str, creds: bool):
        import scanner.web.cors_check as cors

        class _T(httpx.BaseTransport):
            def handle_request(self, request: httpx.Request) -> httpx.Response:
                origin = request.headers.get("Origin", "")
                headers = {"content-type": "text/html"}
                if acao_mode == "reflect":
                    headers["access-control-allow-origin"] = origin
                elif acao_mode == "wildcard":
                    headers["access-control-allow-origin"] = "*"
                if creds:
                    headers["access-control-allow-credentials"] = "true"
                return httpx.Response(200, text="<html></html>", headers=headers)

        eng = ScanEngine(base_url, rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=True, verify=False)
        return cors.run(eng)

    def test_wildcard_no_creds_is_low(self, base_url):
        f = [x for x in self._run(base_url, "wildcard", False) if "Wildcard Origin (" in x.title]
        assert f and f[0].severity == Severity.LOW          # public CDN/API config — not HIGH

    def test_wildcard_with_creds_is_critical(self, base_url):
        assert any(x.severity == Severity.CRITICAL for x in self._run(base_url, "wildcard", True))

    def test_reflected_no_creds_is_medium(self, base_url):
        f = [x for x in self._run(base_url, "reflect", False) if "No Credentials" in x.title]
        assert f and f[0].severity == Severity.MEDIUM       # readable but unauthenticated → not HIGH

    def test_reflected_with_creds_is_critical(self, base_url):
        assert any(x.severity == Severity.CRITICAL for x in self._run(base_url, "reflect", True))


class TestCveMapping:
    _NVD = {"vulnerabilities": [{"cve": {
        "id": "CVE-2021-23017", "published": "2021-05-25T00:00:00", "lastModified": "2021-06-01T00:00:00",
        "descriptions": [{"lang": "en", "value": "nginx resolver off-by-one"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N"},
                                       "baseSeverity": "CRITICAL"}]},
        "weaknesses": [{"description": [{"value": "CWE-787"}]}], "references": [],
        "configurations": [{"nodes": [{"cpeMatch": [{
            "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", "vulnerable": True,
            "versionStartIncluding": "0.6.18", "versionEndExcluding": "1.21.0"}]}]}]}}]}

    def test_version_accurate_no_false_positive(self, tmp_path, monkeypatch):
        from scanner.cve import db as cvedb, feed_downloader as fd
        from scanner.vulns import cve_mapping
        from scanner.engine import ScanEngine

        monkeypatch.setattr(cvedb, "DB_PATH", tmp_path / "v.sqlite")
        monkeypatch.setattr(cve_mapping, "_NVD_DELAY", 0)
        monkeypatch.setattr(fd, "query_nvd", lambda *a, **k: self._NVD)
        eng = ScanEngine("https://target.test", rate_delay=0)

        # Detected version IS in the affected range -> mapped.
        hits = cve_mapping.lookup("nginx", "1.18.0", eng)
        assert any(f.raw.get("cve_id") == "CVE-2021-23017" for f in hits)
        assert all(f.module == "cve_mapping" for f in hits)
        # Patched version is NOT in range -> no finding (the old keywordSearch would have matched).
        assert cve_mapping.lookup("nginx", "1.25.0", eng) == []
        # No CPE alias for an unknown product -> no guessing, no false positive.
        assert cve_mapping.lookup("AcmeCustomServer", "1.0", eng) == []


class TestWafDetect:
    @staticmethod
    def _eng(home_status: int, headers: dict | None = None, probe_status: int | None = None):
        import scanner.recon.waf_detect as waf

        class _T(httpx.BaseTransport):
            def handle_request(self, request: httpx.Request) -> httpx.Response:
                if request.url.query and probe_status is not None:      # the malicious probe
                    return httpx.Response(probe_status, text="blocked")
                return httpx.Response(home_status, text="<html></html>", headers=headers or {})

        eng = ScanEngine("https://t.test", rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=True, verify=False)
        return eng, waf

    def test_header_fingerprint(self):
        eng, waf = self._eng(200, headers={"cf-ray": "abc-123"})
        assert any("Cloudflare" in f.title for f in waf.run(eng))

    def test_no_waf_is_info_not_low(self):
        eng, waf = self._eng(200, probe_status=200)
        f = [x for x in waf.run(eng) if "No WAF" in x.title]
        assert f and f[0].severity == Severity.INFO

    def test_503_site_not_flagged_as_waf(self):
        eng, waf = self._eng(503, probe_status=503)        # site down, not a WAF
        assert not any("Generic WAF" in f.title for f in waf.run(eng))

    def test_payload_block_is_generic_waf(self):
        eng, waf = self._eng(200, probe_status=406)        # clean 200, malicious 406
        assert any("Generic WAF" in f.title for f in waf.run(eng))


# ---------------------------------------------------------------------------
# Playbook HTML rendering (clickable badge -> readable page, not raw Markdown)
# ---------------------------------------------------------------------------

class TestPlaybookHtmlRendering:
    def test_local_md_playbook_rendered_to_html(self, tmp_path):
        import re
        from pathlib import Path
        from scanner.engine import Finding, Severity
        from scanner.output.report_html import generate_html

        skilldir = tmp_path / "skills" / "exploiting-sql-injection-vulnerabilities"
        skilldir.mkdir(parents=True)
        md = skilldir / "SKILL.md"
        md.write_text("---\nname: x\ntags:\n  - sqli\n---\n# Exploit SQLi\n\n```bash\nsqlmap -u URL\n```\n",
                      encoding="utf-8")

        f = Finding(module="sqli_detect", title="SQLi", description="x", severity=Severity.CRITICAL)
        f.skill_refs = [{"name": "exploiting-sql-injection-vulnerabilities",
                         "description": "Weaponize SQL injection.", "href": md.as_uri(),
                         "tags": ["sqli"], "mitre": ["T1190"]}]

        out = generate_html([f], "http://demo.test", 40, output_path=str(tmp_path / "reports"))
        report = Path(out).read_text(encoding="utf-8")
        hrefs = re.findall(r'class="ref-pill ref-play" href="([^"]+)"', report)
        assert hrefs and hrefs[0].endswith(".html")            # badge now points to rendered HTML
        pb = tmp_path / "reports" / "playbooks" / "exploiting-sql-injection-vulnerabilities.html"
        assert pb.is_file()
        page = pb.read_text(encoding="utf-8")
        assert "<pre>" in page and "sqlmap -u URL" in page      # markdown actually rendered
        assert "name: x" not in page                            # YAML frontmatter stripped

    def test_github_https_playbook_link_left_untouched(self, tmp_path):
        from scanner.engine import Finding, Severity
        from scanner.output.report_html import generate_html

        gh = "https://github.com/x/y/blob/main/skills/z/SKILL.md"
        f = Finding(module="sqli_detect", title="SQLi", description="x", severity=Severity.HIGH)
        f.skill_refs = [{"name": "z", "description": "d", "href": gh, "tags": [], "mitre": []}]
        generate_html([f], "http://d.test", 30, output_path=str(tmp_path / "reports"))
        assert f.skill_refs[0]["href"] == gh                    # GitHub renders Markdown already

    def test_github_url_helper_resolves_bundle(self):
        from scanner.intel.skills_kb import github_url
        u = github_url("exploiting-sql-injection-vulnerabilities")
        assert u.startswith("https://github.com/") and u.endswith("SKILL.md")
        assert github_url("does-not-exist-zzz") == ""

    def test_unreadable_local_md_falls_back_to_github(self, tmp_path):
        # A local file:// SKILL.md href that cannot be read must NOT stay a raw .md link:
        # the badge is repointed to the skill's GitHub (rendered) page.
        from scanner.engine import Finding, Severity
        from scanner.output.report_html import generate_html
        from scanner.intel.skills_kb import github_url

        name = "exploiting-sql-injection-vulnerabilities"
        missing = tmp_path / "skills" / name / "SKILL.md"   # never created → unreadable
        f = Finding(module="sqli_detect", title="SQLi", description="x", severity=Severity.CRITICAL)
        f.skill_refs = [{"name": name, "description": "d", "href": missing.as_uri(),
                         "tags": [], "mitre": []}]
        generate_html([f], "http://d.test", 40, output_path=str(tmp_path / "reports"))
        href = f.skill_refs[0]["href"]
        assert href == github_url(name)
        assert href.startswith("https://github.com/") and not href.startswith("file:")

    def test_missing_markdown_lib_repoints_to_github(self, tmp_path, monkeypatch):
        # When the `markdown` library is absent, a local SKILL.md cannot be rendered — the badge
        # must fall back to the GitHub page (rendered), never a raw file:// .md (the reported bug).
        import builtins
        from scanner.engine import Finding, Severity
        from scanner.output.report_html import generate_html
        from scanner.intel.skills_kb import github_url

        name = "exploiting-sql-injection-vulnerabilities"
        skilldir = tmp_path / "skills" / name
        skilldir.mkdir(parents=True)
        md = skilldir / "SKILL.md"
        md.write_text("# x\n", encoding="utf-8")             # exists locally, but markdown is missing

        real_import = builtins.__import__

        def fake_import(n, *a, **k):
            if n == "markdown":
                raise ImportError("simulated missing markdown")
            return real_import(n, *a, **k)

        monkeypatch.setattr(builtins, "__import__", fake_import)

        f = Finding(module="sqli_detect", title="SQLi", description="x", severity=Severity.CRITICAL)
        f.skill_refs = [{"name": name, "description": "d", "href": md.as_uri(),
                         "tags": [], "mitre": []}]
        generate_html([f], "http://d.test", 40, output_path=str(tmp_path / "reports"))
        href = f.skill_refs[0]["href"]
        assert href == github_url(name)
        assert href.startswith("https://github.com/") and "/blob/" in href
        assert not href.startswith("file:")                 # never a raw local .md


class TestExpandedSkillMatching:
    """The 754-skill library: smarter offensive matching, curated blue-team remediation, and the
    Skills Library page — all additive and precise."""

    @pytest.fixture(autouse=True)
    def _fresh_caches(self):
        from scanner.intel import skills_kb
        caches = (skills_kb.find_skills_repo, skills_kb._load_index, skills_kb._skill_detail,
                  skills_kb._load_bundle, skills_kb._skill_meta)
        for fn in caches:
            fn.cache_clear()
        yield
        for fn in caches:
            fn.cache_clear()

    def test_finding_has_remediation_refs_default(self):
        f = Finding(module="x", title="t", description="", severity=Severity.LOW)
        assert f.remediation_refs == []

    def test_curated_offensive_map_still_authoritative(self):
        from scanner.intel import skills_kb
        f = Finding(module="sqli_detect", title="SQL Injection: id", description="",
                    severity=Severity.CRITICAL)
        skills_kb.enrich([f])
        assert [s["name"] for s in f.skill_refs][:1] == ["exploiting-sql-injection-vulnerabilities"]

    def test_offensive_fallback_is_offensive_only(self):
        """A module absent from the curated map still gets an offensive playbook (never blue-team)."""
        import config
        from scanner.intel import skills_kb
        assert "sensitive_files" not in config.MODULE_SKILL_MAP
        f = Finding(module="sensitive_files", title=".env file exposed", description="",
                    severity=Severity.CRITICAL)
        skills_kb.enrich([f])
        names = [s["name"] for s in f.skill_refs]
        assert names, "the scorer should attach a relevant offensive playbook"
        assert all(n.startswith(skills_kb._OFFENSIVE_PREFIXES) for n in names)

    def test_broad_technique_alone_never_matches(self):
        """A shared but broad ATT&CK technique with zero lexical overlap must not attach noise."""
        from scanner.intel import skills_kb
        f = Finding(module="zz_unknown", title="Xyzzy plugh quux", description="",
                    severity=Severity.MEDIUM)
        f.mitre = ["T1190"]                       # shared by many skills; lexically irrelevant title
        assert skills_kb.match_skills(f) == []

    def test_curated_remediation_is_blue_team(self):
        from scanner.intel import skills_kb
        f = Finding(module="sqli_detect", title="SQL Injection: id", description="",
                    severity=Severity.CRITICAL)
        skills_kb.enrich([f])
        names = [s["name"] for s in f.remediation_refs]
        assert "implementing-web-application-logging-with-modsecurity" in names
        assert all(not n.startswith(skills_kb._OFFENSIVE_PREFIXES) for n in names)

    def test_remediation_never_duplicates_offensive(self):
        from scanner.intel import skills_kb
        f = Finding(module="cloud_buckets", title="Open S3 bucket readable", description="",
                    severity=Severity.HIGH)
        skills_kb.enrich([f])
        off = {s["name"] for s in f.skill_refs}
        rem = {s["name"] for s in f.remediation_refs}
        assert off.isdisjoint(rem)

    def test_info_finding_gets_no_remediation(self):
        from scanner.intel import skills_kb
        f = Finding(module="ssl_check", title="TLS configuration", description="",
                    severity=Severity.INFO)
        assert skills_kb.match_remediation(f) == []

    def test_all_skills_accessor(self):
        from scanner.intel.skills_kb import all_skills
        sk = all_skills()
        assert len(sk) >= 100
        keys = {"name", "description", "subdomain", "tags", "mitre", "offensive", "href"}
        assert keys <= set(sk[0])

    def test_skills_library_page_builds(self):
        from scanner.intel.skills_library import _build_html
        html = _build_html()
        assert html.count('class="skill"') >= 100      # one card per skill
        assert 'id="q"' in html                          # searchable
        assert "intent off" in html and "intent def" in html   # red/blue markers
        assert "chip atk" in html                        # ATT&CK chips
        assert "<section" in html                        # grouped by subdomain

    def test_bundle_has_subdomain_and_scale(self):
        import json
        from pathlib import Path
        p = Path(__file__).resolve().parent.parent / "scanner" / "intel" / "playbooks.json"
        bundle = json.loads(p.read_text(encoding="utf-8"))
        assert len(bundle) >= 700
        assert all("subdomain" in s and "offensive" in s for s in bundle)


class TestReportRefsCollapse:
    """Per-finding detail is collapsed into an expandable <details> so the report stays scannable."""

    def test_secondary_refs_collapsed_primary_visible(self):
        from scanner.output.report_html import _refs_html
        f = Finding(module="sqli_detect", title="SQLi: id", description="x",
                    severity=Severity.CRITICAL, cwe="CWE-89", owasp="A03:2021 Injection", cvss=9.8)
        f.mitre = ["T1190"]
        f.redteam_tools = ["sqlmap"]
        f.skill_refs = [{"name": "exploiting-sql-injection-vulnerabilities",
                         "href": "https://x/y", "mitre": []}]
        f.remediation_refs = [{"name": "implementing-web-application-logging-with-modsecurity",
                               "href": "https://x/z", "mitre": []}]
        f.poc = "sqlmap -u URL --batch"
        html = _refs_html(f, "#f85149")
        before = html.split("<details")[0]      # the always-visible part
        # at-a-glance classification stays visible
        for cls in ("ref-id", "ref-cvss", "ref-cwe", "ref-owasp"):
            assert cls in before, f"{cls} should be visible up front"
        # the heavy stuff is NOT in the always-visible row …
        for cls in ("ref-mitre", "ref-tool", "ref-play", "ref-fix", "poc-block"):
            assert cls not in before, f"{cls} should be collapsed"
        # … it lives inside the <details>
        assert "<details" in html and "</details>" in html
        for cls in ("ref-mitre", "ref-tool", "ref-play", "ref-fix", "poc-block"):
            assert cls in html, f"{cls} should still be present inside the details"

    def test_no_details_for_sparse_finding(self):
        from scanner.output.report_html import _refs_html
        f = Finding(module="basic_info", title="IP Address", description="1.2.3.4",
                    severity=Severity.INFO)
        html = _refs_html(f, "#58a6ff")
        assert "<details" not in html                 # nothing to collapse
        assert '<div class="refs">' in html           # primary row (finding ID) still rendered

    def test_poc_not_duplicated_in_description_cell(self):
        from scanner.output.report_html import _findings_table_html
        f = Finding(module="sqli_detect", title="SQLi", description="param id",
                    severity=Severity.CRITICAL)
        f.poc = "sqlmap -u URL --batch"
        table = _findings_table_html([f])
        # the PoC appears once (inside the details), not also in the description cell
        assert table.count("poc-block") == 1


# ---------------------------------------------------------------------------
# hephaestus_tls — offensive TLS audit (SSLyze) — tls_scan / menu option 9
# ---------------------------------------------------------------------------

from types import SimpleNamespace as _NS    # noqa: E402


def _att(result):
    return _NS(status=_NS(name="COMPLETED"), result=result)


def _cipher(name, anon=False, ks=256, eph=None):
    return _NS(cipher_suite=_NS(name=name, openssl_name=name, is_anonymous=anon, key_size=ks),
               ephemeral_key=eph)


def _ciphers(specs):
    return _att(_NS(accepted_cipher_suites=[_cipher(*s) if isinstance(s, tuple) else _cipher(s)
                                            for s in specs]))


class TestHephaestusTls:
    def test_profile_registered_and_menu(self):
        from config import PROFILE_MODULES
        assert PROFILE_MODULES["tls_scan"] == ["scanner.tls.hephaestus_tls"]

    def test_host_port_parsing(self):
        from scanner.tls.hephaestus_tls import _host_port
        assert _host_port("https://example.com") == ("example.com", 443)
        assert _host_port("https://example.com:8443/x") == ("example.com", 8443)
        assert _host_port("example.com") == ("example.com", 443)

    def test_protocol_severity_mapping(self):
        from scanner.tls.hephaestus_tls import _analyze_protocols
        sr = _NS(ssl_3_0_cipher_suites=_ciphers(["DES-CBC3-SHA"]),
                 tls_1_0_cipher_suites=_ciphers(["AES128-SHA"]),
                 tls_1_2_cipher_suites=_ciphers([("ECDHE-RSA-AES128-GCM-SHA256", False, 128, object())]))
        findings, supported = _analyze_protocols(sr, "t.test", 443)
        sev = {f.title: f.severity for f in findings}
        assert sev.get("SSL 3.0 Enabled") == Severity.HIGH
        assert sev.get("TLS 1.0 Enabled") == Severity.MEDIUM
        assert sev.get("TLS 1.3 Not Supported") == Severity.LOW   # 1.2 present, 1.3 absent
        assert "SSL 3.0" in supported and "TLS 1.2" in supported

    def test_weak_and_anonymous_ciphers(self):
        from scanner.tls.hephaestus_tls import _analyze_ciphers
        sr = _NS(tls_1_2_cipher_suites=_ciphers([
            ("RC4-MD5", False, 128, None),            # weak
            ("ADH-AES128-SHA", True, 128, object()),  # anonymous
            ("ECDHE-RSA-AES256-GCM-SHA384", False, 256, object())]))
        titles = {f.title: f.severity for f in _analyze_ciphers(sr, "t.test", 443)}
        assert titles.get("Anonymous/NULL Cipher Suites Accepted") == Severity.HIGH
        assert titles.get("Weak Cipher Suites Accepted") == Severity.MEDIUM

    def test_no_forward_secrecy(self):
        from scanner.tls.hephaestus_tls import _analyze_ciphers
        sr = _NS(tls_1_2_cipher_suites=_ciphers([("AES256-SHA", False, 256, None)]))   # static RSA only
        titles = [f.title for f in _analyze_ciphers(sr, "t.test", 443)]
        assert "No Forward Secrecy" in titles

    def test_forward_secrecy_present_not_flagged(self):
        from scanner.tls.hephaestus_tls import _analyze_ciphers
        sr = _NS(tls_1_2_cipher_suites=_ciphers([("ECDHE-RSA-AES128-GCM-SHA256", False, 128, object())]))
        assert "No Forward Secrecy" not in [f.title for f in _analyze_ciphers(sr, "t.test", 443)]

    def test_known_tls_vulnerabilities(self):
        from scanner.tls.hephaestus_tls import _analyze_vulns
        sr = _NS(heartbleed=_att(_NS(is_vulnerable_to_heartbleed=True)),
                 openssl_ccs_injection=_att(_NS(is_vulnerable_to_ccs_injection=True)),
                 robot=_att(_NS(robot_result=_NS(name="VULNERABLE_STRONG_ORACLE"))),
                 tls_compression=_att(_NS(supports_compression=True)),
                 session_renegotiation=_att(_NS(supports_secure_renegotiation=False)))
        sev = {f.title.split(" (")[0]: f.severity for f in _analyze_vulns(sr, "t.test", 443)}
        assert sev.get("Heartbleed") == Severity.CRITICAL
        assert sev.get("OpenSSL CCS Injection") == Severity.HIGH
        assert sev.get("ROBOT Attack Exposure") == Severity.HIGH
        assert sev.get("TLS Compression Enabled") == Severity.MEDIUM
        assert sev.get("Insecure Renegotiation Supported") == Severity.MEDIUM

    def test_certificate_findings(self):
        from scanner.tls.hephaestus_tls import _cert_findings
        # expired (also fails chain validation) + hostname mismatch — must NOT double-report untrusted
        exp = {"days_left": -5, "expiry": "2020-01-01", "subject": "CN=old",
               "hostname_match": False, "self_signed": False, "trusted": False, "weak_sig": False}
        sev = {f.title: f.severity for f in _cert_findings(exp, "t.test", 443)}
        assert sev.get("Certificate Expired") == Severity.HIGH
        assert sev.get("Certificate Hostname Mismatch") == Severity.HIGH
        assert "Untrusted Certificate Chain" not in sev    # expiry already explains the untrust
        # genuinely untrusted (unknown CA) but valid dates and not self-signed -> still reported
        unk = {"days_left": 200, "expiry": "x", "subject": "CN=ok", "hostname_match": True,
               "self_signed": False, "trusted": False, "weak_sig": False}
        assert any(f.title == "Untrusted Certificate Chain" for f in _cert_findings(unk, "t.test", 443))
        # self-signed
        ss = {"days_left": 200, "expiry": "x", "subject": "CN=self", "hostname_match": True,
              "self_signed": True, "trusted": False, "weak_sig": False}
        assert any(f.title == "Self-Signed / Untrusted Certificate" and f.severity == Severity.HIGH
                   for f in _cert_findings(ss, "t.test", 443))
        # weak signature -> MEDIUM
        ws = {"days_left": 200, "expiry": "x", "subject": "CN=ok", "hostname_match": True,
              "self_signed": False, "trusted": True, "weak_sig": True, "sig": "sha1"}
        assert any(f.title == "Weakly Signed Certificate" and f.severity == Severity.MEDIUM
                   for f in _cert_findings(ws, "t.test", 443))
        # all good -> INFO valid chain
        ok = {"days_left": 200, "expiry": "x", "subject": "CN=ok", "hostname_match": True,
              "self_signed": False, "trusted": True, "weak_sig": False}
        valid = _cert_findings(ok, "t.test", 443)
        assert valid and valid[0].severity == Severity.INFO

    def test_finding_carries_offensive_schema(self):
        from scanner.tls.hephaestus_tls import _analyze_vulns
        f = _analyze_vulns(_NS(heartbleed=_att(_NS(is_vulnerable_to_heartbleed=True))), "t.test", 443)[0]
        assert f.module == "hephaestus_tls" and f.cwe and f.owasp.startswith("A02:2021")
        assert f.raw["offensive_impact"] and f.raw["evidence"] and f.raw["references"]
        assert f.raw["affected_component"] == "TLS/SSL endpoint (t.test:443)"
        assert "T1557" in f.mitre

    def test_run_graceful_when_host_unresolvable(self):
        from scanner.tls import hephaestus_tls
        eng = _NS(url="https://nonexistent.invalid.host.local")
        fs = hephaestus_tls.run(eng)
        assert len(fs) == 1 and fs[0].severity == Severity.INFO and "Skipped" in fs[0].title


# ---------------------------------------------------------------------------
# Hades v1.0 polish — entry point, reports, confidence, graceful install
# ---------------------------------------------------------------------------

class TestV1Polish:
    def test_every_finding_has_a_confidence(self):
        # A module that sets no confidence still gets one, derived from severity.
        assert Finding("m", "t", "d", Severity.HIGH).raw["confidence"] == "high"
        assert Finding("m", "t", "d", Severity.MEDIUM).raw["confidence"] == "medium"
        assert Finding("m", "t", "d", Severity.INFO).raw["confidence"] == "low"
        # An explicit confidence is preserved.
        assert Finding("m", "t", "d", Severity.HIGH, raw={"confidence": "low"}).raw["confidence"] == "low"

    def test_json_report_schema_and_always_written(self, tmp_path):
        import json
        from scanner.output.report_json import generate_json
        f = Finding("hephaestus_tls", "TLS 1.0 Enabled", "d", Severity.MEDIUM,
                    cwe="CWE-326", owasp="A02:2021 Cryptographic Failures", mitre=["T1557"],
                    raw={"confidence": "high", "evidence": ["Protocol: TLS 1.0"],
                         "references": ["https://example/ref"]})
        out = generate_json([f], "http://t.test", 55, output_path=str(tmp_path))
        fj = json.load(open(out, encoding="utf-8"))["findings"][0]
        for k in ("severity", "confidence", "cwe", "owasp", "mitre_attack", "evidence",
                  "references", "recommendation", "poc"):
            assert k in fj, f"missing JSON key: {k}"
        assert fj["confidence"] == "high" and fj["evidence"] == ["Protocol: TLS 1.0"]

    def test_pdf_output_was_removed(self):
        import main
        assert not hasattr(main, "OUTPUT_FORMATS")
        with pytest.raises(SystemExit):                 # --output flag no longer exists
            main.build_parser().parse_args(["--output", "pdf"])

    def test_favicon_graceful_without_mmh3(self, monkeypatch):
        from scanner.web import favicon_hash
        monkeypatch.setattr(favicon_hash, "mmh3", None)
        fs = favicon_hash.run(_NS(url="http://t.test"))
        assert len(fs) == 1 and fs[0].severity == Severity.INFO and "Skipped" in fs[0].title

    def test_whois_graceful_without_lib(self, monkeypatch):
        from scanner.recon import whois_lookup
        monkeypatch.setattr(whois_lookup, "whois", None)
        fs = whois_lookup.run(_NS(url="http://t.test"))
        assert len(fs) == 1 and fs[0].severity == Severity.INFO and "Skipped" in fs[0].title

    def test_print_report_paths_runs(self):
        from scanner.output.console import print_report_paths
        print_report_paths("reports/x.html", "reports/x.json", "logs/x.log")   # must not raise

    def test_cli_entrypoint_exists(self):
        import hades
        import main
        assert callable(main.cli) and hasattr(hades, "cli")


# ---------------------------------------------------------------------------
# RedTeam Arsenal — reference page (menu option 666 / --arsenal)
# ---------------------------------------------------------------------------

class TestRedTeamArsenal:
    def test_tool_data_integrity(self):
        from scanner.arsenal.arsenal_data import CATEGORIES
        from scanner.arsenal.redteam_arsenal import _tool_url
        assert len(CATEGORIES) >= 18
        total = linked = nolink = 0
        for c in CATEGORIES:
            assert c["icon"] and c["name"] and c["attack"] and c["tools"]
            for (name, desc, url, star) in c["tools"]:
                total += 1
                assert name and desc and isinstance(star, bool)
                resolved = _tool_url(url)
                if url is None:
                    nolink += 1
                    assert resolved == ""                 # no link is ever invented
                else:
                    linked += 1
                    assert resolved.startswith(("http://", "https://"))   # a real project link
        assert total >= 150
        # Almost every tool now carries a real link; only built-ins/bundles have none.
        assert nolink <= 12 and linked >= total - 12

    def test_html_page_generation(self, tmp_path):
        from pathlib import Path
        from scanner.arsenal.redteam_arsenal import generate_arsenal
        out = generate_arsenal(output_path=str(tmp_path))
        assert out and out.endswith("hades_redteam_arsenal.html")
        page = Path(out).read_text(encoding="utf-8")
        for needle in ("RED", "Active Directory", "Sqlmap", "BloodHound",
                       "github.com/projectdiscovery/nuclei", 'id="q"', "★"):
            assert needle in page, f"missing in arsenal page: {needle}"

    def test_open_arsenal_does_not_open_browser(self, monkeypatch):
        import scanner.arsenal.redteam_arsenal as arsenal
        called = {"open": False}
        monkeypatch.setattr(arsenal.webbrowser, "open", lambda *a, **k: called.__setitem__("open", True))
        path = arsenal.open_arsenal(open_browser=False)
        assert path and not called["open"]

    def test_arsenal_flag_registered(self):
        import main
        assert main.build_parser().parse_args(["--arsenal"]).arsenal is True


class _RecordTransport(httpx.BaseTransport):
    """Mock transport that records every request (prefix-matched responses)."""

    def __init__(self, responses: dict):
        self.responses = responses
        self.requests: list = []

    def handle_request(self, request: httpx.Request):
        self.requests.append(request)
        u = str(request.url)
        for key, resp in self.responses.items():
            if u.startswith(key):
                return resp
        return httpx.Response(404, text="")


class _FreshTransport(httpx.BaseTransport):
    """Builds a FRESH response per call (so self-baseline re-fetches work); handler(url) -> body|None."""

    def __init__(self, handler):
        self.handler = handler

    def handle_request(self, request: httpx.Request):
        body = self.handler(str(request.url))
        return httpx.Response(404, text="") if body is None else httpx.Response(200, html=body)


class TestAuthenticatedSession:
    def _engine(self, transport) -> ScanEngine:
        eng = ScanEngine("https://example.com", rate_delay=0)
        eng._client = httpx.Client(transport=transport, follow_redirects=True, verify=False)
        return eng

    def test_login_establishes_session_and_replays_csrf(self):
        login_form = ('<form method="post" action="/login">'
                      '<input type="hidden" name="csrf" value="tok123">'
                      '<input name="username"><input type="password" name="password"></form>')
        t = _RecordTransport({
            "https://example.com/login": httpx.Response(
                200, html=login_form, headers={"set-cookie": "session=abc; Path=/"}),
            "https://example.com": httpx.Response(200, html="<p>Welcome admin — Logout</p>"),
        })
        eng = self._engine(t)
        eng.login_url, eng.login_data, eng.login_check = (
            "/login", "username=admin&password=secret", "Logout")
        eng._establish_session()
        assert eng.authenticated is True
        assert eng._client.cookies.get("session") == "abc"     # cookie persisted in the shared jar
        posts = [r for r in t.requests if r.method == "POST"]
        assert posts, "a login POST should have been sent"
        body = posts[0].content
        assert b"username=admin" in body and b"password=secret" in body
        assert b"csrf=tok123" in body                           # hidden CSRF field replayed
        eng.close()

    def test_login_not_confirmed_when_check_absent(self):
        t = _RecordTransport({
            "https://example.com/login": httpx.Response(
                200, html='<form method="post" action="/login"><input name="username"></form>'),
            "https://example.com": httpx.Response(200, html="<p>Please log in</p>"),
        })
        eng = self._engine(t)
        eng.login_url, eng.login_data, eng.login_check = "/login", "username=admin&password=x", "Logout"
        eng._establish_session()
        assert eng.authenticated is False
        eng.close()

    def test_request_anonymous_bypasses_session_client(self):
        sess = _RecordTransport({"https://example.com/x": httpx.Response(200, text="SESSION")})
        anon = _RecordTransport({"https://example.com/x": httpx.Response(200, text="ANON")})
        eng = ScanEngine("https://example.com", rate_delay=0)
        eng._client = httpx.Client(transport=sess, follow_redirects=True, verify=False)
        eng._anon_client = httpx.Client(transport=anon, follow_redirects=True, verify=False)
        r = eng.request_anonymous("GET", "https://example.com/x")
        assert r.text == "ANON"          # routed through the anonymous client …
        assert not sess.requests         # … and never touched the session client
        eng.close()


class TestIdorDetect:
    def _eng(self, responses: dict, **kw) -> ScanEngine:
        kw.setdefault("rate_delay", 0)
        eng = ScanEngine("https://example.com", **kw)
        eng._client = httpx.Client(transport=MockTransport(responses), follow_redirects=True, verify=False)
        return eng

    @staticmethod
    def _crawl(eng, param_urls):
        from scanner.crawler import CrawlResult
        eng._crawl_result = CrawlResult(parametrised_urls=list(param_urls))

    # A big shared template + a small differing owner line ⇒ "different object, same page type".
    _NAV = "<nav>" + "Home Profile Orders Settings Logout " * 18 + "</nav>"

    def _record(self, owner):
        return ("<html><body>" + self._NAV + "<h1>Account</h1><p>Owner: " + owner +
                "</p><footer>(c) corp test corp test corp test</footer></body></html>")

    def test_idor_enumeration_detected(self):
        from scanner.vulns import idor_detect
        eng = self._eng({
            "https://example.com/account?id=5": httpx.Response(200, html=self._record("Alice Anderson 5")),
            "https://example.com/account?id=6": httpx.Response(200, html=self._record("Robert Brown 6")),
        })
        self._crawl(eng, ["https://example.com/account?id=5"])
        findings = idor_detect.run(eng)
        assert findings, "expected an IDOR enumeration finding"
        f = findings[0]
        assert f.module == "idor_detect" and f.severity.value == "high"
        assert "id=6" in f.raw.get("proof_url", "")
        eng.close()

    def test_bola_missing_authz_detected(self):
        from scanner.vulns import idor_detect
        obj = "<html><body>" + ("private account record " * 50) + "<p>Owner id 10</p></body></html>"
        eng = self._eng({"https://example.com/doc?id=10": httpx.Response(200, html=obj)})
        eng._anon_client = httpx.Client(
            transport=MockTransport({"https://example.com/doc?id=10": httpx.Response(200, html=obj)}),
            follow_redirects=True, verify=False)
        eng.authenticated = True
        self._crawl(eng, ["https://example.com/doc?id=10"])
        findings = idor_detect.run(eng)
        assert any("without a session" in f.title for f in findings)
        eng.close()

    def test_no_fp_on_identical_pages(self):
        from scanner.vulns import idor_detect
        same = "<html><body>" + ("catalogue product page " * 50) + "</body></html>"
        eng = self._eng({
            "https://example.com/p?id=5": httpx.Response(200, html=same),
            "https://example.com/p?id=6": httpx.Response(200, html=same),
        })
        self._crawl(eng, ["https://example.com/p?id=5"])
        assert idor_detect.run(eng) == []          # identical objects (ratio ~1.0) → not flagged
        eng.close()

    def test_non_id_params_ignored(self):
        from scanner.vulns import idor_detect
        # 'cat' is not an object-reference name → never probed (keeps catalogue params out of noise).
        eng = self._eng({
            "https://example.com/list?cat=5": httpx.Response(200, html=self._record("A 5")),
            "https://example.com/list?cat=6": httpx.Response(200, html=self._record("B 6")),
        })
        self._crawl(eng, ["https://example.com/list?cat=5"])
        assert idor_detect.run(eng) == []
        eng.close()

    def test_skipped_in_safe_mode(self):
        import config
        from scanner.vulns import idor_detect
        eng = self._eng({"https://example.com/account?id=5": httpx.Response(200, html="x" * 400)},
                        rate_delay=config.SAFE_MODE_RATE_DELAY)
        self._crawl(eng, ["https://example.com/account?id=5"])
        assert idor_detect.run(eng) == []
        eng.close()

    # ── JSON / API awareness ──────────────────────────────────────────────
    def test_idor_json_api_enumeration(self):
        from scanner.vulns import idor_detect
        from scanner.crawler import CrawlResult
        def obj(i, name):
            return httpx.Response(200, json={"id": i, "name": name, "email": f"{name}@corp.test",
                                             "role": "user"})
        eng = self._eng({
            "https://example.com/api/users/5": obj(5, "alice"),
            "https://example.com/api/users/6": obj(6, "bob"),
        })
        eng._crawl_result = CrawlResult(internal_links={"https://example.com/api/users/5"})
        findings = idor_detect.run(eng)
        assert findings, "expected a JSON IDOR finding (same schema, different values)"
        assert "/api/users/6" in findings[0].raw["proof_url"]
        assert findings[0].poc.startswith("curl ")
        eng.close()

    def test_bola_json_api_detected(self):
        from scanner.vulns import idor_detect
        from scanner.crawler import CrawlResult
        payload = {"id": 10, "iban": "FR7612345", "balance": 4200}
        eng = self._eng({"https://example.com/api/orders/10": httpx.Response(200, json=payload)})
        eng._anon_client = httpx.Client(
            transport=MockTransport({"https://example.com/api/orders/10": httpx.Response(200, json=payload)}),
            follow_redirects=True, verify=False)
        eng.authenticated = True
        eng._crawl_result = CrawlResult(internal_links={"https://example.com/api/orders/10"})
        findings = idor_detect.run(eng)
        bola = [f for f in findings if "without a session" in f.title]
        assert bola and bola[0].raw["confidence"] == "high"
        eng.close()

    # ── self-baseline noise floor (dynamic pages) ─────────────────────────
    _SHARED = "<html><body>" + ("stable dashboard navigation footer panel " * 22) + "{body}</body></html>"

    def _fresh_eng(self, handler):
        eng = ScanEngine("https://example.com", rate_delay=0)
        eng._client = httpx.Client(transport=_FreshTransport(handler), follow_redirects=True, verify=False)
        return eng

    def test_self_baseline_ignores_dynamic_noise(self):
        import uuid
        from scanner.vulns import idor_detect
        from scanner.crawler import CrawlResult
        # Every id returns the SAME object; only a per-request token changes (dynamic page).
        def handler(url):
            if "/account" in url and "id=" in url:
                return self._SHARED.format(body=f"<p>Owner: Alice</p><span>{uuid.uuid4()}</span>")
            return None
        eng = self._fresh_eng(handler)
        eng._crawl_result = CrawlResult(parametrised_urls=["https://example.com/account?id=5"])
        assert idor_detect.run(eng) == []          # token-only churn must NOT look like another object
        eng.close()

    def test_self_baseline_still_detects_real_object(self):
        import uuid
        from scanner.vulns import idor_detect
        from scanner.crawler import CrawlResult
        # Same template, but a substantially different data block per id → a real other object.
        blocks = {"5": "Owner: Alice Anderson " * 12, "6": "Owner: Robert Brown plus extra detail " * 12}
        def handler(url):
            for i, blk in blocks.items():
                if f"id={i}" in url:
                    return self._SHARED.format(body=f"<p>{blk}</p><span>{uuid.uuid4()}</span>")
            return None
        eng = self._fresh_eng(handler)
        eng._crawl_result = CrawlResult(parametrised_urls=["https://example.com/account?id=5"])
        findings = idor_detect.run(eng)
        assert findings and "id=6" in findings[0].raw["proof_url"]
        eng.close()

    def test_menu_option_11_maps_to_auth_idor(self):
        import main
        from unittest.mock import patch
        with patch("main.Prompt.ask", return_value="11"):
            assert main.prompt_scan_choice() == ("auth_idor", None)

    def test_extract_login_form_parses_real_form(self):
        import main
        from bs4 import BeautifulSoup
        html = ('<form action="/do_login" method="post">'
                '<input type="hidden" name="csrf" value="x">'
                '<input type="text" name="pseudo"><input type="password" name="mdp"></form>')
        action, uf, pf = main._extract_login_form(BeautifulSoup(html, "html.parser"),
                                                  "https://site.tld/login")
        assert action == "https://site.tld/do_login" and uf == "pseudo" and pf == "mdp"

    def test_discover_login_searches_root_not_deep_path(self):
        import main
        from unittest.mock import patch
        # Target is a deep /signup/ page, but discovery must search the site ROOT and follow the
        # homepage 'login' link — not read the signup form on the targeted page.
        home = '<html><a href="/connexion">Se connecter</a><a href="/about">About</a></html>'
        login = ('<form action="/auth" method="post">'
                 '<input name="pseudo"><input type="password" name="mdp"></form>')
        def fake_fetch(u):
            if u.endswith("/connexion"):
                return httpx.Response(200, html=login)
            if u == "https://t":
                return httpx.Response(200, html=home)
            return httpx.Response(404, text="")
        with patch("main._fetch", side_effect=fake_fetch):
            action, uf, pf = main._discover_login("https://t/signup/create")
        assert action == "https://t/auth" and uf == "pseudo" and pf == "mdp"

    def test_extract_login_form_skips_registration(self):
        import main
        from bs4 import BeautifulSoup
        # A registration form (two password inputs) then a real login form on the same page.
        html = (
            '<form action="/register"><input name="name">'
            '<input type="password" name="pw1"><input type="password" name="pw2"></form>'
            '<form action="/login"><input name="login">'
            '<input type="password" name="pass"></form>'
        )
        action, uf, pf = main._extract_login_form(BeautifulSoup(html, "html.parser"), "https://s.tld/x")
        assert action == "https://s.tld/login" and uf == "login" and pf == "pass"
        # A lone signup form (single password but a signup action) is not treated as login.
        signup = '<form action="/signup"><input name="u"><input type="password" name="p"></form>'
        assert main._extract_login_form(BeautifulSoup(signup, "html.parser"), "https://s.tld/x") is None

    def test_prompt_login_manual_when_form_not_detected(self):
        import main
        from unittest.mock import patch
        # Order: login_url, username field, username value, password field, password value, check.
        answers = ["https://t/login", "pseudo", "testhades", "password", "hades31", "Déconnexion"]
        with patch("main._discover_login", return_value=None), \
             patch("main._autodetect_login_form", return_value=None), \
             patch("main.Prompt.ask", side_effect=answers):
            url, data, check = main.prompt_login("https://t")
        assert url == "https://t/login"
        assert data == "pseudo=testhades&password=hades31"   # field names typed manually
        assert check == "Déconnexion"

    def test_prompt_login_autodiscovers_login_page(self):
        import main
        from unittest.mock import patch
        # The login page + fields are found from just the site URL; the user accepts (Enter) and
        # only types the values.
        answers = ["https://t/do_login", "", "testhades", "", "hades31", "Logout"]
        with patch("main._discover_login", return_value=("https://t/do_login", "pseudo", "pwd")), \
             patch("main.Prompt.ask", side_effect=answers):
            url, data, check = main.prompt_login("https://t")
        assert url == "https://t/do_login"                   # discovered submit action is used
        assert data == "pseudo=testhades&pwd=hades31"        # discovered field names applied

    def test_prompt_login_blank_url_cancels(self):
        import main
        from unittest.mock import patch
        with patch("main._discover_login", return_value=None), \
             patch("main.Prompt.ask", side_effect=[""]):
            assert main.prompt_login("https://t") == (None, None, None)

    def test_idor_wired(self):
        import config
        from scanner.output.console import _VERIFIABLE_MODULES
        assert "scanner.vulns.idor_detect" in config.PROFILE_MODULES["full"]
        assert config.FINDING_TAXONOMY["idor_detect"]["cwe"] == "CWE-639"
        assert "idor_detect" in _VERIFIABLE_MODULES
        assert main_login_flags_registered()


def main_login_flags_registered() -> bool:
    import main
    ns = main.build_parser().parse_args(
        ["--url", "https://x", "--login-url", "/login", "--login-data", "u=a&p=b", "--login-check", "Logout"])
    return ns.login_url == "/login" and ns.login_data == "u=a&p=b" and ns.login_check == "Logout"


class TestFullScanOrchestration:
    """The profile runner must never hang on a slow module and must isolate per-module errors."""

    def _engine(self, modules):
        eng = ScanEngine("https://example.com", rate_delay=0, threads=4, modules=modules)
        eng._client = httpx.Client(transport=MockTransport({}), follow_redirects=True, verify=False)
        return eng

    def test_hung_module_is_abandoned_and_scan_completes(self, monkeypatch):
        import time
        from scanner import engine as eng_mod
        monkeypatch.setattr(eng_mod, "MODULE_TIMEOUT", 0.3)
        eng = self._engine(["fast_a", "hang_b", "fast_c"])

        def fake_run(self, path):
            if path == "hang_b":
                time.sleep(1.0)                          # far past the 0.3s budget
                return []
            return [Finding(module=path, title=f"f-{path}", description="", severity=Severity.LOW)]

        monkeypatch.setattr(ScanEngine, "_run_module", fake_run)
        start = time.monotonic()
        findings = eng.run_scan()
        elapsed = time.monotonic() - start

        names = sorted(f.module for f in findings)
        assert names == ["fast_a", "fast_c"]             # the OK modules' findings are returned
        assert elapsed < 0.9                             # did NOT wait for the 1s hang
        statuses = {s["name"]: s["status"] for s in eng._run_stats}
        assert statuses["hang_b"] == "timeout"
        eng.close()

    def test_module_error_is_isolated(self, monkeypatch):
        eng = self._engine(["good", "boom"])

        def fake_run(self, path):
            if path == "boom":
                raise RuntimeError("module blew up")
            return [Finding(module=path, title="ok", description="", severity=Severity.INFO)]

        monkeypatch.setattr(ScanEngine, "_run_module", fake_run)
        findings = eng.run_scan()                        # must not raise
        assert [f.module for f in findings] == ["good"]
        statuses = {s["name"]: s["status"] for s in eng._run_stats}
        assert statuses == {"good": "ok", "boom": "error"}
        eng.close()

    def test_run_summary_stats_recorded(self, monkeypatch):
        eng = self._engine(["m1", "m2"])
        monkeypatch.setattr(ScanEngine, "_run_module",
                            lambda self, path: [Finding(module=path, title="t", description="",
                                                        severity=Severity.LOW)])
        eng.run_scan()
        assert len(eng._run_stats) == 2
        assert all({"name", "seconds", "count", "status"} <= set(s) for s in eng._run_stats)
        assert sum(s["count"] for s in eng._run_stats) == 2
        eng.close()


class _CountingTransport(httpx.BaseTransport):
    """Counts requests per URL; returns a fixed status (default 200 'ok')."""

    def __init__(self, status: int = 200):
        self.status = status
        self.count: dict[str, int] = {}

    def handle_request(self, request: httpx.Request):
        u = str(request.url)
        self.count[u] = self.count.get(u, 0) + 1
        return httpx.Response(self.status, text="ok")


class _BoomTransport(httpx.BaseTransport):
    """Simulates an unreachable host (connection refused)."""

    def handle_request(self, request: httpx.Request):
        raise httpx.ConnectError("connection refused")


class TestFullScanPerf:
    """Speed/reliability: shared idempotent-GET cache + target pre-flight."""

    def _engine(self, transport, **kw):
        eng = ScanEngine("https://example.com", rate_delay=0, **kw)
        eng._client = httpx.Client(transport=transport, follow_redirects=True, verify=False)
        return eng

    def test_homepage_and_allowlisted_paths_cached(self):
        t = _CountingTransport()
        eng = self._engine(t)
        for _ in range(5):
            eng.get()                                # homepage ×5 → one fetch
        for _ in range(3):
            eng.get("/robots.txt")                   # robots ×3 → one fetch
        assert t.count["https://example.com"] == 1
        assert t.count["https://example.com/robots.txt"] == 1
        eng.close()

    def test_non_allowlisted_and_kwargs_gets_not_cached(self):
        t = _CountingTransport()
        eng = self._engine(t)
        for _ in range(2):
            eng.get("/dir/probe")                    # not allowlisted → not cached
        for _ in range(2):
            eng.get(headers={"X-Probe": "1"})        # kwargs → not cached (even for the homepage)
        assert t.count["https://example.com/dir/probe"] == 2
        assert t.count["https://example.com"] == 2
        eng.close()

    def test_preflight_aborts_on_unreachable_host(self):
        eng = self._engine(_BoomTransport(), profile="full")
        assert eng.run_scan() == []                  # connection error → abort, no modules run
        eng.close()

    def test_preflight_continues_on_http_error(self, monkeypatch):
        # A 500 on the HTTP root means the host is UP → the scan proceeds (only a connection-level
        # failure aborts).
        eng = self._engine(_CountingTransport(status=500), profile="full")
        ran = {"n": 0}
        def fake(self, path):
            ran["n"] += 1
            return [Finding(module=path, title="t", description="", severity=Severity.INFO)]
        monkeypatch.setattr(ScanEngine, "_run_module", fake)
        monkeypatch.setattr("scanner.engine.PROFILE_MODULES", {"full": ["m_a", "m_b"]})
        findings = eng.run_scan()
        assert ran["n"] == 2 and len(findings) == 2   # the 500 root did NOT abort the scan
        eng.close()

    def test_preflight_skipped_for_non_web_profile(self, monkeypatch):
        eng = self._engine(_BoomTransport(), profile="db_scan")
        ran = {"n": 0}
        monkeypatch.setattr(ScanEngine, "_run_module",
                            lambda self, path: ran.__setitem__("n", ran["n"] + 1) or [])
        monkeypatch.setattr("scanner.engine.PROFILE_MODULES", {"db_scan": ["db"], "full": ["x"]})
        eng.run_scan()                               # must NOT abort despite the unreachable HTTP root
        assert ran["n"] == 1
        eng.close()

    def test_preflight_skipped_for_single_module_run(self, monkeypatch):
        eng = self._engine(_BoomTransport(), modules=["only_one"])
        ran = {"n": 0}
        monkeypatch.setattr(ScanEngine, "_run_module",
                            lambda self, path: ran.__setitem__("n", ran["n"] + 1) or [])
        eng.run_scan()                               # explicit --module run → no pre-flight
        assert ran["n"] == 1
        eng.close()

    def test_circuit_breaker_fast_fails_when_open(self, monkeypatch):
        from scanner import engine as eng_mod
        monkeypatch.setattr(eng_mod, "CIRCUIT_BREAKER_FAILS", 3)

        class _Timeout(httpx.BaseTransport):
            def __init__(self):
                self.n = 0
            def handle_request(self, request):
                self.n += 1
                raise httpx.ReadTimeout("slow")

        t = _Timeout()
        eng = self._engine(t)
        for _ in range(3):                           # 3 consecutive timeouts trip the breaker
            with pytest.raises(httpx.HTTPError):
                eng.request("GET", "https://example.com/x")
        assert t.n == 3
        with pytest.raises(httpx.ConnectError):      # breaker open → fast-fail, transport NOT hit
            eng.request("GET", "https://example.com/y")
        assert t.n == 3
        eng.close()

    def test_circuit_breaker_resets_on_success(self, monkeypatch):
        from scanner import engine as eng_mod
        monkeypatch.setattr(eng_mod, "CIRCUIT_BREAKER_FAILS", 3)

        class _Flaky(httpx.BaseTransport):
            fail = True
            def handle_request(self, request):
                if self.fail:
                    raise httpx.ConnectError("down")
                return httpx.Response(200, text="ok")

        f = _Flaky()
        eng = self._engine(f)
        for _ in range(2):                           # 2 fails — below the threshold of 3
            with pytest.raises(httpx.HTTPError):
                eng.request("GET", "https://example.com/x")
        f.fail = False
        assert eng.request("GET", "https://example.com/x").status_code == 200   # success resets
        assert eng._fail_streak == 0 and eng._breaker_open_until == 0.0
        eng.close()

    def test_rate_limiter_concurrency_parallelises(self):
        import time
        from scanner.engine import RateLimiter
        def measure(concurrency, n=10):
            rl = RateLimiter(0.05, concurrency)
            t0 = time.monotonic()
            for _ in range(n):
                rl.acquire()
            return time.monotonic() - t0
        serial = measure(1)             # one lane → ~ (n-1)*0.05 ≈ 0.45s
        concurrent = measure(5)         # five lanes → bursts, far faster
        assert concurrent < serial / 3

    def test_safe_mode_is_a_single_polite_lane(self):
        import config
        eng = ScanEngine("https://x", rate_delay=config.SAFE_MODE_RATE_DELAY)
        assert eng._rate_limiter._burst == 1                       # strictly serial when polite
        assert eng._rate_limiter._delay == config.SAFE_MODE_RATE_DELAY   # is_safe_mode() still works
        eng.close()

    def test_engine_is_safe_mode_single_source_of_truth(self):
        """ScanEngine.is_safe_mode() is the one safe-mode check; _common.is_safe_mode delegates to it
        and stays tolerant of mock engines (the four module-local copies were removed)."""
        import config
        from scanner.vulns._common import is_safe_mode
        safe = ScanEngine("https://x", rate_delay=config.SAFE_MODE_RATE_DELAY)
        fast = ScanEngine("https://x", rate_delay=0)
        try:
            assert safe.is_safe_mode() is True and fast.is_safe_mode() is False
            assert is_safe_mode(safe) is True and is_safe_mode(fast) is False
            assert is_safe_mode(object()) is False                 # no engine API → graceful False
        finally:
            safe.close()
            fast.close()

    def test_normal_mode_caps_concurrency(self):
        import config
        eng = ScanEngine("https://x", rate_delay=0.5, threads=20)
        assert eng._rate_limiter._burst == config.MAX_CONCURRENCY   # capped, not 20
        eng.close()


class TestVulnInfoSeparation:
    """Informational (INFO) findings are presented separately from real vulnerabilities."""

    @staticmethod
    def _vuln():
        return Finding(module="headers_check", title="Missing CSP", description="No CSP header",
                       severity=Severity.HIGH, cwe="CWE-693", owasp="A05:2021 Misconfig", cvss=6.1)

    @staticmethod
    def _info(title="Server: nginx", desc="banner"):
        return Finding(module="basic_info", title=title, description=desc, severity=Severity.INFO)

    # ── HTML ──────────────────────────────────────────────────────────────
    def test_html_splits_vulns_and_info(self, tmp_path):
        import re
        from pathlib import Path
        from scanner.output.report_html import generate_html
        out = generate_html([self._vuln(), self._info("Server: IIS", "banner")], "http://d.test", 55,
                            output_path=str(tmp_path / "reports"))
        h = Path(out).read_text(encoding="utf-8")
        assert ">Vulnerabilities<" in h and ">Information<" in h
        table = re.search(r'<table class="findings-table">.*?</table>', h, re.S).group(0)
        assert "Missing CSP" in table                 # the vuln is in the severity table
        assert "Server: IIS" not in table             # the INFO item is NOT in the severity table
        assert 'class="info-item"' in h and "info-chip" in h
        assert "Server: IIS" in h.split(">Information<")[1]   # … it's in the Information section
        assert ">INFO<" not in table                  # no INFO sev-badge row

    def test_html_no_info_section_when_no_info(self, tmp_path):
        from pathlib import Path
        from scanner.output.report_html import generate_html
        h = Path(generate_html([self._vuln()], "http://d.test", 70,
                               output_path=str(tmp_path / "reports"))).read_text(encoding="utf-8")
        assert ">Information<" not in h and 'class="info-item"' not in h

    def test_html_no_vulnerabilities_note_when_info_only(self, tmp_path):
        from pathlib import Path
        from scanner.output.report_html import generate_html
        h = Path(generate_html([self._info()], "http://d.test", 100,
                               output_path=str(tmp_path / "reports"))).read_text(encoding="utf-8")
        assert "No vulnerabilities found" in h
        assert 'class="info-item"' in h and ">Information<" in h

    # ── Console ───────────────────────────────────────────────────────────
    def _render(self, findings):
        from rich.console import Console
        import scanner.output.console as cons
        rec = Console(record=True, width=120)
        old = cons.console
        cons.console = rec
        try:
            cons.print_findings(findings, "http://t")
        finally:
            cons.console = old
        return rec.export_text()

    def test_console_splits_vulns_and_info(self):
        txt = self._render([self._vuln(), self._info("Server: nginx", "banner")])
        assert "Vulnerabilities —" in txt
        assert "Information & Recon" in txt and "not scored" in txt
        assert "Server: nginx" in txt and "Missing CSP" in txt

    def test_console_no_info_section_when_no_info(self):
        txt = self._render([self._vuln()])
        assert "Vulnerabilities —" in txt
        assert "Information & Recon" not in txt

    def test_console_no_vulns_note_when_info_only(self):
        txt = self._render([self._info()])
        assert "No vulnerabilities found" in txt
        assert "Information & Recon" in txt


# ---------------------------------------------------------------------------
# Evidence layer — builder, per-module wiring, and rendering (console/HTML/JSON)
# ---------------------------------------------------------------------------

class TestEvidence:
    """The shared scanner.evidence builder."""

    def test_from_response_shape(self):
        from scanner import evidence as ev
        req = httpx.Request("GET", "http://t.test/admin?id=1")
        resp = httpx.Response(200, text="hi", headers={"content-type": "text/plain"}, request=req)
        lines = ev.from_response(resp, indicator="login form")
        assert lines[0].startswith("GET /admin?id=1 → 200")
        assert "text/plain" in lines[0]
        assert any("matched: login form" in line for line in lines)

    def test_from_response_tolerates_missing_request(self):
        from scanner import evidence as ev
        stub = type("_R", (), {"text": "body", "status_code": 200})()
        lines = ev.from_response(stub, indicator="x")
        assert lines and lines[0].startswith("200")     # no method/path, but never raises

    def test_from_parts(self):
        from scanner import evidence as ev
        assert ev.from_parts("get", "/a", 403) == ["GET /a → 403"]
        assert "matched: gone" in ev.from_parts("GET", "/a", 404, indicator="gone")[1]

    def test_sanitize_caps_and_strips(self):
        from scanner import evidence as ev
        assert ev._sanitize("a\x00b\tc   d") == "ab c d"
        assert ev._sanitize("x" * 500).endswith("…") and len(ev._sanitize("x" * 500)) <= 161

    def test_confidence_from(self):
        from scanner import evidence as ev
        assert ev.confidence_from(0) == "low"
        assert ev.confidence_from(1) == "medium"
        assert ev.confidence_from(2) == "high"
        assert ev.confidence_from(0, active=True) == "medium"
        assert ev.confidence_from(1, active=True) == "high"

    def test_as_list_normalises(self):
        from scanner import evidence as ev
        assert ev.as_list(None) == []
        assert ev.as_list("x") == ["x"]
        assert ev.as_list(["a", "b"]) == ["a", "b"]


class TestEvidenceWiring:
    """Representative modules attach a non-empty raw['evidence'] to their actionable findings."""

    def test_command_injection_finding_has_evidence(self):
        from scanner.vulns._common import Injector
        from scanner.vulns.command_injection import _test
        inj = Injector(label="URL parameter 'q'", param="q",
                       inject=lambda p: _resp("result: uid=0(root) gid=0(root)"),
                       proof=lambda p: "https://t/?q=" + p, url="https://t/?q=1")
        f = _test(None, inj, False)
        assert f is not None
        evd = f.raw.get("evidence")
        assert evd and any("uid=0(root)" in line for line in evd)
        assert any("injected into URL parameter 'q'" in line for line in evd)

    def test_cors_reflected_origin_has_evidence(self, base_url):
        from scanner.web.cors_check import run
        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                origin = request.headers.get("origin", "")
                return httpx.Response(200, text="ok", headers={
                    "access-control-allow-origin": origin,
                    "access-control-allow-credentials": "true"})
        eng = ScanEngine(base_url, rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=True, verify=False)
        vulns = [f for f in run(eng) if f.severity != Severity.INFO]
        assert vulns and all(f.raw.get("evidence") for f in vulns)
        assert any("ACAO" in line for f in vulns for line in f.raw["evidence"])

    def test_headers_missing_csp_has_evidence(self, base_url):
        from scanner.web.headers_check import run
        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                return httpx.Response(200, text="<html></html>",
                                      headers={"content-type": "text/html"})
        eng = ScanEngine(base_url, rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=True, verify=False)
        csp = [f for f in run(eng)
               if (f.raw.get("header") or "").lower() == "content-security-policy"
               and "missing" in f.title.lower()]
        assert csp and csp[0].raw.get("evidence")
        assert any("absent" in line.lower() for line in csp[0].raw["evidence"])


class TestEvidenceRendering:
    @staticmethod
    def _f_with_evidence():
        return Finding(module="cors_check", title="CORS reflected origin", description="d",
                       severity=Severity.HIGH,
                       raw={"confidence": "high",
                            "evidence": ["GET / → 200 OK, 1.2 KB (text/html)",
                                         "matched: reflected origin evil.example.com"]})

    def test_html_renders_evidence_box(self, tmp_path):
        from pathlib import Path
        from scanner.output.report_html import generate_html
        out = generate_html([self._f_with_evidence()], "http://d.test", 60,
                            output_path=str(tmp_path / "reports"))
        h = Path(out).read_text(encoding="utf-8")
        assert "evidence-box" in h and "reflected origin evil.example.com" in h

    def test_json_emits_evidence_list(self, tmp_path):
        import json
        from pathlib import Path
        from scanner.output.report_json import generate_json
        out = generate_json([self._f_with_evidence()], "http://d.test", 60,
                            output_path=str(tmp_path / "reports"))
        data = json.loads(Path(out).read_text(encoding="utf-8"))
        assert data["findings"][0]["evidence"][0].startswith("GET / → 200 OK")

    def test_console_renders_evidence_line(self):
        from rich.console import Console
        import scanner.output.console as cons
        rec = Console(record=True, width=160)
        old = cons.console
        cons.console = rec
        try:
            cons.print_findings([self._f_with_evidence()], "http://t")
            txt = rec.export_text()
        finally:
            cons.console = old
        assert "evidence" in txt and "reflected origin" in txt


class TestExploitationWalkthrough:
    def test_sqli_finding_carries_ordered_steps(self, base_url):
        from scanner.vulns.sqli_detect import _finding
        f = _finding(f"{base_url}/c?id=1", "id", "boolean-based blind", "1 AND 1=1", "")
        steps = f.raw.get("exploitation")
        assert isinstance(steps, list) and len(steps) == 4
        assert all(s["command"].startswith("sqlmap -u") for s in steps)
        assert "--dbs" in steps[0]["command"] and "--tables" in steps[1]["command"]
        assert "--columns" in steps[2]["command"] and "--dump" in steps[3]["command"]
        # back-compat: the single sqlmap command + proof URL are still present
        assert f.raw["sqlmap"].startswith('sqlmap -u "') and "--technique=B" in f.raw["sqlmap"]
        assert "exploitation walkthrough" in f.description.lower()

    def test_html_renders_exploitation_walkthrough(self, tmp_path):
        from pathlib import Path
        from scanner.engine import Finding, Severity
        from scanner.output.report_html import generate_html
        f = Finding(module="sqli_detect", title="SQLi", description="d", severity=Severity.CRITICAL,
                    raw={"confidence": "high", "exploitation": [
                        {"step": 1, "description": "List the databases.", "command": "sqlmap -u X --dbs"},
                        {"step": 2, "description": "Dump the data.", "command": "sqlmap -u X --dump"}]})
        h = Path(generate_html([f], "http://d.test", 20,
                               output_path=str(tmp_path / "reports"))).read_text(encoding="utf-8")
        assert "Exploitation walkthrough" in h and "exp-cmd" in h
        assert "sqlmap -u X --dbs" in h and "List the databases." in h

    def test_console_renders_exploit_chain(self):
        from rich.console import Console
        from scanner.engine import Finding, Severity
        import scanner.output.console as cons
        f = Finding(module="command_injection", title="RCE", description="d", severity=Severity.CRITICAL,
                    raw={"confidence": "high", "exploitation": [
                        {"step": 1, "description": "Confirm the RCE.", "command": "commix -u X --batch"}]})
        rec = Console(record=True, width=160)
        old = cons.console
        cons.console = rec
        try:
            cons.print_findings([f], "http://t")
            txt = rec.export_text()
        finally:
            cons.console = old
        assert "exploit chain" in txt and "commix -u X --batch" in txt

    def test_exploitable_modules_emit_steps(self):
        """Each exploitable module's _exploitation_steps builds a non-empty, tool-specific chain."""
        from scanner.vulns._common import Injector
        inj = Injector(label="URL parameter 'q'", param="q", inject=lambda p: None,
                       proof=lambda p: "https://t/?q=" + p, url="https://t/?q=1")
        from scanner.vulns import command_injection, ssti_detect, lfi_detect, ssrf_detect
        assert any("commix" in s["command"] for s in command_injection._exploitation_steps(inj, "x"))
        assert any("tplmap" in s["command"] for s in ssti_detect._exploitation_steps(inj, "x"))
        assert any("base64" in s["command"] for s in lfi_detect._exploitation_steps(inj, "x"))
        assert any("169.254.169.254" in s["command"] for s in ssrf_detect._exploitation_steps(inj, "x"))


class TestStatefulFormXss:
    """A reflected XSS in a stateful (ASP.NET-style) POST form is detected because Hades re-fetches a
    fresh hidden token (__VIEWSTATE/CSRF) right before submitting — a stale replay would be rejected."""

    def test_xss_detected_through_token_gated_post_form(self, base_url):
        import threading
        from urllib.parse import parse_qs
        from scanner.vulns.xss_detect import run

        issued: set[str] = set()
        lock = threading.Lock()
        counter = {"n": 0}

        def _login_html(token: str) -> str:
            return (f'<html><body><form method="post" action="/login.aspx">'
                    f'<input type="hidden" name="__VIEWSTATE" value="{token}">'
                    f'<input type="text" name="tfUName" value="">'
                    f'<input type="submit" name="btnLogin" value="Login"></form></body></html>')

        class _T(httpx.BaseTransport):
            def handle_request(self, request):
                p = request.url.path
                if request.method == "GET" and p in ("", "/"):
                    return httpx.Response(200, text='<a href="/login.aspx">login</a>',
                                          headers={"content-type": "text/html"})
                if p == "/login.aspx" and request.method == "GET":
                    with lock:
                        counter["n"] += 1
                        tok = f"vs{counter['n']}"
                        issued.add(tok)
                    return httpx.Response(200, text=_login_html(tok),
                                          headers={"content-type": "text/html"})
                if p == "/login.aspx" and request.method == "POST":
                    body = parse_qs(request.content.decode("utf-8", "ignore"))
                    vs = (body.get("__VIEWSTATE") or [""])[0]
                    uname = (body.get("tfUName") or [""])[0]
                    with lock:
                        valid = vs in issued
                    if not valid:                       # stale/missing token → framework error page
                        return httpx.Response(200, text="<html>The state information is invalid.</html>",
                                              headers={"content-type": "text/html"})
                    # vulnerable: the posted username is reflected UNENCODED into a value attribute
                    return httpx.Response(
                        200, headers={"content-type": "text/html"},
                        text=f'<html><body><input type="text" name="tfUName" value="{uname}"></body></html>')
                return httpx.Response(404, text="nf")

        eng = ScanEngine(base_url, rate_delay=0)
        eng._client = httpx.Client(transport=_T(), follow_redirects=True, verify=False)

        findings = run(eng)
        xss = [f for f in findings
               if f.severity == Severity.HIGH and "tfUName" in (f.raw.get("location") or "")]
        assert xss, "reflected XSS in the token-gated login form should be detected"
        assert xss[0].raw.get("evidence")
