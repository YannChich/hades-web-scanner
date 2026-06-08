"""
make_report_screenshot — render a representative Hades HTML report and capture it to
``assets/screenshots/hades-report.png`` for the README.

It showcases the v2 reporting features: the per-finding **⧉ evidence** box and the collapsible
**⛓ Exploitation walkthrough**. Findings are built with the real module factories (so the taxonomy
badges, evidence and exploitation chains are authentic), then enriched with playbook badges if the
skills bundle is present. Local only — no network. Requires Playwright/Chromium
(``playwright install chromium``).

Run:  python docs/make_report_screenshot.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scanner.engine import Finding, Severity            # noqa: E402
from scanner.vulns import command_injection, sqli_detect, xss_detect  # noqa: E402
from scanner.vulns._common import Injector              # noqa: E402
from scanner.web import headers_check                   # noqa: E402
from scanner.output.report_html import generate_html    # noqa: E402

TARGET = "http://testaspnet.vulnweb.com/"


def _findings() -> list[Finding]:
    fs: list[Finding] = []

    # SQL injection (CRITICAL) — evidence + full sqlmap exploitation walkthrough.
    sqli = sqli_detect._finding(f"{TARGET}Comments.aspx?id=0", "id",
                                "boolean-based blind", "0 AND 1=1", "MSSQL")
    sqli.raw["evidence"] = [
        "injected into URL parameter 'id': 0 AND 1=1",
        "GET /Comments.aspx?id=0+AND+1%3D1 → 200 OK, 5.1 KB (text/html)",
        "matched: TRUE≈baseline (5.1 KB) while FALSE differs (1.2 KB) — blind boolean split",
    ]
    fs.append(sqli)

    # OS command injection (CRITICAL) — commix chain.
    inj = Injector(label="URL parameter 'host'", param="host", inject=lambda p: None,
                   proof=lambda p: f"{TARGET}tools/ping?host=" + p, url=f"{TARGET}tools/ping?host=1")
    fs.append(command_injection._finding(
        inj, "; id", "output-based", "uid=0(root) gid=0(root)",
        ["injected into URL parameter 'host': ; id",
         "GET /tools/ping?host=;+id → 200 OK, 0.4 KB (text/plain)",
         "matched: command output in response: uid=0(root) gid=0(root)"]))

    # Reflected XSS (HIGH) — dalfox chain.
    fs.append(xss_detect._finding(
        "URL parameter 'searchFor'", "html_text", "<q9f2c>", Severity.HIGH, "high",
        f"{TARGET}search.aspx?searchFor=%3Cq9f2c%3E",
        ["injected into URL parameter 'searchFor': <q9f2c>",
         "GET /search.aspx?searchFor=<q9f2c> → 200 OK, 8.0 KB (text/html)",
         "matched: breakout survived unencoded in HTML text context"]))

    # Exposed .git (CRITICAL) — git-dumper chain.
    fs.append(Finding(
        module="git_dumper",
        title="Exposed .git — Repository Metadata Extracted",
        description=("The exposed /.git/ directory leaks repository metadata. "
                     "Remote(s): https://github.com/acme/storefront.git. 214 tracked file(s). "
                     "The full source/history can be reconstructed (git-dumper)."),
        severity=Severity.CRITICAL,
        recommendation=("Block all access to /.git/ at the web server and never deploy it to "
                        "production. Rotate any secret ever committed."),
        raw={"confidence": "high",
             "evidence": ["GET /.git/HEAD → 200 (starts with 'ref:') — repository directory is exposed",
                          "/.git/config remote(s): https://github.com/acme/storefront.git",
                          "/.git/index parsed → 214 tracked file(s)"],
             "exploitation": [
                 {"step": 1, "description": "Reconstruct the full source tree from the exposed .git.",
                  "command": f"git-dumper {TARGET}.git/ ./loot_src"},
                 {"step": 2, "description": "Mine the commit history for committed secrets.",
                  "command": "cd loot_src && git log -p | grep -iE 'password|secret|api[_-]?key|token'"}]}))

    # Missing CSP (MEDIUM) — evidence = the observed header state.
    fs.append(headers_check._missing(
        "Content-Security-Policy", "content-security-policy", Severity.MEDIUM,
        "Define a Content-Security-Policy, starting from default-src 'self'."))

    # A couple of INFO items for the calm Information section.
    fs.append(Finding(module="basic_info", title="Server: Microsoft-IIS/8.5",
                      description="Backend web server banner.", severity=Severity.INFO))
    fs.append(Finding(module="tech_stack", title="ASP.NET 4.0.30319 detected",
                      description="Identified from the X-AspNet-Version response header.",
                      severity=Severity.INFO))
    return fs


def main() -> None:
    findings = _findings()
    try:
        from scanner.intel.skills_kb import enrich
        enrich(findings)
    except Exception:  # noqa: BLE001 — playbook badges are optional eye-candy
        pass

    report = generate_html(findings, TARGET, 38, output_path=str(ROOT / "reports"))
    out = ROOT / "assets" / "screenshots" / "hades-report.png"
    out.parent.mkdir(parents=True, exist_ok=True)

    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1200, "height": 1500}, device_scale_factor=2)
        page.goto(Path(report).as_uri())
        # Open the first exploitation walkthrough so the screenshot shows both states (expanded + summary).
        page.evaluate(
            "() => { const d = document.querySelector('details.exploit-box'); if (d) d.open = true; }")
        page.wait_for_timeout(250)
        table = page.query_selector("table.findings-table")
        (table or page).screenshot(path=str(out))
        browser.close()
    print(f"saved {out}")


if __name__ == "__main__":
    main()
