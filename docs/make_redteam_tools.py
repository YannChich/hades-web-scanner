"""
make_redteam_tools — generate Hades_RedTeam_Tools_Reference.pdf.

Bundles the entire RedTeam-Tools knowledge base (its README) into a single, self-contained
PDF so a client who receives a Hades report — but has no access to the RedTeam-Tools repo —
still has every tool's description and usage. The PDF opens with a cross-reference table that
maps each Hades finding type (by its exact title) to the relevant RedTeam tools named in the
scan report, then reproduces the full RedTeam-Tools catalogue.

Rendering goes through the already-installed headless Chromium (Playwright), so it works on
Windows without the native GTK libraries WeasyPrint needs.

Run:  python docs/make_redteam_tools.py
"""
from __future__ import annotations

import html
import sys
from pathlib import Path

# Force UTF-8 stdout so status prints don't crash on a non-UTF8 console codepage.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Make `import config` resolve from the project root (parent of docs/).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import markdown  # noqa: E402
from config import (  # noqa: E402
    AI_EXTERNAL_TOOLS,
    FINDING_TAXONOMY,
    MODULE_REDTEAM_MAP,
    REDTEAM_REPO_CANDIDATES,
)

OUT = Path(__file__).resolve().parent / "Hades_RedTeam_Tools_Reference.pdf"

# Exact finding-title templates Hades emits, per module (so the client can match a
# line in the report to a row in the cross-reference). Modules absent here fall back
# to a humanised label.
_FINDING_TITLES: dict[str, str] = {
    "sqli_detect":       "SQL Injection ({technique}): {param}",
    "xss_detect":        "Reflected XSS: {param} [{context}]",
    "command_injection": "OS Command Injection ({technique}): {param}",
    "ssti_detect":       "Server-Side Template Injection: {param} ({engine})",
    "lfi_detect":        "Local File Inclusion / Path Traversal: {param}",
    "open_redirect":     "Open Redirect: {param}",
    "ssrf_detect":       "Server-Side Request Forgery: {param}",
    "jwt_attacks":       "JWT Accepts 'alg:none' / Weak Secret / Claims Exposed",
    "auth_bypass":       "403/401 Access-Control Bypass: {path}",
    "cve_mapping":       "CVE: {cve_id} — {technology} {version}",
    "default_creds":     "Default-Credential Risk / Valid Credentials Found",
    "bruteforce":        "Valid Credentials Found ({kind}): {user}/{pwd}",
    "git_dumper":        "Exposed .git Directory — Source Code Downloadable",
    "cloud_buckets":     "Open {provider} Bucket — World-Readable: {name}",
    "sensitive_files":   "Sensitive File Exposed [200]: {path}",
    "backup_files":      "Backup File Exposed: {path}",
    "dir_scan":          "Directory/Path Found: {path}",
    "admin_panel":       "Admin Panel Found: {path}",
    "js_recon":          "Secret in JavaScript / Hidden Endpoints",
    "subdomain_scan":    "Subdomain Discovered: {subdomain}",
    "dns_check":         "DNS Record / SPF / DMARC Issue",
    "port_scan":         "Open Port: {port}/tcp ({service})",
    "headers_check":     "Missing Security Header: {header}",
    "cors_check":        "CORS Misconfiguration",
    "clickjacking":      "Clickjacking — Missing X-Frame-Options / CSP",
    "llm_recon":         "AI/LLM: Prompt Injection / Exposed Key / LLM Server",
    "email_exposure":    "Exposed Email Address: {email}",
    "waf_detect":        "WAF / CDN Detected: {vendor}",
    "tech_stack":        "Technology Detected: {technology}",
    "basic_info":        "Server / IP / OS Fingerprint",
}


def _humanise(module: str) -> str:
    return module.replace("_", " ").title()


def _find_readme() -> Path:
    for cand in REDTEAM_REPO_CANDIDATES:
        p = Path(cand) / "README.md"
        if p.is_file():
            return p
    raise FileNotFoundError(
        "RedTeam-Tools/README.md not found. Searched: "
        + ", ".join(str(Path(c) / 'README.md') for c in REDTEAM_REPO_CANDIDATES)
    )


def _mapping_rows() -> str:
    """Build the 'Hades finding → RedTeam tools' cross-reference table rows."""
    rows = ""
    for module, tools in MODULE_REDTEAM_MAP.items():
        title = _FINDING_TITLES.get(module, _humanise(module))
        tax = FINDING_TAXONOMY.get(module, {})
        refs = " / ".join(x for x in (tax.get("cwe", ""), (tax.get("owasp", "") or "").split(" ")[0]) if x)
        if module == "llm_recon":
            refs = "OWASP-LLM / ATLAS"
        # External AI tools aren't in this catalogue — mark them with an asterisk.
        tool_pills = "".join(
            f'<span class="tp">{html.escape(t)}{"*" if t in AI_EXTERNAL_TOOLS else ""}</span>'
            for t in tools)
        rows += (
            f"<tr><td class='ft'>{html.escape(title)}</td>"
            f"<td class='fm'>{html.escape(module)}</td>"
            f"<td class='fr'>{html.escape(refs)}</td>"
            f"<td>{tool_pills}</td></tr>"
        )
    return rows


_CSS = """
@page { size: A4; margin: 18mm 14mm; }
* { box-sizing: border-box; }
body { font-family: -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
       color: #1b1f24; font-size: 11px; line-height: 1.5; }
h1, h2, h3 { color: #8a0303; line-height: 1.2; }
h1 { font-size: 26px; border-bottom: 3px solid #8a0303; padding-bottom: 6px; }
h2 { font-size: 18px; margin-top: 22px; border-bottom: 1px solid #e0c9c9; padding-bottom: 3px;
     page-break-after: avoid; }
h3 { font-size: 14px; margin-top: 16px; }
a { color: #0b62c4; text-decoration: none; }
code { background: #f3f0ee; padding: 1px 4px; border-radius: 3px; font-size: 0.92em;
       font-family: 'Consolas', ui-monospace, monospace; }
pre { background: #0d1117; color: #d6e2ef; padding: 10px 12px; border-radius: 6px;
      overflow-x: auto; font-size: 10px; line-height: 1.45; white-space: pre-wrap;
      word-break: break-word; }
pre code { background: transparent; color: inherit; padding: 0; }
img { max-width: 360px; height: auto; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; font-size: 10px; }
th, td { border: 1px solid #d9d2cc; padding: 5px 7px; text-align: left; vertical-align: top; }
th { background: #f6efe9; color: #6a0a0a; }
details { margin: 6px 0; }
summary { font-weight: bold; cursor: default; }
/* Cover + mapping */
.cover { text-align: center; padding: 40px 0 26px; page-break-after: always; }
.cover .brand { font-size: 46px; letter-spacing: 8px; color: #8a0303; font-weight: 800; }
.cover .sub { color: #555; letter-spacing: 3px; font-size: 12px; margin-top: 6px; }
.cover .desc { max-width: 560px; margin: 22px auto 0; color: #333; font-size: 12px; }
.cover .warn { margin-top: 26px; color: #8a0303; font-size: 11px; }
.map-title { color: #8a0303; }
table.map td.ft { font-weight: 600; color: #1b1f24; width: 30%; }
table.map td.fm { color: #6a6a6a; font-family: ui-monospace, monospace; width: 16%; }
table.map td.fr { color: #6e40c9; width: 16%; }
.tp { display: inline-block; background: #1c1808; color: #e3b341; border: 1px solid #9e6a03;
      border-radius: 9px; padding: 1px 7px; margin: 1px 3px 1px 0; font-size: 9px;
      font-weight: 600; white-space: nowrap; }
"""


def build_html() -> str:
    readme = _find_readme().read_text(encoding="utf-8")
    body = markdown.markdown(
        readme,
        extensions=["tables", "fenced_code", "sane_lists", "toc", "attr_list", "md_in_html"],
    )
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Hades — RedTeam Tools Reference</title><style>{_CSS}</style></head><body>

<div class="cover">
  <div class="brand">† HADES †</div>
  <div class="sub">RED TEAM TOOLS — FULL REFERENCE</div>
  <div class="desc">A self-contained catalogue of 150+ offensive security tools, organised by
    the MITRE ATT&amp;CK kill chain. Bundled so this report stands alone — no external
    repository access required. Each Hades finding names the relevant tools below; their full
    descriptions follow in the catalogue.</div>
  <div class="warn">⚠ For authorised security testing only. Source: github.com/A-poc/RedTeam-Tools</div>
</div>

<h1 class="map-title">Cross-Reference — Hades Finding → RedTeam Tools</h1>
<p>Map a finding from your Hades scan report (by its exact title) to the offensive tools that
exploit or validate it. Tool details are in the catalogue that follows.</p>
<table class="map">
  <thead><tr><th>Finding (exact Hades title)</th><th>Module</th><th>CWE / OWASP</th>
  <th>RedTeam tools</th></tr></thead>
  <tbody>{_mapping_rows()}</tbody>
</table>
<p style="font-size:9px;color:#777;margin-top:6px;">
  * AI red-team tools (garak, PyRIT, promptfoo) are external references and are not part of this
  RedTeam-Tools catalogue.
</p>

<div style="page-break-before: always;"></div>
{body}
</body></html>"""


def main() -> None:
    from playwright.sync_api import sync_playwright

    document = build_html()
    print(f"Rendering RedTeam-Tools reference -> {OUT.name} ...")
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        try:
            page.set_content(document, wait_until="load", timeout=60000)
        except Exception:  # noqa: BLE001 — remote images may stall; render anyway
            pass
        # Expand every <details> so collapsed content is printed in full.
        page.evaluate("document.querySelectorAll('details').forEach(d => d.open = true)")
        page.pdf(
            path=str(OUT),
            format="A4",
            print_background=True,
            margin={"top": "16mm", "bottom": "16mm", "left": "12mm", "right": "12mm"},
            display_header_footer=True,
            header_template="<span></span>",
            footer_template=(
                '<div style="width:100%;font-size:8px;color:#999;padding:0 12mm;'
                'display:flex;justify-content:space-between;">'
                '<span>Hades — RedTeam Tools Reference</span>'
                '<span>Page <span class="pageNumber"></span> / <span class="totalPages"></span></span>'
                '</div>'
            ),
        )
        browser.close()
    print(f"Saved: {OUT}  ({OUT.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
