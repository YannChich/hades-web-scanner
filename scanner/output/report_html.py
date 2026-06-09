"""
report_html — exports scan findings as a self-contained dark-themed HTML report.

All styles are inlined. No external dependencies or CDN references.
"""
from __future__ import annotations

import html
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse
from urllib.request import url2pathname

from loguru import logger

if TYPE_CHECKING:
    from scanner.engine import Finding

from scanner import evidence as ev
from scanner.output import web_theme
from scanner.output.scorer import calculate_score
from scanner.severity import HTML_BG as _SEV_BG
from scanner.severity import HTML_COLOR as _SEV_COLOR
from scanner.severity import SEVERITY_ORDER as _SEV_ORDER

# ---------------------------------------------------------------------------
# Style constants
# ---------------------------------------------------------------------------

_GRADE_COLOR: dict[str, str] = {
    "A": "#34d399", "B": "#60a5fa",
    "C": "#ffd700", "D": "#ff6b35", "F": "#ff2d55",
}


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

_CSS = web_theme.ROOT_VARS + web_theme.BASE_CSS + """
/* ── Report-specific layout (palette, body font & reset come from web_theme) ── */

/* ── Header ── */
.header {
  background: linear-gradient(135deg, var(--bg-2) 0%, var(--surface) 100%);
  border-bottom: 1px solid var(--border);
  padding: 30px 40px 22px;
}
.header h1 {
  font-family: var(--mono);
  font-size: 2.3rem;
  color: var(--red);
  letter-spacing: 6px;
  text-shadow: 0 0 22px var(--red-glow);
  margin-bottom: 4px;
}
.header .prompt { font-family: var(--mono); color: var(--green); font-size: 0.8rem; letter-spacing: .5px; }
.header .prompt .pdim { color: var(--muted); }
.header .tagline { color: var(--muted); font-size: 0.8rem; letter-spacing: 2px; margin-top: 2px; }
.meta { margin-top: 16px; display: flex; gap: 28px; flex-wrap: wrap; }
.meta-item { color: var(--muted); font-size: 0.8rem; }
.meta-item span { color: var(--ink); font-weight: 600; font-family: var(--mono); }

/* ── Main layout ── */
.container { max-width: 1200px; margin: 0 auto; padding: 32px 40px; }

/* ── Score section ── */
.score-section {
  display: flex;
  align-items: center;
  gap: 48px;
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 26px 34px;
  margin-bottom: 30px;
  flex-wrap: wrap;
}

.gauge-wrap { text-align: center; }
.gauge-label { font-family: var(--mono); font-size: 0.7rem; color: var(--muted); letter-spacing: 2px; margin-top: 10px; }

.gauge {
  width: 140px;
  height: 140px;
  border-radius: 50%;
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
  background: conic-gradient(
    var(--gauge-color) calc(var(--score-pct) * 1%  * 3.6deg),
    #1b2330 0deg
  );
  box-shadow: 0 0 26px var(--gauge-glow);
}
.gauge::before {
  content: '';
  position: absolute;
  width: 104px;
  height: 104px;
  background: var(--surface-2);
  border-radius: 50%;
}
.gauge-inner {
  position: relative;
  z-index: 1;
  text-align: center;
}
.gauge-score { font-family: var(--mono); font-size: 1.9rem; font-weight: bold; color: var(--gauge-color); }
.gauge-total { font-family: var(--mono); font-size: 0.7rem; color: var(--muted); }

.grade-badge {
  font-family: var(--mono);
  font-size: 3.4rem;
  font-weight: bold;
  color: var(--grade-color);
  text-shadow: 0 0 18px var(--grade-color);
  line-height: 1;
}
.grade-label { font-family: var(--mono); font-size: 0.7rem; color: var(--muted); letter-spacing: 2px; margin-top: 4px; }

.counts-grid {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 12px;
  flex: 1;
  min-width: 280px;
}
.count-card {
  background: var(--bg-2);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 12px 8px;
  text-align: center;
  border-top: 3px solid var(--sev-color);
}
.count-card .sev-name { font-family: var(--mono); font-size: 0.62rem; color: var(--muted); letter-spacing: 1px; }
.count-card .sev-num  { font-family: var(--mono); font-size: 1.6rem; font-weight: bold; color: var(--sev-color); }

/* ── Section headings ── */
.section-title {
  font-family: var(--mono);
  font-size: 0.78rem;
  letter-spacing: 3px;
  color: var(--muted);
  text-transform: uppercase;
  border-bottom: 1px solid var(--border-soft);
  padding-bottom: 8px;
  margin-bottom: 16px;
  margin-top: 36px;
}
.section-title::before { content: "\\2590 "; color: var(--red); }

/* ── Findings table ── */
.findings-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.84rem;
}
.findings-table th {
  background: var(--surface-2);
  color: var(--muted);
  font-family: var(--mono);
  font-weight: 600;
  letter-spacing: 2px;
  text-transform: uppercase;
  font-size: 0.68rem;
  padding: 10px 12px;
  text-align: left;
  border-bottom: 1px solid var(--border);
}
.findings-table td {
  padding: 9px 12px;
  border-bottom: 1px solid var(--border-soft);
  vertical-align: top;
}
.findings-table tr { background: var(--row-bg); }
.findings-table tr:hover td { background: rgba(255,255,255,0.03); }

.sev-badge {
  font-family: var(--mono);
  display: inline-block;
  padding: 2px 8px;
  border-radius: 5px;
  font-size: 0.66rem;
  font-weight: bold;
  letter-spacing: 1px;
  color: var(--sev-color);
  background: var(--sev-bg);
  border: 1px solid var(--sev-color);
  white-space: nowrap;
}
.module-tag {
  font-family: var(--mono);
  color: var(--muted);
  font-size: 0.74rem;
  white-space: nowrap;
}
.title-cell { color: var(--bright); font-weight: 600; }
.desc-cell  { color: var(--muted); max-width: 440px; }
.rec-cell   { color: var(--blue); max-width: 260px; font-size: 0.78rem; }

/* ── Evidence box: the exact request/response that proves the finding ── */
.evidence-box {
  margin-top: 7px;
  padding: 6px 9px;
  border-left: 3px solid var(--green);
  background: rgba(57, 211, 83, 0.06);
  border-radius: 4px;
  font-family: var(--mono);
  font-size: 0.7rem;
  line-height: 1.5;
  color: var(--ink);
  word-break: break-word;
}
.ev-tag  { display: block; color: var(--green); font-weight: bold; font-size: 0.62rem;
           letter-spacing: 0.5px; margin-bottom: 2px; }
.ev-line { color: var(--muted); }

/* ── Exploitation walkthrough: collapsible copy-paste kill chain ── */
.exploit-box { margin-top: 7px; }
.exploit-box > summary {
  cursor: pointer; color: var(--red); font-weight: bold; font-size: 0.72rem;
  font-family: var(--mono); letter-spacing: 0.3px; list-style: none;
}
.exploit-box > summary::-webkit-details-marker { display: none; }
.exploit-box > summary::before { content: "▸ "; }
.exploit-box[open] > summary::before { content: "▾ "; }
.exp-list { margin: 6px 0 0; padding-left: 18px; }
.exp-list li { margin-bottom: 7px; }
.exp-desc { color: var(--ink); font-size: 0.76rem; }
.exp-cmd {
  margin: 3px 0 0; padding: 5px 8px; border-radius: 4px;
  background: var(--bg-2); border: 1px solid var(--border);
  color: var(--green); font-family: var(--mono); font-size: 0.72rem;
  white-space: pre-wrap; word-break: break-all;
}

/* ── Framework reference pills (ID / CVSS / CWE / OWASP / ATT&CK) ── */
.refs { margin-top: 6px; display: flex; flex-wrap: wrap; gap: 5px; }
.ref-pill {
  font-family: var(--mono);
  display: inline-block;
  padding: 1px 7px;
  border-radius: 6px;
  font-size: 0.64rem;
  font-weight: bold;
  letter-spacing: 0.4px;
  border: 1px solid var(--border);
  background: var(--bg-2);
  color: var(--muted);
  white-space: nowrap;
}
.ref-id    { color: var(--ink); border-color: #3b4350; }
.ref-cvss  { color: var(--sev-color); border-color: var(--sev-color); }
.ref-cwe   { color: var(--purple); border-color: var(--purple-line); }
.ref-owasp { color: var(--orange); border-color: #bb8009; }
.ref-mitre { color: var(--blue); border-color: #1f6feb; }
.ref-tool  { color: var(--yellow); border-color: #9e6a03; background: #1c1808; }
.ref-play  { color: var(--purple); border-color: var(--purple-line); background: #1a1430; }
.ref-fix   { color: var(--green); border-color: var(--green-deep); background: #0c1f12; }
/* Every reference badge is a link to its canonical explanation page. */
a.ref-pill { text-decoration: none; cursor: pointer; transition: filter .15s, box-shadow .15s; }
a.ref-pill:hover { text-decoration: none; filter: brightness(1.35); box-shadow: 0 0 0 1px currentColor; }
a.ref-play:hover { text-decoration: none; background: #241a3d; filter: none; box-shadow: none; }
a.ref-fix:hover  { text-decoration: none; background: #12351c; filter: none; box-shadow: none; }
/* Per-finding expandable: keeps ATT&CK / tools / playbooks / PoC out of the way until wanted. */
.ref-more { margin-top: 5px; }
.ref-more > summary { font-family: var(--mono); color: var(--faint); font-size: 0.7rem; font-weight: 600;
  letter-spacing: .3px; cursor: pointer; list-style: none; display: inline-block; padding: 1px 0; user-select: none; }
.ref-more > summary::-webkit-details-marker { display: none; }
.ref-more > summary::before { content: "▸ "; color: var(--red); }
.ref-more[open] > summary::before { content: "▾ "; color: var(--green); }
.ref-more > summary:hover { color: var(--muted); }
.ref-more > .refs { margin-top: 5px; }
.ref-more > .poc-block { margin-top: 5px; }
/* Recommended-playbooks section */
.play-list { list-style: none; }
.play-list li {
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-left: 3px solid var(--purple-line);
  border-radius: 6px;
  padding: 12px 16px;
  margin-bottom: 10px;
}
.play-list .play-name { font-family: var(--mono); color: var(--purple); font-weight: bold; font-size: 0.88rem; }
.play-list .play-meta { font-family: var(--mono); color: var(--blue); font-size: 0.7rem; letter-spacing: 1px; margin: 3px 0; }
.play-list .play-desc { color: var(--muted); font-size: 0.82rem; }
.poc-block {
  margin-top: 6px;
  padding: 7px 10px;
  background: var(--code);
  border: 1px solid var(--border);
  border-left: 3px solid var(--green);
  border-radius: 6px;
  color: var(--green);
  font: 0.74rem/1.5 var(--mono);
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
}

/* ── Recommendations ── */
.rec-list { list-style: none; }
.rec-list li {
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-left: 3px solid var(--blue);
  border-radius: 6px;
  padding: 12px 16px;
  margin-bottom: 10px;
  font-size: 0.84rem;
}
.rec-list .rec-module { font-family: var(--mono); color: var(--blue); font-size: 0.72rem; letter-spacing: 1px; }
.rec-list .rec-text   { color: var(--ink); margin-top: 4px; }

/* ── Information section (recon / context — visually distinct from the vulnerability table) ── */
.info-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 10px; margin-top: 8px; }
.info-item { background: var(--surface-2); border: 1px solid var(--border); border-left: 3px solid var(--sev-info);
  border-radius: 8px; padding: 11px 14px; }
.info-head { display: flex; align-items: center; gap: 8px; }
.info-chip { font-family: var(--mono); font-size: 0.58rem; font-weight: 700; letter-spacing: .5px;
  color: var(--sev-info); border: 1px solid #1f6feb; background: #0b1530; border-radius: 8px; padding: 1px 7px; white-space: nowrap; }
.info-module { font-family: var(--mono); color: var(--muted); font-size: 0.72rem; }
.info-title { color: var(--bright); font-weight: 600; font-size: 0.86rem; margin-top: 6px; }
.info-desc { color: var(--muted); font-size: 0.8rem; margin-top: 3px; word-break: break-word; }

/* ── Footer ── */
.footer {
  text-align: center;
  padding: 24px;
  color: var(--faint);
  font-size: 0.75rem;
  border-top: 1px solid var(--border-soft);
  margin-top: 48px;
}
"""

# ---------------------------------------------------------------------------
# HTML building helpers
# ---------------------------------------------------------------------------

def _e(text: str) -> str:
    """HTML-escape a string."""
    return html.escape(str(text), quote=True)


def _gauge_html(score: int, grade: str) -> str:
    gauge_color = _GRADE_COLOR.get(grade, "#c9d1d9")
    grade_color = gauge_color
    return f"""
<div class="gauge-wrap">
  <div class="gauge" style="--score-pct:{score};--gauge-color:{gauge_color};--gauge-glow:{gauge_color}44;">
    <div class="gauge-inner">
      <div class="gauge-score">{score}</div>
      <div class="gauge-total">/100</div>
    </div>
  </div>
  <div class="gauge-label">SECURITY SCORE</div>
</div>
<div style="text-align:center;">
  <div class="grade-badge" style="--grade-color:{grade_color};">{grade}</div>
  <div class="grade-label">GRADE</div>
</div>
"""


def _counts_html(counts: dict[str, int]) -> str:
    cards = ""
    for sev in _SEV_ORDER:
        color = _SEV_COLOR[sev]
        cards += (
            f'<div class="count-card" style="--sev-color:{color};">'
            f'<div class="sev-name">{sev.upper()}</div>'
            f'<div class="sev-num">{counts[sev]}</div>'
            f"</div>"
        )
    return f'<div class="counts-grid">{cards}</div>'


# Every reference badge links to a canonical explanation page (like the playbook pills do).
_OWASP_2021_SLUG: dict[str, str] = {
    "A01": "A01_2021-Broken_Access_Control",
    "A02": "A02_2021-Cryptographic_Failures",
    "A03": "A03_2021-Injection",
    "A04": "A04_2021-Insecure_Design",
    "A05": "A05_2021-Security_Misconfiguration",
    "A06": "A06_2021-Vulnerable_and_Outdated_Components",
    "A07": "A07_2021-Identification_and_Authentication_Failures",
    "A08": "A08_2021-Software_and_Data_Integrity_Failures",
    "A09": "A09_2021-Security_Logging_and_Monitoring_Failures",
    "A10": "A10_2021-Server-Side_Request_Forgery_%28SSRF%29",
}


def _cwe_url(cwe: str) -> str:
    m = re.search(r"CWE-(\d+)", cwe or "")
    return f"https://cwe.mitre.org/data/definitions/{m.group(1)}.html" if m else ""


def _owasp_url(owasp: str) -> str:
    code = (owasp or "").split(":")[0].strip().upper()
    slug = _OWASP_2021_SLUG.get(code)
    return f"https://owasp.org/Top10/{slug}/" if slug else "https://owasp.org/www-project-top-ten/"


def _mitre_url(tech: str) -> str:
    m = re.fullmatch(r"\s*(T\d{4})(?:\.(\d{3}))?\s*", tech or "")
    if not m:
        return ""
    return f"https://attack.mitre.org/techniques/{m.group(1)}/" + (f"{m.group(2)}/" if m.group(2) else "")


def _cvss_url(f: Finding) -> str:
    vec = (f.raw or {}).get("cvss_vector", "") if hasattr(f, "raw") else ""
    m = re.match(r"CVSS:(\d\.\d)", vec or "")
    if m:
        return f"https://www.first.org/cvss/calculator/{m.group(1)}#{vec}"
    return "https://www.first.org/cvss/"   # generic CVSS explanation (no vector available)


def _cve_url(cve_id: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}" if re.fullmatch(r"CVE-\d{4}-\d+", cve_id or "") else ""


def _tool_url(tool: str) -> str:
    # No per-tool registry, so point at a GitHub repository search that reliably surfaces the tool.
    from urllib.parse import quote
    return f"https://github.com/search?q={quote(tool)}&type=repositories"


def _link_pill(cls: str, label: str, href: str, title: str, extra_style: str = "") -> str:
    """A reference badge; an <a> when a canonical page exists, otherwise a plain <span>."""
    style = f' style="{extra_style}"' if extra_style else ""
    if href:
        return (f'<a class="ref-pill {cls}" href="{_e(href)}" target="_blank" rel="noopener" '
                f'title="{_e(title)}"{style}>{label}</a>')
    return f'<span class="ref-pill {cls}" title="{_e(title)}"{style}>{label}</span>'


def _refs_html(f: Finding, sev_color: str) -> str:
    """A finding's references: a compact always-visible classification row (ID/CVSS/CWE/OWASP), plus a
    collapsible <details> holding the ATT&CK techniques, tools, playbooks and PoC — so the report stays
    scannable instead of drowning each finding in a wall of badges."""
    raw = f.raw or {}
    cve_id = raw.get("cve_id", "")

    # ── Primary: at-a-glance classification (always visible) ──
    primary: list[str] = []
    if cve_id:                                  # real CVE → NVD; else the internal Hades finding ID
        primary.append(_link_pill("ref-id", _e(cve_id), _cve_url(cve_id), f"View {cve_id} on NVD"))
    else:
        primary.append(f'<span class="ref-pill ref-id">{_e(f.finding_id)}</span>')
    if f.cvss is not None:
        primary.append(_link_pill("ref-cvss", f"CVSS {f.cvss:g}", _cvss_url(f),
                                  "CVSS scoring (FIRST)", f"--sev-color:{sev_color};"))
    if f.cwe:
        primary.append(_link_pill("ref-cwe", _e(f.cwe), _cwe_url(f.cwe), f"{f.cwe} on cwe.mitre.org"))
    if f.owasp:
        code = f.owasp.split(" ")[0]            # short code, e.g. "A06:2021"
        primary.append(_link_pill("ref-owasp", _e(code), _owasp_url(f.owasp), f"OWASP {code}"))

    # ── Secondary: how it's abused & what to do next (collapsed in <details>) ──
    secondary: list[str] = []
    for tech in f.mitre:
        secondary.append(_link_pill("ref-mitre", _e(tech), _mitre_url(tech), f"ATT&CK {tech}"))
    for tool in (f.redteam_tools or []):
        secondary.append(_link_pill("ref-tool", f"🛠 {_e(tool)}", _tool_url(tool), f"Find {tool} on GitHub"))
    for s in (f.skill_refs or []):
        href = s.get("href") or "#"
        secondary.append(f'<a class="ref-pill ref-play" href="{_e(href)}" target="_blank" rel="noopener" '
                         f'title="Open the offensive playbook">📘 {_e(s["name"])}</a>')
    for s in (getattr(f, "remediation_refs", None) or []):
        href = s.get("href") or "#"
        secondary.append(f'<a class="ref-pill ref-fix" href="{_e(href)}" target="_blank" rel="noopener" '
                         f'title="Open the remediation playbook">🛡 Fix: {_e(s["name"])}</a>')

    html = f'<div class="refs">{"".join(primary)}</div>'

    poc_html = f'<div class="poc-block">$ {_e(f.poc)}</div>' if f.poc else ""
    if secondary or poc_html:
        bits: list[str] = []
        if f.mitre:
            bits.append("ATT&CK")
        if f.redteam_tools:
            bits.append("tools")
        if f.skill_refs or getattr(f, "remediation_refs", None):
            bits.append("playbooks")
        if poc_html:
            bits.append("PoC")
        count = f" ({len(secondary)})" if secondary else ""
        summary = f"Details — {' · '.join(bits)}{count}"
        inner = (f'<div class="refs">{"".join(secondary)}</div>' if secondary else "") + poc_html
        html += f'<details class="ref-more"><summary>{summary}</summary>{inner}</details>'
    return html


def _evidence_html(f: Finding) -> str:
    """A compact monospace box showing the exact request/response that proves the finding."""
    items = ev.as_list((f.raw or {}).get("evidence"))
    if not items:
        return ""
    lines = "".join(f'<div class="ev-line">{_e(it)}</div>' for it in items[:4])
    return f'<div class="evidence-box"><span class="ev-tag">⧉ evidence</span>{lines}</div>'


def _exploitation_html(f: Finding) -> str:
    """A collapsible, ordered walkthrough of the copy-paste commands that weaponise the finding
    (e.g. the sqlmap kill chain under a confirmed SQL injection). Kept in <details> so the report
    stays uncluttered."""
    steps = (f.raw or {}).get("exploitation")
    if not isinstance(steps, list) or not steps:
        return ""
    items = ""
    for s in steps:
        desc = _e(str(s.get("description", "")))
        cmd = _e(str(s.get("command", "")))
        items += (f'<li><span class="exp-desc">{desc}</span>'
                  f'<pre class="exp-cmd">$ {cmd}</pre></li>')
    return (f'<details class="exploit-box"><summary>⛓ Exploitation walkthrough '
            f'({len(steps)} steps)</summary><ol class="exp-list">{items}</ol></details>')


def _findings_table_html(findings: list[Finding]) -> str:
    if not findings:
        return "<p style='color:var(--muted);'>No findings recorded.</p>"

    rows = ""
    for f in findings:
        sev = f.severity.value
        color = _SEV_COLOR.get(sev, "#c9d1d9")
        bg    = _SEV_BG.get(sev, "transparent")
        desc = (f'<td class="desc-cell">{_e(f.description[:200])}'
                f'{"…" if len(f.description) > 200 else ""}'
                f'{_evidence_html(f)}{_exploitation_html(f)}</td>')
        rows += (
            f'<tr style="--row-bg:{bg};">'
            f'<td><span class="sev-badge" style="--sev-color:{color};--sev-bg:{bg};">'
            f"{sev.upper()}</span></td>"
            f'<td class="module-tag">{_e(f.module)}</td>'
            f'<td class="title-cell">{_e(f.title)}{_refs_html(f, color)}</td>'
            f'{desc}'
            f'<td class="rec-cell">{_e(f.recommendation[:160])}{"…" if len(f.recommendation) > 160 else ""}</td>'
            f"</tr>"
        )

    return f"""
<table class="findings-table">
  <thead>
    <tr>
      <th>Severity</th><th>Module</th><th>Title</th>
      <th>Description</th><th>Recommendation</th>
    </tr>
  </thead>
  <tbody>{rows}</tbody>
</table>
"""


def _information_html(infos: list[Finding]) -> str:
    """INFO findings (recon / context) as a calm card grid — clearly distinct from the red
    vulnerabilities table (no severity badge, blue accent)."""
    if not infos:
        return ""
    cards = ""
    for f in infos:
        desc = f.description[:300] + ("…" if len(f.description) > 300 else "")
        cards += (
            '<div class="info-item">'
            '<div class="info-head"><span class="info-chip">ℹ INFO</span>'
            f'<span class="info-module">{_e(f.module)}</span></div>'
            f'<div class="info-title">{_e(f.title)}</div>'
            f'<div class="info-desc">{_e(desc)}</div></div>'
        )
    return f'<div class="info-grid">{cards}</div>'


_DB_REMEDIATION: dict[str, str] = {
    "Redis": "Set 'requirepass', enable protected-mode, bind to 127.0.0.1, firewall port 6379.",
    "MongoDB": "Enable authorization, bind to a private IP, and firewall port 27017.",
    "MySQL/MariaDB": "Set a strong root password, 'bind-address=127.0.0.1', remove anonymous users, require TLS.",
    "PostgreSQL": "Harden pg_hba.conf (no 'trust'), 'listen_addresses=localhost', require SSL.",
    "MSSQL": "Disable/secure the 'sa' account, restrict to a private network, enable Force Encryption.",
    "Elasticsearch": "Enable security (auth), bind to a private IP, firewall ports 9200/9300.",
    "CouchDB": "Set admin credentials (disable Admin Party) and bind to a private IP.",
    "Memcached": "Disable UDP, bind to 127.0.0.1, enable SASL, firewall port 11211.",
}
_DB_GRADE_COLOR = {"SECURE": "#2ea043", "AT RISK": "#d29922",
                   "EXPOSED": "#db6d28", "CRITICAL": "#f85149"}


def _db_section_html(findings: list[Finding]) -> str:
    db = [f for f in findings if f.module == "db_security"]
    if not db:
        return ""

    score_f = next((f for f in db if f.raw.get("db_category") == "score"), None)
    score = int(score_f.raw.get("score", 0)) if score_f else 0
    grade = score_f.raw.get("grade", "") if score_f else ""
    color = _DB_GRADE_COLOR.get(grade, "var(--muted)")

    rows = ""
    for f in sorted(db, key=lambda x: _SEV_ORDER.index(x.severity.value)):
        if f.raw.get("db_category") == "score":
            continue
        sev = f.severity.value
        rows += (
            f'<tr><td><span class="sev-badge" style="--sev-color:{_SEV_COLOR.get(sev, "#c9d1d9")};'
            f'--sev-bg:{_SEV_BG.get(sev, "transparent")};">{sev.upper()}</span></td>'
            f'<td class="title-cell">{_e(f.title)}</td>'
            f'<td class="desc-cell">{_e(f.description[:220])}{"…" if len(f.description) > 220 else ""}'
            f'{_evidence_html(f)}</td></tr>'
        )

    # Red-team attack path (ordered exploitation commands) + extracted loot.
    from scanner.db.db_security import build_playbook, collect_loot  # noqa: PLC0415
    plan = build_playbook(findings)
    loot = collect_loot(findings)
    attack_html = ""
    if plan:
        def _cmd_pre(cmd: str) -> str:
            return (f'<pre style="margin:6px 0 0 0;padding:8px 10px;background:var(--bg-2);'
                    f'border:1px solid var(--border);border-radius:6px;color:var(--green);overflow-x:auto;'
                    f'font:600 12px/1.5 ui-monospace,monospace;">$ {_e(cmd)}</pre>')

        def _step_html(s: dict) -> str:
            attack = (f'<span style="margin-left:8px;color:var(--purple);font:600 11px ui-monospace,'
                      f'monospace;">⟦{_e(s["attack"])}⟧</span>' if s.get("attack") else "")
            evidence = (f'<div style="margin-top:4px;color:var(--green);font:12px ui-monospace,'
                        f'monospace;">⧉ evidence: {_e(s["evidence"])}</div>' if s.get("evidence") else "")
            sub = s.get("steps") or []
            if len(sub) > 1:
                body = "".join(
                    f'<div style="margin:6px 0 0 0;color:var(--muted);font:12px system-ui;">'
                    f'{st.get("step")}. {_e(str(st.get("description", "")))}</div>'
                    f'{_cmd_pre(str(st.get("command", "")))}' for st in sub)
            else:
                body = _cmd_pre(s["command"])
            return (
                f'<li><span class="sev-badge" style="--sev-color:{_SEV_COLOR.get(s["severity"], "#c9d1d9")};'
                f'--sev-bg:{_SEV_BG.get(s["severity"], "transparent")};">{s["severity"].upper()}</span> '
                f'{_e(s["title"])}{attack}{body}{evidence}</li>'
            )
        steps = "".join(_step_html(s) for s in plan)
        attack_html += (
            '<div class="section-title" style="font-size:16px;margin-top:18px;">'
            '⚔ Attack Path — Exploitation Commands</div>'
            f'<ol class="rec-list">{steps}</ol>'
        )
    if loot:
        loot_items = "".join(f"<li>{_e(item)}</li>" for item in loot[:15])
        attack_html += (
            '<div class="section-title" style="font-size:16px;margin-top:18px;">'
            '💰 Loot Extracted</div>'
            f'<ul class="rec-list">{loot_items}</ul>'
        )

    engines = sorted({f.raw.get("engine") for f in db if f.raw.get("engine")})
    checklist = [_DB_REMEDIATION[e] for e in engines if e in _DB_REMEDIATION]
    checklist += [
        "Never expose database ports directly to the internet — use a VPN or allowlist.",
        "Remove database admin web interfaces (phpMyAdmin, Adminer…) from public access.",
        "Move database dumps/backups out of the web root.",
        "Use parameterised queries to prevent SQL and NoSQL injection.",
    ]
    checklist_html = "".join(f"<li>{_e(item)}</li>" for item in checklist)

    return f"""
  <div class="section-title">Database Security</div>
  <div style="margin:0 0 18px 0;">
    <div style="font:600 13px/1 system-ui;color:var(--muted);margin-bottom:6px;">DB EXPOSURE SCORE</div>
    <div style="background:var(--surface-2);border:1px solid var(--border);border-radius:8px;height:26px;overflow:hidden;">
      <div style="width:{score}%;height:100%;background:{color};
                  display:flex;align-items:center;justify-content:flex-end;padding-right:10px;
                  color:#0d1117;font:700 13px system-ui;">{score}/100</div>
    </div>
    <div style="margin-top:6px;font:700 15px system-ui;color:{color};">{_e(grade)}</div>
  </div>
  <table class="findings-table">
    <thead><tr><th>Severity</th><th>Finding</th><th>Detail</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  {attack_html}
  <div class="section-title" style="font-size:16px;margin-top:18px;">Remediation Checklist</div>
  <ul class="rec-list">{checklist_html}</ul>
"""


def _attack_path_html(findings: list[Finding], base_url: str) -> str:
    """Unified kill-chain attack path: ordered, copy-paste exploitation steps by ATT&CK phase."""
    from scanner.output.attack_path import build_attack_path  # noqa: PLC0415

    groups = build_attack_path(findings, base_url)
    if not groups:
        return ""

    total = sum(len(g["steps"]) for g in groups)
    blocks = ""
    for g in groups:
        steps = ""
        for s in g["steps"]:
            sev = s["severity"]
            mitre = "".join(_link_pill("ref-mitre", _e(t), _mitre_url(t), f"ATT&CK {t}") for t in s["mitre"])
            cmd = (f'<pre style="margin:6px 0 0 0;padding:8px 10px;background:var(--bg-2);'
                   f'border:1px solid var(--border);border-radius:6px;color:var(--green);overflow-x:auto;'
                   f'font:600 12px/1.5 ui-monospace,monospace;">$ {_e(s["command"])}</pre>'
                   if s["command"] else "")
            play = (f'<div style="margin-top:4px;color:var(--purple);font-size:0.78rem;">'
                    f'📘 {_e(s["playbook"])}</div>' if s["playbook"] else "")
            tools = (f'<div style="margin-top:4px;color:var(--yellow);font-size:0.78rem;">'
                     f'🛠 tools: {_e(", ".join(s["tools"]))}</div>' if s["tools"] else "")
            evid = (f'<div style="margin-top:4px;color:var(--green);font:12px ui-monospace,monospace;">'
                    f'⧉ evidence: {_e(s["evidence"])}</div>' if s["evidence"] else "")
            steps += (
                f'<li><span style="color:var(--muted);">#{s["n"]}</span> '
                f'<span class="sev-badge" style="--sev-color:{_SEV_COLOR.get(sev, "#c9d1d9")};'
                f'--sev-bg:{_SEV_BG.get(sev, "transparent")};">{sev.upper()}</span> '
                f'<span style="color:var(--bright);font-weight:bold;">{_e(s["title"])}</span> '
                f'<span style="color:var(--muted);font-size:0.72rem;">[{_e(s["id"])}]</span> {mitre}'
                f'{cmd}{play}{tools}{evid}</li>'
            )
        blocks += (
            f'<div class="section-title" style="font-size:15px;margin-top:16px;color:var(--blue);">'
            f'▼ {_e(g["phase"])} <span style="color:var(--faint);font-size:12px;">{_e(g["tactic"])}</span></div>'
            f'<ol class="rec-list">{steps}</ol>'
        )

    return f"""
  <div class="section-title">Attack Path — Kill Chain</div>
  <p style="color:var(--muted);font-size:0.8rem;margin-bottom:8px;">
    {total} actionable step(s) grouped by MITRE ATT&CK tactic in attacker order. Commands are
    copy-paste — authorised targets only.
  </p>
  {blocks}
"""


def _playbooks_html(findings: list[Finding]) -> str:
    """Consolidated 'Recommended Playbooks' section from the skills-library enrichment."""
    from scanner.intel.skills_kb import distinct_skills  # noqa: PLC0415

    skills = distinct_skills(findings)
    if not skills:
        return ""

    items = ""
    for s in skills:
        href = s.get("href") or "#"
        mitre = " · ".join(s.get("mitre", [])[:4])
        tags = " · ".join(s.get("tags", [])[:5])
        meta = " &nbsp;|&nbsp; ".join(p for p in (mitre, tags) if p)
        items += (
            f'<li><a class="play-name" href="{_e(href)}">📘 {_e(s["name"])}</a>'
            f'{f"<div class=\"play-meta\">{_e(meta)}</div>" if meta else ""}'
            f'<div class="play-desc">{_e((s.get("description") or "").strip())}</div></li>'
        )
    return f"""
  <div class="section-title">Recommended Playbooks</div>
  <p style="color:var(--muted);font-size:0.8rem;margin-bottom:14px;">
    Expert procedures matched from the cybersecurity skills library — each link opens the full
    step-by-step playbook (detection, exploitation, and remediation).
  </p>
  <ul class="play-list">{items}</ul>
"""


def _recommendations_html(findings: list[Finding]) -> str:
    seen: set[str] = set()
    recs: list[tuple[str, str]] = []
    for f in findings:
        rec = (f.recommendation or "").strip()
        if rec and rec not in seen:
            seen.add(rec)
            recs.append((f.module, rec))
        if len(recs) >= 10:
            break

    if not recs:
        return "<p style='color:var(--muted);'>No recommendations available.</p>"

    items = "".join(
        f'<li><div class="rec-module">{_e(mod)}</div>'
        f'<div class="rec-text">{_e(rec)}</div></li>'
        for mod, rec in recs
    )
    return f'<ul class="rec-list">{items}</ul>'


# ---------------------------------------------------------------------------
# Main export
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Playbook rendering — turn a local SKILL.md into a readable styled HTML page
# ---------------------------------------------------------------------------

_PLAYBOOK_CSS = """
.wrap{max-width:900px;margin:0 auto;padding:36px 22px 80px;}
.pb-head{border-bottom:2px solid var(--red);padding-bottom:14px;margin-bottom:22px;}
.pb-kicker{font-family:var(--mono);color:var(--purple);font-weight:700;letter-spacing:2px;font-size:.72rem;text-transform:uppercase;}
h1.pb-title{margin:6px 0 8px;font-size:1.7rem;color:var(--bright);}
.pb-desc{color:var(--muted);font-size:1rem;margin:0 0 12px;}
.pb-tags{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px;}
.pb-tag{font-family:var(--mono);font-size:.64rem;font-weight:700;letter-spacing:.5px;border:1px solid var(--purple-line);
  color:var(--purple);background:#1a1430;border-radius:8px;padding:2px 8px;white-space:nowrap;}
.pb-tag.atk{border-color:#1f6feb;color:var(--blue);background:var(--bg-2);}
.content h1,.content h2,.content h3{color:var(--bright);margin-top:1.6em;border-bottom:1px solid var(--border);padding-bottom:.3em;}
.content h2{font-size:1.3rem;} .content h3{font-size:1.08rem;border-bottom:none;}
.content a{color:var(--link);} .content strong{color:var(--bright);}
.content code{background:var(--code);color:var(--blue);padding:2px 6px;border-radius:5px;font-size:.86em;font-family:var(--mono);}
.content pre{background:var(--code);border:1px solid var(--border);border-left:3px solid var(--green);border-radius:8px;
  padding:14px 16px;overflow-x:auto;}
.content pre code{background:none;color:var(--green);padding:0;}
.content table{border-collapse:collapse;width:100%;margin:1em 0;}
.content th,.content td{border:1px solid var(--border);padding:7px 11px;text-align:left;}
.content th{background:var(--surface-2);color:var(--bright);}
.content blockquote{border-left:3px solid var(--purple-line);margin:1em 0;padding:.4em 1em;color:var(--muted);background:var(--surface-2);}
.content ul,.content ol{padding-left:1.4em;}
.pb-foot{margin-top:48px;padding-top:16px;border-top:1px solid var(--border-soft);color:var(--faint);font-size:.8rem;}
.pb-foot a{color:var(--purple);}
"""


def _strip_frontmatter(md: str) -> str:
    if md.startswith("---"):
        parts = md.split("---", 2)
        if len(parts) == 3:
            return parts[2].lstrip("\n")
    return md


def _playbook_page(skill: dict, md_text: str) -> str:
    """Render one SKILL.md into a self-contained, dark-themed HTML page."""
    import markdown  # local import — optional dependency
    body = markdown.markdown(
        _strip_frontmatter(md_text),
        extensions=["fenced_code", "tables", "toc", "sane_lists", "nl2br"],
    )
    name = skill.get("name", "playbook")
    title = name.replace("-", " ").title()
    tags = "".join(f'<span class="pb-tag">{_e(t)}</span>' for t in (skill.get("tags") or [])[:8])
    atk = "".join(f'<span class="pb-tag atk">{_e(m)}</span>' for m in (skill.get("mitre") or [])[:6])
    desc = _e((skill.get("description") or "").strip())
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Playbook — {_e(title)}</title><style>{web_theme.ROOT_VARS}{web_theme.BASE_CSS}{_PLAYBOOK_CSS}</style></head>
<body><div class="wrap">
  <div class="pb-head">
    <div class="pb-kicker">📘 Expert Playbook · Hades</div>
    <h1 class="pb-title">{_e(title)}</h1>
    <p class="pb-desc">{desc}</p>
    <div class="pb-tags">{atk}{tags}</div>
  </div>
  <div class="content">{body}</div>
  <div class="pb-foot">Rendered by Hades from the Anthropic-Cybersecurity-Skills library ·
    for authorised security testing only.</div>
</div></body></html>"""


def _render_playbooks_to_html(findings: list[Finding], output_dir: str) -> None:
    """Render local SKILL.md playbooks to styled HTML and rewrite each finding's href in place.

    Clicking a playbook badge then opens a readable page instead of raw Markdown. If local
    rendering is not possible — the `markdown` library is missing, or a file can't be read or
    rendered — the badge is repointed to the skill's GitHub page (which renders Markdown) so it
    never opens a raw .md file. GitHub (https) links are left untouched.
    """
    from scanner.intel.skills_kb import github_url  # noqa: PLC0415

    try:
        import markdown  # noqa: F401
        have_markdown = True
    except ImportError:
        have_markdown = False

    pb_dir = Path(output_dir) / "playbooks"
    rendered: dict[str, str] = {}

    def _fallback(name: str, s: dict) -> None:
        """Repoint a badge to the GitHub-rendered page; leave it unchanged if no URL is known."""
        gh = github_url(name)
        if gh:
            s["href"] = rendered[name] = gh

    for f in findings:
        refs = (getattr(f, "skill_refs", None) or []) + (getattr(f, "remediation_refs", None) or [])
        for s in refs:
            href = s.get("href", "")
            if not (href.startswith("file:") and href.lower().rstrip("/").endswith(".md")):
                continue
            name = s.get("name", "playbook")
            if name in rendered:
                s["href"] = rendered[name]
                continue
            if not have_markdown:
                _fallback(name, s)
                continue
            try:
                md_path = Path(url2pathname(urlparse(href).path))
                md_text = md_path.read_text(encoding="utf-8")
            except OSError as exc:
                logger.debug(f"report_html: cannot read playbook {name}: {exc}")
                _fallback(name, s)
                continue
            try:
                pb_dir.mkdir(parents=True, exist_ok=True)
                out = pb_dir / (re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:80] + ".html")
                out.write_text(_playbook_page(s, md_text), encoding="utf-8")
            except Exception as exc:  # noqa: BLE001 — rendering must never break the report
                logger.debug(f"report_html: cannot render playbook {name}: {exc}")
                _fallback(name, s)
                continue
            uri = out.resolve().as_uri()
            s["href"] = rendered[name] = uri


def generate_html(
    findings: list[Finding],
    url: str,
    score: int,
    output_path: str = "reports",
) -> str | None:
    """
    Generate a self-contained dark-theme HTML report.
    Returns the file path on success, None on error.
    """
    _, grade = calculate_score(findings)
    now = datetime.now(timezone.utc)
    timestamp_file  = now.strftime("%Y%m%d_%H%M%S")
    timestamp_human = now.strftime("%Y-%m-%d %H:%M:%S UTC")

    counts: dict[str, int] = {s: 0 for s in _SEV_ORDER}
    for f in findings:
        counts[f.severity.value] += 1

    sorted_findings = sorted(
        findings,
        key=lambda f: _SEV_ORDER.index(f.severity.value),
    )

    # Render local SKILL.md playbooks to readable HTML pages and repoint the badges — must run
    # BEFORE the finding tables are rendered so the rewritten hrefs land in the table markup.
    _render_playbooks_to_html(findings, output_path)

    # Vulnerabilities (score-affecting) vs informational/recon context — separate sections.
    vulns = [f for f in sorted_findings if f.severity.value != "info"]
    infos = [f for f in sorted_findings if f.severity.value == "info"]
    vulns_html = (_findings_table_html(vulns) if vulns
                  else '<p style="color:var(--green);font-weight:600;">✓ No vulnerabilities found.</p>')
    info_section = (f'<div class="section-title">Information</div>{_information_html(infos)}'
                    if infos else "")

    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Hades Report — {_e(url)}</title>
  <style>{_CSS}</style>
</head>
<body>

<div class="header">
  <h1>HADES</h1>
  <div class="prompt"><span class="pdim">$</span> hades <span class="pdim">--target</span> {_e(url)} <span class="pdim">--profile full --report</span></div>
  <div class="tagline">WEB SECURITY SCANNER  ·  AUTOMATED VULNERABILITY REPORT</div>
  <div class="meta">
    <div class="meta-item">TARGET &nbsp;<span>{_e(url)}</span></div>
    <div class="meta-item">SCAN DATE &nbsp;<span>{_e(timestamp_human)}</span></div>
    <div class="meta-item">TOTAL FINDINGS &nbsp;<span>{len(findings)}</span></div>
  </div>
</div>

<div class="container">

  <!-- Score & counts -->
  <div class="score-section">
    {_gauge_html(score, grade)}
    {_counts_html(counts)}
  </div>

  <!-- Vulnerabilities (CRITICAL…LOW; INFO/recon is shown separately below) -->
  <div class="section-title">Vulnerabilities</div>
  {vulns_html}

  <!-- Unified kill-chain attack path (web/recon/vuln modules) -->
  {_attack_path_html(findings, url)}

  <!-- Database security (only when a db_scan ran) -->
  {_db_section_html(findings)}

  <!-- Recommended playbooks (only when the skills library enriched findings) -->
  {_playbooks_html(findings)}

  <!-- Recommendations -->
  <div class="section-title">Recommendations</div>
  {_recommendations_html(vulns)}

  <!-- Information (recon / context — not vulnerabilities) -->
  {info_section}

</div>

<div class="footer">
  Generated by Hades &nbsp;•&nbsp; {_e(timestamp_human)} &nbsp;•&nbsp;
  For authorised security testing only.
</div>

</body>
</html>
"""

    os.makedirs(output_path, exist_ok=True)
    file_path = os.path.join(output_path, f"webscan_report_{timestamp_file}.html")

    try:
        with open(file_path, "w", encoding="utf-8") as fh:
            fh.write(document)
        logger.info(f"HTML report saved: {file_path}")
        return file_path
    except OSError as exc:
        logger.error(f"report_html: failed to write {file_path}: {exc}")
        return None
