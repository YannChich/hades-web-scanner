"""
report_html — exports scan findings as a self-contained dark-themed HTML report.

All styles are inlined. No external dependencies or CDN references.
"""
from __future__ import annotations

import html
import os
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from scanner.engine import Finding

from scanner.output.scorer import calculate_score

# ---------------------------------------------------------------------------
# Style constants
# ---------------------------------------------------------------------------

_SEV_COLOR: dict[str, str] = {
    "critical": "#ff2d55",
    "high":     "#ff6b35",
    "medium":   "#ffd700",
    "low":      "#34d399",
    "info":     "#60a5fa",
}

_SEV_BG: dict[str, str] = {
    "critical": "rgba(255,45,85,0.08)",
    "high":     "rgba(255,107,53,0.08)",
    "medium":   "rgba(255,215,0,0.08)",
    "low":      "rgba(52,211,153,0.08)",
    "info":     "rgba(96,165,250,0.06)",
}

_GRADE_COLOR: dict[str, str] = {
    "A": "#34d399", "B": "#60a5fa",
    "C": "#ffd700", "D": "#ff6b35", "F": "#ff2d55",
}

_SEV_ORDER: list[str] = ["critical", "high", "medium", "low", "info"]


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

_CSS = """
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: 'Courier New', Courier, monospace;
  background: #0a0e1a;
  color: #c9d1d9;
  font-size: 14px;
  line-height: 1.6;
}

a { color: #60a5fa; text-decoration: none; }
a:hover { text-decoration: underline; }

/* ── Header ── */
.header {
  background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
  border-bottom: 1px solid #00ff4133;
  padding: 32px 40px 24px;
}
.header h1 {
  font-size: 2.4rem;
  color: #00ff41;
  letter-spacing: 4px;
  text-shadow: 0 0 20px #00ff4155;
  margin-bottom: 4px;
}
.header .tagline { color: #8b949e; font-size: 0.85rem; letter-spacing: 2px; }
.meta { margin-top: 16px; display: flex; gap: 32px; flex-wrap: wrap; }
.meta-item { color: #8b949e; font-size: 0.82rem; }
.meta-item span { color: #c9d1d9; font-weight: bold; }

/* ── Main layout ── */
.container { max-width: 1200px; margin: 0 auto; padding: 32px 40px; }

/* ── Score section ── */
.score-section {
  display: flex;
  align-items: center;
  gap: 48px;
  background: #161b22;
  border: 1px solid #30363d;
  border-radius: 8px;
  padding: 28px 36px;
  margin-bottom: 32px;
  flex-wrap: wrap;
}

.gauge-wrap { text-align: center; }
.gauge-label { font-size: 0.75rem; color: #8b949e; letter-spacing: 2px; margin-top: 10px; }

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
    #21262d 0deg
  );
  box-shadow: 0 0 24px var(--gauge-glow);
}
.gauge::before {
  content: '';
  position: absolute;
  width: 104px;
  height: 104px;
  background: #161b22;
  border-radius: 50%;
}
.gauge-inner {
  position: relative;
  z-index: 1;
  text-align: center;
}
.gauge-score { font-size: 1.8rem; font-weight: bold; color: var(--gauge-color); }
.gauge-total { font-size: 0.7rem; color: #8b949e; }

.grade-badge {
  font-size: 3.5rem;
  font-weight: bold;
  color: var(--grade-color);
  text-shadow: 0 0 20px var(--grade-color);
  line-height: 1;
}
.grade-label { font-size: 0.75rem; color: #8b949e; letter-spacing: 2px; margin-top: 4px; }

.counts-grid {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 12px;
  flex: 1;
  min-width: 280px;
}
.count-card {
  background: #0d1117;
  border: 1px solid #30363d;
  border-radius: 6px;
  padding: 12px 8px;
  text-align: center;
  border-top: 3px solid var(--sev-color);
}
.count-card .sev-name { font-size: 0.65rem; color: #8b949e; letter-spacing: 1px; }
.count-card .sev-num  { font-size: 1.6rem; font-weight: bold; color: var(--sev-color); }

/* ── Section headings ── */
.section-title {
  font-size: 0.8rem;
  letter-spacing: 3px;
  color: #8b949e;
  text-transform: uppercase;
  border-bottom: 1px solid #21262d;
  padding-bottom: 8px;
  margin-bottom: 16px;
  margin-top: 36px;
}

/* ── Findings table ── */
.findings-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.82rem;
}
.findings-table th {
  background: #161b22;
  color: #8b949e;
  font-weight: normal;
  letter-spacing: 2px;
  text-transform: uppercase;
  font-size: 0.7rem;
  padding: 10px 12px;
  text-align: left;
  border-bottom: 1px solid #30363d;
}
.findings-table td {
  padding: 8px 12px;
  border-bottom: 1px solid #21262d;
  vertical-align: top;
}
.findings-table tr { background: var(--row-bg); }
.findings-table tr:hover td { background: #ffffff08; }

.sev-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 0.68rem;
  font-weight: bold;
  letter-spacing: 1px;
  color: var(--sev-color);
  background: var(--sev-bg);
  border: 1px solid var(--sev-color);
  white-space: nowrap;
}
.module-tag {
  color: #8b949e;
  font-size: 0.78rem;
  white-space: nowrap;
}
.title-cell { color: #e6edf3; font-weight: bold; }
.desc-cell  { color: #8b949e; max-width: 420px; }
.rec-cell   { color: #60a5fa; max-width: 260px; font-size: 0.78rem; }

/* ── Recommendations ── */
.rec-list { list-style: none; }
.rec-list li {
  background: #161b22;
  border: 1px solid #30363d;
  border-left: 3px solid #ffd700;
  border-radius: 4px;
  padding: 12px 16px;
  margin-bottom: 10px;
  font-size: 0.84rem;
}
.rec-list .rec-module { color: #ffd700; font-size: 0.72rem; letter-spacing: 1px; }
.rec-list .rec-text   { color: #c9d1d9; margin-top: 4px; }

/* ── Footer ── */
.footer {
  text-align: center;
  padding: 24px;
  color: #484f58;
  font-size: 0.75rem;
  border-top: 1px solid #21262d;
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


def _findings_table_html(findings: list[Finding]) -> str:
    if not findings:
        return "<p style='color:#8b949e;'>No findings recorded.</p>"

    rows = ""
    for f in findings:
        sev = f.severity.value
        color = _SEV_COLOR.get(sev, "#c9d1d9")
        bg    = _SEV_BG.get(sev, "transparent")
        rows += (
            f'<tr style="--row-bg:{bg};">'
            f'<td><span class="sev-badge" style="--sev-color:{color};--sev-bg:{bg};">'
            f"{sev.upper()}</span></td>"
            f'<td class="module-tag">{_e(f.module)}</td>'
            f'<td class="title-cell">{_e(f.title)}</td>'
            f'<td class="desc-cell">{_e(f.description[:200])}{"…" if len(f.description) > 200 else ""}</td>'
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
    color = _DB_GRADE_COLOR.get(grade, "#8b949e")

    rows = ""
    for f in sorted(db, key=lambda x: _SEV_ORDER.index(x.severity.value)):
        if f.raw.get("db_category") == "score":
            continue
        sev = f.severity.value
        rows += (
            f'<tr><td><span class="sev-badge" style="--sev-color:{_SEV_COLOR.get(sev, "#c9d1d9")};'
            f'--sev-bg:{_SEV_BG.get(sev, "transparent")};">{sev.upper()}</span></td>'
            f'<td class="title-cell">{_e(f.title)}</td>'
            f'<td class="desc-cell">{_e(f.description[:220])}{"…" if len(f.description) > 220 else ""}</td></tr>'
        )

    # Red-team attack path (ordered exploitation commands) + extracted loot.
    from scanner.db.db_security import build_playbook, collect_loot  # noqa: PLC0415
    plan = build_playbook(findings)
    loot = collect_loot(findings)
    attack_html = ""
    if plan:
        def _step_html(s: dict) -> str:
            attack = (f'<span style="margin-left:8px;color:#bc8cff;font:600 11px ui-monospace,'
                      f'monospace;">⟦{_e(s["attack"])}⟧</span>' if s.get("attack") else "")
            evidence = (f'<div style="margin-top:4px;color:#39d353;font:12px ui-monospace,'
                        f'monospace;">⧉ evidence: {_e(s["evidence"])}</div>' if s.get("evidence") else "")
            return (
                f'<li><span class="sev-badge" style="--sev-color:{_SEV_COLOR.get(s["severity"], "#c9d1d9")};'
                f'--sev-bg:{_SEV_BG.get(s["severity"], "transparent")};">{s["severity"].upper()}</span> '
                f'{_e(s["title"])}{attack}<pre style="margin:6px 0 0 0;padding:8px 10px;background:#0d1117;'
                f'border:1px solid #30363d;border-radius:6px;color:#39d353;overflow-x:auto;'
                f'font:600 12px/1.5 ui-monospace,monospace;">$ {_e(s["command"])}</pre>{evidence}</li>'
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
    <div style="font:600 13px/1 system-ui;color:#8b949e;margin-bottom:6px;">DB EXPOSURE SCORE</div>
    <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;height:26px;overflow:hidden;">
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
        return "<p style='color:#8b949e;'>No recommendations available.</p>"

    items = "".join(
        f'<li><div class="rec-module">{_e(mod)}</div>'
        f'<div class="rec-text">{_e(rec)}</div></li>'
        for mod, rec in recs
    )
    return f'<ul class="rec-list">{items}</ul>'


# ---------------------------------------------------------------------------
# Main export
# ---------------------------------------------------------------------------

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
  <div class="tagline">WEB SECURITY SCANNER  •  AUTOMATED VULNERABILITY REPORT</div>
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

  <!-- Findings table -->
  <div class="section-title">Findings</div>
  {_findings_table_html(sorted_findings)}

  <!-- Database security (only when a db_scan ran) -->
  {_db_section_html(findings)}

  <!-- Recommendations -->
  <div class="section-title">Recommendations</div>
  {_recommendations_html(sorted_findings)}

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
