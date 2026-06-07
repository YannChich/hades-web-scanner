"""
skills_library — generate & open the Skills Library reference page.

A self-contained, dark-themed, searchable HTML catalogue of the whole Anthropic-Cybersecurity-Skills
library (the 754 expert playbooks Hades draws on), grouped by subdomain. Each card shows the skill's
purpose, an offensive/defensive marker, its ATT&CK techniques and tags, and links to the rendered
SKILL.md on GitHub. Not a scan — reference material that opens in the browser (like the RedTeam
Arsenal page). Works offline from the bundled playbooks.json when the full library is absent.
"""
from __future__ import annotations

import html
import os
import webbrowser
from datetime import datetime, timezone

from loguru import logger
from rich.console import Console
from rich.panel import Panel

from scanner.intel.skills_kb import all_skills, github_url

console = Console()


def _e(text: str) -> str:
    return html.escape(str(text), quote=True)


_CSS = """
:root{--bg:#0a0a0f;--panel:#12141c;--card:#161b22;--ink:#c9d1d9;--muted:#8b949e;--red:#b3122a;
  --purple:#8957e5;--accent:#d2a8ff;--border:#272d38;--atk:#79c0ff;--off:#ff7b72;--def:#56d364;}
*{box-sizing:border-box;}
body{margin:0;background:radial-gradient(1200px 600px at 50% -10%,#1a0c12 0%,var(--bg) 60%);
  color:var(--ink);font:15px/1.6 -apple-system,Segoe UI,Roboto,sans-serif;}
.wrap{max-width:1200px;margin:0 auto;padding:30px 22px 90px;}
.head{text-align:center;border-bottom:2px solid var(--purple);padding-bottom:18px;margin-bottom:8px;}
.kicker{font-size:2.4rem;}
h1{margin:.2em 0 .1em;font-size:2rem;letter-spacing:3px;color:#fff;}
h1 .hl{color:var(--purple);}
.tag{color:var(--muted);letter-spacing:1px;font-size:.9rem;}
.stats{display:flex;gap:10px;justify-content:center;flex-wrap:wrap;margin:16px 0 6px;}
.stat{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:8px 16px;}
.stat b{color:#fff;font-size:1.25rem;} .stat span{color:var(--muted);font-size:.72rem;letter-spacing:1px;}
.legend{color:var(--muted);font-size:.78rem;text-align:center;margin-top:6px;}
.search{position:sticky;top:0;z-index:5;padding:14px 0;background:linear-gradient(var(--bg),var(--bg) 70%,transparent);}
#q{width:100%;padding:12px 16px;border-radius:12px;border:1px solid var(--border);background:var(--card);
  color:var(--ink);font-size:1rem;outline:none;}
#q:focus{border-color:var(--purple);box-shadow:0 0 0 2px #8957e533;}
.cat{margin-top:34px;}
.cat-h{display:flex;align-items:baseline;gap:12px;border-left:4px solid var(--purple);padding-left:12px;margin-bottom:4px;}
.cat-h h2{margin:0;font-size:1.35rem;color:#fff;text-transform:capitalize;}
.cat-h .count{margin-left:auto;color:var(--muted);font-size:.75rem;}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:12px;margin-top:12px;}
.skill{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:14px 16px;
  transition:border-color .15s,transform .15s;display:flex;flex-direction:column;gap:7px;}
.skill:hover{border-color:var(--purple);transform:translateY(-2px);}
.skill .row{display:flex;align-items:center;gap:8px;}
.skill a.name{color:#fff;font-weight:700;font-size:.98rem;text-decoration:none;line-height:1.3;}
.skill a.name:hover{color:var(--accent);text-decoration:underline;}
.intent{margin-left:auto;font-size:.58rem;font-weight:700;letter-spacing:.5px;border-radius:9px;
  padding:2px 8px;white-space:nowrap;border:1px solid;}
.intent.off{color:var(--off);border-color:#da3633;background:#2419170d;background:#2a1414;}
.intent.def{color:var(--def);border-color:#238636;background:#0c1f12;}
.skill .desc{color:var(--muted);font-size:.84rem;}
.chips{display:flex;flex-wrap:wrap;gap:5px;margin-top:2px;}
.chip{font-size:.62rem;border-radius:8px;padding:2px 7px;border:1px solid var(--border);color:var(--muted);}
.chip.atk{color:var(--atk);border-color:#1f6feb;background:#0b1530;}
.empty{display:none;color:var(--muted);text-align:center;padding:40px;}
.foot{margin-top:54px;padding-top:18px;border-top:1px solid #21262d;color:#484f58;text-align:center;font-size:.8rem;}
"""

_JS = """
const q=document.getElementById('q');
const skills=[...document.querySelectorAll('.skill')];
const cats=[...document.querySelectorAll('.cat')];
const empty=document.getElementById('empty');
q.addEventListener('input',()=>{
  const t=q.value.trim().toLowerCase();let shown=0;
  skills.forEach(el=>{const hit=!t||el.dataset.s.includes(t);el.style.display=hit?'':'none';if(hit)shown++;});
  cats.forEach(c=>{const any=[...c.querySelectorAll('.skill')].some(e=>e.style.display!=='none');
    c.style.display=any?'':'none';
    const cnt=c.querySelector('.count');if(cnt)cnt.textContent=[...c.querySelectorAll('.skill')].filter(e=>e.style.display!=='none').length+' skills';});
  empty.style.display=shown?'none':'block';
});
"""


def _skill_card(s: dict) -> str:
    name = s["name"]
    link = github_url(name) or s.get("href") or "#"
    label = name.replace("-", " ")
    intent = ('<span class="intent off">OFFENSIVE</span>' if s.get("offensive")
              else '<span class="intent def">DEFENSIVE</span>')
    atk = "".join(f'<span class="chip atk">{_e(m)}</span>' for m in (s.get("mitre") or [])[:6])
    tags = "".join(f'<span class="chip">{_e(t)}</span>' for t in (s.get("tags") or [])[:6])
    search = _e(f"{name} {s.get('subdomain','')} {s.get('description','')} "
                f"{' '.join(s.get('tags') or [])} {' '.join(s.get('mitre') or [])}".lower())
    return (
        f'<div class="skill" data-s="{search}">'
        f'<div class="row"><a class="name" href="{_e(link)}" target="_blank" rel="noopener">{_e(label)}</a>{intent}</div>'
        f'<div class="desc">{_e(s.get("description",""))}</div>'
        f'<div class="chips">{atk}{tags}</div></div>'
    )


def _build_html() -> str:
    skills = all_skills()
    by_sub: dict[str, list[dict]] = {}
    for s in skills:
        by_sub.setdefault(s.get("subdomain") or "other", []).append(s)
    off = sum(1 for s in skills if s.get("offensive"))
    sections = []
    for sub in sorted(by_sub):
        cards = "".join(_skill_card(s) for s in by_sub[sub])
        anchor = sub.lower().replace(" ", "-").replace("/", "")
        sections.append(
            f'<section class="cat" id="{_e(anchor)}">'
            f'<div class="cat-h"><h2>{_e(sub.replace("-", " "))}</h2>'
            f'<span class="count">{len(by_sub[sub])} skills</span></div>'
            f'<div class="grid">{cards}</div></section>'
        )
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Hades — Skills Library</title><style>{_CSS}</style></head>
<body><div class="wrap">
  <div class="head">
    <div class="kicker">📚</div>
    <h1>SKILLS <span class="hl">LIBRARY</span></h1>
    <div class="tag">The expert-playbook knowledge base Hades draws on · grouped by subdomain · {_e(now)}</div>
    <div class="stats">
      <div class="stat"><b>{len(skills)}</b><br><span>SKILLS</span></div>
      <div class="stat"><b>{len(by_sub)}</b><br><span>SUBDOMAINS</span></div>
      <div class="stat"><b>{off}</b><br><span>OFFENSIVE</span></div>
      <div class="stat"><b>{len(skills) - off}</b><br><span>DEFENSIVE</span></div>
    </div>
    <div class="legend">Click a skill to open its full playbook on GitHub · search by name, subdomain, tag or ATT&amp;CK ID</div>
  </div>
  <div class="search"><input id="q" type="search" placeholder="🔎  Filter {len(skills)} skills — name, subdomain, tag or T-number…" autofocus></div>
  {''.join(sections)}
  <div id="empty" class="empty">No skill matches your search.</div>
  <div class="foot">Generated by Hades · references the Anthropic-Cybersecurity-Skills library
    (credit: its authors). Hades only links to these playbooks.</div>
</div><script>{_JS}</script></body></html>"""


def generate_skills_page(output_path: str = "reports") -> str | None:
    """Write the Skills Library HTML page and return its path (or None on error / no data)."""
    if not all_skills():
        logger.warning("skills_library: no skills available (no repo and no bundle) — page skipped")
        return None
    os.makedirs(output_path, exist_ok=True)
    file_path = os.path.join(output_path, "hades_skills_library.html")
    try:
        with open(file_path, "w", encoding="utf-8") as fh:
            fh.write(_build_html())
        logger.info(f"Skills Library page written: {file_path}")
        return file_path
    except OSError as exc:
        logger.error(f"skills_library: failed to write {file_path}: {exc}")
        return None


def open_skills_library(open_browser: bool = True) -> str | None:
    """Generate the Skills Library page, announce it, and (optionally) open it in the browser."""
    skills = all_skills()
    if not skills:
        console.print("[yellow]No skills library found.[/yellow] Clone "
                      "[cyan]Anthropic-Cybersecurity-Skills[/cyan] next to Hades (or set "
                      "[cyan]HADES_SKILLS_PATH[/cyan]); the bundled set is used otherwise.")
        return None
    path = generate_skills_page()
    if not path:
        console.print("[red]Could not generate the Skills Library page.[/red]")
        return None
    abspath = os.path.abspath(path)
    subdomains = len({s.get("subdomain") for s in skills})
    console.print()
    console.print(Panel(
        f"[bold]📚 Skills Library[/bold] — {len(skills)} expert playbooks across {subdomains} subdomains.\n"
        f"[cyan]{abspath}[/cyan]",
        title="[bold magenta]Skills Library[/bold magenta]", border_style="magenta", padding=(1, 2)))
    if open_browser:
        try:
            webbrowser.open(f"file://{abspath}")
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"skills_library: could not open browser: {exc}")
    return path
