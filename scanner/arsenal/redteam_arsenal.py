"""
redteam_arsenal — generate & open the RedTeam Arsenal reference page (menu option 666).

Not a scan module: it renders a self-contained, dark-themed HTML page cataloguing the offensive
toolset grouped by attack type — each tool with its purpose and a GitHub link — and opens it in the
browser. Reference material only; Hades neither bundles nor runs these tools.
"""
from __future__ import annotations

import html
import os
import webbrowser
from datetime import datetime, timezone
from urllib.parse import quote

from loguru import logger
from rich.console import Console
from rich.panel import Panel

from scanner.arsenal.arsenal_data import CATEGORIES

console = Console()


def _e(text: str) -> str:
    return html.escape(str(text), quote=True)


def _tool_url(url: str | None, name: str) -> str:
    """A real repo when known, otherwise a GitHub repository search that always resolves."""
    if url and url.startswith("http"):
        return url
    return f"https://github.com/search?q={quote(name + ' security tool')}&type=repositories"


_CSS = """
:root{--bg:#0a0a0f;--panel:#12141c;--card:#161b22;--ink:#c9d1d9;--muted:#8b949e;--red:#b3122a;
  --purple:#8957e5;--accent:#d2a8ff;--border:#272d38;--star:#e3b341;}
*{box-sizing:border-box;}
body{margin:0;background:radial-gradient(1200px 600px at 50% -10%,#1a0c12 0%,var(--bg) 60%);
  color:var(--ink);font:15px/1.6 -apple-system,Segoe UI,Roboto,sans-serif;}
.wrap{max-width:1200px;margin:0 auto;padding:30px 22px 90px;}
.head{text-align:center;border-bottom:2px solid var(--red);padding-bottom:18px;margin-bottom:8px;}
.skull{font-size:2.6rem;}
h1{margin:.2em 0 .1em;font-size:2rem;letter-spacing:3px;color:#fff;}
h1 .six{color:var(--red);}
.tag{color:var(--muted);letter-spacing:1px;font-size:.9rem;}
.stats{display:flex;gap:10px;justify-content:center;flex-wrap:wrap;margin:16px 0 6px;}
.stat{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:8px 16px;}
.stat b{color:#fff;font-size:1.25rem;} .stat span{color:var(--muted);font-size:.72rem;letter-spacing:1px;}
.search{position:sticky;top:0;z-index:5;padding:14px 0;background:linear-gradient(var(--bg),var(--bg) 70%,transparent);}
#q{width:100%;padding:12px 16px;border-radius:12px;border:1px solid var(--border);background:var(--card);
  color:var(--ink);font-size:1rem;outline:none;}
#q:focus{border-color:var(--purple);box-shadow:0 0 0 2px #8957e533;}
.cat{margin-top:34px;}
.cat-h{display:flex;align-items:baseline;gap:12px;border-left:4px solid var(--purple);padding-left:12px;margin-bottom:4px;}
.cat-h h2{margin:0;font-size:1.35rem;color:#fff;}
.cat-h .why{color:var(--accent);font-size:.82rem;}
.cat-h .count{margin-left:auto;color:var(--muted);font-size:.75rem;}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:12px;margin-top:12px;}
.tool{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:14px 16px;
  transition:border-color .15s,transform .15s;display:flex;flex-direction:column;gap:7px;}
.tool:hover{border-color:var(--purple);transform:translateY(-2px);}
.tool .row{display:flex;align-items:center;gap:8px;}
.tool a.name{color:#fff;font-weight:700;font-size:1.02rem;text-decoration:none;}
.tool a.name:hover{color:var(--accent);text-decoration:underline;}
.star{color:var(--star);}
.badge{margin-left:auto;font-size:.6rem;font-weight:700;letter-spacing:.5px;border:1px solid #6e40c9;
  color:var(--accent);background:#1d162e;border-radius:9px;padding:2px 8px;white-space:nowrap;}
.tool .desc{color:var(--muted);font-size:.86rem;}
.tool .gh{color:#58a6ff;font-size:.74rem;text-decoration:none;}
.tool .gh:hover{text-decoration:underline;}
.empty{display:none;color:var(--muted);text-align:center;padding:40px;}
.foot{margin-top:54px;padding-top:18px;border-top:1px solid #21262d;color:#484f58;text-align:center;font-size:.8rem;}
.legend{color:var(--muted);font-size:.78rem;text-align:center;margin-top:6px;}
"""

_JS = """
const q=document.getElementById('q');
const tools=[...document.querySelectorAll('.tool')];
const cats=[...document.querySelectorAll('.cat')];
const empty=document.getElementById('empty');
q.addEventListener('input',()=>{
  const t=q.value.trim().toLowerCase();let shown=0;
  tools.forEach(el=>{const hit=!t||el.dataset.s.includes(t);el.style.display=hit?'':'none';if(hit)shown++;});
  cats.forEach(c=>{const any=[...c.querySelectorAll('.tool')].some(e=>e.style.display!=='none');
    c.style.display=any?'':'none';
    const cnt=c.querySelector('.count');if(cnt)cnt.textContent=[...c.querySelectorAll('.tool')].filter(e=>e.style.display!=='none').length+' tools';});
  empty.style.display=shown?'none':'block';
});
"""


def _tool_card(name: str, desc: str, url: str | None, star: bool, category: str) -> str:
    link = _tool_url(url, name)
    search = _e(f"{name} {category} {desc}".lower())
    star_html = '<span class="star" title="Modern / essential pick">★</span>' if star else ""
    badge = f'<span class="badge">{_e(category)}</span>'
    return (
        f'<div class="tool" data-s="{search}">'
        f'<div class="row"><a class="name" href="{_e(link)}" target="_blank" rel="noopener">'
        f'{_e(name)}</a>{star_html}{badge}</div>'
        f'<div class="desc">{_e(desc)}</div>'
        f'<a class="gh" href="{_e(link)}" target="_blank" rel="noopener">↗ {_e(link.replace("https://", ""))}</a>'
        f'</div>'
    )


def _build_html() -> str:
    total = sum(len(c["tools"]) for c in CATEGORIES)
    starred = sum(1 for c in CATEGORIES for t in c["tools"] if t[3])
    sections = []
    for c in CATEGORIES:
        cards = "".join(_tool_card(n, d, u, s, c["name"]) for (n, d, u, s) in c["tools"])
        anchor = c["name"].lower().replace(" ", "-").replace("/", "")
        sections.append(
            f'<section class="cat" id="{_e(anchor)}">'
            f'<div class="cat-h"><span style="font-size:1.4rem">{c["icon"]}</span>'
            f'<h2>{_e(c["name"])}</h2><span class="why">{_e(c["attack"])}</span>'
            f'<span class="count">{len(c["tools"])} tools</span></div>'
            f'<div class="grid">{cards}</div></section>'
        )
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Hades — RedTeam Arsenal</title><style>{_CSS}</style></head>
<body><div class="wrap">
  <div class="head">
    <div class="skull">☠</div>
    <h1>RED<span class="six">TEAM</span> ARSENAL</h1>
    <div class="tag">The offensive toolbox · grouped by attack type · {_e(now)}</div>
    <div class="stats">
      <div class="stat"><b>{total}</b><br><span>TOOLS</span></div>
      <div class="stat"><b>{len(CATEGORIES)}</b><br><span>CATEGORIES</span></div>
      <div class="stat"><b>{starred}</b><br><span>★ ESSENTIAL</span></div>
    </div>
    <div class="legend">★ = modern / essential pick · click a tool to open its GitHub</div>
  </div>
  <div class="search"><input id="q" type="search" placeholder="🔎  Filter {total} tools — name, category or purpose…" autofocus></div>
  {''.join(sections)}
  <div id="empty" class="empty">No tool matches your search.</div>
  <div class="foot">Generated by Hades · reference only — for authorised security testing.
    Hades does not bundle or run these tools.</div>
</div><script>{_JS}</script></body></html>"""


def generate_arsenal(output_path: str = "reports") -> str | None:
    """Write the RedTeam Arsenal HTML page and return its path (or None on error)."""
    os.makedirs(output_path, exist_ok=True)
    file_path = os.path.join(output_path, "hades_redteam_arsenal.html")
    try:
        with open(file_path, "w", encoding="utf-8") as fh:
            fh.write(_build_html())
        logger.info(f"RedTeam Arsenal page written: {file_path}")
        return file_path
    except OSError as exc:
        logger.error(f"redteam_arsenal: failed to write {file_path}: {exc}")
        return None


def open_arsenal(open_browser: bool = True) -> str | None:
    """Generate the arsenal page, announce it, and (optionally) open it in the browser."""
    path = generate_arsenal()
    if not path:
        console.print("[red]Could not generate the RedTeam Arsenal page.[/red]")
        return None
    total = sum(len(c["tools"]) for c in CATEGORIES)
    abspath = os.path.abspath(path)
    console.print()
    console.print(Panel(
        f"[bold]☠  RedTeam Arsenal[/bold] — {total} offensive tools across {len(CATEGORIES)} categories.\n"
        f"[cyan]{abspath}[/cyan]",
        title="[bold red]666 · The Arsenal[/bold red]", border_style="red", padding=(1, 2)))
    if open_browser:
        try:
            webbrowser.open(f"file://{abspath}")
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"redteam_arsenal: could not open browser: {exc}")
    return path
