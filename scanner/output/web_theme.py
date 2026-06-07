"""
web_theme — the single source of truth for Hades' HTML look (UI/UX v2).

Every HTML surface (the scan report, the RedTeam Arsenal page, the Skills Library page and the
rendered playbook pages) shares this dark **Kali / red-team** theme so the product feels like one
tool: a deep slate background, a red primary accent with a terminal-green secondary, quiet taxonomy
hues, a clean sans body with monospace reserved for code/IDs, and a thin red→green signature bar.

Pages compose their `<style>` as ``ROOT_VARS + BASE_CSS + <page-specific layout>`` (or call
``page()`` for the whole document), keeping their existing class names — this only restyles.
Severity colours are mirrored from ``scanner/severity.py`` so they never drift.
"""
from __future__ import annotations

from scanner.severity import HTML_COLOR as _SEV

# ── Palette + type tokens (CSS custom properties) ──────────────────────────
ROOT_VARS = f""":root{{
  /* surfaces */
  --bg:#0a0c10; --bg-2:#0d1117; --surface:#12161d; --surface-2:#161b22; --card:#161b22;
  --code:#0b0f14;
  /* text */
  --ink:#c9d1d9; --bright:#e6edf3; --muted:#7d8590; --faint:#54606e;
  /* lines */
  --border:#272d38; --border-soft:#1b212b;
  /* brand: red primary + terminal-green secondary */
  --red:#ff3b3b; --red-deep:#b3122a; --red-glow:rgba(255,59,59,.33);
  --green:#39d353; --green-deep:#2ea043; --green-glow:rgba(57,211,83,.30);
  /* quiet taxonomy accents */
  --purple:#d2a8ff; --purple-line:#8957e5; --orange:#ffa657; --blue:#79c0ff;
  --yellow:#e3b341; --link:#58a6ff;
  /* severity (mirrors scanner/severity.py HTML_COLOR) */
  --sev-critical:{_SEV['critical']}; --sev-high:{_SEV['high']}; --sev-medium:{_SEV['medium']};
  --sev-low:{_SEV['low']}; --sev-info:{_SEV['info']};
  /* convenience aliases used by the reference pages (Arsenal / Skills Library) */
  --panel:#12161d; --accent:#d2a8ff; --star:#e3b341; --off:#ff7b72; --def:#56d364; --atk:#79c0ff;
  /* type */
  --sans:-apple-system,BlinkMacSystemFont,'Segoe UI',Inter,Roboto,Helvetica,Arial,sans-serif;
  --mono:ui-monospace,'SF Mono',Consolas,'Liberation Mono','Courier New',monospace;
}}"""

# ── Shared base: reset, body, signature bar, links, code, scrollbar, footer ─
BASE_CSS = """
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
html{scroll-behavior:smooth;}
body{
  font-family:var(--sans); color:var(--ink); background:var(--bg);
  font-size:14px; line-height:1.6; -webkit-font-smoothing:antialiased;
  background-image:
    radial-gradient(1000px 460px at 50% -10%, rgba(179,18,42,.16) 0%, transparent 70%),
    linear-gradient(rgba(255,255,255,.012) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,.012) 1px, transparent 1px);
  background-size:auto, 44px 44px, 44px 44px;
}
/* unifying signature: a thin red→green bar across the very top of every page */
body::before{content:"";position:fixed;top:0;left:0;right:0;height:2px;z-index:60;
  background:linear-gradient(90deg,var(--red) 0%,var(--red-deep) 50%,var(--green) 100%);
  box-shadow:0 0 12px var(--red-glow);}
a{color:var(--link);text-decoration:none;} a:hover{text-decoration:underline;}
code,kbd,samp{font-family:var(--mono);}
::selection{background:var(--red-deep);color:#fff;}
::-webkit-scrollbar{width:11px;height:11px;}
::-webkit-scrollbar-track{background:var(--bg);}
::-webkit-scrollbar-thumb{background:#222a34;border-radius:6px;border:2px solid var(--bg);}
::-webkit-scrollbar-thumb:hover{background:#303a47;}
/* shared footer (class: hades-foot) */
.hades-foot{text-align:center;padding:26px;color:var(--faint);font-size:.75rem;
  border-top:1px solid var(--border-soft);margin-top:48px;}
.hades-foot .prompt{color:var(--green);font-family:var(--mono);}
"""


def page(title: str, body_html: str, extra_css: str = "") -> str:
    """Wrap a page body in the shared v2 document scaffold (head + theme + chrome)."""
    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">'
        f"<title>{title}</title><style>{ROOT_VARS}{BASE_CSS}{extra_css}</style></head>"
        f"<body>{body_html}</body></html>"
    )
