"""
make_menu_screenshot — render the Hades interactive menu to a dark-themed SVG for the README.

Hades' menu is interactive (it waits for input), so it cannot be captured from a live TTY in CI.
Instead we replay the exact banner + menu (options 1-9 and 666) through a recording
``rich.Console`` and export a crisp, dark-terminal SVG that renders inline on GitHub.

    python docs/make_menu_screenshot.py

Output: assets/screenshots/hades-menu.svg  (committed README asset)
"""
from __future__ import annotations

import os
import sys

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.terminal_theme import TerminalTheme
from rich.text import Text
from rich.theme import Theme

# Keep these in sync with main.py THEME and scanner/output/console.py banner.
THEME = Theme({
    "banner":    "bold bright_red",
    "accent":    "bold cyan",
    "warn":      "bold yellow",
    "danger":    "bold red",
    "info":      "dim white",
    "ok":        "bold green",
    "separator": "bright_black",
})

_BANNER_ART = (
    "██   ██  █████  ██████  ███████ ███████\n"
    "██   ██ ██   ██ ██   ██ ██      ██     \n"
    "███████ ███████ ██   ██ █████   ███████\n"
    "██   ██ ██   ██ ██   ██ ██           ██\n"
    "██   ██ ██   ██ ██████  ███████ ███████"
)
_TAGLINE = "Web Security Scanner  -  Kali-style recon & vulnerability detection"

# Hades dark terminal palette (background #0d0d0f, soft foreground), exported into the SVG chrome.
HADES_TERMINAL = TerminalTheme(
    (13, 13, 15),
    (201, 209, 217),
    [
        (13, 13, 15),     # black
        (179, 18, 42),    # red
        (57, 211, 83),    # green
        (227, 179, 65),   # yellow
        (88, 166, 255),   # blue
        (137, 87, 229),   # magenta
        (57, 197, 187),   # cyan
        (201, 209, 217),  # white
    ],
    [
        (110, 118, 129),  # bright black
        (255, 92, 110),   # bright red
        (86, 211, 100),   # bright green
        (255, 215, 0),    # bright yellow
        (121, 192, 255),  # bright blue
        (210, 168, 255),  # bright magenta
        (86, 211, 199),   # bright cyan
        (255, 255, 255),  # bright white
    ],
)

MENU = [
    ("1",   "Quick scan",                     "Fast surface scan (basic info, headers, SSL, robots)"),
    ("2",   "Full scan",                      "All modules - most thorough"),
    ("3",   "Single module",                  "Run just one tool of your choice"),
    ("4",   "Database Security",              "Dedicated DB audit (ports, auth, SQLi, dumps, score)"),
    ("5",   "AI / LLM Security",              "AI attack surface (prompt injection, exposed keys & LLM servers)"),
    ("6",   "Engagement (auto-pwn)",          "Actively EXPLOIT confirmed vulns (RCE/LFI/SSRF)"),
    ("7",   "OOB / Blind vulns",              "Out-of-band detection of blind SSRF/RCE/XSS via callbacks"),
    ("8",   "CVE Vulnerability Intelligence", "Match detected tech to CVEs (local KEV/EPSS + NVD)"),
    ("9",   "TLS / SSL Attack Surface",       "Offensive TLS audit via SSLyze (ciphers, certs, ROBOT)"),
]


def build_svg(out_path: str) -> None:
    console = Console(theme=THEME, record=True, width=108)

    console.print(Panel(
        Align.center(Text(_BANNER_ART, style="bold bright_red")),
        box=box.DOUBLE,
        border_style="bold bright_red",
        title="[bold white]H A D E S[/bold white]",
        subtitle=f"[bold cyan]{_TAGLINE}[/bold cyan]",
        padding=(1, 6),
    ))
    console.print()
    console.print("[info]What would you like to run?[/info]")
    for num, name, desc in MENU:
        console.print(f"  [accent]{num:>3}[/accent].  [ok]{name:<32}[/ok]  [info]{desc}[/info]")
    console.print(f"  [danger]{'666':>3}[/danger].  [danger]{'RedTeam Arsenal':<32}[/danger]  "
                  "[info]Open the offensive-tools reference page (no scan)[/info]")
    console.print(f"  [accent]{'777':>3}[/accent].  [ok]{'Skills Library':<32}[/ok]  "
                  "[info]Browse the 754 expert playbooks Hades draws on (no scan)[/info]")
    console.print()
    console.print("[accent]>[/accent]  Choose an option [info][2][/info]: [banner]█[/banner]")

    console.save_svg(out_path, title="hades  -  scan menu", theme=HADES_TERMINAL)


def main() -> int:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out_dir = os.path.join(root, "assets", "screenshots")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "hades-menu.svg")
    build_svg(out_path)
    sys.stdout.write(f"wrote {out_path}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
