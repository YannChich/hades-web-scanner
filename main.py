"""
WebScan — entry point.
Handles CLI argument parsing, the interactive menu, and delegates to the scan engine.
"""

import argparse
import sys
import io
from typing import Optional

# Force UTF-8 on Windows so box-drawing characters in the banner render correctly.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from loguru import logger
from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.text import Text
from rich.theme import Theme

from scanner.engine import run_scan
from scanner.output.logger import setup_logging

# ---------------------------------------------------------------------------
# Rich console with cybersecurity colour palette
# ---------------------------------------------------------------------------
THEME = Theme({
    "banner":    "bold bright_red",
    "accent":    "bold cyan",
    "warn":      "bold yellow",
    "danger":    "bold red",
    "info":      "dim white",
    "ok":        "bold green",
    "separator": "bright_black",
})
console = Console(theme=THEME)

# ---------------------------------------------------------------------------
# ASCII banner — "HADES" in block letters, framed by print_banner()
# ---------------------------------------------------------------------------
BANNER = (
    "██   ██  █████  ██████  ███████ ███████\n"
    "██   ██ ██   ██ ██   ██ ██      ██     \n"
    "███████ ███████ ██   ██ █████   ███████\n"
    "██   ██ ██   ██ ██   ██ ██           ██\n"
    "██   ██ ██   ██ ██████  ███████ ███████"
)

BANNER_TITLE = "[bold white]†  H A D E S  †[/bold white]"
TAGLINE = "Ψ  Web Security Scanner  ·  v1.0  ·  authorized testing only  Ψ"

DISCLAIMER = (
    "[warn]! LEGAL DISCLAIMER:[/warn]  "
    "[accent]Hades[/accent] is for [accent]authorized security testing only[/accent]. "
    "Scanning systems without explicit written permission is illegal. "
    "The author assumes no liability for misuse."
)

PROFILES = ("quick", "passive", "cms", "full", "db_scan", "ai_scan", "engage")
OUTPUT_FORMATS = ("json", "html", "pdf")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def print_banner() -> None:
    art = Text(BANNER, style="banner")
    console.print(
        Panel(
            Align.center(art),
            box=box.DOUBLE,
            border_style="banner",
            title=BANNER_TITLE,
            subtitle=f"[accent]{TAGLINE}[/accent]",
            padding=(1, 6),
        )
    )
    console.print()
    console.print(Panel(DISCLAIMER, border_style="yellow", padding=(0, 2)))
    console.print()


def validate_url(url: str) -> str:
    """Ensure the URL starts with http:// or https://."""
    if not url.startswith(("http://", "https://")):
        console.print("[danger]✗  URL must start with http:// or https://[/danger]")
        sys.exit(1)
    return url


def resolve_module(name: str) -> str:
    """Map a short module name (or dotted path) to its full dotted-path, or exit."""
    from config import ALL_MODULES
    name = name.strip()
    for path in ALL_MODULES:
        if path == name or path.split(".")[-1] == name:
            return path
    console.print(f"[danger]✗  Unknown module: {name}[/danger]")
    available = ", ".join(p.split(".")[-1] for p in ALL_MODULES)
    console.print(f"[info]   Available modules: {available}[/info]")
    sys.exit(1)


def select_single_module() -> str:
    """Show the grouped module catalog and return the chosen module dotted-path."""
    from config import MODULE_CATALOG

    console.print("\n[info]Available modules:[/info]")
    index: list[str] = []
    for category, mods in MODULE_CATALOG.items():
        console.print(f"\n  [accent]{category}[/accent]")
        for path in mods:
            index.append(path)
            console.print(f"    [accent]{len(index):>2}[/accent]. [ok]{path.split('.')[-1]}[/ok]")

    console.print()
    choice = Prompt.ask(
        "[ok]  Module number[/ok]",
        choices=[str(i) for i in range(1, len(index) + 1)],
    ).strip()
    return index[int(choice) - 1]


def prompt_url() -> str:
    """Interactively prompt for a valid target URL."""
    url = ""
    while not url:
        url = Prompt.ask("[ok]  Target URL[/ok]").strip()
        if not url.startswith(("http://", "https://")):
            console.print("[danger]  Must start with http:// or https://. Try again.[/danger]")
            url = ""
    return url


def prompt_scan_choice() -> tuple[str, Optional[list[str]]]:
    """
    Show the scan-type menu and return (label, modules).
    *modules* is None for a profile scan, or a one-element list for a single module.
    """
    console.print("[info]What would you like to run?[/info]")
    console.print("  [accent]1[/accent]. [ok]Quick scan[/ok]         Fast surface scan (basic info, headers, SSL, robots)")
    console.print("  [accent]2[/accent]. [ok]Full scan[/ok]          All modules — most thorough")
    console.print("  [accent]3[/accent]. [ok]Single module[/ok]      Run just one tool of your choice")
    console.print("  [accent]4[/accent]. [ok]Database Security[/ok]  Dedicated DB audit (ports, auth, SQLi, dumps, score)")
    console.print("  [accent]5[/accent]. [ok]AI / LLM Security[/ok]   AI attack surface (prompt injection, exposed keys & LLM servers)")
    console.print("  [accent]6[/accent]. [ok]Engagement (auto-pwn)[/ok] Actively exploit confirmed vulns (RCE/LFI/SSRF) — use with --exploit")
    console.print()

    choice = Prompt.ask("[ok]  Choice[/ok]", choices=["1", "2", "3", "4", "5", "6"], default="2").strip()

    match choice:
        case "1":
            return "quick", None
        case "3":
            module = select_single_module()
            return module.split(".")[-1], [module]
        case "4":
            return "db_scan", None
        case "5":
            return "ai_scan", None
        case "6":
            return "engage", None
        case _:
            return "full", None


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hades",
        description="Hades — terminal-based web security scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:  hades --url https://example.com --profile full --output html",
    )

    parser.add_argument(
        "--url", "-u",
        metavar="URL",
        help="Target URL to scan (must include http:// or https://)",
    )
    parser.add_argument(
        "--profile", "-p",
        choices=PROFILES,
        default=None,
        metavar="PROFILE",
        help=f"Scan profile: {', '.join(PROFILES)}. If omitted, an interactive menu is shown.",
    )
    parser.add_argument(
        "--module", "-m",
        metavar="NAME",
        help="Run a single module only (e.g. headers_check). Overrides --profile.",
    )
    parser.add_argument(
        "--output", "-o",
        choices=OUTPUT_FORMATS,
        metavar="FORMAT",
        help=f"Export report as: {', '.join(OUTPUT_FORMATS)}",
    )
    parser.add_argument(
        "--proxy",
        metavar="URL",
        help="HTTP/HTTPS proxy  (e.g. http://127.0.0.1:8080)",
    )
    parser.add_argument(
        "--threads", "-t",
        type=int,
        default=10,
        metavar="N",
        help="Number of concurrent threads (default: 10)",
    )
    parser.add_argument(
        "--ignore-robots",
        action="store_true",
        help="Ignore robots.txt restrictions during active scanning",
    )
    parser.add_argument(
        "--exploit",
        action="store_true",
        help="After the scan, launch sqlmap against any confirmed SQL injection "
             "(requires sqlmap; authorised targets only)",
    )
    parser.add_argument(
        "--bruteforce",
        action="store_true",
        help="Opt-in: actively spray common credentials against login forms and HTTP "
             "Basic-Auth (authorised targets only; off by default)",
    )
    parser.add_argument(
        "--wordlist", "-w",
        metavar="FILE",
        help="Custom wordlist path (overrides built-in lists)",
    )
    parser.add_argument(
        "--cookies",
        metavar="STRING",
        help='Cookie header value  (e.g. "session=abc123; token=xyz")',
    )
    parser.add_argument(
        "--auth-token",
        metavar="TOKEN",
        help="Bearer token for Authorization header",
    )

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    log_path = setup_logging()
    print_banner()

    parser = build_parser()
    args = parser.parse_args()

    modules: Optional[list[str]] = None

    # --- Target URL: from flag, otherwise prompt ---
    if args.url:
        url: str = validate_url(args.url)
    else:
        console.print("[accent]---  Interactive Mode  ---[/accent]\n")
        url = prompt_url()
        console.print()

    # --- Scan scope: explicit flags win, otherwise show the menu ---
    if args.module:
        modules = [resolve_module(args.module)]
        profile: str = args.module
    elif args.profile:
        profile = args.profile
    else:
        profile, modules = prompt_scan_choice()

    scope = f"module=[ok]{profile}[/ok]" if modules else f"profile=[ok]{profile}[/ok]"
    console.print(f"\n[accent]>>  Starting scan[/accent]  target=[ok]{url}[/ok]  {scope}")
    console.print(f"[info]    Log: {log_path}[/info]\n")

    run_scan(
        url=url,
        profile=profile,
        output_format=args.output,
        proxy=args.proxy,
        threads=args.threads,
        ignore_robots=args.ignore_robots,
        wordlist=args.wordlist,
        cookies=args.cookies,
        auth_token=args.auth_token,
        modules=modules,
        exploit=args.exploit,
        bruteforce=args.bruteforce,
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[warn]!  Scan aborted by user.[/warn]")
        sys.exit(0)
