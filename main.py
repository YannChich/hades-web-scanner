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
    "banner":    "bold red",       # HADES wordmark / brand
    "accent":    "bold green",     # menu numbers, prompts (Kali terminal green)
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

PROFILES = ("quick", "passive", "cms", "full", "db_scan", "ai_scan", "engage", "oob_scan",
            "cve_scan", "tls_scan")


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
    console.print("  [accent]6[/accent]. [ok]Engagement (auto-pwn)[/ok] Actively EXPLOIT confirmed vulns (RCE/LFI/SSRF) — asks for authorisation")
    console.print("  [accent]7[/accent]. [ok]OOB / Blind vulns[/ok]   Out-of-band detection of blind SSRF/RCE/XSS via callbacks")
    console.print("  [accent]8[/accent]. [ok]CVE Vulnerability Intelligence[/ok]  Match detected tech to CVEs (local KEV/EPSS + NVD)")
    console.print("  [accent]9[/accent]. [ok]TLS / SSL Attack Surface[/ok]  Offensive TLS audit via SSLyze (protocols, ciphers, certs, Heartbleed/ROBOT)")
    console.print("  [accent]10[/accent]. [ok]Skills Library[/ok]   Browse the 754 expert playbooks Hades draws on (no scan)")
    console.print("  [accent]11[/accent]. [ok]IDOR / Access Control[/ok]  Authenticated scan for broken access control (IDOR/BOLA) — asks for the login")
    console.print("  [danger]666[/danger]. [danger]RedTeam Arsenal[/danger]   Open the offensive-tools reference page (no scan — ignores the target)")
    console.print()

    choice = Prompt.ask("[ok]  Choice[/ok]",
                        choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "666"],
                        default="2").strip()

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
        case "7":
            return "oob_scan", None
        case "8":
            return "cve_scan", None
        case "9":
            return "tls_scan", None
        case "666":
            return "arsenal", None
        case "10":
            return "skills", None
        case "11":
            return "auth_idor", None
        case _:
            return "full", None


def _autodetect_login_form(*urls: str) -> "Optional[tuple[str, Optional[str], str]]":
    """Fetch a login page and read its form: return (action_url, username_field, password_field).

    Returns None if no form with a password input is found (or the page can't be fetched), so the
    caller can fall back to asking for the field names manually. Best-effort, never fatal.
    """
    import httpx
    from bs4 import BeautifulSoup
    from urllib.parse import urljoin

    for u in urls:
        if not u:
            continue
        try:
            resp = httpx.get(u, follow_redirects=True, verify=False, timeout=10,
                             headers={"User-Agent": "Hades/1.0 (authenticated-scan setup)"})
        except Exception:  # noqa: BLE001 — best-effort one-off setup fetch
            continue
        soup = BeautifulSoup(resp.text, "html.parser")
        for form in soup.find_all("form"):
            pw = form.find("input", attrs={"type": "password"})
            if not pw or not pw.get("name"):
                continue
            user_field = None
            for inp in form.find_all("input"):
                itype = (inp.get("type") or "text").lower()
                if itype in ("text", "email", "tel") and inp.get("name"):
                    user_field = inp.get("name")
                    break
            return urljoin(u, form.get("action") or u), user_field, pw.get("name")
    return None


def prompt_login(url: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Interactively collect login details for the authenticated IDOR scan (menu option 11).

    Reads the login form automatically (real field names + submit URL) so the user only types their
    username/password values; falls back to asking for the field names if the form can't be read.
    """
    from urllib.parse import urlencode

    console.print("\n[accent]Authenticated scan — log in first[/accent]")
    console.print("[info]  Press Enter on the Login URL to skip and scan without logging in.[/info]\n")

    login_url = Prompt.ask(
        "  [ok]Login page URL[/ok] [info]— the page that shows the login form[/info]",
        default=f"{url.rstrip('/')}/login").strip()
    if not login_url:
        return None, None, None

    detected = _autodetect_login_form(login_url, url)
    if detected:
        action, user_field, pass_field = detected
        login_url = action                       # use the form's real submit URL (fixes guessed URLs)
        console.print(f"  [ok]✓ Login form detected[/ok] [info]— submits to[/info] [ok]{action}[/ok]"
                      f"[info]; fields:[/info] user=[ok]{user_field or '?'}[/ok], "
                      f"password=[ok]{pass_field}[/ok]. [info]Press Enter to accept each.[/info]")
        user_default = user_field or "username"
    else:
        console.print("  [warn]Couldn't read the form automatically.[/warn] [info]Type the field "
                      "NAMES from each input's [/info][ok]name=\"...\"[/ok][info] attribute "
                      "(right-click the box → Inspect) — not the visible label.[/info]")
        user_default, pass_field = "username", "password"

    user_field = (Prompt.ask("  [ok]Username field name[/ok]", default=user_default).strip()
                  or user_default)
    user_value = Prompt.ask(f"  [ok]Value for '{user_field}'[/ok] [info](your username)[/info]").strip()
    pass_field = (Prompt.ask("  [ok]Password field name[/ok]", default=pass_field).strip()
                  or pass_field)
    pass_value = Prompt.ask(f"  [ok]Value for '{pass_field}'[/ok] [info](your password — hidden)[/info]",
                            password=True)
    login_data = urlencode({user_field: user_value, pass_field: pass_value})

    login_check = Prompt.ask(
        "  [ok]Logged-in text[/ok] [info]— a word shown ONLY when logged in (e.g. your pseudo, "
        "Logout, Déconnexion); matched case-insensitively[/info]",
        default="Logout").strip()

    console.print(f"\n  [info]→ Will POST to[/info] [ok]{login_url}[/ok] "
                  f"[info]with[/info] [ok]{user_field}={user_value}&{pass_field}=••••••[/ok] "
                  f"[info](+ any CSRF token), then check the page contains[/info] "
                  f"[ok]\"{login_check}\"[/ok].\n")
    return login_url, login_data, (login_check or None)


# Profiles whose --exploit flag can be offered interactively (engage handles its own prompt).
_EXPLOIT_PROFILES = {"full", "db_scan", "ai_scan"}


def prompt_exploit(profile: str) -> bool:
    """Offer active exploitation for an offensive profile (interactive mode, no --exploit flag)."""
    if not sys.stdin.isatty():
        return False
    detail = {
        "db_scan": "extract real data from exposed DBs and replay harvested credentials",
        "ai_scan": "send a benign canary to confirm prompt injection",
        "full":    "launch sqlmap against any confirmed SQL injection",
    }.get(profile, "actively exploit confirmed issues")
    console.print(f"\n[warn]Active exploitation?[/warn] [info]On an authorised target, Hades can {detail}, "
                  "and write evidence to loot/.[/info]")
    answer = Prompt.ask("[ok]  Enable active exploitation[/ok]", choices=["y", "n"], default="n").strip().lower()
    return answer == "y"


def confirm_engagement(already_authorised: bool) -> bool:
    """
    The 'engage' profile is exploitation-first: it actively attacks confirmed vulnerabilities.
    Require an explicit authorisation here (unless --exploit already gave it). Returns True to
    run active exploitation, False to fall back to detection-only.
    """
    if already_authorised:
        return True
    # No interactive terminal (piped / CI): can't prompt — stay safe (detection-only).
    if not sys.stdin.isatty():
        console.print("[warn]  Engagement needs authorisation but there is no interactive terminal — "
                      "running detection-only. Pass --exploit to authorise non-interactively.[/warn]\n")
        return False
    console.print(Panel(
        "[danger]⚔  ENGAGEMENT MODE — ACTIVE EXPLOITATION[/danger]\n\n"
        "This profile does not just detect: it [danger]actively exploits[/danger] confirmed "
        "vulnerabilities (command execution, arbitrary file read, SSRF) on the target and writes "
        "the captured evidence to [accent]loot/[/accent].\n\n"
        "Only continue on systems you are [accent]explicitly authorised[/accent] to attack.",
        border_style="danger", title="[danger]! Authorisation required[/danger]", padding=(1, 2)))
    try:
        answer = Prompt.ask(
            "[danger]  Type 'attack' to authorise active exploitation[/danger]",
            default="no",
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = "no"
    if answer in ("attack", "yes", "y"):
        return True
    console.print("[warn]  Not authorised — running the engagement in detection-only mode.[/warn]\n")
    return False


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
        "--no-open",
        action="store_true",
        help="Do not auto-open the HTML report in a browser when the scan finishes",
    )
    parser.add_argument(
        "--arsenal",
        action="store_true",
        help="Open the RedTeam Arsenal — a reference page of offensive tools by attack type "
             "(no scan; also available as menu option 666)",
    )
    parser.add_argument(
        "--skills",
        action="store_true",
        help="Open the Skills Library — a searchable page of the expert playbooks Hades draws on, "
             "grouped by subdomain (no scan; also available as menu option 10)",
    )
    parser.add_argument(
        "--oob-host",
        metavar="HOST",
        help="Reachable address for out-of-band callbacks (oob_scan); auto-detected if omitted",
    )
    parser.add_argument(
        "--oob-port",
        type=int,
        default=0,
        metavar="PORT",
        help="Port for the out-of-band callback listener (oob_scan; 0 = auto-pick a free port)",
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
    parser.add_argument(
        "--login-url",
        metavar="URL",
        help="Log in before scanning so the crawler + active modules run authenticated "
             "(form action or login page; relative to --url is fine). Use with --login-data",
    )
    parser.add_argument(
        "--login-data",
        metavar="STRING",
        help='Login credentials as form data (e.g. "username=admin&password=secret"); '
             "CSRF hidden fields on the login form are picked up automatically",
    )
    parser.add_argument(
        "--login-check",
        metavar="STRING",
        help='Text that proves the session is authenticated (e.g. "Logout") — used to confirm login',
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

    # RedTeam Arsenal (reference page) — no target/scan needed.
    if args.arsenal:
        from scanner.arsenal.redteam_arsenal import open_arsenal
        open_arsenal(open_browser=not args.no_open)
        return

    # Skills Library (reference page) — no target/scan needed.
    if args.skills:
        from scanner.intel.skills_library import open_skills_library
        open_skills_library(open_browser=not args.no_open)
        return

    modules: Optional[list[str]] = None

    # --- Target URL: from flag, otherwise prompt ---
    if args.url:
        url: str = validate_url(args.url)
    else:
        console.print("[accent]---  Interactive Mode  ---[/accent]\n")
        url = prompt_url()
        console.print()

    # --- Scan scope: explicit flags win, otherwise show the menu ---
    # "interactive" = the user is choosing from menus (no scope flag given), so we also
    # prompt for the most useful options instead of requiring more flags.
    interactive = args.profile is None and args.module is None
    if args.module:
        modules = [resolve_module(args.module)]
        profile: str = args.module
    elif args.profile:
        profile = args.profile
    elif sys.stdin.isatty():
        profile, modules = prompt_scan_choice()
    else:
        # No scan-type flag and no interactive terminal (piped / CI) — default to a full scan
        # so the run never blocks waiting on the menu.
        profile = "full"

    # Menu option 666 — open the RedTeam Arsenal reference page instead of scanning.
    if profile == "arsenal":
        from scanner.arsenal.redteam_arsenal import open_arsenal
        open_arsenal(open_browser=not args.no_open)
        return

    # Menu option 10 — open the Skills Library reference page instead of scanning.
    if profile == "skills":
        from scanner.intel.skills_library import open_skills_library
        open_skills_library(open_browser=not args.no_open)
        return

    # Login details: from flags by default; menu option 11 collects them interactively and
    # runs the IDOR / access-control module authenticated.
    login_url, login_data, login_check = args.login_url, args.login_data, args.login_check
    if profile == "auth_idor":
        login_url, login_data, login_check = prompt_login(url)
        modules = ["scanner.vulns.idor_detect"]
        profile = "idor_detect"          # display label only — `modules` overrides the engine profile

    # The HTML and JSON reports are always generated (see run_scan).

    # --- Active exploitation ---
    # engage is exploitation-first (its own confirmation); other offensive profiles can be
    # offered the choice interactively so --exploit isn't required.
    exploit = args.exploit
    if profile == "engage":
        exploit = confirm_engagement(args.exploit)
    elif interactive and not exploit and profile in _EXPLOIT_PROFILES:
        exploit = prompt_exploit(profile)

    scope = f"module=[ok]{profile}[/ok]" if modules else f"profile=[ok]{profile}[/ok]"
    console.print(f"\n[accent]>>  Starting scan[/accent]  target=[ok]{url}[/ok]  {scope}")
    console.print(f"[info]    Log: {log_path}[/info]\n")

    run_scan(
        url=url,
        profile=profile,
        proxy=args.proxy,
        threads=args.threads,
        ignore_robots=args.ignore_robots,
        wordlist=args.wordlist,
        cookies=args.cookies,
        auth_token=args.auth_token,
        login_url=login_url,
        login_data=login_data,
        login_check=login_check,
        modules=modules,
        exploit=exploit,
        bruteforce=args.bruteforce,
        open_report=not args.no_open,
        oob_host=args.oob_host,
        oob_port=args.oob_port,
    )


def cli() -> int:
    """Run Hades with friendly top-level error handling. Returns a process exit code."""
    try:
        main()
        return 0
    except KeyboardInterrupt:
        console.print("\n[warn]!  Scan aborted by user.[/warn]")
        return 0
    except SystemExit as exc:          # argparse --help / validation errors
        return int(exc.code or 0)
    except Exception as exc:  # noqa: BLE001 — never dump a raw traceback at the user
        logger.exception("hades: unhandled error")
        console.print(f"\n[danger]✗  Hades stopped on an unexpected error:[/danger] [info]{exc}[/info]")
        console.print("[info]   Full details were written to the log file under  logs/  — "
                      "please re-run, or open an issue with that log.[/info]")
        return 1


if __name__ == "__main__":
    sys.exit(cli())
