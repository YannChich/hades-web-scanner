"""
build_vulndb — build / refresh the local Hades CVE database for offline matching.

Pulls the free, no-key public feeds into data/vulndb/hades_vulndb.sqlite:
  - CISA KEV + FIRST EPSS   (enrichment base — fast)
  - the full NVD 2.0 corpus (every CVE + its CPE version ranges — the offline "CVE bank")

Run it once to enable the full offline corpus; afterwards every `cve_scan` (menu option 8) matches
locally and `update_vulndb_if_stale` keeps it current incrementally.

    python tools/build_vulndb.py              # KEV/EPSS + full corpus (incremental if already built)
    python tools/build_vulndb.py --full       # force a full corpus rebuild
    python tools/build_vulndb.py --enrich-only  # only refresh KEV + EPSS, skip NVD

An optional free NVD API key speeds the build ~10x (never required):
    setx NVD_API_KEY <key>        (Windows)   /   export NVD_API_KEY=<key>   (Linux/macOS)
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

# Make the webscan root importable (this file is webscan/tools/build_vulndb.py).
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from rich.console import Console  # noqa: E402
from rich.progress import (BarColumn, Progress, SpinnerColumn,  # noqa: E402
                           TextColumn, TimeElapsedColumn)

from scanner.cve import feed_downloader as fd  # noqa: E402

console = Console()


def main() -> int:
    ap = argparse.ArgumentParser(description="Build/refresh the local Hades CVE database.")
    ap.add_argument("--full", action="store_true",
                    help="Force a full NVD corpus rebuild (otherwise incremental once built).")
    ap.add_argument("--enrich-only", action="store_true",
                    help="Only (re)build the CISA KEV + FIRST EPSS enrichment, skip the NVD corpus.")
    args = ap.parse_args()

    keyed = bool(fd._nvd_api_key())
    console.rule("[bold]Hades — local CVE database build")
    console.print(f"  NVD API key: [{'green' if keyed else 'yellow'}]"
                  f"{'detected (fast mode)' if keyed else 'none (free mode, ~6s/page)'}[/]")

    # 1) Enrichment base (KEV + EPSS) — always quick and useful on its own.
    console.print("[bold]\n[1/2] CISA KEV + FIRST EPSS enrichment[/bold]")
    if not fd.build_database():
        console.print("[red]  KEV/EPSS build failed — check connectivity.[/red]")
        return 1

    if args.enrich_only:
        console.print("[green]\nDone (enrichment only).[/green]")
        return 0

    # 2) Full NVD corpus.
    mode = "full rebuild" if args.full or not fd.has_full_nvd() else "incremental refresh"
    console.print(f"[bold]\n[2/2] NVD corpus — {mode}[/bold]")
    started = time.time()
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  BarColumn(), TextColumn("{task.completed:,}/{task.total:,} CVEs"),
                  TimeElapsedColumn(), console=console) as prog:
        task = prog.add_task("downloading", total=None)

        def cb(done: int, total: int, ingested: int) -> None:
            prog.update(task, total=total or None, completed=done,
                        description=f"ingested {ingested:,}")

        try:
            ingested = fd.sync_full_nvd(force_full=args.full, progress=cb)
        except KeyboardInterrupt:
            console.print("\n[yellow]  Interrupted — partial corpus kept; re-run to resume.[/yellow]")
            return 130

    size = fd.nvd_corpus_size()
    console.print(f"[green]\nDone. Ingested {ingested:,} records this run; "
                  f"local corpus now holds {size:,} CVEs "
                  f"({time.time() - started:.0f}s).[/green]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
