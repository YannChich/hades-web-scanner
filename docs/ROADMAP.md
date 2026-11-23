# Hades — Roadmap & Backlog

> Working backlog for Hades. The daily autonomous session reads this file, picks the
> **top unchecked task** in **In progress / Next up**, implements it in small atomic
> commits, ticks the box, and moves the entry to **Done** with its date.

## How the daily session works

- Runs ~1h/day. Scope is **building the tool** (code, modules, tests, docs, refactors) —
  never running Hades against live external targets.
- Keep the project's DA: a cohesive dark Kali / red-team aesthetic, detection-only by default,
  offensive actions gated behind `--exploit`.
- Quality gate before every push: `python tools/check_imports.py` and `pytest` must pass.
  Never leave `main` broken. No filler/empty commits.
- Atomic commits: one coherent change = one commit. Add/extend tests for new behaviour.
- When a backlog item is done, check it off here and append a one-line entry under **Done**.

---

## In progress / Next up (priority order)

Several of these are inspired by ARTEX (an autonomous pentest platform) but reimagined
natively for Hades' Python CLI architecture — no code is copied.

- [x] **Retest / diff loop** (`--retest`): persist each scan's findings to
  `reports/history/<host>.json`; on re-run, compare against the last scan and label every
  finding `new` / `still-present` / `fixed`. Surface a diff panel in console + HTML report.
- [ ] **Scope / deny rules** (`--scope`, `--deny`): allowlist/denylist of hosts and path
  prefixes enforced in `engine.py` before any request leaves. Out-of-scope requests are
  blocked and logged. Accept a scope file (`--scope-file`).
- [ ] **Findings verification status**: add a `verified: bool` + `verification` note to
  `Finding`, tied to the request/response in `raw["evidence"]`. Render a `✓ verified` badge
  in HTML and a column in console. Active-injection findings set it from their proof.
- [ ] **Coverage ledger**: track which modules ran vs skipped vs errored per target, and
  which discovered endpoints/params were actually probed. Render a "Coverage" section in the
  HTML report (tested vs untested, DA-consistent).
- [ ] **Noise governor**: extend the token-bucket limiter with adaptive pacing + jitter and a
  `--quiet`/`--aggressive` profile that tunes concurrency and delays. Back off on 429/503.
- [ ] **Scan resume / checkpoint**: persist engine progress so an interrupted scan can
  resume (`--resume`) instead of restarting from scratch.
- [ ] **SARIF export** (`report_sarif.py`): emit findings in SARIF 2.1.0 so results load into
  GitHub code scanning / CI dashboards.

## Backlog (unordered ideas)

- [ ] JSON schema + `--schema` dump for the JSON report (stable contract for downstream tools).
- [ ] `--diff-only` flag to report just the delta vs the previous scan.
- [ ] Per-finding "false-positive" suppression file (`.hadesignore`).
- [ ] Markdown report exporter for quick GitHub/issue pasting.
- [ ] Config file support (`hades.toml`) for default flags per project.
- [ ] More unit tests: raise coverage on `scanner/vulns/*` and `scanner/output/*`.
- [ ] CI workflow (GitHub Actions): run `pytest` + `check_imports` on every push/PR.

---

## Done

<!-- Append finished items here, newest first: `- YYYY-MM-DD — <what shipped>` -->

- 2026-11-23 — Retest / diff loop (`--retest`): per-target history store with finding
  fingerprinting; findings labelled new / still-present / fixed with a diff panel in the
  console and HTML report, retest status in the JSON report, and score delta vs the last run.
- 2026-11-23 — Fixed a red `main`: the offline skills-library fallback now accepts a shared
  module keyword, so common modules get an offensive playbook without the full external library.
- 2026-11-22 — Added this roadmap/backlog to drive the daily autonomous work session.
