"""
skills_kb — wire Hades findings to the external Anthropic-Cybersecurity-Skills library.

For every actionable finding, this layer attaches the matching expert *playbook(s)*
from a local clone of the 754-skill library: a curated module→skill map (authoritative),
a db_security per-category map, and a conservative keyword fallback. Each matched skill is
read once for its framework tags (MITRE ATT&CK / OWASP) and an exploitation teaser, then
surfaced in the console, JSON, and HTML reports.

The whole layer is **optional and graceful**: if the skills repo is not found next to the
project (or via the HADES_SKILLS_PATH env var), enrichment silently no-ops and the scan is
unaffected.
"""
from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger

from config import (
    DB_CATEGORY_SKILL_MAP,
    MODULE_SKILL_MAP,
    SKILLS_REPO_CANDIDATES,
    SKILLS_REPO_ENV,
)

if TYPE_CHECKING:
    from scanner.engine import Finding

# Modules whose findings never warrant a playbook (pure context).
_SKIP_MODULES = {"basic_info", "whois_lookup", "robots_txt", "sitemap",
                 "email_exposure", "favicon_hash", "redirect_chain"}

# Offensive skill-name prefixes — the keyword fallback only accepts these, so it never
# attaches a defensive (detecting-/hunting-/analyzing-…) playbook to an attack finding.
_OFFENSIVE_PREFIXES = ("performing-", "exploiting-", "testing-", "scanning-",
                       "conducting-", "attacking-", "bypassing-", "abusing-", "cracking-")


# ---------------------------------------------------------------------------
# Repo discovery (cached)
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def find_skills_repo() -> Path | None:
    """Locate the skills library: env override first, then candidate paths. None if absent."""
    env = os.environ.get(SKILLS_REPO_ENV, "").strip()
    candidates = ([env] if env else []) + SKILLS_REPO_CANDIDATES
    for cand in candidates:
        if not cand:
            continue
        p = Path(cand)
        if (p / "index.json").is_file() and (p / "skills").is_dir():
            logger.debug(f"skills_kb: using skills library at {p}")
            return p
    logger.debug("skills_kb: no skills library found — enrichment disabled")
    return None


@lru_cache(maxsize=1)
def _load_index() -> dict[str, dict]:
    """Return {skill_name: {description, path}} from the repo's index.json (cached)."""
    repo = find_skills_repo()
    if repo is None:
        return {}
    try:
        data = json.loads((repo / "index.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.warning(f"skills_kb: cannot read index.json: {exc}")
        return {}
    return {s["name"]: s for s in data.get("skills", []) if s.get("name")}


@lru_cache(maxsize=1)
def _load_bundle() -> dict[str, dict]:
    """Bundled metadata for the skills Hades references (scanner/intel/playbooks.json).

    Shipped with the repo so a plain `git clone` still resolves playbooks (description +
    framework tags + a GitHub link) even without the full external skills library.
    """
    p = Path(__file__).resolve().parent / "playbooks.json"
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.warning(f"skills_kb: cannot read bundled playbooks.json: {exc}")
        return {}
    return {s["name"]: s for s in data if s.get("name")}


# ---------------------------------------------------------------------------
# Minimal SKILL.md frontmatter parsing (no YAML dependency)
# ---------------------------------------------------------------------------

def _frontmatter_list(block: str, key: str) -> list[str]:
    """Extract a simple YAML list (key:\\n  - a\\n  - b) from a frontmatter block."""
    out: list[str] = []
    capturing = False
    for line in block.splitlines():
        if re.match(rf"^{re.escape(key)}\s*:\s*$", line):
            capturing = True
            continue
        if capturing:
            m = re.match(r"^\s*-\s+(.+?)\s*$", line)
            if m:
                out.append(m.group(1).strip().strip("'\""))
            elif line.strip() and not line.startswith((" ", "\t")):
                break  # next top-level key → list ended
    return out


@lru_cache(maxsize=256)
def _skill_detail(name: str) -> dict | None:
    """Resolve a skill name to {name, description, href, tags, mitre}. Cached.

    Prefers the full local library (rich detail + a file:// link to SKILL.md); falls back to
    the bundled playbooks.json (description + tags + a GitHub link) so enrichment still works
    on a plain clone. `href` is the clickable link (file:// or https) for reports.
    """
    repo = find_skills_repo()
    if repo is not None:
        index = _load_index()
        if name in index:
            entry = index[name]
            rel_dir = entry.get("path", f"skills/{name}")
            md_path = repo / rel_dir / "SKILL.md"
            tags: list[str] = []
            mitre: list[str] = []
            try:
                text = md_path.read_text(encoding="utf-8")
                if text.startswith("---"):
                    block = text.split("---", 2)[1]
                    tags = _frontmatter_list(block, "tags")
                    mitre = _frontmatter_list(block, "mitre_attack")
            except OSError:
                pass
            # Prefer Hades's curated one-liner (complete, offensive) over the library's index.json
            # description, which is truncated mid-sentence (e.g. "…using sqlmap to").
            curated = (_load_bundle().get(name, {}) or {}).get("description", "").strip()
            return {
                "name": name,
                "description": curated or (entry.get("description") or "").strip(),
                "href": md_path.as_uri() if md_path.is_file() else "",
                "tags": tags,
                "mitre": mitre,
            }
    # Fallback: bundled metadata shipped with the repo (links to upstream on GitHub).
    b = _load_bundle().get(name)
    if b:
        return {
            "name": name,
            "description": b.get("description", ""),
            "href": b.get("url", ""),
            "tags": b.get("tags", []),
            "mitre": b.get("mitre", []),
        }
    return None


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def _module_keyword(module: str) -> str:
    """Primary keyword from a module name, e.g. 'ssrf_detect' → 'ssrf'."""
    return module.split("_")[0].lower()


def _candidate_names(finding: "Finding") -> list[str]:
    """Ordered skill names for a finding: db-category map, module map, then keyword fallback."""
    module = finding.module
    if module in _SKIP_MODULES:
        return []
    # INFO findings are context, not actionable issues — no exploitation playbook.
    if finding.severity.value == "info":
        return []

    # db_security: route by the per-finding category.
    if module == "db_security":
        cat = (finding.raw or {}).get("db_category", "")
        return list(DB_CATEGORY_SKILL_MAP.get(cat, []))

    if module in MODULE_SKILL_MAP:
        return list(MODULE_SKILL_MAP[module])

    # Conservative fallback: an *offensive* skill whose name carries the module
    # keyword as a whole token (split on '-'), so 'port' matches a port skill but
    # not 'reports', and only a red-team playbook (never a blue-team one) is picked.
    kw = _module_keyword(module)
    if len(kw) >= 4:
        hits = [n for n in _load_index()
                if kw in n.lower().split("-") and n.lower().startswith(_OFFENSIVE_PREFIXES)]
        return hits[:1]
    return []


def match_skills(finding: "Finding", limit: int = 3) -> list[dict]:
    """Return up to *limit* resolved skill details relevant to *finding* (may be empty)."""
    details: list[dict] = []
    for name in _candidate_names(finding):
        d = _skill_detail(name)
        if d:
            details.append(d)
        if len(details) >= limit:
            break
    return details


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def enrich(findings: list["Finding"]) -> int:
    """
    Attach matching skill playbooks to each finding (sets finding.skill_refs).
    Returns the number of findings enriched. No-op (returns 0) only when neither the full
    skills library nor the bundled playbooks.json is available.
    """
    if find_skills_repo() is None and not _load_bundle():
        return 0
    enriched = 0
    for f in findings:
        try:
            refs = match_skills(f)
        except Exception as exc:  # noqa: BLE001 — enrichment must never break a scan
            logger.debug(f"skills_kb: match failed for {f.module}: {exc}")
            refs = []
        if refs:
            f.skill_refs = refs
            enriched += 1
    return enriched


def distinct_skills(findings: list["Finding"]) -> list[dict]:
    """Unique matched skills across all findings (for a consolidated report section)."""
    seen: set[str] = set()
    out: list[dict] = []
    for f in findings:
        for s in getattr(f, "skill_refs", []) or []:
            if s["name"] not in seen:
                seen.add(s["name"])
                out.append(s)
    return out
