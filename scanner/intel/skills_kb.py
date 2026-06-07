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
    MODULE_REMEDIATION_MAP,
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


def github_url(name: str) -> str:
    """Upstream GitHub (Markdown-rendered) URL for a skill, from the bundle. '' if unknown.

    Used as a safe fallback for the HTML report: when a local SKILL.md cannot be rendered to a
    styled page (the `markdown` lib is missing, or a read/render error), the playbook badge is
    repointed here so it opens a rendered page on GitHub instead of a raw .md file.
    """
    entry = _load_bundle().get(name)
    return (entry or {}).get("url", "") if entry else ""


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


def _frontmatter_scalar(block: str, key: str) -> str:
    """Extract a simple scalar frontmatter value (key: value) from a block. '' if absent."""
    m = re.search(rf"^{re.escape(key)}\s*:\s*(.+)$", block, re.M)
    return m.group(1).strip().strip("'\"") if m else ""


def _frontmatter_description(block: str) -> str:
    """The full (possibly multi-line) frontmatter ``description``, whitespace-normalised.

    The library's descriptions span several indented lines; the truncated copy in index.json is
    avoided in favour of this complete text.
    """
    out: list[str] = []
    capturing = False
    for line in block.splitlines():
        if not capturing:
            m = re.match(r"^description\s*:\s*(.*)$", line)
            if not m:
                continue
            first = m.group(1).strip()
            if first and first not in (">", "|", ">-", "|-", ">+", "|+"):
                out.append(first)
            capturing = True
            continue
        if re.match(r"^[A-Za-z0-9_]+\s*:", line):   # next top-level key → description ended
            break
        if line.strip():
            out.append(line.strip())
    return re.sub(r"\s+", " ", " ".join(out)).strip().strip("'\"")


def _skill_teaser(block: str) -> str:
    """A one-sentence teaser from the frontmatter description (first sentence, period-terminated)."""
    d = _frontmatter_description(block)
    if not d:
        return ""
    m = re.match(r"^(.*?[.!?])(?:\s|$)", d)
    t = (m.group(1) if m else d).strip()
    if t and not t.endswith((".", "!", "?")):
        t += "."
    return t


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
# Library-wide metadata index (for relevance matching and the Skills Library page)
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _skill_meta() -> dict[str, dict]:
    """Frontmatter metadata for every skill: {name: {mitre, tags, subdomain, description, offensive}}.

    Built once (cached) from the full local repo when present (parsing the 754 SKILL.md files), else
    derived from the bundled playbooks.json so matching still works on a plain clone. Empty only when
    neither source is available — matching then degrades to the curated maps, exactly as before.
    """
    out: dict[str, dict] = {}
    repo = find_skills_repo()
    if repo is not None:
        for name, entry in _load_index().items():
            rel = entry.get("path", f"skills/{name}")
            md = repo / rel / "SKILL.md"
            tags: list[str] = []
            mitre: list[str] = []
            subdomain = ""
            try:
                text = md.read_text(encoding="utf-8")
            except OSError:
                continue
            teaser = ""
            if text.startswith("---"):
                block = text.split("---", 2)[1]
                tags = _frontmatter_list(block, "tags")
                mitre = _frontmatter_list(block, "mitre_attack")
                subdomain = _frontmatter_scalar(block, "subdomain")
                teaser = _skill_teaser(block)
            tagset = {t.lower() for t in tags}
            out[name] = {
                "mitre": set(mitre),
                "tags": tagset,
                "words": tagset | _name_words(name),
                "subdomain": subdomain,
                "description": teaser or (entry.get("description") or "").strip().strip("'\""),
                "offensive": name.lower().startswith(_OFFENSIVE_PREFIXES),
            }
        if out:
            return out
    # Offline: derive from the bundle (carries name/description/tags/mitre/subdomain after the build).
    for name, b in _load_bundle().items():
        tagset = {t.lower() for t in (b.get("tags") or [])}
        out[name] = {
            "mitre": set(b.get("mitre", []) or []),
            "tags": tagset,
            "words": tagset | _name_words(name),
            "subdomain": b.get("subdomain", ""),
            "description": (b.get("description") or "").strip(),
            "offensive": name.lower().startswith(_OFFENSIVE_PREFIXES),
        }
    return out


def _name_words(name: str) -> set[str]:
    """Meaningful tokens from a skill name, minus the leading verb (performing-, detecting-, …)."""
    toks = [w for w in name.lower().split("-") if len(w) >= 3]
    return set(toks[1:]) if len(toks) > 1 else set(toks)


def all_skills() -> list[dict]:
    """Every known skill as {name, description, subdomain, tags, mitre, offensive, href} — for the
    Skills Library page. Resolves an `href` (local rendered SKILL.md or GitHub) via `_skill_detail`."""
    items: list[dict] = []
    for name, m in _skill_meta().items():
        detail = _skill_detail(name) or {}
        items.append({
            "name": name,
            "description": m.get("description") or detail.get("description", ""),
            "subdomain": m.get("subdomain", ""),
            "tags": sorted(m.get("tags", set())),
            "mitre": sorted(m.get("mitre", set())),
            "offensive": m.get("offensive", False),
            "href": detail.get("href", "") or github_url(name),
        })
    items.sort(key=lambda s: (s["subdomain"], s["name"]))
    return items


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def _module_keyword(module: str) -> str:
    """Primary keyword from a module name, e.g. 'ssrf_detect' → 'ssrf'."""
    return module.split("_")[0].lower()


def _finding_keywords(finding: "Finding") -> set[str]:
    """Lexical signals for a finding: its module keyword + alphabetic title tokens (≥4 chars)."""
    kws = {_module_keyword(finding.module)}
    kws.update(re.findall(r"[a-z]{4,}", finding.title.lower()))
    return kws


def _score_skill(finding: "Finding", meta: dict, keywords: set[str]) -> tuple[int, int]:
    """Relevance of a skill to a finding as (technique_score, keyword_overlap).

    technique_score weighs ATT&CK overlap (exact technique 3, base technique 2); keyword_overlap is
    the count of shared lexical tokens (finding module/title vs the skill's tags + name words).
    """
    fmitre = set(finding.mitre or [])
    exact = fmitre & meta["mitre"]
    fbase = {t.split(".")[0] for t in fmitre}
    sbase = {t.split(".")[0] for t in meta["mitre"]}
    base_only = (fbase & sbase) - {t.split(".")[0] for t in exact}
    tech = 3 * len(exact) + 2 * len(base_only)
    return tech, len(keywords & meta["words"])


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

    # Smarter fallback (long-tail modules not in the curated map): rank *offensive* library skills
    # by ATT&CK technique + tag/keyword relevance and take the best 1–2 above a precision threshold.
    names = _scored_names(finding, limit=2)
    if names:
        return names

    # Last resort when no library metadata is available: the old conservative keyword pick.
    kw = _module_keyword(module)
    if len(kw) >= 4:
        hits = [n for n in _load_index()
                if kw in n.lower().split("-") and n.lower().startswith(_OFFENSIVE_PREFIXES)]
        return hits[:1]
    return []


def _scored_names(finding: "Finding", *, limit: int) -> list[str]:
    """Offensive library skill names ranked by relevance to *finding* (long-tail fallback).

    A skill is accepted only when it is **lexically** relevant (≥1 shared token) AND either shares
    an ATT&CK technique or shares a 2nd token — so a broad shared technique alone is never enough to
    attach a playbook. This keeps the long-tail matches precise. Returns up to *limit* names.
    """
    meta = _skill_meta()
    if not meta:
        return []
    kws = _finding_keywords(finding)
    scored: list[tuple[int, str]] = []
    for name, m in meta.items():
        if not m["offensive"]:
            continue
        tech, kw = _score_skill(finding, m, kws)
        if kw == 0 or (tech == 0 and kw < 2):
            continue
        scored.append((tech + kw, name))
    scored.sort(key=lambda x: (-x[0], x[1]))
    return [name for _, name in scored[:limit]]


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


def match_remediation(finding: "Finding", limit: int = 2) -> list[dict]:
    """Curated *defensive* (detect/fix) playbook(s) for a finding — the blue-team complement to
    match_skills, from config.MODULE_REMEDIATION_MAP. Only modules with a genuinely relevant
    defensive skill are mapped, so a remediation badge is always accurate (never forced). May be []."""
    if finding.module in _SKIP_MODULES or finding.severity.value == "info":
        return []
    details: list[dict] = []
    for name in MODULE_REMEDIATION_MAP.get(finding.module, [])[:limit]:
        d = _skill_detail(name)
        if d:
            details.append(d)
    return details


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def enrich(findings: list["Finding"]) -> int:
    """
    Attach matching playbooks to each finding: the offensive skill(s) in `finding.skill_refs`, and
    the best blue-team remediation skill in `finding.remediation_refs`. Returns the number of
    findings enriched. No-op (returns 0) only when neither the full skills library nor the bundled
    playbooks.json is available.
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
        try:
            rem = match_remediation(f)
        except Exception as exc:  # noqa: BLE001 — enrichment must never break a scan
            logger.debug(f"skills_kb: remediation match failed for {f.module}: {exc}")
            rem = []
        if refs and rem:  # never show the same skill as both offensive and remediation
            ref_names = {s["name"] for s in refs}
            rem = [s for s in rem if s["name"] not in ref_names]
        if refs:
            f.skill_refs = refs
        if rem:
            f.remediation_refs = rem
        if refs or rem:
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
