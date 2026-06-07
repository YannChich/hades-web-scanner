"""
build_playbooks_bundle — generate scanner/intel/playbooks.json.

Hades enriches findings with expert playbooks from a local clone of the (large) external
Anthropic-Cybersecurity-Skills library, and ships a searchable Skills Library page. So that a plain
`git clone` of Hades keeps working **offline**, this script extracts lightweight metadata for the
**whole** library into a single bundled JSON: a list of
{name, description, subdomain, mitre, tags, offensive, url}.

`scanner/intel/skills_kb` falls back to this bundle whenever the full library is not present — for
the playbook references, the ATT&CK/tag relevance matching, and the Skills Library catalogue.

Run (with the skills library cloned alongside the project, or HADES_SKILLS_PATH set):
    python tools/build_playbooks_bundle.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.intel.skills_kb import (  # noqa: E402
    _OFFENSIVE_PREFIXES,
    _frontmatter_list,
    _frontmatter_scalar,
    _load_index,
    _skill_teaser,
    find_skills_repo,
)

_GITHUB = "https://github.com/mukul975/Anthropic-Cybersecurity-Skills/blob/main/{path}/SKILL.md"
OUT = Path(__file__).resolve().parent.parent / "scanner" / "intel" / "playbooks.json"


def main() -> None:
    repo = find_skills_repo()
    if repo is None:
        sys.exit("Skills library not found — clone Anthropic-Cybersecurity-Skills alongside the "
                 "project (or set HADES_SKILLS_PATH) before building the bundle.")
    index = _load_index()
    bundle = []
    for name, entry in sorted(index.items()):
        rel = entry.get("path", f"skills/{name}")
        md = repo / rel / "SKILL.md"
        tags, mitre, subdomain, teaser = [], [], "", ""
        if md.is_file():
            text = md.read_text(encoding="utf-8")
            if text.startswith("---"):
                block = text.split("---", 2)[1]
                tags = _frontmatter_list(block, "tags")
                mitre = _frontmatter_list(block, "mitre_attack")
                subdomain = _frontmatter_scalar(block, "subdomain")
                teaser = _skill_teaser(block)
        bundle.append({
            "name": name,
            "description": teaser or (entry.get("description") or "").strip().strip("'\""),
            "subdomain": subdomain,
            "mitre": mitre,
            "tags": tags,
            "offensive": name.lower().startswith(_OFFENSIVE_PREFIXES),
            "url": _GITHUB.format(path=rel),
        })
    OUT.write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")
    size_kb = OUT.stat().st_size / 1024
    print(f"Wrote {len(bundle)} skill(s) -> {OUT.relative_to(OUT.parents[2])}  ({size_kb:.0f} KB)")


if __name__ == "__main__":
    main()
