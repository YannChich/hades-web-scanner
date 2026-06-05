"""
build_playbooks_bundle — generate scanner/intel/playbooks.json.

Hades enriches findings with expert playbooks from a local clone of the (large) external
Anthropic-Cybersecurity-Skills library. So that a plain `git clone` of Hades still shows the
playbook references offline, this script extracts the metadata for ONLY the skills Hades
actually references (config.MODULE_SKILL_MAP + DB_CATEGORY_SKILL_MAP) into a small bundled
JSON: {name, description, mitre, tags, url}. skills_kb falls back to this bundle when the full
library is not present.

Run (with the skills library cloned alongside the project):
    python tools/build_playbooks_bundle.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import DB_CATEGORY_SKILL_MAP, MODULE_SKILL_MAP  # noqa: E402
from scanner.intel.skills_kb import (  # noqa: E402
    _frontmatter_list,
    _load_index,
    find_skills_repo,
)

_GITHUB = "https://github.com/mukul975/Anthropic-Cybersecurity-Skills/blob/main/{path}/SKILL.md"
OUT = Path(__file__).resolve().parent.parent / "scanner" / "intel" / "playbooks.json"


def _referenced_skills() -> list[str]:
    names: list[str] = []
    for group in (*MODULE_SKILL_MAP.values(), *DB_CATEGORY_SKILL_MAP.values()):
        for n in group:
            if n not in names:
                names.append(n)
    return names


def main() -> None:
    repo = find_skills_repo()
    if repo is None:
        sys.exit("Skills library not found — clone Anthropic-Cybersecurity-Skills alongside the "
                 "project (or set HADES_SKILLS_PATH) before building the bundle.")
    index = _load_index()
    bundle = []
    for name in _referenced_skills():
        entry = index.get(name, {})
        rel = entry.get("path", f"skills/{name}")
        md = repo / rel / "SKILL.md"
        tags, mitre = [], []
        if md.is_file():
            text = md.read_text(encoding="utf-8")
            if text.startswith("---"):
                block = text.split("---", 2)[1]
                tags = _frontmatter_list(block, "tags")
                mitre = _frontmatter_list(block, "mitre_attack")
        bundle.append({
            "name": name,
            "description": (entry.get("description") or "").strip().strip("'\""),
            "mitre": mitre,
            "tags": tags,
            "url": _GITHUB.format(path=rel),
        })
    OUT.write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {len(bundle)} playbook(s) -> {OUT.relative_to(OUT.parents[2])}")


if __name__ == "__main__":
    main()
