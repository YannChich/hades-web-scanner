"""Quick import-health check — run after any module edit to catch broken imports.

Lives in tools/ but imports the project from the webscan root, so it works regardless of
the current working directory. The module list is derived from config, so newly added
modules are checked automatically.
"""
import importlib
import sys
import traceback
from pathlib import Path

# Make the webscan root importable (this file is webscan/tools/check_imports.py).
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from config import PROFILE_MODULES  # noqa: E402

# Every module referenced by any profile, plus the shared/infra modules.
_INFRA = [
    "config", "scanner.engine", "scanner.crawler", "scanner.exploit",
    "scanner.db.db_security", "scanner.vulns._common",
    "scanner.output.console", "scanner.output.scorer", "scanner.output.logger",
    "scanner.output.report_json", "scanner.output.report_html", "scanner.output.report_pdf",
]
MODULES = sorted({m for mods in PROFILE_MODULES.values() for m in mods} | set(_INFRA))


def main() -> int:
    errors: list[tuple[str, str]] = []
    for mod in MODULES:
        try:
            importlib.import_module(mod)
            print(f"OK  {mod}")
        except Exception as exc:  # noqa: BLE001
            errors.append((mod, traceback.format_exc()))
            print(f"ERR {mod}: {exc}")

    if errors:
        print(f"\n[HOOK] {len(errors)} import error(s) detected:")
        for mod, tb in errors:
            print(f"  --- {mod} ---\n{tb}")
        return 1
    print(f"\n[HOOK] All {len(MODULES)} modules OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
