"""Hook entry point: reads Claude Code PostToolUse JSON from stdin, runs import check if a webscan .py file was edited."""
import json
import os
import subprocess
import sys

WEBSCAN_DIR = os.path.normpath(r"C:\Users\yanou\Project\webscan")


def main() -> None:
    data = json.loads(sys.stdin.read())
    file_path = data.get("tool_input", {}).get("file_path", "")

    if WEBSCAN_DIR.lower() in os.path.normpath(file_path).lower() and file_path.endswith(".py"):
        result = subprocess.run(
            [sys.executable, "check_imports.py"],
            cwd=WEBSCAN_DIR,
        )
        sys.exit(result.returncode)


if __name__ == "__main__":
    main()
