#!/usr/bin/env python3
"""
Hades — Web Security Scanner. The v1.0 launcher.

Quick start:
    pip install -r requirements.txt
    python hades.py --url https://example.com

This is the canonical entry point; it delegates to the CLI in main.py (which keeps working
on its own for backward compatibility).
"""
import sys

from main import cli

if __name__ == "__main__":
    sys.exit(cli())
