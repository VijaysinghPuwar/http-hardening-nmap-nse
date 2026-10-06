#!/usr/bin/env python3
"""Fails if a tracked text file contains an em dash (U+2014), a TODO
placeholder, or an absolute home-directory path. Run from the repo root."""

from __future__ import annotations

import re
import subprocess
import sys

BANNED = [
    (re.compile("—"), "em dash"),
    (re.compile(r"\bTODO\b|\bFIXME\b|\bXXX\b"), "placeholder"),
    (re.compile(r"/Users/[A-Za-z0-9_.-]+/|/home/[a-z][a-z0-9_-]*/"), "absolute home path"),
]
SELF = "scripts/check_text.py"


def main() -> int:
    files = subprocess.run(
        ["git", "ls-files", "-co", "--exclude-standard"], capture_output=True, text=True, check=True
    ).stdout.split()
    problems = 0
    for path in files:
        if path == SELF:
            continue
        try:
            with open(path, encoding="utf-8") as f:
                lines = f.readlines()
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue
        for n, line in enumerate(lines, 1):
            for pattern, what in BANNED:
                if pattern.search(line):
                    print(f"{path}:{n}: {what}: {line.strip()[:100]}")
                    problems += 1
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
