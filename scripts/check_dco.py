#!/usr/bin/env python3
"""Fail a pull request when any included commit lacks a DCO sign-off."""
from __future__ import annotations

import argparse
import re
import subprocess
import sys

SIGN_OFF = re.compile(r"(?mi)^Signed-off-by:\s+.+\s+<[^<>\s]+@[^<>\s]+>\s*$")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--range", required=True, dest="commit_range")
    args = parser.parse_args()
    result = subprocess.run(
        ["git", "log", "--format=%H%x00%B%x00", args.commit_range],
        text=True, capture_output=True, timeout=60,
    )
    if result.returncode:
        print(result.stderr.strip())
        return 2
    fields = result.stdout.split("\x00")
    missing: list[str] = []
    for index in range(0, len(fields) - 1, 2):
        commit = fields[index].strip()
        body = fields[index + 1]
        if commit and not SIGN_OFF.search(body):
            missing.append(commit)
    if missing:
        print("DCO_SIGNOFF_FAIL")
        for commit in missing:
            print(commit)
        return 1
    print(f"DCO_SIGNOFF_PASS commits={(len(fields) - 1) // 2}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
