#!/usr/bin/env python3
"""Machine-readable public-surface diff against the frozen Legacy capture."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    legacy = json.loads((root / "spec" / "legacy-public-surface.json").read_text())
    wire = json.loads((root / "spec" / "wire-contract.json").read_text())
    old = legacy["captured_tools"]
    current = {name: sorted(body["request"]["properties"]) for name, body in wire["tools"].items()}
    all_names = sorted(set(old) | set(current))
    classification = legacy["classification_policy"]["all_tools"]
    tools = []
    unclassified = []
    for name in all_names:
        if name not in old or name not in current:
            unclassified.append(name)
            continue
        old_fields = set(old[name])
        new_fields = set(current[name])
        tools.append({
            "name": name,
            "classification": classification,
            "added_fields": sorted(new_fields - old_fields),
            "removed_fields": sorted(old_fields - new_fields),
            "reason": legacy["classification_policy"]["reason"],
        })
    report = {
        "status": "pass" if not unclassified else "blocked",
        "legacy_source_sha256": legacy["source_sha256"],
        "legacy_tool_count": len(old),
        "current_tool_count": len(current),
        "current_tools": sorted(current),
        "tools": tools,
        "unclassified": unclassified,
        "statement_limit": "Tool-name and request-field migration classification only; not wire compatibility or deployment evidence.",
    }
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0 if not unclassified else 1


if __name__ == "__main__":
    sys.exit(main())
