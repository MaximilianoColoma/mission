#!/usr/bin/env python3
"""Staged, idempotent, machine-readable clean-room installer."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

PRODUCT = "mission"
TOOL_COUNT = 13
STAGES = [
    "prerequisites", "artifact", "venv", "dependencies", "command",
    "config", "storage", "integration", "doctor", "complete",
]


def emit(body: dict, code: int = 0) -> int:
    print(json.dumps(body, ensure_ascii=False, sort_keys=True))
    return code


def error(stage: str, code: str, reason: str, next_action: str) -> int:
    return emit({
        "ok": False, "stage": stage, "error_code": code,
        "reason": reason, "next_action": next_action,
    }, 1)


def run(command: list[str], *, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True, timeout=180)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", action="store_true")
    parser.add_argument("--stage", choices=STAGES)
    parser.add_argument("--target", type=Path, default=Path.home() / ".local" / "share" / PRODUCT)
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.manifest:
        return emit({"ok": True, "product": PRODUCT, "stages": STAGES})

    root = Path(__file__).resolve().parents[1]
    target = args.target.resolve()
    scrubbed = [item for item in os.environ.get("WITMIS_ENV_SCRUBBED", "").split(",") if item]
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    uv = shutil.which("uv", path=env.get("PATH"))
    selected = [args.stage] if args.stage else STAGES
    marker = target / ".install-state.json"
    rerun = marker.is_file()
    doctor = None

    for stage in selected:
        if stage == "prerequisites":
            if uv is None:
                return error(stage, "UV_NOT_FOUND", "uv is required for locked installation", "Install uv and rerun the prerequisites stage")
            if sys.version_info < (3, 11):
                return error(stage, "PYTHON_TOO_OLD", "Python 3.11 or newer is required", "Install Python 3.11+ and rerun")
        elif stage == "artifact":
            (target / "lib").mkdir(parents=True, exist_ok=True)
            shutil.copy2(root / "scripts" / "mcp_smoke.py", target / "lib" / "mcp_smoke.py")
        elif stage == "venv":
            if uv is None:
                return error(stage, "UV_NOT_FOUND", "uv is required", "Run prerequisites after installing uv")
            target.mkdir(parents=True, exist_ok=True)
        elif stage == "dependencies":
            if uv is None:
                return error(stage, "UV_NOT_FOUND", "uv is required", "Run prerequisites after installing uv")
            sync_env = dict(env)
            sync_env["UV_PROJECT_ENVIRONMENT"] = str(target / ".venv")
            result = run([uv, "sync", "--locked", "--no-dev"], cwd=root, env=sync_env)
            if result.returncode:
                return error(stage, "LOCKED_SYNC_FAILED", result.stderr.strip() or result.stdout.strip(), "Repair pyproject.toml/uv.lock consistency and rerun dependencies")
        elif stage == "command":
            bin_dir = target / "bin"
            bin_dir.mkdir(parents=True, exist_ok=True)
            command = bin_dir / f"{PRODUCT}-doctor"
            command.write_text(f"#!/bin/bash\nexec '{target / '.venv/bin/python'}' '{target / 'lib/mcp_smoke.py'}'\n")
            command.chmod(command.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        elif stage == "config":
            config = target / "config.json"
            if not config.exists():
                config.write_text(json.dumps({"product": PRODUCT, "data_dir": str(target / "data")}, indent=2) + "\n")
        elif stage == "storage":
            (target / "data").mkdir(parents=True, exist_ok=True)
        elif stage == "integration":
            descriptor = {"product": PRODUCT, "command": str(target / "bin" / f"{PRODUCT}-doctor")}
            (target / "mcp.json").write_text(json.dumps(descriptor, indent=2) + "\n")
        elif stage == "doctor":
            executable = target / "bin" / f"{PRODUCT}-doctor"
            result = run([str(executable)], cwd=target, env=env)
            expected = f"MCP_FIRST_RUN_PASS product={PRODUCT} tools={TOOL_COUNT}"
            if result.returncode or expected not in result.stdout:
                return error(stage, "DOCTOR_FAILED", result.stderr.strip() or result.stdout.strip(), "Inspect the installed environment and rerun doctor")
            doctor = {"product": PRODUCT, "tools": TOOL_COUNT, "status": "pass"}
        elif stage == "complete":
            body = {
                "ok": True, "stage": "complete", "product": PRODUCT,
                "target": str(target), "env_scrubbed": scrubbed,
                "idempotent_rerun": rerun, "doctor": doctor,
            }
            marker.write_text(json.dumps(body, indent=2) + "\n")
            return emit(body)
        if args.stage:
            return emit({"ok": True, "stage": stage, "product": PRODUCT, "target": str(target), "env_scrubbed": scrubbed})
    return 0


if __name__ == "__main__":
    sys.exit(main())
