"""GHR-005 preimplementation acceptance for staged fresh-home installation."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

PRODUCT = "mission"
TOOL_COUNT = 13
STAGES = [
    "prerequisites", "artifact", "venv", "dependencies", "command",
    "config", "storage", "integration", "doctor", "complete",
]


def run_installer(root: Path, *args: str, env=None):
    command = [str(root / "install.sh"), *args]
    return subprocess.run(command, cwd=root, text=True, capture_output=True, env=env, timeout=180)


def parse_last_json(output: str):
    lines = [line for line in output.splitlines() if line.strip()]
    assert lines, output
    return json.loads(lines[-1])


def test_manifest_declares_exact_resumable_stage_protocol():
    root = Path(__file__).resolve().parents[1]
    result = run_installer(root, "--manifest", "--json")
    assert result.returncode == 0, result.stderr
    body = parse_last_json(result.stdout)
    assert body == {"ok": True, "product": PRODUCT, "stages": STAGES}


def test_fresh_home_full_install_doctor_and_idempotent_rerun(tmp_path):
    root = Path(__file__).resolve().parents[1]
    target = tmp_path / "fresh-home"
    hostile_env = dict(os.environ)
    hostile_env["PYTHONPATH"] = "/definitely/not/a/project"
    hostile_env["PYTHONHOME"] = "/definitely/not/a/python"

    first = run_installer(root, "--target", str(target), "--non-interactive", "--json", env=hostile_env)
    assert first.returncode == 0, first.stdout + first.stderr
    first_body = parse_last_json(first.stdout)
    assert first_body["ok"] is True and first_body["stage"] == "complete"
    assert set(first_body["env_scrubbed"]) == {"PYTHONPATH", "PYTHONHOME"}
    assert (target / ".venv" / "bin" / "python").is_file()
    assert (target / "bin" / f"{PRODUCT}-doctor").is_file()
    assert (target / "config.json").is_file()
    assert (target / "data").is_dir()
    descriptor = json.loads((target / "mcp.json").read_text())
    assert descriptor["command"] == str(target / "bin" / f"{PRODUCT}-doctor")
    assert first_body["doctor"] == {"product": PRODUCT, "tools": TOOL_COUNT, "status": "pass"}

    second = run_installer(root, "--target", str(target), "--non-interactive", "--json")
    assert second.returncode == 0, second.stdout + second.stderr
    second_body = parse_last_json(second.stdout)
    assert second_body["ok"] is True and second_body["idempotent_rerun"] is True


def test_negative_prerequisite_stage_is_machine_readable(tmp_path):
    root = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env["PATH"] = "/nonexistent"
    result = run_installer(root, "--target", str(tmp_path / "blocked"), "--stage", "prerequisites", "--json", env=env)
    assert result.returncode != 0
    body = parse_last_json(result.stdout)
    assert body["ok"] is False
    assert body["stage"] == "prerequisites"
    assert body["error_code"] == "UV_NOT_FOUND"
    assert body["next_action"]
