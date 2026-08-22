"""GHR-006 preimplementation acceptance: legacy surface classification and restart E2E."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest
from fastmcp import Client

from conftest import prepare_call
from mission_public.auth import bind_transport_credential
from mission_public.server import create_server


def body(result):
    return json.loads(result.content[0].text)


async def call(client, token, name, args):
    prepared = prepare_call(token, name, args)
    with bind_transport_credential(token):
        return body(await client.call_tool(name, prepared, raise_on_error=False))


def test_machine_legacy_diff_classifies_every_public_tool():
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, str(root / "scripts" / "legacy_compatibility.py"), "--json"],
        cwd=root, text=True, capture_output=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["status"] == "pass"
    assert report["legacy_tool_count"] == 13
    assert report["current_tool_count"] == 13
    assert report["unclassified"] == []
    assert all(item["classification"] in {"compatible", "additive", "breaking_intentional"} for item in report["tools"])
    assert {item["name"] for item in report["tools"]} == set(report["current_tools"])


@pytest.mark.anyio
async def test_ordinary_lifecycle_and_history_survive_server_recreation(tmp_path, provider, directory):
    db_path = tmp_path / "restart.db"
    planner = provider.issue("planner-a", "planner")
    worker = provider.issue("worker-a", "worker")
    first = create_server(
        db_path=db_path, credential_provider=provider, principal_directory=directory,
        identity_context=provider.context, adapters_enabled=False,
    )
    async with Client(first) as client:
        created = await call(client, planner, "auftrag_create", {
            "caller_instance_id": "planner-a", "id": "A-RESTART-001",
            "title": "Restart proof", "project": "compatibility",
            "steps": json.dumps([{"id": "S1", "name": "Persist"}]),
            "request_id": "restart-create",
        })
        assigned = await call(client, planner, "auftrag_assign", {
            "caller_instance_id": "planner-a", "auftrag_id": "A-RESTART-001",
            "assigned_to": "worker-a", "request_id": "restart-assign",
        })
        started = await call(client, worker, "auftrag_start", {
            "caller_instance_id": "worker-a", "auftrag_id": "A-RESTART-001",
            "request_id": "restart-start",
        })
        checkpoint = await call(client, worker, "auftrag_checkpoint", {
            "caller_instance_id": "worker-a", "auftrag_id": "A-RESTART-001",
            "step_id": "S1", "status": "pass", "checkpoint_data": json.dumps({"evidence": ["persisted"]}),
            "request_id": "restart-checkpoint",
        })
    responses = (created, assigned, started, checkpoint)
    assert all(item["status"] == "ok" for item in responses), responses

    restarted = create_server(
        db_path=db_path, credential_provider=provider, principal_directory=directory,
        identity_context=provider.context, adapters_enabled=False,
    )
    async with Client(restarted) as client:
        got = await call(client, worker, "auftrag_get", {
            "caller_instance_id": "worker-a", "auftrag_id": "A-RESTART-001",
        })
        history = await call(client, planner, "auftrag_get_changelog", {
            "caller_instance_id": "planner-a", "auftrag_id": "A-RESTART-001", "limit": 50,
        })
    assert got["status"] == "ok"
    assert got["auftrag"]["status"] == "validating"
    assert got["auftrag"]["steps"][0]["status"] == "pass"
    actions = {item["action"] for item in history["items"]}
    assert {"create", "assign", "start", "checkpoint"} <= actions
