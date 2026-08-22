#!/usr/bin/env python3
"""Real local Mission lifecycle using the public MCP server and synthetic signed identities."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

from fastmcp import Client

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from conftest import PrincipalDirectory, SyntheticCredentialProvider  # noqa: E402
from mission_public.auth import bind_transport_credential  # noqa: E402
from mission_public.server import create_server  # noqa: E402


def body(result):
    return json.loads(result.content[0].text)


async def main() -> None:
    provider = SyntheticCredentialProvider()
    directory = PrincipalDirectory(provider)
    directory.add("worker-agent")
    planner = provider.issue("planner-agent", "planner")
    worker = provider.issue("worker-agent", "worker")
    auditor = provider.issue("auditor-agent", "auditor")

    async def call(client, token, tool, arguments):
        prepared = provider.prepare(token, tool, arguments)
        with bind_transport_credential(token):
            return body(await client.call_tool(tool, prepared, raise_on_error=False))

    with TemporaryDirectory(prefix="mission-real-demo-") as temporary:
        database = Path(temporary) / "mission.db"
        first = create_server(
            db_path=database, credential_provider=provider,
            principal_directory=directory, identity_context=provider.context,
            adapters_enabled=False,
        )
        async with Client(first) as client:
            created = await call(client, planner, "auftrag_create", {
                "caller_instance_id": "planner-agent", "id": "MISSION-DEMO-001",
                "title": "Ship a validated release", "project": "autonomous-release",
                "steps": json.dumps([{"id": "BUILD", "name": "Build exact candidate"}]),
                "exit_kpis": json.dumps({"required": ["receipt"]}),
                "constraints": "Close requires the declared receipt key; external evidence verification is out of scope.",
                "request_id": "demo-create",
            })
            assigned = await call(client, planner, "auftrag_assign", {
                "caller_instance_id": "planner-agent", "auftrag_id": "MISSION-DEMO-001",
                "assigned_to": "worker-agent", "request_id": "demo-assign",
            })
            assigned_readback = await call(client, planner, "auftrag_get", {
                "caller_instance_id": "planner-agent", "auftrag_id": "MISSION-DEMO-001",
            })
            started = await call(client, worker, "auftrag_start", {
                "caller_instance_id": "worker-agent", "auftrag_id": "MISSION-DEMO-001",
                "request_id": "demo-start",
            })
            checkpoint = await call(client, worker, "auftrag_checkpoint", {
                "caller_instance_id": "worker-agent", "auftrag_id": "MISSION-DEMO-001",
                "step_id": "BUILD", "status": "pass",
                "checkpoint_data": json.dumps({"evidence": ["sha256:demo"]}),
                "request_id": "demo-checkpoint",
            })

        restarted = create_server(
            db_path=database, credential_provider=provider,
            principal_directory=directory, identity_context=provider.context,
            adapters_enabled=False,
        )
        async with Client(restarted) as client:
            restored = await call(client, worker, "auftrag_get", {
                "caller_instance_id": "worker-agent", "auftrag_id": "MISSION-DEMO-001",
            })
            audited = await call(client, auditor, "auftrag_get_changelog", {
                "caller_instance_id": "auditor-agent", "auftrag_id": "MISSION-DEMO-001", "limit": 50,
            })
            closed = await call(client, worker, "auftrag_close", {
                "caller_instance_id": "worker-agent", "auftrag_id": "MISSION-DEMO-001",
                "result": "success", "summary": "Required receipt key declared.",
                "kpi_results": json.dumps({"receipt": {"met": True, "value": 1, "evidence": "synthetic-demo"}}),
                "request_id": "demo-close",
            })
            history = await call(client, planner, "auftrag_get_changelog", {
                "caller_instance_id": "planner-agent", "auftrag_id": "MISSION-DEMO-001", "limit": 50,
            })

        assert created["status"] == "ok"
        assert assigned["status"] == "ok"
        assert assigned_readback["auftrag"]["status"] == "assigned"
        assert started["next_state"] == "active"
        assert checkpoint["next_state"] == "validating"
        assert restored["auftrag"]["status"] == "validating"
        assert audited["status"] == "ok"
        assert closed["next_state"] == "done"
        actions = [item["action"] for item in history["items"] if item["action"] in {"create", "assign", "start", "checkpoint", "close"}]
        assert actions == ["create", "assign", "start", "checkpoint", "close"], actions
        print("queued -> assigned -> active -> validating")
        print("[restart] state restored: validating")
        print("validating -> done")
        print("MISSION_DEMO_PASS state=done restart=pass auditor_read=pass kpi_gate=caller_declared history=create,assign,start,checkpoint,close")


if __name__ == "__main__":
    asyncio.run(main())
