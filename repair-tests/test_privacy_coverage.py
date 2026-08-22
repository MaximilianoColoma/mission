"""Prewritten adversarial acceptance probe for Mission privacy finding P1.

Requirement R1: known labelled names, physical addresses, and IPv4-embedded
IPv6 topology must be fully redacted before persistence.  This test was written
before the corresponding product repair; frozen tests remain untouched.
"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest
from fastmcp import Client

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from conftest import PrincipalDirectory, SyntheticCredentialProvider  # noqa: E402
from mission_public.auth import bind_transport_credential  # noqa: E402
from mission_public.privacy import redact_text  # noqa: E402
from mission_public.server import create_server  # noqa: E402


LEAKS = (
    '"name": "Jane Doe"',
    "Unter den Linden 77",
    "1 Infinite Loop",
    "2001:db8::192.0.2.33",
)


@pytest.mark.parametrize("value", LEAKS)
def test_known_privacy_vectors_are_fully_redacted(value: str) -> None:
    redacted = redact_text(value)
    assert value not in redacted
    assert "[REDACTED:" in redacted
    if value.startswith("2001:"):
        assert "2001:db8" not in redacted


@pytest.mark.anyio
async def test_known_privacy_vectors_do_not_persist_at_rest(tmp_path: Path) -> None:
    db_path = tmp_path / "privacy-repair.db"
    provider = SyntheticCredentialProvider()
    directory = PrincipalDirectory(provider)
    directory.add("worker-a")
    server = create_server(
        db_path=db_path,
        credential_provider=provider,
        principal_directory=directory,
        identity_context=provider.context,
        adapters_enabled=False,
    )
    token = provider.issue("planner-a", "planner")
    arguments = {
        "caller_instance_id": "planner-a",
        "id": "A-PRIVACY-REPAIR",
        "title": LEAKS[0],
        "project": "privacy-repair",
        "description": LEAKS[1],
        "constraints": LEAKS[2],
        "rollback": LEAKS[3],
        "steps": json.dumps([{"id": "S1", "name": "Verify privacy"}]),
        "request_id": "privacy-repair-create",
    }
    arguments = provider.prepare(token, "auftrag_create", arguments)
    async with Client(server) as client:
        with bind_transport_credential(token):
            result = await client.call_tool("auftrag_create", arguments, raise_on_error=False)
    assert json.loads(result.content[0].text)["status"] == "ok"

    with sqlite3.connect(db_path) as db:
        dump = " ".join(
            str(value)
            for table in ("auftraege", "steps", "changelog")
            for row in db.execute(f"SELECT * FROM {table}")
            for value in row
        )
    for leak in LEAKS:
        assert leak not in dump
    assert dump.count("[REDACTED:") >= len(LEAKS)
