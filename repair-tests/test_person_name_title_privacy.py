"""Preimplementation acceptance probe for MIS-PRIVACY-PERSON-NAME-001."""
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
from mission_public.server import create_server  # noqa: E402


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("title", "expected"),
    (
        ("Jane Doe", "[REDACTED:PERSON_NAME]"),
        ("Ada Lovelace", "[REDACTED:PERSON_NAME]"),
        ("Synthetic delivery", "Synthetic delivery"),
    ),
)
async def test_title_person_name_is_redacted_before_persistence(
    tmp_path: Path, title: str, expected: str
) -> None:
    db_path = tmp_path / "person-name-title.db"
    provider = SyntheticCredentialProvider()
    directory = PrincipalDirectory(provider)
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
        "id": "A-PERSON-NAME-TITLE",
        "title": title,
        "project": "privacy-repair",
        "steps": json.dumps([{"id": "S1", "name": "Verify privacy"}]),
        "request_id": "person-name-title-create",
    }
    arguments = provider.prepare(token, "auftrag_create", arguments)
    async with Client(server) as client:
        with bind_transport_credential(token):
            result = await client.call_tool("auftrag_create", arguments, raise_on_error=False)
    assert json.loads(result.content[0].text)["status"] == "ok"

    with sqlite3.connect(db_path) as db:
        stored = db.execute(
            "SELECT title FROM auftraege WHERE id='A-PERSON-NAME-TITLE'"
        ).fetchone()[0]
    assert stored == expected
    if expected != title:
        assert title not in stored