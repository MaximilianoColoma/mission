"""Prewritten regression probes for transport-scoped synthetic authentication.

Requirement TS-001: creating a Mission in-memory endpoint MUST NOT mutate the
process-wide FastMCP Client.call_tool implementation.
Requirement TS-002: the endpoint-scoped forwarding path MUST preserve exact
request binding and normal authenticated MCP calls.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastmcp import Client

from mission_public.auth import Principal, bind_transport_credential
from mission_public.server import create_server
from conftest import PrincipalDirectory as HarnessDirectory
from conftest import SyntheticCredentialProvider as HarnessProvider


class Provider:
    issuer = "test-issuer"
    audience = "mission"

    def __init__(self) -> None:
        self.records: dict[str, Principal] = {}

    def issue(self, subject_id: str, role: str) -> str:
        token = f"token-{len(self.records) + 1}"
        now = datetime.now(timezone.utc)
        self.records[token] = Principal(
            subject_id=subject_id,
            client_id=f"{role}-client",
            role=role,
            credential_type="synthetic_test_provider",
            credential_id=f"cred-{len(self.records) + 1}",
            issuer=self.issuer,
            audience=self.audience,
            issued_at=now,
            expires_at=now + timedelta(hours=1),
            revocation_status="active",
        )
        return token

    def resolve(self, raw_credential: str) -> Principal | None:
        return self.records.get(raw_credential)


class Directory:
    def eligible(self, subject_id: str, tenant: str = "default") -> bool:
        return False


def payload(result):
    return result.structured_content or result.content[0].structured_content


@pytest.mark.anyio
async def test_server_creation_does_not_patch_fastmcp_client(tmp_path):
    original = Client.call_tool
    endpoint = create_server(
        db_path=tmp_path / "mission.db",
        credential_provider=(provider := HarnessProvider()),
        principal_directory=HarnessDirectory(provider),
        identity_context=provider.context,
    )
    assert Client.call_tool is original
    async with Client(endpoint):
        assert Client.call_tool is original


@pytest.mark.anyio
async def test_transport_scoped_forwarding_authenticates_exact_call(tmp_path):
    provider = HarnessProvider()
    token = provider.issue("planner-a", "planner")
    directory = HarnessDirectory(provider)
    endpoint = create_server(
        db_path=tmp_path / "mission.db",
        credential_provider=provider,
        principal_directory=directory,
        identity_context=provider.context,
    )
    async with Client(endpoint) as client:
        with bind_transport_credential(token):
            arguments = provider.prepare(token, "auftrag_list", {"caller_instance_id": "planner-a", "limit": 1, "offset": 0})
            result = await client.call_tool(
                "auftrag_list",
                arguments,
                raise_on_error=False,
            )
    assert payload(result)["status"] == "ok"
