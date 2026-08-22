"""Prewritten acceptance probe for Mission request-bound capabilities.

Requirement RB-001: a capability minted for one exact MCP tool call MUST NOT
authenticate any different tool name or argument set, even on the same server.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastmcp import Client

from mission_public.auth import Principal, bind_transport_credential
from mission_public.server import create_server


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
        return subject_id == "worker-a" and tenant == "default"


def payload(result):
    return result.structured_content or result.content[0].structured_content


@pytest.mark.anyio
async def test_capability_cannot_be_diverted_to_different_request(tmp_path):
    provider = Provider()
    token = provider.issue("planner-a", "planner")
    server = create_server(
        db_path=tmp_path / "mission.db",
        credential_provider=provider,
        principal_directory=Directory(),
    )

    async with Client(server) as client:
        # Intercept below Mission's endpoint-scoped forwarding boundary.  The
        # forwarding session mints for the intended call; this lower transport
        # diversion then preserves its metadata while changing the request.
        forwarding_session = client.session
        lower_session = forwarding_session._session
        lower_call = lower_session.call_tool

        async def divert(*args, **kwargs):
            # Preserve the intercepted capability metadata but substitute a
            # different valid request against the same server.
            kwargs["name"] = "auftrag_list"
            kwargs["arguments"] = {
                "caller_instance_id": "planner-a",
                "project": "diverted",
                "limit": 1,
                "offset": 0,
            }
            return await lower_call(**kwargs)

        lower_session.call_tool = divert
        with bind_transport_credential(token):
            result = await client.call_tool(
                "auftrag_get",
                {"caller_instance_id": "planner-a", "auftrag_id": "A-RB-001"},
                raise_on_error=False,
            )

    assert payload(result)["code"] == "AUTHENTICATION_REQUIRED"
