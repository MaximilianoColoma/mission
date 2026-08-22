"""Preimplementation acceptance probe for Mission credential types.

MIS-CREDENTIAL-TYPE-REQ-001/002: authentication accepts exactly the credential
kinds declared in the frozen public contract and denies undeclared kinds.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from mission_public.auth import Principal, authenticate, bind_transport_credential


class Provider:
    issuer = "https://issuer.synthetic.invalid"
    audience = "mission-public"

    def __init__(self, credential_type: str):
        now = datetime.now(timezone.utc)
        self.principal = Principal(
            subject_id="subject-1",
            client_id="client-1",
            role="worker",
            credential_type=credential_type,
            credential_id="credential-1",
            issuer=self.issuer,
            audience=self.audience,
            issued_at=now - timedelta(seconds=1),
            expires_at=now + timedelta(hours=1),
            revocation_status="active",
        )

    def resolve(self, raw: str) -> Principal:
        assert raw == "opaque-test-credential"
        return replace(self.principal)


@pytest.mark.parametrize(
    "credential_type",
    ["oauth_bearer", "api_key_provider", "synthetic_test_provider"],
)
def test_declared_credential_types_remain_accepted(credential_type):
    with bind_transport_credential("opaque-test-credential"):
        principal = authenticate(Provider(credential_type))
    assert principal.credential_type == credential_type


def test_undeclared_credential_type_is_rejected():
    with bind_transport_credential("opaque-test-credential"):
        with pytest.raises(ValueError, match="authentication required"):
            authenticate(Provider("not_declared"))
