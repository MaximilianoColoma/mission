"""IDU-001..006 preimplementation acceptance tests for the request verifier."""
from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from mission_public.identity import IdentityError, MemoryReplayStore, VerificationContext, _canonical, sign_envelope, verify_envelope


def pub(private):
    return private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def fixture(now=2_000_000_000):
    principal, owner = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    profile_hash = hashlib.sha256(b"profile-v1").hexdigest()
    conditions = json.dumps({
        "capabilities": ["tool_log_record"], "expires_at": now + 120,
        "not_before": now - 1, "principal_pubkey": pub(principal),
        "profile_id": "hermes-handwerker", "profile_version_sha256": profile_hash,
        "tenant_id": "tenant-server", "runtime_generation": "11111111-1111-4111-8111-111111111111"
    }, sort_keys=True, separators=(",", ":"))
    attestation = {"conditions": conditions, "signature": owner.sign(b"witness-mission:agent-auth:v1:owner-attestation:" + conditions.encode()).hex()}
    payload = {"content": "proof", "request_id": "r-1"}
    envelope = {
        "version": "1.0", "principal_pubkey": pub(principal), "owner_pubkey": pub(owner),
        "owner_attestation": attestation, "profile_id": "hermes-handwerker",
        "profile_version_sha256": profile_hash, "tenant_id": "tenant-server",
        "runtime_generation": "11111111-1111-4111-8111-111111111111", "tool_name": "tool_log_record",
        "payload_sha256": hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()).hexdigest(),
        "nonce": "22222222-2222-4222-8222-222222222222", "issued_at": now - 1, "expires_at": now + 60,
    }
    envelope = sign_envelope(envelope, principal)
    context = VerificationContext(
        tenant_id="tenant-server", profile_hashes={"hermes-handwerker": profile_hash},
        active_runtime_generations=frozenset({"11111111-1111-4111-8111-111111111111"}),
        replay_store=MemoryReplayStore(), now=lambda: now,
    )
    return envelope, payload, context, principal


def test_valid_signature_binding_and_atomic_first_use():
    envelope, payload, context, _ = fixture()
    verified = verify_envelope(envelope, "tool_log_record", payload, context)
    assert verified.principal_pubkey == envelope["principal_pubkey"]
    assert verified.owner_pubkey == envelope["owner_pubkey"]
    with pytest.raises(IdentityError, match="REPLAY_DETECTED"):
        verify_envelope(envelope, "tool_log_record", payload, context)


def test_bad_crypto_never_consumes_nonce():
    envelope, payload, context, principal = fixture()
    bad = dict(envelope); bad["signature"] = "00" * 64
    with pytest.raises(IdentityError, match="AUTHENTICATION_REQUIRED"):
        verify_envelope(bad, "tool_log_record", payload, context)
    verify_envelope(sign_envelope({k: v for k, v in envelope.items() if k != "signature"}, principal), "tool_log_record", payload, context)


@pytest.mark.parametrize("mutation,code", [
    (lambda e: e.update(tenant_id="caller-selected"), "TENANT_MISMATCH"),
    (lambda e: e.update(tool_name="tool_log_decision"), "REQUEST_BINDING_MISMATCH"),
    (lambda e: e.update(payload_sha256="00" * 32), "REQUEST_BINDING_MISMATCH"),
    (lambda e: e.update(profile_version_sha256="00" * 32), "PROFILE_BINDING_MISMATCH"),
    (lambda e: e.update(runtime_generation="33333333-3333-4333-8333-333333333333"), "REVOKED_IDENTITY"),
])
def test_binding_failures_are_specific_and_preclaim(mutation, code):
    envelope, payload, context, principal = fixture()
    unsigned = {k: v for k, v in envelope.items() if k != "signature"}; mutation(unsigned)
    altered = sign_envelope(unsigned, principal)
    with pytest.raises(IdentityError, match=code):
        verify_envelope(altered, "tool_log_record", payload, context)
    verify_envelope(envelope, "tool_log_record", payload, context)


def test_replay_store_failure_denies():
    envelope, payload, context, _ = fixture()
    class Broken:
        def claim(self, key, expires_at): raise OSError("down")
    with pytest.raises(IdentityError, match="REPLAY_DETECTED"):
        verify_envelope(envelope, "tool_log_record", payload, replace(context, replay_store=Broken()))


def test_identity_canonicalization_is_finite_rfc8785_numeric():
    assert _canonical({"n": 1e-6}) == b'{"n":0.000001}'
    assert _canonical({"n": 1e21}) == b'{"n":1e+21}'
    assert _canonical({"n": -0.0}) == b'{"n":0}'
    with pytest.raises(IdentityError, match="INVALID_INPUT"):
        _canonical({"n": float("nan")})
