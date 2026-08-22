"""GHR-003 adversarial runtime acceptance: process-shared replay and revocation."""
from __future__ import annotations

import hashlib
import json
import multiprocessing as mp
import time
from dataclasses import replace
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from mission_public.identity import (
    IdentityError,
    SQLiteReplayStore,
    VerificationContext,
    sign_envelope,
    verify_envelope,
)


def _pub(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def _fixture(*, nonce: str | None = None, tenant: str = "tenant-a", generation: str | None = None):
    now = int(time.time())
    principal = Ed25519PrivateKey.generate()
    owner = Ed25519PrivateKey.generate()
    profile_hash = hashlib.sha256(b"profile-v1").hexdigest()
    generation = generation or str(uuid4())
    payload = {"caller_instance_id": _pub(principal), "limit": 1, "offset": 0}
    conditions = json.dumps(
        {
            "capabilities": ["tool_log_search"],
            "expires_at": now + 120,
            "not_before": now - 1,
            "principal_pubkey": _pub(principal),
            "profile_id": "profile-a",
            "profile_version_sha256": profile_hash,
            "tenant_id": tenant,
            "runtime_generation": generation,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    attestation = {
        "conditions": conditions,
        "signature": owner.sign(
            b"witness-mission:agent-auth:v1:owner-attestation:" + conditions.encode()
        ).hex(),
    }
    envelope = sign_envelope(
        {
            "version": "1.0",
            "principal_pubkey": _pub(principal),
            "owner_pubkey": _pub(owner),
            "owner_attestation": attestation,
            "profile_id": "profile-a",
            "profile_version_sha256": profile_hash,
            "tenant_id": tenant,
            "runtime_generation": generation,
            "tool_name": "tool_log_search",
            "payload_sha256": hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "nonce": nonce or str(uuid4()),
            "issued_at": now - 1,
            "expires_at": now + 60,
        },
        principal,
    )
    return envelope, payload, profile_hash, generation


def _process_verify(db_path: str, envelope: dict, payload: dict, profile_hash: str, generation: str, start, queue):
    start.wait()
    context = VerificationContext(
        tenant_id="tenant-a",
        profile_hashes={"profile-a": profile_hash},
        active_runtime_generations=frozenset({generation}),
        replay_store=SQLiteReplayStore(db_path),
    )
    try:
        verify_envelope(envelope, "tool_log_search", payload, context)
        queue.put("OK")
    except IdentityError as exc:
        queue.put(exc.code)


def test_same_envelope_has_exactly_one_winner_across_processes(tmp_path):
    envelope, payload, profile_hash, generation = _fixture()
    ctx = mp.get_context("spawn")
    start = ctx.Event()
    queue = ctx.Queue()
    processes = [
        ctx.Process(
            target=_process_verify,
            args=(str(tmp_path / "replay.db"), envelope, payload, profile_hash, generation, start, queue),
        )
        for _ in range(8)
    ]
    for process in processes:
        process.start()
    start.set()
    results = [queue.get(timeout=20) for _ in processes]
    for process in processes:
        process.join(20)
        assert process.exitcode == 0
    assert results.count("OK") == 1
    assert results.count("REPLAY_DETECTED") == 7


def test_replay_persists_across_fresh_store_instances(tmp_path):
    envelope, payload, profile_hash, generation = _fixture()
    def context():
        return VerificationContext("tenant-a", {"profile-a": profile_hash}, frozenset({generation}), SQLiteReplayStore(str(tmp_path / "replay.db")))
    verify_envelope(envelope, "tool_log_search", payload, context())
    with pytest.raises(IdentityError, match="REPLAY_DETECTED"):
        verify_envelope(envelope, "tool_log_search", payload, context())


def test_same_nonce_is_namespaced_by_principal(tmp_path):
    nonce = str(uuid4())
    first = _fixture(nonce=nonce)
    second = _fixture(nonce=nonce)
    store = SQLiteReplayStore(str(tmp_path / "replay.db"))
    for envelope, payload, profile_hash, generation in (first, second):
        context = VerificationContext("tenant-a", {"profile-a": profile_hash}, frozenset({generation}), store)
        verify_envelope(envelope, "tool_log_search", payload, context)


@pytest.mark.parametrize("kind", ["owner", "principal", "profile", "runtime_generation", "attestation"])
def test_every_declared_revocation_class_denies(kind, tmp_path):
    envelope, payload, profile_hash, generation = _fixture()
    value = {
        "owner": envelope["owner_pubkey"],
        "principal": envelope["principal_pubkey"],
        "profile": profile_hash,
        "runtime_generation": generation,
        "attestation": hashlib.sha256(envelope["owner_attestation"]["conditions"].encode()).hexdigest(),
    }[kind]
    context = VerificationContext(
        "tenant-a", {"profile-a": profile_hash}, frozenset({generation}),
        SQLiteReplayStore(str(tmp_path / "replay.db")), revoked=frozenset({(kind, value)}),
    )
    with pytest.raises(IdentityError, match="REVOKED_IDENTITY"):
        verify_envelope(envelope, "tool_log_search", payload, context)


def test_tenant_stale_profile_and_replaced_runtime_fail_before_nonce_claim(tmp_path):
    envelope, payload, profile_hash, generation = _fixture()
    store = SQLiteReplayStore(str(tmp_path / "replay.db"))
    cases = (
        (VerificationContext("tenant-b", {"profile-a": profile_hash}, frozenset({generation}), store), "TENANT_MISMATCH"),
        (VerificationContext("tenant-a", {"profile-a": "0" * 64}, frozenset({generation}), store), "PROFILE_BINDING_MISMATCH"),
        (VerificationContext("tenant-a", {"profile-a": profile_hash}, frozenset({str(uuid4())}), store), "REVOKED_IDENTITY"),
    )
    for context, code in cases:
        with pytest.raises(IdentityError, match=code):
            verify_envelope(envelope, "tool_log_search", payload, context)
    valid = VerificationContext("tenant-a", {"profile-a": profile_hash}, frozenset({generation}), store)
    verify_envelope(envelope, "tool_log_search", payload, valid)
