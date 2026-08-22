"""GHR-002 preimplementation RED for Mission assignment/lifecycle identity binding."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastmcp import Client

from mission_public.auth import Principal, bind_transport_credential
from mission_public.identity import SQLiteReplayStore, VerificationContext, sign_envelope
from mission_public.server import create_server


def pub(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


class Provider:
    issuer = "test-issuer"
    audience = "mission"
    def __init__(self):
        self.records = {}
    def issue(self, key, role):
        token = f"token-{len(self.records)}"
        now = datetime.now(timezone.utc)
        self.records[token] = Principal(pub(key), f"{role}-client", role, "synthetic_test_provider", token, self.issuer, self.audience, now-timedelta(seconds=1), now+timedelta(hours=1), "active")
        return token
    def resolve(self, raw): return self.records.get(raw)


class Directory:
    def __init__(self, bindings): self.bindings = bindings
    def eligible(self, subject_id, tenant="default"):
        return subject_id in self.bindings and tenant == "default"
    def identity_binding(self, subject_id, tenant="default"):
        return self.bindings.get(subject_id) if tenant == "default" else None


def make_context(tmp_path, profile_hash, generations, now):
    return VerificationContext(
        tenant_id="mission-test-tenant",
        profile_hashes={"mission-worker": profile_hash, "mission-planner": profile_hash},
        active_runtime_generations=frozenset(generations),
        replay_store=SQLiteReplayStore(str(tmp_path / "replay.db")),
        now=lambda: now,
    )


def envelope(key, owner, tool, payload, role_profile, generation, profile_hash, now):
    conditions = json.dumps({
        "capabilities": [tool], "expires_at": now+120, "not_before": now-1,
        "principal_pubkey": pub(key), "profile_id": role_profile,
        "profile_version_sha256": profile_hash, "tenant_id": "mission-test-tenant",
        "runtime_generation": generation,
    }, sort_keys=True, separators=(",", ":"))
    attestation = {"conditions": conditions, "signature": owner.sign(b"witness-mission:agent-auth:v1:owner-attestation:"+conditions.encode()).hex()}
    unsigned = {
        "version":"1.0", "principal_pubkey":pub(key), "owner_pubkey":pub(owner),
        "owner_attestation":attestation, "profile_id":role_profile,
        "profile_version_sha256":profile_hash, "tenant_id":"mission-test-tenant",
        "runtime_generation":generation, "tool_name":tool,
        "payload_sha256":hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()).hexdigest(),
        "nonce":str(uuid4()), "issued_at":now-1, "expires_at":now+60,
    }
    return sign_envelope(unsigned,key)


def result_body(result): return json.loads(result.content[0].text)


async def signed_call(client, token, key, owner, tool, payload, profile, generation, profile_hash, now):
    args = {**payload, "identity_envelope": envelope(key,owner,tool,payload,profile,generation,profile_hash,now)}
    with bind_transport_credential(token):
        return result_body(await client.call_tool(tool,args,raise_on_error=False))


@pytest.mark.anyio
async def test_assignment_and_every_transition_bind_to_verified_instance(tmp_path):
    now = int(time.time())
    owner = Ed25519PrivateKey.generate(); planner = Ed25519PrivateKey.generate(); worker = Ed25519PrivateKey.generate(); foreign = Ed25519PrivateKey.generate()
    planner_gen="11111111-1111-4111-8111-111111111111"; worker_gen="22222222-2222-4222-8222-222222222222"; foreign_gen="33333333-3333-4333-8333-333333333333"
    profile_hash=hashlib.sha256(b"mission-profile-v1").hexdigest()
    provider=Provider(); planner_token=provider.issue(planner,"planner"); worker_token=provider.issue(worker,"worker"); foreign_token=provider.issue(foreign,"worker")
    bindings={
        pub(worker): {"principal_pubkey":pub(worker),"owner_pubkey":pub(owner),"profile_id":"mission-worker","profile_version_sha256":profile_hash,"tenant_id":"mission-test-tenant","runtime_generation":worker_gen},
        pub(foreign): {"principal_pubkey":pub(foreign),"owner_pubkey":pub(owner),"profile_id":"mission-worker","profile_version_sha256":profile_hash,"tenant_id":"mission-test-tenant","runtime_generation":foreign_gen},
    }
    directory=Directory(bindings)
    context=make_context(tmp_path,profile_hash,{planner_gen,worker_gen,foreign_gen},now)
    db_path=tmp_path/"mission.db"
    server=create_server(db_path=db_path,credential_provider=provider,principal_directory=directory,identity_context=context,adapters_enabled=False)
    create={"caller_instance_id":pub(planner),"id":"A-ID-001","title":"Identity","project":"demo","steps":json.dumps([{"id":"S1","name":"Prove"}]),"exit_kpis":json.dumps({"required":[]}),"request_id":"create"}
    assign={"caller_instance_id":pub(planner),"auftrag_id":"A-ID-001","assigned_to":pub(worker),"request_id":"assign"}
    start={"caller_instance_id":pub(worker),"auftrag_id":"A-ID-001","request_id":"start"}
    async with Client(server) as client:
        created = await signed_call(client,planner_token,planner,owner,"auftrag_create",create,"mission-planner",planner_gen,profile_hash,now)
        assert created["status"]=="ok", created
        assert (await signed_call(client,planner_token,planner,owner,"auftrag_assign",assign,"mission-planner",planner_gen,profile_hash,now))["status"]=="ok"
        denied=await signed_call(client,foreign_token,foreign,owner,"auftrag_start",{**start,"caller_instance_id":pub(foreign)},"mission-worker",foreign_gen,profile_hash,now)
        started=await signed_call(client,worker_token,worker,owner,"auftrag_start",start,"mission-worker",worker_gen,profile_hash,now)
    assert denied["code"]=="NOT_FOUND"
    assert started["next_state"]=="active"
    with sqlite3.connect(db_path) as db:
        binding=db.execute("SELECT principal_pubkey,profile_id,profile_version_sha256,runtime_generation FROM auftrag_identity_bindings WHERE auftrag_id='A-ID-001' AND relation='assignee'").fetchone()
        audit=db.execute("SELECT i.principal_pubkey,i.owner_pubkey,i.profile_id,i.profile_version_sha256,i.tenant_id,i.runtime_generation FROM changelog c JOIN identity_audit i USING(event_id) WHERE c.action='start'").fetchone()
    assert binding==(pub(worker),"mission-worker",profile_hash,worker_gen)
    assert audit==(pub(worker),pub(owner),"mission-worker",profile_hash,"mission-test-tenant",worker_gen)


@pytest.mark.anyio
async def test_replaced_or_revoked_runtime_cannot_continue_lifecycle(tmp_path):
    now=int(time.time()); owner=Ed25519PrivateKey.generate(); worker=Ed25519PrivateKey.generate(); profile_hash=hashlib.sha256(b"mission-profile-v1").hexdigest(); generation="44444444-4444-4444-8444-444444444444"
    provider=Provider(); token=provider.issue(worker,"worker")
    directory=Directory({pub(worker):{"principal_pubkey":pub(worker),"owner_pubkey":pub(owner),"profile_id":"mission-worker","profile_version_sha256":profile_hash,"tenant_id":"mission-test-tenant","runtime_generation":generation}})
    context=make_context(tmp_path,profile_hash,set(),now)
    server=create_server(db_path=tmp_path/"mission.db",credential_provider=provider,principal_directory=directory,identity_context=context,adapters_enabled=False)
    payload={"caller_instance_id":pub(worker),"auftrag_id":"SECRET-ID","request_id":"revoked-start"}
    async with Client(server) as client:
        denied=await signed_call(client,token,worker,owner,"auftrag_start",payload,"mission-worker",generation,profile_hash,now)
    assert denied["code"]=="REVOKED_IDENTITY"
