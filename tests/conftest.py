from __future__ import annotations
from datetime import datetime, timedelta, timezone
from dataclasses import asdict
import hashlib
import json
import time
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from mission_public.auth import Principal
from mission_public.identity import MemoryReplayStore, VerificationContext, sign_envelope
from mission_public.server import create_server

_TOKEN_PROVIDERS = {}


def _pub(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


class SyntheticCredentialProvider:
    issuer = "test-issuer"
    audience = "mission"
    def __init__(self):
        self.records={}; self.lookup_failure=False
        self._keys={}; self._generations={}; self._logical={}
        self._owner=Ed25519PrivateKey.generate()
        self._profile_hash=hashlib.sha256(b"mission-synthetic-profile-v1").hexdigest()
        self._replay=MemoryReplayStore()

    def ensure_identity(self, logical):
        if logical not in self._keys:
            self._keys[logical]=Ed25519PrivateKey.generate(); self._generations[logical]=str(uuid4())
        return _pub(self._keys[logical])

    def binding(self, logical):
        principal=self.ensure_identity(logical)
        return {"principal_pubkey":principal,"owner_pubkey":_pub(self._owner),"profile_id":"mission-synthetic","profile_version_sha256":self._profile_hash,"tenant_id":"mission-test-tenant","runtime_generation":self._generations[logical]}

    def context(self):
        return VerificationContext(tenant_id="mission-test-tenant",profile_hashes={"mission-synthetic":self._profile_hash},active_runtime_generations=frozenset(self._generations.values()),replay_store=self._replay,now=lambda:int(time.time()))

    def issue(self,subject_id,role,expires_delta=3600,issued_offset=0,revocation_status="active",issuer=None,audience=None,drop_field=None):
        now=datetime.now(timezone.utc); token=f"synthetic-{len(self.records)+1}"; principal=self.ensure_identity(subject_id)
        value=Principal(subject_id=principal,client_id=f"{role}-client",role=role,credential_type="synthetic_test_provider",credential_id=f"cred-{len(self.records)+1}",issuer=issuer or self.issuer,audience=audience or self.audience,issued_at=now+timedelta(seconds=issued_offset),expires_at=now+timedelta(seconds=expires_delta),revocation_status=revocation_status)
        if drop_field:
            value=asdict(value); value.pop(drop_field,None)
        self.records[token]=value; self._logical[token]=subject_id; _TOKEN_PROVIDERS[token]=self
        return token

    def resolve(self,raw_credential):
        if self.lookup_failure: raise RuntimeError("provider unavailable")
        return self.records.get(raw_credential)

    def revoke(self,token):
        p=self.records[token]; self.records[token]=Principal(**{**p.__dict__,"revocation_status":"revoked"})

    def principal_pubkey(self,token): return self.ensure_identity(self._logical[token])

    def prepare(self,token,tool,args):
        payload=dict(args); logical=self._logical[token]
        if payload.get("caller_instance_id")==logical: payload["caller_instance_id"]=self.principal_pubkey(token)
        for field in ("assigned_to","new_assigned_to"):
            if isinstance(payload.get(field),str) and payload[field]: payload[field]=self.ensure_identity(payload[field])
        now=int(time.time()); key=self._keys[logical]; binding=self.binding(logical)
        conditions=json.dumps({"capabilities":[tool],"expires_at":now+120,"not_before":now-1,"principal_pubkey":binding["principal_pubkey"],"profile_id":binding["profile_id"],"profile_version_sha256":binding["profile_version_sha256"],"tenant_id":binding["tenant_id"],"runtime_generation":binding["runtime_generation"]},sort_keys=True,separators=(",",":"))
        attestation={"conditions":conditions,"signature":self._owner.sign(b"witness-mission:agent-auth:v1:owner-attestation:"+conditions.encode()).hex()}
        try: payload_bytes=json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()
        except UnicodeEncodeError: payload_bytes=json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode()
        envelope={"version":"1.0","principal_pubkey":binding["principal_pubkey"],"owner_pubkey":binding["owner_pubkey"],"owner_attestation":attestation,"profile_id":binding["profile_id"],"profile_version_sha256":binding["profile_version_sha256"],"tenant_id":binding["tenant_id"],"runtime_generation":binding["runtime_generation"],"tool_name":tool,"payload_sha256":hashlib.sha256(payload_bytes).hexdigest(),"nonce":str(uuid4()),"issued_at":now-1,"expires_at":now+60}
        return {**payload,"identity_envelope":sign_envelope(envelope,key)}


def prepare_call(token, tool, args):
    return _TOKEN_PROVIDERS[token].prepare(token, tool, args)


class PrincipalDirectory:
    def __init__(self,provider): self.provider=provider; self.entries={}
    def add(self,subject_id,roles=("worker",),active=True,tenant="default"):
        principal=self.provider.ensure_identity(subject_id); self.entries[principal]={"roles":set(roles),"active":active,"tenant":tenant,"logical":subject_id}
    def eligible(self,subject_id,tenant="default"):
        e=self.entries.get(subject_id); return bool(e and e["active"] and e["tenant"]==tenant and ({"worker","admin"}&e["roles"]))
    def identity_binding(self,subject_id,tenant="default"):
        e=self.entries.get(subject_id)
        return self.provider.binding(e["logical"]) if e and e["active"] and e["tenant"]==tenant else None


class FaultInjector:
    def __init__(self,*stages): self.stages=set(stages)
    def __call__(self,stage):
        if stage in self.stages: raise RuntimeError(f"synthetic fault:{stage}")


@pytest.fixture
def provider(): return SyntheticCredentialProvider()
@pytest.fixture
def directory(provider):
    d=PrincipalDirectory(provider); d.add("worker-a"); d.add("worker-b"); d.add("admin-a",roles=("admin",)); return d
@pytest.fixture
def server(tmp_path,provider,directory): return create_server(db_path=tmp_path/"mission.db",credential_provider=provider,principal_directory=directory,identity_context=provider.context,adapters_enabled=False)
