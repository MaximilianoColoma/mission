"""Renewal-safe cryptographic request-envelope verifier.

Production callers must supply a process-shared ReplayStore (for example
SQLiteReplayStore). MemoryReplayStore exists only for isolated unit tests.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
import sqlite3
from threading import Lock
import time
from typing import Any, Callable, Mapping, Protocol
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import CanonicalizationError, canonicalize

_DOMAIN = b"witness-mission:agent-auth:v1:"
_KEYS = frozenset({"version", "principal_pubkey", "owner_pubkey", "owner_attestation", "profile_id", "profile_version_sha256", "tenant_id", "runtime_generation", "tool_name", "payload_sha256", "nonce", "issued_at", "expires_at", "signature"})
_CONDITION_KEYS = frozenset({"capabilities", "expires_at", "not_before", "principal_pubkey", "profile_id", "profile_version_sha256", "tenant_id", "runtime_generation"})
_HEX32 = re.compile(r"^[0-9a-f]{64}$")
_HEX64 = re.compile(r"^[0-9a-f]{128}$")
_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class IdentityError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class ReplayStore(Protocol):
    def claim(self, key: tuple[str, str, str], expires_at: int) -> bool: ...


class MemoryReplayStore:
    """Thread-safe test store; deliberately not accepted as a production default."""
    def __init__(self) -> None:
        self._lock = Lock(); self._claims: dict[tuple[str, str, str], int] = {}

    def claim(self, key: tuple[str, str, str], expires_at: int) -> bool:
        with self._lock:
            if key in self._claims:
                return False
            self._claims[key] = expires_at
            return True


class SQLiteReplayStore:
    """Atomic shared first-use store suitable for workers sharing one database."""
    def __init__(self, path: str) -> None:
        self.path = path
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS identity_nonce_claims (tenant_id TEXT NOT NULL, principal_pubkey TEXT NOT NULL, nonce TEXT NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY(tenant_id,principal_pubkey,nonce))")

    def claim(self, key: tuple[str, str, str], expires_at: int) -> bool:
        try:
            with sqlite3.connect(self.path, timeout=10) as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("DELETE FROM identity_nonce_claims WHERE expires_at < ?", (int(time.time()),))
                cursor = db.execute("INSERT OR IGNORE INTO identity_nonce_claims VALUES (?,?,?,?)", (*key, expires_at))
                db.commit()
                return cursor.rowcount == 1
        except sqlite3.Error as exc:
            raise OSError("replay store unavailable") from exc


@dataclass(frozen=True)
class VerificationContext:
    tenant_id: str
    profile_hashes: Mapping[str, str]
    active_runtime_generations: frozenset[str]
    replay_store: ReplayStore
    revoked: frozenset[tuple[str, str]] = frozenset()
    now: Callable[[], int] = lambda: int(time.time())
    max_lifetime_seconds: int = 300
    clock_skew_seconds: int = 30


@dataclass(frozen=True)
class VerifiedIdentity:
    principal_pubkey: str
    owner_pubkey: str
    profile_id: str
    profile_version_sha256: str
    tenant_id: str
    runtime_generation: str
    nonce: str
    issued_at: int
    expires_at: int
    payload_sha256: str


def _canonical(value: Any) -> bytes:
    try:
        return canonicalize(value)
    except (CanonicalizationError, TypeError, ValueError, UnicodeError) as exc:
        raise IdentityError("INVALID_INPUT") from exc


def _uuid(value: Any, code: str) -> str:
    if not isinstance(value, str): raise IdentityError(code)
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise IdentityError(code) from exc
    if str(parsed) != value or parsed.version != 4: raise IdentityError(code)
    return value


def _signature_bytes(envelope: Mapping[str, Any]) -> bytes:
    unsigned = {key: value for key, value in envelope.items() if key != "signature"}
    return _DOMAIN + b"request-envelope:" + _canonical(unsigned)


def sign_envelope(envelope: Mapping[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
    result = dict(envelope)
    result["signature"] = private_key.sign(_signature_bytes(result)).hex()
    return result


def verify_envelope(envelope: Any, tool_name: str, payload: Any, context: VerificationContext) -> VerifiedIdentity:
    if not isinstance(envelope, dict) or set(envelope) != _KEYS or envelope.get("version") != "1.0":
        raise IdentityError("INVALID_INPUT")
    principal = envelope.get("principal_pubkey"); owner = envelope.get("owner_pubkey"); signature = envelope.get("signature")
    if not isinstance(principal, str) or not _HEX32.fullmatch(principal) or not isinstance(owner, str) or not _HEX32.fullmatch(owner) or not isinstance(signature, str) or not _HEX64.fullmatch(signature):
        raise IdentityError("AUTHENTICATION_REQUIRED")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(principal)).verify(bytes.fromhex(signature), _signature_bytes(envelope))
    except (ValueError, InvalidSignature) as exc:
        raise IdentityError("AUTHENTICATION_REQUIRED") from exc

    tenant = envelope.get("tenant_id")
    if not isinstance(tenant, str) or not _ID.fullmatch(tenant) or tenant != context.tenant_id:
        raise IdentityError("TENANT_MISMATCH")
    if envelope.get("tool_name") != tool_name or envelope.get("payload_sha256") != hashlib.sha256(_canonical(payload)).hexdigest():
        raise IdentityError("REQUEST_BINDING_MISMATCH")
    profile_id = envelope.get("profile_id"); profile_hash = envelope.get("profile_version_sha256")
    if not isinstance(profile_id, str) or not _ID.fullmatch(profile_id) or not isinstance(profile_hash, str) or not _HEX32.fullmatch(profile_hash) or context.profile_hashes.get(profile_id) != profile_hash:
        raise IdentityError("PROFILE_BINDING_MISMATCH")
    generation = _uuid(envelope.get("runtime_generation"), "REVOKED_IDENTITY")
    if generation not in context.active_runtime_generations:
        raise IdentityError("REVOKED_IDENTITY")
    nonce = _uuid(envelope.get("nonce"), "REPLAY_DETECTED")
    issued = envelope.get("issued_at"); expires = envelope.get("expires_at"); now = context.now()
    if isinstance(issued, bool) or not isinstance(issued, int) or isinstance(expires, bool) or not isinstance(expires, int) or issued > now + context.clock_skew_seconds or expires <= now or expires <= issued or expires - issued > context.max_lifetime_seconds:
        raise IdentityError("AUTHENTICATION_REQUIRED")

    attestation = envelope.get("owner_attestation")
    if not isinstance(attestation, dict) or set(attestation) != {"conditions", "signature"} or not isinstance(attestation.get("conditions"), str) or len(attestation["conditions"].encode()) > 2000 or not isinstance(attestation.get("signature"), str) or not _HEX64.fullmatch(attestation["signature"]):
        raise IdentityError("AUTHENTICATION_REQUIRED")
    try:
        conditions = json.loads(attestation["conditions"])
        if not isinstance(conditions, dict) or set(conditions) != _CONDITION_KEYS or _canonical(conditions).decode() != attestation["conditions"]:
            raise ValueError("conditions")
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(owner)).verify(bytes.fromhex(attestation["signature"]), _DOMAIN + b"owner-attestation:" + attestation["conditions"].encode())
    except (ValueError, json.JSONDecodeError, InvalidSignature) as exc:
        raise IdentityError("AUTHENTICATION_REQUIRED") from exc
    expected = {"principal_pubkey": principal, "profile_id": profile_id, "profile_version_sha256": profile_hash, "tenant_id": tenant, "runtime_generation": generation}
    if any(conditions.get(key) != value for key, value in expected.items()) or not isinstance(conditions.get("capabilities"), list) or tool_name not in conditions["capabilities"] or conditions.get("not_before", now + 1) > now or conditions.get("expires_at", 0) <= now:
        raise IdentityError("AUTHENTICATION_REQUIRED")
    for kind, value in (("owner", owner), ("principal", principal), ("profile", profile_hash), ("runtime_generation", generation), ("attestation", hashlib.sha256(attestation["conditions"].encode()).hexdigest())):
        if (kind, value) in context.revoked:
            raise IdentityError("REVOKED_IDENTITY")
    try:
        claimed = context.replay_store.claim((tenant, principal, nonce), expires)
    except Exception as exc:
        raise IdentityError("REPLAY_DETECTED") from exc
    if not claimed:
        raise IdentityError("REPLAY_DETECTED")
    return VerifiedIdentity(principal, owner, profile_id, profile_hash, tenant, generation, nonce, issued, expires, envelope["payload_sha256"])
