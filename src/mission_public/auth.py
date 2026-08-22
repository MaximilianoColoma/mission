"""Provider-bound, request-scoped authentication for Mission MCP calls."""

from __future__ import annotations

from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator
import hashlib
import json
import secrets
import threading
import unicodedata
import weakref

from fastmcp.client.transports.memory import FastMCPTransport
from typing_extensions import Unpack
from fastmcp.client.transports.base import SessionKwargs


@dataclass(frozen=True)
class Principal:
    subject_id: str
    client_id: str
    role: str
    credential_type: str
    credential_id: str
    issuer: str
    audience: str
    issued_at: datetime
    expires_at: datetime
    revocation_status: str


# ContextVar state is copied into each asyncio task.  There is deliberately no
# process-global credential fallback: a dispatch that loses request context
# must fail closed rather than borrowing another request's authority.
_transport_credential: ContextVar[str | None] = ContextVar(
    "mission_transport_credential", default=None
)
# Request metadata carries a server-issued capability reference only.  Raw
# credential material is never placed in caller-controlled metadata, so the
# previous metadata key is now simply an unknown field with no authority.
_META_KEY = "mission.transport_capability"
_CAPABILITY_BYTES = 32
_ACCEPTED_CREDENTIAL_TYPES = frozenset(
    {"oauth_bearer", "api_key_provider", "synthetic_test_provider"}
)
_lock = threading.Lock()
# Private per-target registry: server identity -> {capability: (bound raw
# credential, exact request fingerprint)}.  The mapping is created by this build for its own servers, keyed
# by the server object itself, so a capability minted for one server is
# meaningless at any other, and an entry exists only for the single in-flight
# call that minted it.
_CAPABILITIES: "weakref.WeakKeyDictionary[Any, dict[str, tuple[str, bytes]]]" = weakref.WeakKeyDictionary()


def register_transport_target(server: Any) -> None:
    """Give this in-process server its own capability registry."""
    try:
        with _lock:
            _CAPABILITIES.setdefault(server, {})
    except TypeError:
        return



def _registry(server: Any) -> dict[str, tuple[str, bytes]] | None:
    try:
        return _CAPABILITIES.get(server)
    except TypeError:
        return None


def _request_fingerprint(name: Any, arguments: Any) -> bytes:
    """Bind authority to the exact JSON tool request, not only its server."""
    if not isinstance(name, str) or not isinstance(arguments, dict):
        raise ValueError("invalid request binding")
    encoded = json.dumps(
        {"name": name, "arguments": arguments},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).digest()


def _issue_capability(server: Any, raw: str, name: Any, arguments: Any) -> str | None:
    """Mint a one-time capability for one exact request at one known server."""
    try:
        fingerprint = _request_fingerprint(name, arguments)
    except (TypeError, ValueError):
        return None
    capability = secrets.token_urlsafe(_CAPABILITY_BYTES)
    with _lock:
        registry = _registry(server)
        if registry is None:
            return None
        registry[capability] = (raw, fingerprint)
    return capability


def _revoke_capability(server: Any, capability: str) -> None:
    with _lock:
        registry = _registry(server)
        if registry is not None:
            registry.pop(capability, None)


def _consume_capability(server: Any, capability: Any, name: Any, arguments: Any) -> str | None:
    """Redeem once and only for the exact request for which it was minted."""
    if not isinstance(capability, str) or not capability:
        return None
    try:
        actual_fingerprint = _request_fingerprint(name, arguments)
    except (TypeError, ValueError):
        return None
    with _lock:
        registry = _registry(server)
        # Pop before comparison: diversion also burns the capability, so neither
        # the diverted nor the later intended request can reuse its authority.
        binding = registry.pop(capability, None) if registry is not None else None
    if binding is None:
        return None
    raw, expected_fingerprint = binding
    return raw if secrets.compare_digest(expected_fingerprint, actual_fingerprint) else None


class _CapabilityForwardingSession:
    """Delegate one client session while containing auth to this endpoint."""

    def __init__(self, session: Any, target: Any) -> None:
        self._session = session
        self._target = target

    def __getattr__(self, name: str) -> Any:
        return getattr(self._session, name)

    async def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None, **kwargs: Any
    ) -> Any:
        raw = _transport_credential.get()
        capability = (
            _issue_capability(self._target, raw, name, arguments or {}) if raw else None
        )
        if capability is None:
            return await self._session.call_tool(name, arguments, **kwargs)
        try:
            meta = dict(kwargs.get("meta") or {})
            meta[_META_KEY] = capability
            kwargs["meta"] = meta
            return await self._session.call_tool(name, arguments, **kwargs)
        finally:
            _revoke_capability(self._target, capability)


class MissionInMemoryTransport(FastMCPTransport):
    """FastMCP transport with endpoint-scoped synthetic auth forwarding.

    The wrapper is attached only to sessions created for this transport.  It
    never mutates FastMCP's process-wide Client class.
    """

    @asynccontextmanager
    async def connect_session(
        self, **session_kwargs: Unpack[SessionKwargs]
    ) -> Iterator[Any]:
        async with super().connect_session(**session_kwargs) as session:
            yield _CapabilityForwardingSession(session, self.server)


@contextmanager
def bind_transport_credential(raw_credential: str | None) -> Iterator[None]:
    """Bind one opaque credential to the current request/task context."""
    token = _transport_credential.set(raw_credential)
    try:
        yield
    finally:
        _transport_credential.reset(token)


def _capability_from_request_meta(meta: Any) -> str | None:
    """Read the capability reference of one MCP request; never a credential."""
    if hasattr(meta, "model_dump"):
        meta = meta.model_dump()
    if not isinstance(meta, dict):
        return None
    return meta.get(_META_KEY)


def credential_from_http_transport() -> str | None:
    """Read the bearer credential of the current HTTP request, if any."""
    try:
        from fastmcp.server.dependencies import get_http_headers

        header = get_http_headers(include={"authorization"}).get("authorization", "")
    except Exception:
        return None
    scheme, _, value = header.partition(" ")
    return value.strip() if scheme.lower() == "bearer" and value.strip() else None


def _in_http_request() -> bool:
    try:
        from fastmcp.server.dependencies import get_http_request

        return get_http_request() is not None
    except Exception:
        return False


def resolve_request_credential(server: Any, meta: Any, name: Any, arguments: Any) -> str | None:
    """Resolve the single credential authority for one dispatch.

    Over HTTP the ``Authorization`` header is the only authority and any
    metadata capability is ignored outright.  Over the in-memory synthetic
    transport the authority is whatever this server itself bound to the
    one-time capability it minted, never anything the caller supplied.
    """
    if _in_http_request():
        return credential_from_http_transport()
    return _consume_capability(
        server, _capability_from_request_meta(meta), name, arguments
    )


def _canonical_identifier(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("invalid principal")
    canonical = unicodedata.normalize("NFC", value)
    if not 1 <= len(canonical.encode("utf-8")) <= 128 or canonical != value:
        raise ValueError("invalid principal")
    return canonical


def authenticate(provider: Any) -> Principal:
    """Resolve and validate the current request credential; uncertainty denies."""
    raw = _transport_credential.get()
    if not isinstance(raw, str) or not raw:
        raise ValueError("authentication required")
    try:
        resolved = provider.resolve(raw)
        if isinstance(resolved, Principal):
            values = {name: getattr(resolved, name) for name in Principal.__dataclass_fields__}
        elif isinstance(resolved, dict):
            required = set(Principal.__dataclass_fields__)
            if set(resolved) != required:
                raise ValueError("invalid claims")
            values = dict(resolved)
        else:
            raise ValueError("invalid credential")
        for field in (
            "subject_id", "client_id", "role", "credential_type", "credential_id",
            "issuer", "audience", "revocation_status",
        ):
            values[field] = _canonical_identifier(values[field])
        principal = Principal(**values)
        now = datetime.now(timezone.utc)
        if principal.credential_type not in _ACCEPTED_CREDENTIAL_TYPES:
            raise ValueError("invalid credential type")
        if principal.role not in {"planner", "worker", "auditor", "admin"}:
            raise ValueError("invalid role")
        if principal.issuer != provider.issuer or principal.audience != provider.audience:
            raise ValueError("invalid authority")
        if not isinstance(principal.issued_at, datetime) or not isinstance(principal.expires_at, datetime):
            raise ValueError("invalid time")
        if principal.issued_at.tzinfo is None or principal.expires_at.tzinfo is None:
            raise ValueError("invalid time")
        issued = principal.issued_at.astimezone(timezone.utc)
        expires = principal.expires_at.astimezone(timezone.utc)
        if issued > now + timedelta(seconds=30) or expires <= now or expires <= issued:
            raise ValueError("invalid lifetime")
        if principal.revocation_status != "active":
            raise ValueError("inactive credential")
        return principal
    except Exception as exc:
        raise ValueError("authentication required") from exc


def assert_caller(principal: Principal, asserted: Any) -> None:
    """Treat caller_instance_id only as an exact canonical assertion."""
    try:
        caller = _canonical_identifier(asserted)
    except ValueError as exc:
        raise PermissionError("identity mismatch") from exc
    if caller != principal.subject_id:
        raise PermissionError("identity mismatch")
