"""Mission public-core lifecycle service."""

from __future__ import annotations

from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import json
import math
import re
import sqlite3
from typing import Any, Callable, Mapping
from uuid import uuid4

from .auth import Principal, assert_caller, authenticate
from .db import Database
from .identity import IdentityError, VerificationContext, VerifiedIdentity, verify_envelope
from .privacy import redact, redact_person_name_field, redact_text

_MAX_EXACT_INT = 2 ** 53 - 1
_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_REQUEST_ID = _ID
_PERIODS = {"1d": 1, "7d": 7, "30d": 30, "90d": 90}
_ROLES = {
    "auftrag_create": {"planner", "admin"},
    "auftrag_list": {"planner", "worker", "auditor", "admin"},
    "auftrag_get": {"planner", "worker", "auditor", "admin"},
    "auftrag_assign": {"planner", "admin"},
    "auftrag_reassign_replace": {"planner", "admin"},
    "auftrag_start": {"worker", "admin"},
    "auftrag_checkpoint": {"worker", "admin"},
    "auftrag_block": {"planner", "worker", "admin"},
    "auftrag_resume": {"planner", "worker", "admin"},
    "auftrag_close": {"worker", "admin"},
    "auftrag_cancel": {"planner", "admin"},
    "auftrag_get_changelog": {"planner", "worker", "auditor", "admin"},
    "get_instance_activity": {"planner", "worker", "auditor", "admin"},
}
_MUTATIONS = {
    "auftrag_create", "auftrag_assign", "auftrag_reassign_replace", "auftrag_start",
    "auftrag_checkpoint", "auftrag_block", "auftrag_resume", "auftrag_close", "auftrag_cancel",
}
_VERIFIED_IDENTITY: ContextVar[VerifiedIdentity | None] = ContextVar(
    "mission_verified_identity", default=None
)
_RAW_REQUEST_ARGS: ContextVar[dict[str, Any] | None] = ContextVar(
    "mission_raw_request_args", default=None
)


class ServiceError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _error(code: str, message: str, correlation_id: str | None = None) -> dict[str, Any]:
    return {"status": "error", "code": code, "correlation_id": correlation_id or str(uuid4()), "message": message}


def _ok(correlation_id: str, **values: Any) -> dict[str, Any]:
    return {"status": "ok", "correlation_id": correlation_id, **values}


def _json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ServiceError("INVALID_INPUT", "Invalid JSON value") from exc


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _loads(value: str, field: str) -> Any:
    try:
        return json.loads(
            value,
            object_pairs_hook=_pairs_no_duplicates,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite number")),
        )
    except (TypeError, json.JSONDecodeError, ValueError) as exc:
        raise ServiceError("INVALID_INPUT", f"Invalid {field}") from exc


def _parse_object(value: str | None, field: str, default: dict | None = None, maximum: int | None = None) -> dict:
    if value in (None, ""):
        parsed: Any = {} if default is None else default
    else:
        if not isinstance(value, str) or (maximum is not None and len(value) > maximum):
            raise ServiceError("INVALID_INPUT", f"Invalid {field}")
        parsed = _loads(value, field)
    if not isinstance(parsed, dict):
        raise ServiceError("INVALID_INPUT", f"Invalid {field}")
    _validate_finite(parsed, field)
    return parsed


def _validate_finite(value: Any, field: str) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ServiceError("INVALID_INPUT", f"Invalid {field}")
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ServiceError("INVALID_INPUT", f"Invalid {field}") from exc
    elif isinstance(value, list):
        for item in value:
            _validate_finite(item, field)
    elif isinstance(value, dict):
        for key, item in value.items():
            _validate_finite(key, field)
            _validate_finite(item, field)


def _jcs_number(value: int | float) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("not a number")
    if isinstance(value, int):
        # RFC8785 numbers are ECMAScript/IEEE-754 doubles.  A Python int beyond
        # the exact-integer domain has no faithful RFC8785 serialization, so it
        # is rejected rather than silently canonicalised to a different value.
        if abs(value) > _MAX_EXACT_INT:
            raise ValueError("integer outside the IEEE-754 exact domain")
        return str(value)
    if not math.isfinite(value):
        raise ValueError("non-finite number")
    if value == 0:
        return "0"
    negative = value < 0
    absolute = -value if negative else value
    text = repr(absolute)
    decimal = Decimal(text)
    if Decimal("1e-6") <= decimal < Decimal("1e21"):
        output = format(decimal, "f")
        if "." in output:
            output = output.rstrip("0").rstrip(".")
    else:
        normalized = format(decimal.normalize(), "e")
        mantissa, exponent = normalized.split("e")
        mantissa = mantissa.rstrip("0").rstrip(".")
        exponent_number = int(exponent)
        output = f"{mantissa}e{'+' if exponent_number >= 0 else ''}{exponent_number}"
    return "-" + output if negative else output


def _jcs(value: Any) -> str:
    """Strict RFC8785-equivalent canonical JSON for validated JSON-domain values."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return _jcs_number(value)
    if isinstance(value, str):
        _validate_finite(value, "payload")
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(_jcs(item) for item in value) + "]"
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        keys = sorted(value, key=lambda key: key.encode("utf-16-be"))
        return "{" + ",".join(_jcs(key) + ":" + _jcs(value[key]) for key in keys) + "}"
    raise ValueError("value is outside the JSON domain")


def _valid_id(value: Any, field: str = "id") -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ServiceError("INVALID_INPUT", f"Invalid {field}")
    return value


def _optional_id(value: Any, field: str) -> str:
    if value in (None, ""):
        return ""
    return _valid_id(value, field)


def _valid_request_id(value: Any) -> str:
    if not isinstance(value, str) or not _REQUEST_ID.fullmatch(value):
        raise ServiceError("INVALID_INPUT", "Invalid request_id")
    return value


def _raw_text(value: Any, field: str, maximum: int, required: bool = False) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str) or len(value) > maximum or (required and not value):
        raise ServiceError("INVALID_INPUT", f"Invalid {field}")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ServiceError("INVALID_INPUT", f"Invalid {field}") from exc
    return value


def _bounded_text(value: Any, field: str, maximum: int, required: bool = False) -> str:
    return redact_text(_raw_text(value, field, maximum, required))


def _bounded_int(value: Any, field: str, minimum: int, maximum: int, optional: bool = True) -> int | None:
    if value is None and optional:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ServiceError("INVALID_INPUT", f"Invalid {field}")
    return value


def _bounded_number(value: Any, field: str, minimum: float, maximum: float) -> int | float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not minimum <= value <= maximum:
        raise ServiceError("INVALID_INPUT", f"Invalid {field}")
    return value


def _parse_string_list(value: Any, field: str, maximum: int) -> list[str]:
    raw = _raw_text(value, field, maximum)
    if not raw:
        return []
    if raw.lstrip().startswith("["):
        parsed = _loads(raw, field)
        if not isinstance(parsed, list) or any(not isinstance(item, str) for item in parsed):
            raise ServiceError("INVALID_INPUT", f"Invalid {field}")
        items = [item.strip() for item in parsed]
    else:
        items = [item.strip() for item in raw.split(",")]
    if any(not item for item in items) or len(set(items)) != len(items):
        raise ServiceError("INVALID_INPUT", f"Invalid {field}")
    return items


class MissionService:
    def __init__(self, db_path: Any, provider: Any, directory: Any,
                 identity_context: VerificationContext | Callable[[], VerificationContext] | None = None,
                 fault_injector: Any = None):
        self.db = Database(db_path)
        self.provider = provider
        self.directory = directory
        self.identity_context = identity_context
        self.fault = fault_injector or (lambda stage: None)

    def invoke(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        args = {key: value for key, value in args.items() if key != "service"}
        envelope = args.pop("identity_envelope", None)
        correlation_id = str(uuid4())
        try:
            context = self.identity_context() if callable(self.identity_context) else self.identity_context
            if context is None or envelope is None:
                raise IdentityError("AUTHENTICATION_REQUIRED")
            verified = verify_envelope(envelope, tool, args, context)
        except IdentityError as exc:
            self._record_event(None, correlation_id, None, "authentication_failure", exc.code, exc.code)
            return _error(exc.code, "Signed identity envelope rejected", correlation_id)
        try:
            principal = authenticate(self.provider)
        except ValueError:
            self._record_event(None, correlation_id, None, "authentication_failure", "AUTHENTICATION_FAILURE", "AUTHENTICATION_REQUIRED")
            return _error("AUTHENTICATION_REQUIRED", "Authentication required", correlation_id)
        token = _VERIFIED_IDENTITY.set(verified)
        raw_token = _RAW_REQUEST_ARGS.set(dict(args))
        try:
            if principal.subject_id != verified.principal_pubkey:
                self._record_event(principal, correlation_id, None, "identity_mismatch", "IDENTITY_MISMATCH", "IDENTITY_MISMATCH", asserted="[REDACTED:MISMATCH]")
                return _error("IDENTITY_MISMATCH", "Transport principal does not match request signer", correlation_id)
            try:
                assert_caller(principal, args.get("caller_instance_id"))
            except PermissionError:
                self._record_event(principal, correlation_id, None, "identity_mismatch", "IDENTITY_MISMATCH", "IDENTITY_MISMATCH", asserted="[REDACTED:MISMATCH]")
                return _error("IDENTITY_MISMATCH", "Caller identity does not match", correlation_id)
            if principal.role not in _ROLES[tool]:
                self._record_event(principal, correlation_id, None, "authorization_denial", "ROLE_DENIED", "PERMISSION_DENIED")
                return _error("PERMISSION_DENIED", "Operation is not permitted", correlation_id)
            if principal.role == "admin":
                try:
                    self._record_event(principal, correlation_id, None, "administrative_credential_action", "ADMIN_CREDENTIAL_USED", "OK", required=True)
                except ServiceError:
                    return _error("INTERNAL_ERROR", "Internal operation failure", correlation_id)
            try:
                result = getattr(self, tool)(principal, correlation_id, **args)
                if tool not in _MUTATIONS:
                    audit_action = "activity_query" if tool == "get_instance_activity" else "read"
                    target = args.get("auftrag_id") or "[REDACTED]"
                    self._record_event(principal, correlation_id, None, audit_action, "OK", "OK", auftrag_id=target, required=True)
                return result
            except ServiceError as exc:
                self._record_event(principal, correlation_id, self._safe_request_id(args.get("request_id")), "invalid_precondition", exc.code, exc.code)
                return _error(exc.code, exc.message, correlation_id)
            except Exception:
                self._record_event(principal, correlation_id, self._safe_request_id(args.get("request_id")), "invalid_precondition", "INTERNAL_ERROR", "INTERNAL_ERROR")
                return _error("INTERNAL_ERROR", "Internal operation failure", correlation_id)
        finally:
            _RAW_REQUEST_ARGS.reset(raw_token)
            _VERIFIED_IDENTITY.reset(token)

    @staticmethod
    def _safe_request_id(value: Any) -> str | None:
        return value if isinstance(value, str) and _REQUEST_ID.fullmatch(value) else None

    def _record_event(self, principal: Principal | None, correlation_id: str, request_id: str | None,
                      action: str, reason_code: str, result_code: str,
                      auftrag_id: str = "[REDACTED]", asserted: str | None = None,
                      required: bool = False) -> None:
        try:
            with self.db.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                self._audit(db, principal, correlation_id, request_id, auftrag_id, action, None, None,
                            reason_code, result_code, asserted=asserted, inject_fault=False)
                db.commit()
        except Exception as exc:
            if required:
                raise ServiceError("INTERNAL_ERROR", "Audit persistence failed") from exc

    @staticmethod
    def _identity() -> VerifiedIdentity:
        identity = _VERIFIED_IDENTITY.get()
        if identity is None:
            raise ServiceError("AUTHENTICATION_REQUIRED", "Identity envelope required")
        return identity

    @staticmethod
    def _write_binding(db: sqlite3.Connection, auftrag_id: str, relation: str,
                       binding: Mapping[str, str]) -> None:
        db.execute(
            "INSERT OR REPLACE INTO auftrag_identity_bindings VALUES(?,?,?,?,?,?,?,?,?)",
            (
                auftrag_id, relation, binding["principal_pubkey"], binding["owner_pubkey"],
                binding["profile_id"], binding["profile_version_sha256"],
                binding["tenant_id"], binding["runtime_generation"], _now(),
            ),
        )

    def _current_binding(self) -> dict[str, str]:
        identity = self._identity()
        return {
            "principal_pubkey": identity.principal_pubkey,
            "owner_pubkey": identity.owner_pubkey,
            "profile_id": identity.profile_id,
            "profile_version_sha256": identity.profile_version_sha256,
            "tenant_id": identity.tenant_id,
            "runtime_generation": identity.runtime_generation,
        }

    def _binding_matches(self, db: sqlite3.Connection, auftrag_id: str,
                         relation: str, principal: Principal) -> bool:
        identity = self._identity()
        row = db.execute(
            "SELECT * FROM auftrag_identity_bindings WHERE auftrag_id=? AND relation=?",
            (auftrag_id, relation),
        ).fetchone()
        return bool(
            row
            and principal.subject_id == identity.principal_pubkey == row["principal_pubkey"]
            and identity.owner_pubkey == row["owner_pubkey"]
            and identity.profile_id == row["profile_id"]
            and identity.profile_version_sha256 == row["profile_version_sha256"]
            and identity.tenant_id == row["tenant_id"]
            and identity.runtime_generation == row["runtime_generation"]
        )

    def _visible(self, db: sqlite3.Connection, principal: Principal, row: sqlite3.Row) -> bool:
        return (
            principal.role in {"auditor", "admin"}
            or (principal.role == "planner" and row["creator_id"] == principal.subject_id and self._binding_matches(db, row["id"], "creator", principal))
            or (principal.role == "worker" and row["assigned_to"] == principal.subject_id and self._binding_matches(db, row["id"], "assignee", principal))
        )

    def _related_mutation(self, db: sqlite3.Connection, principal: Principal,
                          row: sqlite3.Row, mode: str) -> bool:
        if principal.role == "admin":
            return True
        creator = principal.role == "planner" and row["creator_id"] == principal.subject_id and self._binding_matches(db, row["id"], "creator", principal)
        assignee = principal.role == "worker" and row["assigned_to"] == principal.subject_id and self._binding_matches(db, row["id"], "assignee", principal)
        if mode == "creator":
            return creator
        if mode == "assignee":
            return assignee
        return creator or assignee

    @staticmethod
    def _relation_reason(principal: Principal, row: sqlite3.Row, mode: str) -> str:
        if principal.role != "admin":
            return "OK"
        related = row["creator_id"] == principal.subject_id if mode == "creator" else (
            row["assigned_to"] == principal.subject_id if mode == "assignee"
            else row["creator_id"] == principal.subject_id or row["assigned_to"] == principal.subject_id
        )
        return "OK" if related else "ADMIN_RELATION_BYPASS"

    def _find(self, db: sqlite3.Connection, auftrag_id: str, principal: Principal, mode: str = "read") -> sqlite3.Row:
        row = db.execute("SELECT * FROM auftraege WHERE id=?", (auftrag_id,)).fetchone()
        allowed = row is not None and (self._visible(db, principal, row) if mode == "read" else self._related_mutation(db, principal, row, mode))
        if not allowed:
            raise ServiceError("NOT_FOUND", "Auftrag not found")
        return row

    def _audit(self, db: sqlite3.Connection, principal: Principal | None, correlation_id: str,
               request_id: str | None, auftrag_id: str, action: str,
               previous: str | None, next_state: str | None,
               reason_code: str = "OK", result_code: str = "OK",
               asserted: str | None = None, inject_fault: bool = True,
               evidence_reason: str | None = None) -> None:
        if inject_fault:
            self.fault("before_audit_insert")
        event_id = str(uuid4())
        db.execute(
            "INSERT INTO changelog VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (event_id, _now(), correlation_id, request_id,
             principal.subject_id if principal else "[REDACTED]",
             asserted if asserted is not None else (principal.subject_id if principal else None),
             principal.client_id if principal else "[REDACTED]",
             principal.role if principal else "[REDACTED]",
             auftrag_id, action, previous, next_state, reason_code, result_code),
        )
        identity = _VERIFIED_IDENTITY.get()
        db.execute(
            "INSERT INTO identity_audit VALUES(?,?,?,?,?,?,?,?,?)",
            (
                event_id,
                identity.principal_pubkey if identity else "[REDACTED]",
                identity.owner_pubkey if identity else "[REDACTED]",
                identity.profile_id if identity else "[REDACTED]",
                identity.profile_version_sha256 if identity else "[REDACTED]",
                identity.tenant_id if identity else "[REDACTED]",
                identity.runtime_generation if identity else "[REDACTED]",
                identity.nonce if identity else "[REDACTED]",
                identity.payload_sha256 if identity else "[REDACTED]",
            ),
        )
        if evidence_reason:
            # Accepted free-text reasons are durable audit evidence bound to
            # this event.  reason_code keeps carrying the relation verdict
            # (OK / REPLACED / ADMIN_RELATION_BYPASS) unchanged, and the
            # changelog wire projection stays exactly as declared.
            db.execute("INSERT INTO audit_reasons VALUES(?,?)", (event_id, evidence_reason))

    def _mutate(self, tool: str, principal: Principal, correlation_id: str,
                request_id: Any, canonical_args: dict[str, Any], action: Callable) -> dict[str, Any]:
        request_id = _valid_request_id(request_id)
        try:
            raw_args = _RAW_REQUEST_ARGS.get()
            payload_hash = hashlib.sha256(
                _jcs(raw_args if raw_args is not None else canonical_args).encode("utf-8")
            ).hexdigest()
        except (TypeError, ValueError, UnicodeError) as exc:
            raise ServiceError("INVALID_INPUT", "Invalid canonical payload") from exc
        if self.db.tampered:
            raise ServiceError("INTERNAL_ERROR", "Storage integrity check failed")
        db = self.db.connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute(
                "SELECT payload_hash,result_json FROM idempotency WHERE principal_subject_id=? AND tool=? AND request_id=?",
                (principal.subject_id, tool, request_id),
            ).fetchone()
            if prior:
                if prior["payload_hash"] != payload_hash:
                    raise ServiceError("CONFLICT", "Request identifier conflict")
                db.rollback()
                return json.loads(prior["result_json"])
            result, audit = action(db)
            # A seventh element is the accepted free-text reason for this
            # mutation, persisted as audit evidence next to the event.
            *audit, evidence_reason = audit if len(audit) > 6 else (*audit, None)
            self._audit(db, principal, correlation_id, request_id, *audit, evidence_reason=evidence_reason)
            db.execute("INSERT INTO idempotency VALUES(?,?,?,?,?)", (principal.subject_id, tool, request_id, payload_hash, _json(result)))
            db.commit()
            return result
        except ServiceError:
            db.rollback()
            raise
        except Exception as exc:
            db.rollback()
            raise ServiceError("INTERNAL_ERROR", "Internal operation failure") from exc
        finally:
            db.close()

    @staticmethod
    def _parse_steps(value: Any) -> list[dict[str, Any]]:
        raw = _raw_text(value, "steps", 100000, True)
        steps = _loads(raw, "steps")
        if not isinstance(steps, list) or not 1 <= len(steps) <= 100:
            raise ServiceError("INVALID_INPUT", "Invalid steps")
        output: list[dict[str, Any]] = []
        seen: set[str] = set()
        for step in steps:
            if not isinstance(step, dict) or not {"id", "name"} <= set(step) or not set(step) <= {"id", "name", "optional", "acceptance"}:
                raise ServiceError("INVALID_INPUT", "Invalid steps")
            sid = _valid_id(step["id"], "step_id")
            optional = step.get("optional", False)
            if sid in seen or not isinstance(optional, bool):
                raise ServiceError("INVALID_INPUT", "Invalid steps")
            seen.add(sid)
            output.append({
                "id": sid,
                "name": _raw_text(step["name"], "step.name", 500, True),
                "optional": optional,
                "acceptance": _raw_text(step.get("acceptance"), "step.acceptance", 2000),
            })
        return output

    @staticmethod
    def _parse_exit_kpis(value: Any) -> dict[str, list[str]]:
        if value in (None, ""):
            return {"required": []}
        parsed = _parse_object(value, "exit_kpis", maximum=20000)
        if set(parsed) != {"required"} or not isinstance(parsed["required"], list) or len(parsed["required"]) > 50:
            raise ServiceError("INVALID_INPUT", "Invalid exit_kpis")
        required = parsed["required"]
        if len(set(required)) != len(required) or any(not isinstance(item, str) or not _ID.fullmatch(item) for item in required):
            raise ServiceError("INVALID_INPUT", "Invalid exit_kpis")
        return {"required": required}

    def auftrag_create(self, principal: Principal, correlation_id: str, caller_instance_id: str,
                       id: str, title: str, project: str, steps: str, request_id: str,
                       description: str = "", exit_kpis: str = "", constraints: str = "",
                       rollback: str = "", decision_ref: str = "", based_on: str = "",
                       priority: str = "normal", assigned_to: str = "", duration_planned: int | None = None,
                       predecessor_id: str = "", tags: str = "", context_policy: str = "") -> dict[str, Any]:
        aid = _valid_id(id)
        project_value = _valid_id(project, "project")
        parsed_steps = self._parse_steps(steps)
        kpis = self._parse_exit_kpis(exit_kpis)
        if assigned_to or predecessor_id:
            raise ServiceError("INVALID_INPUT", "Invalid assignment fields")
        if priority not in {"low", "normal", "high", "critical"}:
            raise ServiceError("INVALID_INPUT", "Invalid priority")
        duration = _bounded_int(duration_planned, "duration_planned", 0, 31536000)
        raw_fields = {
            "title": _raw_text(title, "title", 500, True),
            "description": _raw_text(description, "description", 4000),
            "constraints": _raw_text(constraints, "constraints", 20000),
            "rollback": _raw_text(rollback, "rollback", 4000),
            "decision_ref": _raw_text(decision_ref, "decision_ref", 128),
            "context_policy": _raw_text(context_policy, "context_policy", 10000),
        }
        raw_tags = _parse_string_list(tags, "tags", 2000)
        raw_based_on = _parse_string_list(based_on, "based_on", 4000)
        canonical = {
            "caller_instance_id": caller_instance_id, "request_id": _valid_request_id(request_id),
            "id": aid, "title": raw_fields["title"], "project": project_value,
            "steps": parsed_steps, "description": raw_fields["description"], "exit_kpis": kpis,
            "constraints": raw_fields["constraints"], "rollback": raw_fields["rollback"],
            "decision_ref": raw_fields["decision_ref"], "based_on": raw_based_on, "priority": priority,
            "assigned_to": "", "duration_planned": duration, "predecessor_id": "",
            "tags": raw_tags, "context_policy": raw_fields["context_policy"],
        }
        fields = redact(raw_fields)
        fields["title"] = redact_person_name_field(raw_fields["title"])
        safe_steps = redact(parsed_steps)
        safe_tags = redact(raw_tags)
        safe_based_on = redact(raw_based_on)

        def operation(db: sqlite3.Connection):
            now = _now()
            try:
                db.execute(
                    """INSERT INTO auftraege
                    (id,title,project,status,creator_id,assigned_to,predecessor_id,description,constraints,rollback,
                     tags,based_on,exit_kpis,context_policy,priority,decision_ref,duration_planned,created_at,updated_at,version)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (aid, fields["title"], project_value, "queued", principal.subject_id, None, None,
                     fields["description"], fields["constraints"], fields["rollback"], _json(safe_tags),
                     _json(safe_based_on), _json(kpis), fields["context_policy"], priority,
                     fields["decision_ref"], duration, now, now, 1),
                )
                self._write_binding(db, aid, "creator", self._current_binding())
                for position, step in enumerate(safe_steps):
                    db.execute(
                        "INSERT INTO steps VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (aid, position, step["id"], step["name"], int(step["optional"]), step["acceptance"], "pending", "{}", "", None),
                    )
            except sqlite3.IntegrityError as exc:
                raise ServiceError("CONFLICT", "Auftrag already exists") from exc
            return _ok(correlation_id, auftrag_id=aid), (aid, "create", None, "queued")

        return self._mutate("auftrag_create", principal, correlation_id, request_id, canonical, operation)

    def auftrag_list(self, principal: Principal, correlation_id: str, caller_instance_id: str,
                     status: str = "", project: str = "", assigned_to: str = "",
                     limit: int = 50, offset: int = 0) -> dict[str, Any]:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100 or not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= 100000:
            raise ServiceError("INVALID_INPUT", "Invalid pagination")
        filters = [
            ("status", _raw_text(status, "status", 128)),
            ("project", _raw_text(project, "project", 128)),
            ("assigned_to", _raw_text(assigned_to, "assigned_to", 128)),
        ]
        clauses: list[str] = []
        params: list[Any] = []
        for column, value in filters:
            if value:
                clauses.append(f"{column}=?")
                params.append(value)
        if principal.role == "planner":
            clauses.append("creator_id=?"); params.append(principal.subject_id)
        if principal.role == "worker":
            clauses.append("assigned_to=?"); params.append(principal.subject_id)
        query = "SELECT * FROM auftraege" + (" WHERE " + " AND ".join(clauses) if clauses else "") + " ORDER BY created_at,id LIMIT ? OFFSET ?"
        params.extend((limit, offset))
        with self.db.connect() as db:
            items = [self._render_auftrag(db, row) for row in db.execute(query, params)]
        return _ok(correlation_id, items=items, limit=limit, offset=offset, next_offset=offset + len(items))

    def auftrag_get(self, principal: Principal, correlation_id: str, auftrag_id: str, caller_instance_id: str) -> dict[str, Any]:
        aid = _valid_id(auftrag_id, "auftrag_id")
        with self.db.connect() as db:
            item = self._render_auftrag(db, self._find(db, aid, principal))
        return _ok(correlation_id, auftrag=item)

    def _simple_transition(self, tool: str, principal: Principal, correlation_id: str,
                           caller_instance_id: str, auftrag_id: str, request_id: str,
                           relation: str, allowed: set[str], next_state: str,
                           extra: Callable | None = None, identity_extra: dict[str, Any] | None = None,
                           evidence_reason: str | None = None) -> dict[str, Any]:
        aid = _valid_id(auftrag_id, "auftrag_id")
        canonical = {"caller_instance_id": caller_instance_id, "auftrag_id": aid, "request_id": _valid_request_id(request_id)}
        canonical.update(identity_extra or {})

        def operation(db: sqlite3.Connection):
            row = self._find(db, aid, principal, relation)
            previous = row["status"]
            if previous not in allowed:
                raise ServiceError("INVALID_TRANSITION", "Invalid lifecycle transition")
            if extra:
                extra(db, row)
            db.execute("UPDATE auftraege SET status=?,updated_at=?,version=version+1 WHERE id=?", (next_state, _now(), aid))
            fields = {"auftrag_id": aid, "next_state": next_state} if tool in {"auftrag_start", "auftrag_cancel"} else {"auftrag_id": aid}
            return _ok(correlation_id, **fields), (aid, tool.removeprefix("auftrag_"), previous, next_state, self._relation_reason(principal, row, relation), "OK", evidence_reason)

        return self._mutate(tool, principal, correlation_id, request_id, canonical, operation)

    def auftrag_assign(self, principal: Principal, correlation_id: str, caller_instance_id: str,
                       auftrag_id: str, assigned_to: str, request_id: str) -> dict[str, Any]:
        aid = _valid_id(auftrag_id, "auftrag_id")
        assignee = _valid_id(assigned_to, "assigned_to")
        if not self.directory.eligible(assignee, tenant="default"):
            raise ServiceError("INVALID_INPUT", "Invalid assigned_to")
        binding = self.directory.identity_binding(assignee, tenant="default") if hasattr(self.directory, "identity_binding") else None
        required_binding = {"principal_pubkey", "owner_pubkey", "profile_id", "profile_version_sha256", "tenant_id", "runtime_generation"}
        if not isinstance(binding, dict) or set(binding) != required_binding or binding["principal_pubkey"] != assignee:
            raise ServiceError("INVALID_INPUT", "Assignee has no complete identity binding")
        canonical = {"caller_instance_id": caller_instance_id, "auftrag_id": aid, "assigned_to": assignee, "request_id": _valid_request_id(request_id)}

        def operation(db: sqlite3.Connection):
            row = self._find(db, aid, principal, "creator")
            if row["status"] != "queued":
                raise ServiceError("INVALID_TRANSITION", "Invalid lifecycle transition")
            db.execute("UPDATE auftraege SET status='assigned',assigned_to=?,updated_at=?,version=version+1 WHERE id=?", (assignee, _now(), aid))
            self._write_binding(db, aid, "assignee", binding)
            return _ok(correlation_id, auftrag_id=aid), (aid, "assign", "queued", "assigned", self._relation_reason(principal, row, "creator"), "OK")

        return self._mutate("auftrag_assign", principal, correlation_id, request_id, canonical, operation)

    def auftrag_start(self, principal: Principal, correlation_id: str, caller_instance_id: str, auftrag_id: str, request_id: str) -> dict[str, Any]:
        def activate(db: sqlite3.Connection, row: sqlite3.Row) -> None:
            first = db.execute("SELECT id FROM steps WHERE auftrag_id=? ORDER BY position LIMIT 1", (row["id"],)).fetchone()
            db.execute("UPDATE steps SET status='active' WHERE auftrag_id=? AND id=?", (row["id"], first["id"]))
        return self._simple_transition("auftrag_start", principal, correlation_id, caller_instance_id, auftrag_id, request_id, "assignee", {"assigned"}, "active", activate)

    def auftrag_checkpoint(self, principal: Principal, correlation_id: str, caller_instance_id: str,
                           auftrag_id: str, step_id: str, status: str, request_id: str,
                           checkpoint_data: str = "", error_message: str = "", duration_actual: int | None = None) -> dict[str, Any]:
        aid = _valid_id(auftrag_id, "auftrag_id")
        sid = _valid_id(step_id, "step_id")
        if status not in {"pass", "fail", "skipped"}:
            raise ServiceError("INVALID_INPUT", "Invalid status")
        data = _parse_object(checkpoint_data, "checkpoint_data", {}, 100000)
        if not set(data) <= {"evidence", "note", "metrics"}:
            raise ServiceError("INVALID_INPUT", "Invalid checkpoint_data")
        if "evidence" in data and (not isinstance(data["evidence"], list) or len(data["evidence"]) > 50 or any(not isinstance(item, str) or len(item) > 1000 for item in data["evidence"])):
            raise ServiceError("INVALID_INPUT", "Invalid checkpoint_data")
        if "note" in data:
            _raw_text(data["note"], "checkpoint_data.note", 4000)
        if "metrics" in data:
            metrics = data["metrics"]
            if not isinstance(metrics, dict) or any(isinstance(value, (dict, list)) or value is None or not isinstance(value, (str, int, float, bool)) for value in metrics.values()):
                raise ServiceError("INVALID_INPUT", "Invalid checkpoint_data")
            _validate_finite(metrics, "checkpoint_data")
        duration = _bounded_int(duration_actual, "duration_actual", 0, 31536000)
        raw_error = _raw_text(error_message, "error_message", 4000)
        canonical = {"caller_instance_id": caller_instance_id, "auftrag_id": aid, "step_id": sid, "status": status,
                     "checkpoint_data": data, "error_message": raw_error, "duration_actual": duration, "request_id": _valid_request_id(request_id)}
        safe_data = redact(data)
        safe_error = redact_text(raw_error)

        def operation(db: sqlite3.Connection):
            row = self._find(db, aid, principal, "assignee")
            if row["status"] != "active":
                raise ServiceError("INVALID_TRANSITION", "Invalid lifecycle transition")
            step = db.execute("SELECT * FROM steps WHERE auftrag_id=? AND id=?", (aid, sid)).fetchone()
            if step is None or step["status"] != "active" or (status == "skipped" and not step["optional"]):
                raise ServiceError("INVALID_TRANSITION", "Invalid step transition")
            next_state = "failed" if status == "fail" else "active"
            db.execute("UPDATE steps SET status=?,checkpoint_data=?,error_message=?,duration_actual=? WHERE auftrag_id=? AND id=?", (status, _json(safe_data), safe_error, duration, aid, sid))
            if status != "fail":
                following = db.execute("SELECT id FROM steps WHERE auftrag_id=? AND position>? AND status='pending' ORDER BY position LIMIT 1", (aid, step["position"])).fetchone()
                if following:
                    db.execute("UPDATE steps SET status='active' WHERE auftrag_id=? AND id=?", (aid, following["id"]))
                else:
                    next_state = "validating"
            db.execute("UPDATE auftraege SET status=?,updated_at=?,version=version+1 WHERE id=?", (next_state, _now(), aid))
            return _ok(correlation_id, auftrag_id=aid, step_id=sid, next_state=next_state), (aid, "checkpoint", "active", next_state, self._relation_reason(principal, row, "assignee"), "OK")

        return self._mutate("auftrag_checkpoint", principal, correlation_id, request_id, canonical, operation)

    def auftrag_block(self, principal: Principal, correlation_id: str, caller_instance_id: str,
                      auftrag_id: str, reason: str, request_id: str, step_id: str = "",
                      block_type: str = "unclassified") -> dict[str, Any]:
        aid = _valid_id(auftrag_id, "auftrag_id")
        raw_reason = _raw_text(reason, "reason", 4000, True)
        sid = _optional_id(step_id, "step_id")
        raw_type = _raw_text(block_type, "block_type", 64)
        canonical = {"caller_instance_id": caller_instance_id, "auftrag_id": aid, "reason": raw_reason,
                     "request_id": _valid_request_id(request_id), "step_id": sid, "block_type": raw_type}
        safe_reason = redact_text(raw_reason)
        safe_type = redact_text(raw_type)

        def operation(db: sqlite3.Connection):
            row = self._find(db, aid, principal, "either")
            previous = row["status"]
            if previous not in {"active", "validating"}:
                raise ServiceError("INVALID_TRANSITION", "Invalid lifecycle transition")
            if sid and db.execute("SELECT 1 FROM steps WHERE auftrag_id=? AND id=?", (aid, sid)).fetchone() is None:
                raise ServiceError("INVALID_INPUT", "Invalid step_id")
            bid = str(uuid4()); now = _now()
            db.execute("INSERT INTO blocks VALUES(?,?,?,?,?,?,?,?,?)", (bid, aid, safe_type, safe_reason, previous, sid or None, now, None, None))
            db.execute("UPDATE auftraege SET status='blocked',updated_at=?,version=version+1 WHERE id=?", (now, aid))
            return _ok(correlation_id, auftrag_id=aid, previous_state=previous, next_state="blocked"), (aid, "block", previous, "blocked", self._relation_reason(principal, row, "either"), "OK")

        return self._mutate("auftrag_block", principal, correlation_id, request_id, canonical, operation)

    def auftrag_resume(self, principal: Principal, correlation_id: str, caller_instance_id: str,
                       auftrag_id: str, resolution: str, request_id: str) -> dict[str, Any]:
        aid = _valid_id(auftrag_id, "auftrag_id")
        raw_resolution = _raw_text(resolution, "resolution", 4000, True)
        canonical = {"caller_instance_id": caller_instance_id, "auftrag_id": aid, "resolution": raw_resolution, "request_id": _valid_request_id(request_id)}
        safe_resolution = redact_text(raw_resolution)

        def operation(db: sqlite3.Connection):
            row = self._find(db, aid, principal, "either")
            if row["status"] != "blocked":
                raise ServiceError("INVALID_TRANSITION", "Invalid lifecycle transition")
            block = db.execute("SELECT * FROM blocks WHERE auftrag_id=? AND resolved_at IS NULL ORDER BY created_at DESC LIMIT 1", (aid,)).fetchone()
            if not block or block["previous_state"] not in {"active", "validating"}:
                raise ServiceError("INVALID_TRANSITION", "Invalid lifecycle transition")
            restored = block["previous_state"]
            now = _now()
            db.execute("UPDATE blocks SET resolved_at=?,resolution=? WHERE id=?", (now, safe_resolution, block["id"]))
            db.execute("UPDATE auftraege SET status=?,updated_at=?,version=version+1 WHERE id=?", (restored, now, aid))
            return _ok(correlation_id, auftrag_id=aid, previous_state="blocked", next_state=restored), (aid, "resume", "blocked", restored, self._relation_reason(principal, row, "either"), "OK")

        return self._mutate("auftrag_resume", principal, correlation_id, request_id, canonical, operation)

    def auftrag_close(self, principal: Principal, correlation_id: str, caller_instance_id: str,
                      auftrag_id: str, result: str, request_id: str, summary: str = "",
                      kpi_results: str = "", duration_actual: int | None = None,
                      execution_quality: float | None = None, decision_quality: float | None = None,
                      root_cause: str = "", root_cause_category: str = "",
                      kpis_verified: str = "", existing_outcome_id: str = "") -> dict[str, Any]:
        aid = _valid_id(auftrag_id, "auftrag_id")
        if result not in {"success", "partial", "fail"}:
            raise ServiceError("INVALID_INPUT", "Invalid result")
        raw_summary = _raw_text(summary, "summary", 4000)
        raw_root = _raw_text(root_cause, "root_cause", 4000)
        if result == "fail" and not raw_root:
            raise ServiceError("INVALID_INPUT", "Invalid root_cause")
        raw_category = _raw_text(root_cause_category, "root_cause_category", 128)
        outcome_id = _optional_id(existing_outcome_id, "existing_outcome_id")
        duration = _bounded_int(duration_actual, "duration_actual", 0, 31536000)
        execution = _bounded_number(execution_quality, "execution_quality", -1, 10)
        decision = _bounded_number(decision_quality, "decision_quality", -1, 10)
        verified = _parse_string_list(kpis_verified, "kpis_verified", 20000)
        parsed_results = _parse_object(kpi_results, "kpi_results", {}, 100000)
        for key, value in parsed_results.items():
            if not isinstance(key, str) or not _ID.fullmatch(key) or not isinstance(value, dict) or not {"met", "value"} <= set(value) or not set(value) <= {"met", "value", "evidence"}:
                raise ServiceError("INVALID_INPUT", "Invalid kpi_results")
            if not isinstance(value["met"], bool) or isinstance(value["value"], (dict, list)) or value["value"] is None or not isinstance(value["value"], (str, int, float, bool)):
                raise ServiceError("INVALID_INPUT", "Invalid kpi_results")
            _validate_finite(value["value"], "kpi_results")
            if "evidence" in value:
                _raw_text(value["evidence"], "kpi_results.evidence", 1000)
        canonical = {
            "caller_instance_id": caller_instance_id, "auftrag_id": aid, "result": result,
            "summary": raw_summary, "kpi_results": parsed_results, "duration_actual": duration,
            "execution_quality": execution, "decision_quality": decision, "root_cause": raw_root,
            "root_cause_category": raw_category, "kpis_verified": verified,
            "existing_outcome_id": outcome_id, "request_id": _valid_request_id(request_id),
        }
        safe_summary = redact_text(raw_summary)
        safe_results = redact(parsed_results)
        safe_root = redact_text(raw_root)
        safe_category = redact_text(raw_category)
        safe_verified = redact(verified)

        def operation(db: sqlite3.Connection):
            row = self._find(db, aid, principal, "assignee")
            if row["status"] != "validating":
                raise ServiceError("INVALID_TRANSITION", "Invalid lifecycle transition")
            steps = list(db.execute("SELECT optional,status FROM steps WHERE auftrag_id=?", (aid,)))
            if any((not step["optional"] and step["status"] != "pass") or (step["optional"] and step["status"] not in {"pass", "skipped"}) for step in steps):
                raise ServiceError("INVALID_TRANSITION", "Step acceptance incomplete")
            required = json.loads(row["exit_kpis"])["required"]
            if set(parsed_results) != set(required):
                raise ServiceError("INVALID_INPUT", "Invalid kpi_results")
            if result in {"success", "partial"} and any(not value["met"] for value in parsed_results.values()):
                raise ServiceError("INVALID_INPUT", "Invalid kpi_results")
            next_state = "failed" if result == "fail" else "done"
            db.execute(
                """UPDATE auftraege SET status=?,close_summary=?,kpi_results=?,duration_actual=?,execution_quality=?,
                   decision_quality=?,root_cause=?,root_cause_category=?,kpis_verified=?,existing_outcome_id=?,
                   updated_at=?,version=version+1 WHERE id=?""",
                (next_state, safe_summary, _json(safe_results), duration, execution, decision, safe_root,
                 safe_category, _json(safe_verified), outcome_id, _now(), aid),
            )
            return _ok(correlation_id, auftrag_id=aid, next_state=next_state), (aid, "close", "validating", next_state, self._relation_reason(principal, row, "assignee"), "OK")

        return self._mutate("auftrag_close", principal, correlation_id, request_id, canonical, operation)

    def auftrag_cancel(self, principal: Principal, correlation_id: str, caller_instance_id: str,
                       auftrag_id: str, request_id: str, reason: str = "") -> dict[str, Any]:
        raw_reason = _raw_text(reason, "reason", 4000)
        return self._simple_transition("auftrag_cancel", principal, correlation_id, caller_instance_id,
                                       auftrag_id, request_id, "creator", {"queued"}, "cancelled",
                                       identity_extra={"reason": raw_reason},
                                       evidence_reason=redact_text(raw_reason))

    def auftrag_reassign_replace(self, principal: Principal, correlation_id: str,
                                  caller_instance_id: str, auftrag_id: str, new_auftrag_id: str,
                                  new_assigned_to: str, request_id: str, reason: str = "",
                                  context_policy: str = "") -> dict[str, Any]:
        old_id = _valid_id(auftrag_id, "auftrag_id")
        new_id = _valid_id(new_auftrag_id, "new_auftrag_id")
        assignee = _valid_id(new_assigned_to, "new_assigned_to")
        if not self.directory.eligible(assignee, tenant="default"):
            raise ServiceError("INVALID_INPUT", "Invalid new_assigned_to")
        binding = self.directory.identity_binding(assignee, tenant="default") if hasattr(self.directory, "identity_binding") else None
        required_binding = {"principal_pubkey", "owner_pubkey", "profile_id", "profile_version_sha256", "tenant_id", "runtime_generation"}
        if not isinstance(binding, dict) or set(binding) != required_binding or binding["principal_pubkey"] != assignee:
            raise ServiceError("INVALID_INPUT", "Replacement assignee has no complete identity binding")
        raw_reason = _raw_text(reason, "reason", 4000)
        raw_context = _raw_text(context_policy, "context_policy", 10000)
        canonical = {"caller_instance_id": caller_instance_id, "auftrag_id": old_id, "new_auftrag_id": new_id,
                     "new_assigned_to": assignee, "reason": raw_reason, "context_policy": raw_context,
                     "request_id": _valid_request_id(request_id)}
        safe_context = redact_text(raw_context)
        safe_reason = redact_text(raw_reason)

        def operation(db: sqlite3.Connection):
            old = self._find(db, old_id, principal, "creator")
            if old["status"] not in {"queued", "assigned"}:
                raise ServiceError("INVALID_TRANSITION", "Invalid lifecycle transition")
            now = _now()
            try:
                db.execute(
                    """INSERT INTO auftraege
                    (id,title,project,status,creator_id,assigned_to,predecessor_id,description,constraints,rollback,
                     tags,based_on,exit_kpis,context_policy,priority,decision_ref,duration_planned,created_at,updated_at,version)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (new_id, old["title"], old["project"], "assigned", old["creator_id"], assignee, old_id,
                     old["description"], old["constraints"], old["rollback"], old["tags"], old["based_on"],
                     old["exit_kpis"], safe_context or old["context_policy"], old["priority"], old["decision_ref"],
                     old["duration_planned"], now, now, 1),
                )
                self._write_binding(db, new_id, "creator", self._current_binding())
                self._write_binding(db, new_id, "assignee", binding)
                remaining = list(db.execute("SELECT * FROM steps WHERE auftrag_id=? AND status NOT IN ('pass','skipped') ORDER BY position", (old_id,)))
                if not remaining:
                    remaining = list(db.execute("SELECT * FROM steps WHERE auftrag_id=? ORDER BY position", (old_id,)))
                for position, step in enumerate(remaining):
                    db.execute("INSERT INTO steps VALUES(?,?,?,?,?,?,?,?,?,?)", (new_id, position, step["id"], step["name"], step["optional"], step["acceptance"], "pending", "{}", "", None))
            except sqlite3.IntegrityError as exc:
                raise ServiceError("CONFLICT", "Replacement already exists") from exc
            previous = old["status"]
            db.execute("UPDATE auftraege SET status='cancelled',updated_at=?,version=version+1 WHERE id=?", (now, old_id))
            return _ok(correlation_id, auftrag_id=new_id, predecessor_id=old_id), (old_id, "reassign_replace", previous, "cancelled", "REPLACED" if principal.role != "admin" or self._relation_reason(principal, old, "creator") == "OK" else "ADMIN_RELATION_BYPASS", "OK", safe_reason)

        return self._mutate("auftrag_reassign_replace", principal, correlation_id, request_id, canonical, operation)

    def auftrag_get_changelog(self, principal: Principal, correlation_id: str,
                               caller_instance_id: str, auftrag_id: str = "", instance_id: str = "",
                               project: str = "", period: str = "30d", action: str = "",
                               limit: int = 50, offset: int = 0) -> dict[str, Any]:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100 or not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= 100000:
            raise ServiceError("INVALID_INPUT", "Invalid pagination")
        if period not in _PERIODS:
            raise ServiceError("INVALID_INPUT", "Invalid period")
        aid = _optional_id(auftrag_id, "auftrag_id")
        instance = _raw_text(instance_id, "instance_id", 128)
        project_value = _raw_text(project, "project", 128)
        action_value = _raw_text(action, "action", 128)
        cutoff = (datetime.now(timezone.utc) - timedelta(days=_PERIODS[period])).isoformat()
        with self.db.connect() as db:
            # No existence probe here: NOT_FOUND is not a declared error of this
            # tool.  The role clauses below already scope the result set, so an
            # absent and an unauthorised auftrag_id are equally an empty page.
            clauses = ["occurred_at>=?"]
            params: list[Any] = [cutoff]
            if aid:
                clauses.append("auftrag_id_or_redacted=?"); params.append(aid)
            if action_value:
                clauses.append("action=?"); params.append(action_value)
            if instance:
                clauses.append("principal_subject_id=?"); params.append(instance)
            if project_value:
                clauses.append("auftrag_id_or_redacted IN (SELECT id FROM auftraege WHERE project=?)"); params.append(project_value)
            if principal.role == "planner":
                clauses.append("auftrag_id_or_redacted IN (SELECT id FROM auftraege WHERE creator_id=?)"); params.append(principal.subject_id)
            elif principal.role == "worker":
                clauses.append("auftrag_id_or_redacted IN (SELECT id FROM auftraege WHERE assigned_to=?)"); params.append(principal.subject_id)
            query = "SELECT * FROM changelog WHERE " + " AND ".join(clauses) + " ORDER BY occurred_at,event_id LIMIT ? OFFSET ?"
            params.extend((limit, offset))
            items = [dict(row) for row in db.execute(query, params)]
        return _ok(correlation_id, items=items, limit=limit, offset=offset, next_offset=offset + len(items))

    def get_instance_activity(self, principal: Principal, correlation_id: str,
                              auftrag_id: str, caller_instance_id: str,
                              limit: int = 50, offset: int = 0) -> dict[str, Any]:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100 or not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= 100000:
            raise ServiceError("INVALID_INPUT", "Invalid pagination")
        aid = _valid_id(auftrag_id, "auftrag_id")
        with self.db.connect() as db:
            self._find(db, aid, principal)
            rows = db.execute(
                "SELECT principal_subject_id,action,occurred_at,auftrag_id_or_redacted,result_code FROM changelog WHERE auftrag_id_or_redacted=? ORDER BY occurred_at,event_id LIMIT ? OFFSET ?",
                (aid, limit, offset),
            )
            items = [{"actor_subject_id": row[0], "action": row[1], "occurred_at": row[2], "auftrag_id": row[3], "result_code": row[4]} for row in rows]
        return _ok(correlation_id, items=items, limit=limit, offset=offset, next_offset=offset + len(items))

    @staticmethod
    def _render_auftrag(db: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
        steps = [
            {"id": step["id"], "name": step["name"], "optional": bool(step["optional"]), "status": step["status"],
             "acceptance": step["acceptance"], "checkpoint_data": json.loads(step["checkpoint_data"]),
             "error_message": step["error_message"], "duration_actual": step["duration_actual"]}
            for step in db.execute("SELECT * FROM steps WHERE auftrag_id=? ORDER BY position", (row["id"],))
        ]
        blocks = [
            {"id": block["id"], "type": block["type"], "reason": block["reason"], "previous_state": block["previous_state"],
             "created_at": block["created_at"], "resolved_at": block["resolved_at"], "resolution": block["resolution"]}
            for block in db.execute("SELECT * FROM blocks WHERE auftrag_id=? ORDER BY created_at", (row["id"],))
        ]
        completed = sum(step["status"] in {"pass", "skipped"} for step in steps)
        total = len(steps)
        return {
            "id": row["id"], "title": row["title"], "project": row["project"], "status": row["status"],
            "creator_id": row["creator_id"], "assigned_to": row["assigned_to"], "predecessor_id": row["predecessor_id"],
            "steps": steps, "created_at": row["created_at"], "updated_at": row["updated_at"],
            "description": row["description"], "context_policy": row["context_policy"],
            "constraints": [row["constraints"]] if row["constraints"] else [], "rollback": row["rollback"],
            "tags": json.loads(row["tags"]), "based_on": json.loads(row["based_on"]), "exit_kpis": json.loads(row["exit_kpis"]),
            "priority": row["priority"], "decision_ref": row["decision_ref"], "duration_planned": row["duration_planned"],
            "close_summary": row["close_summary"], "kpi_results": json.loads(row["kpi_results"]),
            "duration_actual": row["duration_actual"], "execution_quality": row["execution_quality"],
            "decision_quality": row["decision_quality"], "root_cause": row["root_cause"],
            "root_cause_category": row["root_cause_category"], "kpis_verified": json.loads(row["kpis_verified"]),
            "existing_outcome_id": row["existing_outcome_id"], "blocks": blocks,
            "progress": {"completed": completed, "total": total, "percent": (100.0 * completed / total if total else 0.0)},
            "version": row["version"],
        }
