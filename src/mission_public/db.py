"""SQLite persistence and append-only audit protection."""

from __future__ import annotations

import sqlite3
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS auftraege (
 id TEXT PRIMARY KEY, title TEXT NOT NULL, project TEXT NOT NULL, status TEXT NOT NULL,
 creator_id TEXT NOT NULL, assigned_to TEXT, predecessor_id TEXT,
 description TEXT NOT NULL, constraints TEXT NOT NULL, rollback TEXT NOT NULL,
 tags TEXT NOT NULL, based_on TEXT NOT NULL, exit_kpis TEXT NOT NULL,
 context_policy TEXT NOT NULL, priority TEXT NOT NULL,
 decision_ref TEXT NOT NULL DEFAULT '', duration_planned INTEGER,
 close_summary TEXT NOT NULL DEFAULT '', kpi_results TEXT NOT NULL DEFAULT '{}',
 duration_actual INTEGER, execution_quality REAL, decision_quality REAL,
 root_cause TEXT NOT NULL DEFAULT '', root_cause_category TEXT NOT NULL DEFAULT '',
 kpis_verified TEXT NOT NULL DEFAULT '[]', existing_outcome_id TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL, version INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS steps (
 auftrag_id TEXT NOT NULL, position INTEGER NOT NULL, id TEXT NOT NULL,
 name TEXT NOT NULL, optional INTEGER NOT NULL, acceptance TEXT NOT NULL,
 status TEXT NOT NULL, checkpoint_data TEXT NOT NULL, error_message TEXT NOT NULL,
 duration_actual INTEGER,
 PRIMARY KEY (auftrag_id, id),
 FOREIGN KEY (auftrag_id) REFERENCES auftraege(id)
);
CREATE TABLE IF NOT EXISTS blocks (
 id TEXT PRIMARY KEY, auftrag_id TEXT NOT NULL, type TEXT NOT NULL,
 reason TEXT NOT NULL, previous_state TEXT NOT NULL, step_id TEXT,
 created_at TEXT NOT NULL, resolved_at TEXT, resolution TEXT,
 FOREIGN KEY (auftrag_id) REFERENCES auftraege(id)
);
CREATE TABLE IF NOT EXISTS changelog (
 event_id TEXT PRIMARY KEY, occurred_at TEXT NOT NULL, correlation_id TEXT NOT NULL,
 request_id TEXT, principal_subject_id TEXT NOT NULL, asserted_subject_id TEXT,
 client_id TEXT NOT NULL, role TEXT NOT NULL, auftrag_id_or_redacted TEXT NOT NULL,
 action TEXT NOT NULL, previous_state TEXT, next_state TEXT,
 reason_code TEXT NOT NULL, result_code TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS idempotency (
 principal_subject_id TEXT NOT NULL, tool TEXT NOT NULL, request_id TEXT NOT NULL,
 payload_hash TEXT NOT NULL, result_json TEXT NOT NULL,
 PRIMARY KEY (principal_subject_id, tool, request_id)
);
CREATE TABLE IF NOT EXISTS auftrag_identity_bindings (
 auftrag_id TEXT NOT NULL, relation TEXT NOT NULL,
 principal_pubkey TEXT NOT NULL, owner_pubkey TEXT NOT NULL,
 profile_id TEXT NOT NULL, profile_version_sha256 TEXT NOT NULL,
 tenant_id TEXT NOT NULL, runtime_generation TEXT NOT NULL,
 bound_at TEXT NOT NULL,
 PRIMARY KEY (auftrag_id, relation),
 FOREIGN KEY (auftrag_id) REFERENCES auftraege(id)
);
CREATE TABLE IF NOT EXISTS identity_audit (
 event_id TEXT PRIMARY KEY, principal_pubkey TEXT NOT NULL,
 owner_pubkey TEXT NOT NULL, profile_id TEXT NOT NULL,
 profile_version_sha256 TEXT NOT NULL, tenant_id TEXT NOT NULL,
 runtime_generation TEXT NOT NULL, envelope_nonce TEXT NOT NULL,
 payload_sha256 TEXT NOT NULL,
 FOREIGN KEY (event_id) REFERENCES changelog(event_id)
);
"""
_AUDIT_REASONS_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_reasons (
 event_id TEXT PRIMARY KEY, reason TEXT NOT NULL,
 FOREIGN KEY (event_id) REFERENCES changelog(event_id)
);
"""
_TRIGGER_UPDATE = """CREATE TRIGGER changelog_no_update BEFORE UPDATE ON changelog
BEGIN SELECT RAISE(ABORT, 'changelog is append-only'); END"""
_TRIGGER_DELETE = """CREATE TRIGGER changelog_no_delete BEFORE DELETE ON changelog
BEGIN SELECT RAISE(ABORT, 'changelog is append-only'); END"""
_IDENTITY_TRIGGER_UPDATE = """CREATE TRIGGER identity_audit_no_update BEFORE UPDATE ON identity_audit
BEGIN SELECT RAISE(ABORT, 'identity audit is append-only'); END"""
_IDENTITY_TRIGGER_DELETE = """CREATE TRIGGER identity_audit_no_delete BEFORE DELETE ON identity_audit
BEGIN SELECT RAISE(ABORT, 'identity audit is append-only'); END"""
_REQUIRED_AUDIT_COLUMNS = {
    "event_id", "occurred_at", "correlation_id", "request_id",
    "principal_subject_id", "asserted_subject_id", "client_id", "role",
    "auftrag_id_or_redacted", "action", "previous_state", "next_state",
    "reason_code", "result_code",
}
_ADDED_AUFTRAG_COLUMNS = {
    "decision_ref": "TEXT NOT NULL DEFAULT ''",
    "duration_planned": "INTEGER",
    "close_summary": "TEXT NOT NULL DEFAULT ''",
    "kpi_results": "TEXT NOT NULL DEFAULT '{}'",
    "duration_actual": "INTEGER",
    "execution_quality": "REAL",
    "decision_quality": "REAL",
    "root_cause": "TEXT NOT NULL DEFAULT ''",
    "root_cause_category": "TEXT NOT NULL DEFAULT ''",
    "kpis_verified": "TEXT NOT NULL DEFAULT '[]'",
    "existing_outcome_id": "TEXT NOT NULL DEFAULT ''",
}


class Database:
    def __init__(self, path: str | Path):
        self.path = str(path)
        existed = Path(path).exists()
        with self.connect() as db:
            if not existed:
                db.executescript(_SCHEMA)
                db.execute(_TRIGGER_UPDATE)
                db.execute(_TRIGGER_DELETE)
                db.execute(_IDENTITY_TRIGGER_UPDATE)
                db.execute(_IDENTITY_TRIGGER_DELETE)
                db.execute("INSERT INTO metadata(key,value) VALUES('schema','1')")
            else:
                self._migrate_auftrag_columns(db)
                db.executescript(_SCHEMA)
                trigger_names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
                if "identity_audit_no_update" not in trigger_names:
                    db.execute(_IDENTITY_TRIGGER_UPDATE)
                if "identity_audit_no_delete" not in trigger_names:
                    db.execute(_IDENTITY_TRIGGER_DELETE)
            # Redacted mutation reasons are audit evidence attached to the
            # changelog event; the changelog wire projection stays closed.
            db.executescript(_AUDIT_REASONS_SCHEMA)
            self.tampered = not self._integrity_ok(db)

    def connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        return db

    @staticmethod
    def _migrate_auftrag_columns(db: sqlite3.Connection) -> None:
        columns = {row[1] for row in db.execute("PRAGMA table_info(auftraege)")}
        for name, declaration in _ADDED_AUFTRAG_COLUMNS.items():
            if name not in columns:
                db.execute(f"ALTER TABLE auftraege ADD COLUMN {name} {declaration}")

    @staticmethod
    def _integrity_ok(db: sqlite3.Connection) -> bool:
        try:
            columns = {row[1] for row in db.execute("PRAGMA table_info(changelog)")}
            triggers = {
                row[0]: " ".join(row[1].split()).rstrip(";") for row in db.execute(
                    "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND name IN (?,?)",
                    ("changelog_no_update", "changelog_no_delete"),
                )
            }
            expected_triggers = {
                "changelog_no_update": " ".join(_TRIGGER_UPDATE.split()).rstrip(";"),
                "changelog_no_delete": " ".join(_TRIGGER_DELETE.split()).rstrip(";"),
            }
            marker = db.execute("SELECT value FROM metadata WHERE key=?", ("schema",)).fetchone()
            identity_columns = {row[1] for row in db.execute("PRAGMA table_info(identity_audit)")}
            expected_identity_columns = {
                "event_id", "principal_pubkey", "owner_pubkey", "profile_id",
                "profile_version_sha256", "tenant_id", "runtime_generation",
                "envelope_nonce", "payload_sha256",
            }
            identity_triggers = {
                row[0]: " ".join(row[1].split()).rstrip(";") for row in db.execute(
                    "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND name IN (?,?)",
                    ("identity_audit_no_update", "identity_audit_no_delete"),
                )
            }
            expected_identity_triggers = {
                "identity_audit_no_update": " ".join(_IDENTITY_TRIGGER_UPDATE.split()).rstrip(";"),
                "identity_audit_no_delete": " ".join(_IDENTITY_TRIGGER_DELETE.split()).rstrip(";"),
            }
            return (
                columns == _REQUIRED_AUDIT_COLUMNS
                and triggers == expected_triggers
                and identity_columns == expected_identity_columns
                and identity_triggers == expected_identity_triggers
                and marker is not None and marker[0] == "1"
            )
        except sqlite3.DatabaseError:
            return False
