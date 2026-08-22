"""Preimplementation acceptance probe for closed Mission audit columns.

MIS-AUDIT-EXTRA-COLUMN-REQ-001/002: changelog is a closed audit schema.
Adding any undeclared column must make a reopened Database report tampering.
"""
from __future__ import annotations

import sqlite3

import pytest

from mission_public.db import Database


def test_forbidden_extra_changelog_column_enters_tampered_mode(tmp_path):
    db_path = tmp_path / "mission.db"
    initial = Database(db_path)
    assert initial.tampered is False

    with sqlite3.connect(db_path) as db:
        db.execute("ALTER TABLE changelog ADD COLUMN credential TEXT")

    reopened = Database(db_path)
    assert reopened.tampered is True


def test_forbidden_extra_identity_audit_column_enters_tampered_mode(tmp_path):
    db_path = tmp_path / "mission-identity.db"
    assert Database(db_path).tampered is False
    with sqlite3.connect(db_path) as db:
        db.execute("ALTER TABLE identity_audit ADD COLUMN raw_token TEXT")
    assert Database(db_path).tampered is True


def test_identity_audit_triggers_block_update_and_delete(tmp_path):
    db_path = tmp_path / "mission-identity-trigger.db"
    Database(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute("PRAGMA foreign_keys=ON")
        # A parent event is needed for the foreign key.
        db.execute("INSERT INTO changelog VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
            "e1", "now", "c1", None, "p", "p", "client", "admin",
            "[REDACTED]", "read", None, None, "OK", "OK",
        ))
        db.execute("INSERT INTO identity_audit VALUES(?,?,?,?,?,?,?,?,?)", (
            "e1", "p", "o", "profile", "0" * 64, "tenant", "generation", "nonce", "0" * 64,
        ))
        with pytest.raises(sqlite3.DatabaseError):
            db.execute("UPDATE identity_audit SET owner_pubkey='changed'")
        with pytest.raises(sqlite3.DatabaseError):
            db.execute("DELETE FROM identity_audit")
