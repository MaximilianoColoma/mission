from __future__ import annotations
import hashlib
import json
from pathlib import Path


def test_vendored_identity_contract_matches_accepted_canonical_digest():
    root = Path(__file__).resolve().parents[1]
    lock = json.loads((root / "spec" / "identity-envelope.lock.json").read_text())
    observed = hashlib.sha256((root / lock["local_projection"]).read_bytes()).hexdigest()
    assert lock["canonical_repository"] == "MaximilianoColoma/witness"
    assert lock["canonical_path"] == "spec/identity-envelope.json"
    assert observed == lock["accepted_sha256"]
