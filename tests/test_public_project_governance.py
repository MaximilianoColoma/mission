"""GHR-012 preimplementation acceptance for professional Apache-2.0 public-project metadata."""
from __future__ import annotations

import hashlib
from pathlib import Path
import tomllib

PRODUCT = "Mission"
PACKAGE = "mission-public"
ROOT = Path(__file__).resolve().parents[1]
APACHE_LICENSE_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
HOLDER = "Maximiliano Coloma-Seegers"


def text(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def test_apache_license_notice_and_v010_package_metadata():
    license_bytes = (ROOT / "LICENSE").read_bytes()
    assert hashlib.sha256(license_bytes).hexdigest() == APACHE_LICENSE_SHA256
    notice = text("NOTICE")
    assert PRODUCT in notice
    assert f"Copyright 2026 {HOLDER}" in notice
    assert "Apache License, Version 2.0" in notice
    project = tomllib.loads(text("pyproject.toml"))["project"]
    assert project["name"] == PACKAGE
    assert project["version"] == "0.1.0"
    assert project["license"] == "Apache-2.0"
    assert set(project["license-files"]) == {"LICENSE", "NOTICE"}


def test_governance_keeps_official_center_and_contract_authority_clear():
    governance = text("GOVERNANCE.md")
    trademarks = text("TRADEMARKS.md")
    readme = text("README.md")
    for phrase in ("Benevolent Dictator", HOLDER, "Security", "Release", "Compatibility"):
        assert phrase in governance
    assert "Apache-2.0" in readme
    assert "not deployed" in readme.lower()
    assert "official" in readme.lower()
    assert "does not grant permission" in trademarks
    assert "fork" in trademarks.lower() and "rename" in trademarks.lower()
    if PRODUCT == "Witness":
        assert "canonical identity-envelope" in governance
    else:
        assert "Witness" in governance and "digest-locked" in governance


def test_dco_contributions_support_and_github_entrypoints_are_complete():
    contributing = text("CONTRIBUTING.md")
    support = text("SUPPORT.md")
    assert "Developer Certificate of Origin" in contributing
    assert "Signed-off-by:" in contributing
    assert "pull request" in contributing.lower()
    assert "security" in contributing.lower()
    assert "best effort" in support.lower()
    assert "SECURITY.md" in support
    assert (ROOT / ".github" / "ISSUE_TEMPLATE" / "bug_report.yml").is_file()
    assert (ROOT / ".github" / "ISSUE_TEMPLATE" / "feature_request.yml").is_file()
    assert (ROOT / ".github" / "pull_request_template.md").is_file()
    assert (ROOT / "scripts" / "check_dco.py").is_file()
    workflow = text(".github/workflows/ci.yml")
    assert "Verify DCO sign-offs" in workflow
    assert "fetch-depth: 0" in workflow
