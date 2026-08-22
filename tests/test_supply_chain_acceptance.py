"""GHR-007 preimplementation acceptance for reproducible, reconciled supply-chain evidence."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

PRODUCT = "mission"
PACKAGE = "mission_public"


def test_two_builds_sbom_licenses_imports_and_scans_bind_same_artifacts(tmp_path):
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, str(root / "scripts" / "supply_chain.py"), "--output", str(tmp_path)],
        cwd=root, text=True, capture_output=True, timeout=240,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout.splitlines()[-1])
    assert report["status"] == "pass"
    assert report["product"] == PRODUCT
    assert report["builds"]["first"] == report["builds"]["second"]
    assert set(report["builds"]["first"]) == {"wheel", "sdist"}
    assert all(len(value) == 64 for value in report["builds"]["first"].values())
    assert report["reconciliation"]["package"] == PACKAGE
    assert report["reconciliation"]["missing_expected_files"] == []
    assert report["reconciliation"]["unexpected_import_roots"] == []
    assert report["scans"] == {"pii_findings": [], "secret_findings": []}
    assert report["licenses"]["unknown"] == []

    for name in ("sbom.spdx.json", "licenses.json", "scan.json", "supply-chain-report.json"):
        assert (tmp_path / name).is_file(), name
    sbom = json.loads((tmp_path / "sbom.spdx.json").read_text())
    assert sbom["spdxVersion"] == "SPDX-2.3"
    assert sbom["documentNamespace"].endswith(report["builds"]["first"]["wheel"])
    assert {item["name"] for item in sbom["packages"]} >= {PRODUCT}
    assert sbom["externalDocumentRefs"][0]["checksum"]["checksumValue"] == report["builds"]["first"]["wheel"]
