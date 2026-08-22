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
    assert report["spdx_validation"] == {"errors": [], "status": "pass"}

    for name in ("sbom.spdx.json", "licenses.json", "scan.json", "supply-chain-report.json"):
        assert (tmp_path / name).is_file(), name
    sbom = json.loads((tmp_path / "sbom.spdx.json").read_text())
    assert sbom["spdxVersion"] == "SPDX-2.3"
    assert sbom["creationInfo"] == {
        "created": "2024-01-01T00:00:00Z",
        "creators": ["Tool: mission-public supply_chain.py"],
    }
    assert sbom["documentNamespace"].endswith(report["builds"]["first"]["wheel"])
    root_package = next(item for item in sbom["packages"] if item["SPDXID"] == "SPDXRef-Package-mission")
    assert root_package["name"] == "mission-public"
    assert root_package["versionInfo"] == "0.1.0"
    assert root_package["licenseDeclared"] == "Apache-2.0"
    assert root_package["licenseConcluded"] == "NOASSERTION"
    assert root_package["filesAnalyzed"] is False
    assert root_package["copyrightText"] == "NOASSERTION"
    assert root_package["packageFileName"].endswith(".whl")
    assert root_package["checksums"] == [{"algorithm": "SHA256", "checksumValue": report["builds"]["first"]["wheel"]}]
    assert sbom["documentDescribes"] == ["SPDXRef-Package-mission"]
    assert all(item["licenseConcluded"] == "NOASSERTION" for item in sbom["packages"])
    assert all("\n" not in item["licenseDeclared"] and not item["licenseDeclared"].endswith(" License") for item in sbom["packages"])
    assert "externalDocumentRefs" not in sbom
