#!/usr/bin/env python3
"""Build twice and bind SBOM, licenses, import reconciliation and scans to artifact digests."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile

PRODUCT = "mission"
DISTRIBUTION = "mission-public"
PACKAGE = "mission_public"
SECRET_PATTERNS = {
    "private_key": re.compile(r"-----BEGIN[A-Z ]*PRIVATE KEY-----"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b"),
    "stripe_secret": re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{10,}\b"),
}
PII_PATTERNS = {
    "email": re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])"),
}
SPDX_LICENSES = {
    "Apache-2.0", "Apache-2.0 OR BSD-2-Clause", "Apache-2.0 OR BSD-3-Clause",
    "BSD-2-Clause", "BSD-3-Clause", "ISC", "MIT", "MIT-0", "MPL-2.0",
    "PSF-2.0", "Unlicense",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def clean(root: Path) -> None:
    for path in (root / "build", root / "dist"):
        shutil.rmtree(path, ignore_errors=True)
    for path in (root / "src").glob("*.egg-info"):
        shutil.rmtree(path, ignore_errors=True)


def normalize_sdist(path: Path) -> None:
    """Rewrite tar/gzip metadata so equal sources produce equal archives."""
    entries: list[tuple[tarfile.TarInfo, bytes]] = []
    with tarfile.open(path, "r:gz") as archive:
        for member in sorted(archive.getmembers(), key=lambda item: item.name):
            payload = archive.extractfile(member).read() if member.isfile() else b""
            member.mtime = 1704067200
            member.uid = member.gid = 0
            member.uname = member.gname = ""
            member.pax_headers = {}
            entries.append((member, payload))
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for member, payload in entries:
            archive.addfile(member, io.BytesIO(payload) if member.isfile() else None)
    with path.open("wb") as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=1704067200) as compressed:
            compressed.write(raw.getvalue())


def build(root: Path, destination: Path) -> dict[str, Path]:
    clean(root)
    destination.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["SOURCE_DATE_EPOCH"] = "1704067200"
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    result = subprocess.run(
        ["uv", "build", "--out-dir", str(destination)], cwd=root, env=env,
        text=True, capture_output=True, timeout=180,
    )
    if result.returncode:
        raise RuntimeError(result.stderr or result.stdout)
    wheel = next(destination.glob("*.whl"))
    sdist = next(destination.glob("*.tar.gz"))
    normalize_sdist(sdist)
    clean(root)
    return {"wheel": wheel, "sdist": sdist}


def license_inventory() -> tuple[list[dict], list[str], list[str]]:
    packages: dict[str, dict] = {}
    unknown: list[str] = []
    owner_decisions: list[str] = []
    for dist in importlib.metadata.distributions():
        name = dist.metadata.get("Name")
        if not name:
            continue
        normalized = name.lower()
        expression = dist.metadata.get("License-Expression") or dist.metadata.get("License")
        if not expression:
            classifiers = [item for item in (dist.metadata.get_all("Classifier") or []) if item.startswith("License ::")]
            expression = classifiers[-1].split("::")[-1].strip() if classifiers else None
        if normalized == DISTRIBUTION and not expression:
            owner_decisions.append(normalized)
            expression = "NOASSERTION_OWNER_DECISION"
        elif not expression:
            unknown.append(normalized)
            expression = "NOASSERTION"
        packages[normalized] = {"name": normalized, "version": dist.version, "license": expression}
    return sorted(packages.values(), key=lambda item: item["name"]), sorted(set(unknown)), sorted(set(owner_decisions))


def spdx_license(expression: str) -> str:
    """Return a valid declared SPDX expression without guessing ambiguous licenses."""
    if expression in SPDX_LICENSES:
        return expression
    if expression == "MIT License" or "Permission is hereby granted, free of charge" in expression:
        return "MIT"
    return "NOASSERTION"


def validate_spdx(sbom: dict) -> dict[str, object]:
    """Fail closed on the SPDX invariants this deterministic generator owns."""
    errors: list[str] = []
    creation = sbom.get("creationInfo", {})
    if not creation.get("created") or not creation.get("creators"):
        errors.append("creationInfo")
    packages = sbom.get("packages", [])
    ids = [item.get("SPDXID") for item in packages]
    if len(ids) != len(set(ids)) or any(not item for item in ids):
        errors.append("package-SPDXID")
    for package in packages:
        for field in ("name", "SPDXID", "versionInfo", "downloadLocation", "filesAnalyzed", "licenseConcluded", "licenseDeclared", "copyrightText"):
            if field not in package:
                errors.append(f"{package.get('SPDXID', 'unknown')}:{field}")
        for field in ("licenseConcluded", "licenseDeclared"):
            value = package.get(field)
            if value != "NOASSERTION" and value not in SPDX_LICENSES:
                errors.append(f"{package.get('SPDXID', 'unknown')}:{field}:invalid")
    if sbom.get("documentDescribes") != [f"SPDXRef-Package-{PRODUCT}"]:
        errors.append("documentDescribes")
    return {"status": "pass" if not errors else "blocked", "errors": sorted(set(errors))}


def scan(root: Path) -> dict[str, list[dict]]:
    findings = {"secret_findings": [], "pii_findings": []}
    paths = []
    for base in (root / "src", root / "spec", root / "scripts"):
        paths.extend(path for path in base.rglob("*") if path.is_file() and path.suffix in {".py", ".json", ".md", ".sh"})
    for path in sorted(paths):
        text = path.read_text(encoding="utf-8", errors="strict")
        relative = str(path.relative_to(root))
        for label, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(text):
                findings["secret_findings"].append({"file": relative, "class": label, "line": text.count("\n", 0, match.start()) + 1})
        for label, pattern in PII_PATTERNS.items():
            for match in pattern.finditer(text):
                findings["pii_findings"].append({"file": relative, "class": label, "line": text.count("\n", 0, match.start()) + 1})
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    root = Path(__file__).resolve().parents[1]
    first_paths = build(root, output / "build-1")
    second_paths = build(root, output / "build-2")
    first = {kind: sha(path) for kind, path in first_paths.items()}
    second = {kind: sha(path) for kind, path in second_paths.items()}

    with zipfile.ZipFile(first_paths["wheel"]) as archive:
        files = sorted(archive.namelist())
    expected = {f"{PACKAGE}/__init__.py", f"{PACKAGE}/server.py", f"{PACKAGE}/request-schemas.json"}
    missing = sorted(expected - set(files))
    roots = {name.split("/", 1)[0] for name in files if "/" in name and ".dist-info/" not in name}
    unexpected_roots = sorted(roots - {PACKAGE})

    packages, unknown, owner_decisions = license_inventory()
    licenses = {"packages": packages, "unknown": unknown, "owner_decisions": owner_decisions}
    scans = scan(root)
    root_metadata = next(item for item in packages if item["name"] == DISTRIBUTION)
    dependency_metadata = [item for item in packages if item["name"] != DISTRIBUTION]
    root_package = {
        "name": DISTRIBUTION,
        "SPDXID": f"SPDXRef-Package-{PRODUCT}",
        "versionInfo": root_metadata["version"],
        "packageFileName": first_paths["wheel"].name,
        "downloadLocation": f"https://github.com/MaximilianoColoma/{PRODUCT}/releases/download/v{root_metadata['version']}/{first_paths['wheel'].name}",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": spdx_license(root_metadata["license"]),
        "copyrightText": "NOASSERTION",
        "checksums": [{"algorithm": "SHA256", "checksumValue": first["wheel"]}],
    }
    dependency_packages = [
        {
            "name": item["name"], "SPDXID": f"SPDXRef-Package-{index}",
            "versionInfo": item["version"], "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False, "licenseConcluded": "NOASSERTION",
            "licenseDeclared": spdx_license(item["license"]), "copyrightText": "NOASSERTION",
        }
        for index, item in enumerate(dependency_metadata)
    ]
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{PRODUCT}-supply-chain",
        "documentNamespace": f"https://github.com/MaximilianoColoma/{PRODUCT}/sbom/{first['wheel']}",
        "creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": [f"Tool: {DISTRIBUTION} supply_chain.py"]},
        "documentDescribes": [f"SPDXRef-Package-{PRODUCT}"],
        "packages": [root_package] + dependency_packages,
    }
    spdx_validation = validate_spdx(sbom)
    status = "pass" if first == second and not missing and not unexpected_roots and not unknown and not any(scans.values()) and spdx_validation["status"] == "pass" else "blocked"
    report = {
        "status": status, "product": PRODUCT, "builds": {"first": first, "second": second},
        "reconciliation": {"package": PACKAGE, "missing_expected_files": missing, "unexpected_import_roots": unexpected_roots},
        "scans": scans, "licenses": {"unknown": unknown, "owner_decisions": owner_decisions}, "spdx_validation": spdx_validation,
        "statement_limit": "Build and supply-chain evidence only; owner license choice, release, publication and deployment remain separate gates.",
    }
    (output / "sbom.spdx.json").write_text(json.dumps(sbom, indent=2, sort_keys=True) + "\n")
    (output / "licenses.json").write_text(json.dumps(licenses, indent=2, sort_keys=True) + "\n")
    (output / "scan.json").write_text(json.dumps(scans, indent=2, sort_keys=True) + "\n")
    (output / "supply-chain-report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if status == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
