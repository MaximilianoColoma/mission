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
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{PRODUCT}-supply-chain",
        "documentNamespace": f"https://github.com/MaximilianoColoma/{PRODUCT}/sbom/{first['wheel']}",
        "packages": [{"name": PRODUCT, "SPDXID": f"SPDXRef-Package-{PRODUCT}", "versionInfo": "0.0.0", "downloadLocation": "NOASSERTION", "licenseConcluded": "NOASSERTION"}] + [
            {"name": item["name"], "SPDXID": f"SPDXRef-Package-{index}", "versionInfo": item["version"], "downloadLocation": "NOASSERTION", "licenseConcluded": item["license"]}
            for index, item in enumerate(packages)
        ],
        "externalDocumentRefs": [{"externalDocumentId": "DocumentRef-wheel", "spdxDocument": first_paths["wheel"].name, "checksum": {"algorithm": "SHA256", "checksumValue": first["wheel"]}}],
    }
    status = "pass" if first == second and not missing and not unexpected_roots and not unknown and not any(scans.values()) else "blocked"
    report = {
        "status": status, "product": PRODUCT, "builds": {"first": first, "second": second},
        "reconciliation": {"package": PACKAGE, "missing_expected_files": missing, "unexpected_import_roots": unexpected_roots},
        "scans": scans, "licenses": {"unknown": unknown, "owner_decisions": owner_decisions},
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
