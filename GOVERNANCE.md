# Governance

## Official project

Mission is maintained as the official upstream project by Maximiliano Coloma-Seegers, acting as Benevolent Dictator for the project. Maintainers may be appointed for bounded areas and remain accountable to the published contracts and security policy.

Apache-2.0 permits forks. Official status, project names, release channels, compatibility claims, and security advisories remain governed here; see `TRADEMARKS.md`.

## Decision process

Substantial changes begin as an issue or design discussion and arrive through a pull request. Maintainers seek reasoned consensus. When consensus is unavailable, the Benevolent Dictator decides transparently using this priority: security and truth, contract authority, backwards Compatibility, maintainability, then delivery speed.

## Canonical authority

The public and wire contracts under `spec/` govern Mission. The canonical identity-envelope contract lives in the official Witness repository; Mission consumes a versioned, digest-locked projection. Mission must not become a second protocol authority.

## Contributions

Contributions use the Developer Certificate of Origin process in `CONTRIBUTING.md`. Passing CI is necessary but not sufficient for acceptance. Maintainers may decline changes that fragment contracts, weaken default-deny Security, add unbounded authority, or create an unsustainable maintenance burden.

## Release

A Release requires protected-main CI, reproducible artifacts, SBOM and license reconciliation, secret/PII scans, an immutable manifest, and independent validation. A tag or GitHub release does not claim deployment or user impact.

## Security and compatibility

Security reports follow `SECURITY.md`. Compatibility is measured against declared public/wire contracts and published migration notes; repository visibility does not relax identity, privacy, audit, or fail-closed requirements.
