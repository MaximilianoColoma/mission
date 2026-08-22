# Contributing

Thank you for helping improve the project. Start with an issue for material behavior, contract, identity, persistence, or compatibility changes.

## Workflow

1. Fork the repository and create a focused branch.
2. Add or update acceptance tests before implementation.
3. Run the complete local verification command from `README.md`.
4. Submit a pull request using the template and explain contract, security, compatibility, evidence, and rollback effects.
5. Address maintainer review; protected CI must pass before merge.

Security vulnerabilities must not be filed as public issues. Follow `SECURITY.md`.

## Developer Certificate of Origin

Contributions use the Developer Certificate of Origin 1.1. By adding a sign-off, you certify that you have the right to submit the contribution under the project license.

Sign every commit with:

```text
Signed-off-by: Your Name <your.email@example.com>
```

Git can add this using `git commit -s`. The sign-off is a provenance statement, not a copyright assignment or CLA.

## Scope and conduct

Keep changes bounded, avoid unrelated rewrites, preserve one canonical authority per contract, and never include credentials, personal data, generated environments, or proprietary third-party material. Maintainers may request a smaller change or an explicit migration plan.
