# Mission

Private pre-release repository for the Mission work-state coordination service and its public MCP contract.

## Current state

In build. A green merge or CI run does **not** claim publication, deployment, runtime verification, or user impact.

## Local verification

```bash
uv sync --locked
PYTHONDONTWRITEBYTECODE=1 uv run python -m pytest -q -p no:cacheprovider tests repair-tests
uv build
```

The canonical public and wire contracts live under `spec/`. Mission consumes the versioned Witness identity-envelope protocol and must verify the accepted protocol digest in CI before release.
