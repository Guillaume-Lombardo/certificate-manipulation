# certificate-manipulation

Consolidate, split, filter certificates.

## Quickstart

```bash
uv sync --group dev
uv run pre-commit install
uv run ruff format .
uv run ruff check .
uv run ty check src tests
uv run pytest
uv run pre-commit run --all-files
```

## CLI Usage

```bash
uv tool run certificate-manipulation --help
uv tool run certificate-manipulation combine --inputs ./a.crt ./b.pem --output ./bundle.pem
uv tool run certificate-manipulation split --input ./bundle.pem --output-dir ./out --ext crt
uv tool run certificate-manipulation convert --input ./a.crt --output ./a.pem --to pem
uv tool run certificate-manipulation filter --input ./bundle.pem --output ./filtered.pem --subject-cn router
uv tool run certificate-manipulation filter --input ./bundle.pem --output ./active.pem --exclude-expired
```

### Exit Codes

- `0`: Success
- `1`: Validation error
- `2`: Runtime/parse error
- `3`: Partial success (`--on-invalid skip` with rejected certificates)

## Project Layout

- `src/certificate_manipulation`: package code
- `tests/unit`: fast default tests
- `tests/integration`: component-level tests
- `tests/end2end`: user-facing behavior tests
- `skills`: AI helper skills for coding workflows

## Release

1. Bump `version` in `pyproject.toml`.
2. Create and push a git tag: `vX.Y.Z`.
3. GitHub Action publishes to PyPI.

For manual validation, use workflow dispatch with `publish_target=testpypi`.
