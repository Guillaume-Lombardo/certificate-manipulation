# certificate-manipulation

Consolidate, split, filter certificates.

Input formats currently supported:

- PEM/CRT (`.pem`, `.crt`)
- DER/CER (`.der`, `.cer`)
- PKCS7 bundles (`.p7b`, `.p7c`)

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
uv tool run certificate-manipulation combine --inputs ./a.crt ./b.der ./chain.p7b --output ./bundle.pem
uv tool run certificate-manipulation split --input ./bundle.pem --output-dir ./out --ext crt
uv tool run certificate-manipulation convert --input ./a.crt --output ./a.pem --to pem
uv tool run certificate-manipulation filter --input ./bundle.pem --output ./filtered.pem --subject-cn router
uv tool run certificate-manipulation filter --input ./bundle.pem --output ./active.pem --exclude-expired
uv tool run certificate-manipulation filter --input ./bundle.pem --output ./regex.pem --subject-cn-regex "^router-.*"
uv tool run certificate-manipulation filter --input ./bundle.pem --output ./or.pem --subject-cn router --issuer-cn corp-root --logic or
```

## Benchmark

Run a basic performance check on a generated large bundle:

```bash
uv run python scripts/benchmark_large_bundle.py --cert-count 500
```

The script prints JSON timings for `combine`, `split`, and `filter`.
If the workdir already exists, rerun with `--clean`.

### Exit Codes

- `0`: Success
- `1`: Validation error
- `2`: Runtime/parse error
- `3`: Partial success (`--on-invalid skip` with rejected certificates)

## Troubleshooting

- `No PEM certificates found`: ensure files contain `-----BEGIN CERTIFICATE-----` / `-----END CERTIFICATE-----` blocks.
- Exit code `3`: operation completed with `--on-invalid skip`, at least one invalid cert was ignored.
- `No valid certificates found`: input exists but contains no parsable X.509 PEM certificates.
- `No certificates matched filter criteria`: input is valid but your filter is too restrictive.
- Existing output path collisions: default `--overwrite version` writes `name.v2.ext`, `name.v3.ext`, etc.

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
