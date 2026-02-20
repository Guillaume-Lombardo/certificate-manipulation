# Troubleshooting

## Common errors

### `No PEM certificates found`

Cause: input content does not contain valid PEM certificate boundaries.

Checks:

- verify the file contains `-----BEGIN CERTIFICATE-----`
- verify the file contains `-----END CERTIFICATE-----`
- verify file encoding is UTF-8 text

### Exit code `3`

Cause: operation succeeded with partial data because `--on-invalid skip` ignored invalid certificate blocks/files.

Checks:

- inspect warnings in logs
- rerun with `--on-invalid fail` to identify first failing certificate

### `No valid certificates found in input bundle`

Cause: input bundle exists but no certificate block could be parsed.

Checks:

- run `split` or `filter` input through a text viewer and inspect malformed blocks
- confirm all certificates are PEM X.509 (DER/P7B are not supported in V1/V2)

### `No certificates matched filter criteria`

Cause: certificates are valid but filter criteria are too restrictive.

Checks:

- remove filters one by one (`--subject-cn`, `--issuer-cn`, dates, fingerprint)
- test with only one criterion to locate the mismatch

## Operational tips

- Keep `--overwrite version` for deterministic non-destructive outputs.
- Prefer `--filename-template fingerprint` when CN collisions are likely.
- Use `scripts/benchmark_large_bundle.py` to detect local performance regressions before PR.
