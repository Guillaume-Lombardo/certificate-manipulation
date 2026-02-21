# Public Contracts

This document defines the stability boundary to prepare `certificate-manipulation` for `1.0.0`.

## Stability Policy

- CLI command names and options listed below are considered stable for `1.0.0`.
- Python symbols exported in `src/certificate_manipulation/__init__.py` are considered stable for `1.0.0`.
- Any breaking change to these contracts must:
  - be documented in `CHANGELOG.md`,
  - be highlighted in PR scope/impact,
  - include migration notes.

## Stable CLI Surface

Root command:

- `certificate-manipulation`

Subcommands:

- `combine`
- `split`
- `convert`
- `filter`

Common behavior contracts:

- deterministic exit codes:
  - `0`: success
  - `1`: validation error
  - `2`: runtime/parse error
  - `3`: partial success (`--on-invalid skip` with rejected certificates)
- default overwrite policy: `version`
- default invalid certificate policy: `fail`

Command options (stable):

- `combine`:
  - `--inputs`
  - `--recursive`
  - `--output`
  - `--deduplicate`
  - `--sort`
  - `--on-invalid`
  - `--overwrite`
  - `--report-json`
- `split`:
  - `--input`
  - `--output-dir`
  - `--ext`
  - `--filename-template`
  - `--on-invalid`
  - `--overwrite`
  - `--report-json`
- `convert`:
  - `--input`
  - `--output`
  - `--to`
  - `--overwrite`
  - `--report-json`
- `filter`:
  - `--input`
  - `--output`
  - `--subject-cn`
  - `--subject-cn-regex`
  - `--issuer-cn`
  - `--issuer-cn-regex`
  - `--not-after-lt`
  - `--not-before-gt`
  - `--fingerprint`
  - `--exclude-expired`
  - `--logic`
  - `--on-invalid`
  - `--overwrite`
  - `--report-json`

## Stable Python API Surface

Public symbols are exported from `src/certificate_manipulation/__init__.py`.

Core functions:

- `combine`
- `split`
- `convert`
- `filter_certificates`
- `configure_logging`
- `get_logger`
- `get_settings`
- `run_async`

Core data models:

- `CertificateRecord`
- `OperationReport`
- `CombineRequest` / `CombineResult`
- `SplitRequest` / `SplitResult`
- `ConvertRequest` / `ConvertResult`
- `FilterRequest` / `FilterResult`

Core enums:

- `CliCommand`
- `OutputExt`
- `OverwritePolicy`
- `InvalidCertPolicy`
- `SortMode`
- `SplitNamingStrategy`
- `FilterLogicMode`

Exceptions:

- `PackageError`
- `ValidationError`
- `OperationError`
- `CertificateParseError`
- `SettingsError`
- `AsyncExecutionError`
