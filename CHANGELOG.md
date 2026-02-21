# Changelog

All notable changes to this project are documented in this file.

The format is inspired by Keep a Changelog and this project follows Semantic Versioning targets for the upcoming `1.0.0` release.

## [Unreleased]

- No unreleased changes yet.

## [1.0.0] - 2026-02-21

### Added

- Frozen public contract baseline for CLI and Python API in `docs/engineering/CONTRACTS.md`.
- Hardened release process in `docs/engineering/RELEASE_RUNBOOK.md`.
- Contract regression tests for CLI help surface and Python public exports.
- Formal changelog tracking included in source distributions.

### Changed

- Release documentation in `README.md` now delegates to the release runbook.
- Engineering docs index now links contract and release governance artifacts.

## [0.1.0] - 2026-02-21

### Added

- Initial package release with deterministic CLI for certificate workflows:
  - `combine`
  - `split`
  - `convert`
  - `filter`
- Strongly typed domain models and enums for public contracts.
- Overwrite strategies (`version`, `force`, `fail`) and invalid certificate handling (`fail`, `skip`).
- Project quality gates and CI for formatting, linting, typing, and tests.
- CI benchmark workflow with machine-readable artifact output and threshold checks.
- Benchmark script support for JSON report export and threshold assertions.
- CLI `--report-json` option on `combine`, `split`, `convert`, and `filter`.
- Extended certificate input format support for DER/CER and PKCS7 bundles.
- Advanced filter options with regex matching and criteria combination mode (`AND`/`OR`).
- Filter option to exclude expired certificates (`--exclude-expired`).
- End-to-end and unit tests for contract and benchmark behavior.

### Changed

- CLI dispatch logic refactored into command-specific functions.
- Documentation extended with benchmark usage and release guidance.
