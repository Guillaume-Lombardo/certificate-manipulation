# AGENTS.md

## Mission

Build and maintain a robust Python package, `certificate-manipulation` (module `certificate_manipulation`), to manipulate certificate files reliably (combine, split, filter, and related operations).

## Product Scope

- Primary user value: deterministic and safe certificate file transformations.
- Supported flow types:
  - combine multiple certificates into a target bundle
  - split bundles/chains into individual certificate files
  - filter certificates by explicit criteria
- Delivery surface:
  - Python package API
  - CLI commands with explicit contracts

## Current Stage

This template includes AI delivery tooling:

- agent governance (`agent.md`)
- reusable project skills (`skills/*`)
- workflow index (`SKILLS.md`)

## Working Rules

- Use English as the default language for docstrings, README, and core project artifacts.
- Allow French only as a secondary translation or complementary version when needed.
- Keep architecture modular and boundaries explicit.
- Keep runtime dependencies explicit and configurable.
- Do not couple business logic to infrastructure details.
- Prefer typed enums for user-facing choices:
  - use `enum.StrEnum` for single-choice values
  - use `enum.Flag`/`enum.IntFlag` for combinable choices
  - provide explicit conversions from `str` to enum/flag and back
- Write Google-style docstrings with explicit types in `Args` and `Returns` (and `Raises` when relevant).
- `Args` entries must follow `name (Type): ...` format.
- `Returns` must always include the explicit return type (for example `int: ...` or `list[str]: ...`).

## Domain Contracts

- Keep certificate operations explicit and typed:
  - operation mode (`combine`, `split`, `filter`, and future additions)
  - deterministic input/output path behavior
  - explicit overwrite policy and conflict handling
- Keep certificate parsing and validation isolated from I/O orchestration.
- Keep filtering criteria explicit (for example issuer/subject/date/fingerprint) with predictable matching rules.
- Ensure all user-facing outputs are stable and reproducible across runs.

## Quality Gates

- Unit tests are the default run target.
- Before closing any PR, run all tests from `tests/unit`, `tests/integration`, and `tests/end2end`.
- Test markers are auto-applied by `tests/conftest.py`.
- Add at least one end-to-end test for each major user-visible flow.
- Add integration tests for boundary behavior when relevant.
- When a bug is reported, write a failing test first, then implement the fix.

## Delivery Workflow

- Implement each run, phase, and feature in a dedicated branch created for that specific scope.
- Do not develop features directly on the main branch.
- Standard Git flow is mandatory for each delivery:
  - commit local changes
  - push feature branch
  - open GitHub Pull Request
- Use PR review and CI as mandatory validation before merge.
- After opening the PR, wait for automatic GitHub Copilot review.
- Analyze all Copilot comments and apply only technically relevant feedback in code/tests/docs.
- Explicitly justify non-relevant feedback in the PR discussion.
- After applying fixes, ask the user whether a new GitHub analysis/review cycle should be triggered.
- If a new analysis is requested, wait for the new review and repeat the analysis/feedback loop until all relevant points are resolved.
- Merge with squash only when CI, review feedback, and user validation are complete.
- After merge, switch back to `main`, pull latest changes, and delete the feature branch locally (and remotely when applicable).
- Before each push/PR, run one explicit dead-code pass and remove unused code/paths/imports no longer referenced.
- Before every push/PR, ensure docs/config bootstrap are synchronized with code changes:
  - update `README.md` when CLI behavior, setup, or workflow changes
  - update `.env.template` when environment variables change
  - update local `.env` accordingly for validation runs
- Before implementation and before merge, review and respect engineering guidance in:
  - `docs/engineering/DEFINITION_OF_DONE.md`
  - `docs/engineering/REVIEW_RUNBOOK.md`
  - `docs/adr/README.md`
- Document architecture decisions in `docs/adr/` whenever a change introduces or modifies a structural/architectural choice.
- Keep unit tests mirrored to package layout under `tests/unit/...`.
- Example: `src/certificate_manipulation/settings.py` maps to `tests/unit/test_settings.py`.
- Do not modify `ruff.toml` unless the user explicitly requests it.

## Pre-PR Checklist

Run locally:

- `uv run ruff format .`
- `uv run ruff check .`
- `uv run ty check src tests`
- `uv run pytest -m unit`
- `uv run pytest -m integration`
- `uv run pytest -m end2end`
- `uv run pre-commit run --all-files`
- Run a dead-code cleanup pass (remove unused code, stale helpers, and obsolete branches).
- Verify Google-style docstrings include explicit types in `Args` and `Returns` for modified code paths.
- Confirm documentation/config sync:
  - `README.md` updated if behavior changed
  - `.env.template` updated if env contract changed
  - local `.env` updated for manual/e2e validation
  - `docs/adr/*` updated when architecture decisions changed

## Skills

Project skills live in `skills/`:

- `skills/architecture/SKILL.md`
- `skills/testing/SKILL.md`
- `skills/code-style/SKILL.md`
- `skills/tooling/SKILL.md`
- `skills/review-followup/SKILL.md`
