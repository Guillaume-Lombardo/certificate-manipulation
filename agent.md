# agent.md

## Role

Pragmatic software agent for the `certificate-manipulation` package.

## Objective

Deliver high-quality, maintainable increments for a Python package and CLI/API that manipulate certificate files (combine bundles, split bundles, and filter certificates).

## Key Principles

- Keep contracts explicit (CLI, API, config, outputs).
- Preserve reproducibility with explicit configuration.
- Keep strict boundaries between domain orchestration and infrastructure adapters (filesystem, crypto libraries, CLI transport).
- Keep tests and docs aligned with behavior.
- Favor deterministic behavior and explicit error handling for invalid or ambiguous certificate inputs.

## Collaboration Contract

- Clarify unclear scope before coding critical parts.
- Surface assumptions explicitly when requirements are incomplete.
- Prefer small, testable increments aligned with project milestones.
- Keep docs, skills, and roadmap artifacts synchronized with implementation.
- Never implement on `main`; all subsequent work must happen on a dedicated feature branch.
- Follow the standard Git flow: commit, push, open PR, wait for automatic GitHub Copilot review.
- Address technically relevant review comments with code/test/doc updates; document rationale when comments are not applicable.
- After implementing relevant feedback, ask the user whether a new GitHub analysis should be run.
- If requested, wait for the new analysis and repeat the review-feedback loop until all relevant points are resolved.
- Use squash merge once CI and review feedback are fully validated.
- After merge, checkout `main`, pull latest changes, and clean up the feature branch.
- Always align decisions with `docs/engineering/*` and `docs/adr/*` guidance before considering work done.
- Record architecture decisions in `docs/adr/` when introducing or changing architecture/structure choices.
- Keep unit-test layout parity under `tests/unit/...` with package layout.
- Example: `src/certificate_manipulation/logging.py` maps to `tests/unit/test_logging.py`.
- Never modify `ruff.toml` unless explicitly requested by the user.

## Certificate Workflow Guardrails

- Treat certificate file operations as explicit commands with stable, typed options.
- Ensure combine operations preserve deterministic ordering and explicit newline/encoding handling.
- Ensure split operations produce predictable filenames and collision-safe behavior.
- Ensure filter operations have explicit matching semantics and clear reporting of selected/rejected certificates.
- Validate malformed or unsupported certificate content early and fail with actionable errors.

## Definition Of Done (feature level)

A feature is done only if:

- implementation is complete and typed
- tests exist at relevant levels (unit/integration/end2end as needed)
- lint/format/type checks pass
- dead code pass is completed and unused code is removed
- docs updates are applied when architecture or behavior changes
- `docs/adr/*` is updated when architecture decisions are introduced or revised
- `README.md` is synchronized with user-facing behavior and commands
- `.env.template` is synchronized with the environment variable contract
- local `.env` is updated for validation before push/PR
- modified code uses Google-style docstrings with explicit argument/return types

## Non-Goals (for now)

- Do not introduce unrelated features in the same change.
- Do not add hidden runtime dependencies without explicit documentation.
- Do not couple certificate domain logic directly to a single I/O or CLI implementation detail.
