# SKILLS.md

## Purpose

This file maps project delivery skills to the `certificate-manipulation` roadmap and clarifies when each skill should be applied during implementation and review cycles.

## Core Skills (Project Local)

- `skills/architecture/SKILL.md`
  - Use for module boundaries, operation orchestration design, and explicit contracts between domain logic and adapters.
- `skills/testing/SKILL.md`
  - Use for test strategy across unit/integration/end2end and when adding regression tests for bugs.
- `skills/code-style/SKILL.md`
  - Use for style/lint/type consistency, docstring format, and enum/model conventions.
- `skills/tooling/SKILL.md`
  - Use for local tooling workflow (`uv`, `ruff`, `ty`, `pytest`, `pre-commit`) and dev setup reliability.
- `skills/review-followup/SKILL.md`
  - Use to close review comments and ensure PR feedback is fully addressed.

## Skill Usage by Milestone

- M1 (Core CLI/API)
  - Prioritize: architecture + testing + tooling.
  - Focus: base contracts, deterministic I/O behavior, and baseline command behavior.
- M2 (Certificate Operations)
  - Prioritize: architecture + testing.
  - Focus: combine/split/filter flows, boundary handling, and predictable error surfaces.
- M3 (Hardening)
  - Prioritize: architecture + testing + review-followup.
  - Focus: malformed input handling, edge-case robustness, and observability/logging quality.

## Operating Rules

- Prefer the smallest skill set that fully covers the task.
- Keep artifacts in English by default (French as complementary only if needed).
- Update this file if new project-local skills are added or if roadmap ownership changes significantly.
- Enforce docstring typing for modified code:
  - `Args` entries use `name (Type): ...`
  - `Returns` always starts with explicit type (`Type: ...`)
- For delivery execution, enforce the Git workflow loop:
  - commit + push + PR
  - wait for GitHub Copilot automatic review
  - analyze comments and apply relevant fixes
  - comment each review conversation with resolution details or rationale
  - resolve conversations only after the explanation comment is posted
  - ask user if a new GitHub analysis should be triggered
  - repeat when needed, then squash merge
  - return to `main`, pull, and clean feature branch
- Before implementation/review completion, read and apply:
  - `docs/engineering/DEFINITION_OF_DONE.md`
  - `docs/engineering/REVIEW_RUNBOOK.md`
  - `docs/adr/README.md`
