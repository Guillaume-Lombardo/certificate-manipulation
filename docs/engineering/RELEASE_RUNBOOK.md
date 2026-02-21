# Release Runbook

This runbook defines the hardened process for producing a release.

## Preconditions

- Release work is on a dedicated branch (never directly on `main`).
- CI is green on the release PR.
- Open review conversations are answered and resolved.
- `CHANGELOG.md` has an `Unreleased` section ready to be cut.

## Local Validation Gate

Run all mandatory checks:

```bash
uv run ruff format .
uv run ruff check .
uv run ty check src tests scripts
uv run pytest -m unit
uv run pytest -m integration
uv run pytest -m end2end
uv run pre-commit run --all-files
```

## Prepare Version

1. Update version in:
   - `pyproject.toml`
   - `src/certificate_manipulation/__init__.py`
2. Move relevant items from `Unreleased` to a dated version section in `CHANGELOG.md`.
3. Commit version and changelog update.

## Build and Verify Artifacts

```bash
uv run python -m build
uv run twine check dist/*
```

## Publish Flow

1. Merge release PR into `main` (squash merge).
2. Sync local `main`:

```bash
git checkout main
git pull --ff-only
```

3. Create and push tag:

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

4. Verify GitHub release workflow completion.

## Post-Release

- Confirm package availability on target index (PyPI/TestPyPI).
- Add follow-up issue for any deferred release debt.
