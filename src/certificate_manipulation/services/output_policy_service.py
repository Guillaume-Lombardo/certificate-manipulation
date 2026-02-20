"""Output conflict policy helpers."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from certificate_manipulation.domain.enums import OverwritePolicy
from certificate_manipulation.exceptions import ValidationError

if TYPE_CHECKING:
    from pathlib import Path


def resolve_output_path(output: Path, policy: OverwritePolicy) -> Path:
    """Resolve final path according to overwrite policy.

    Args:
        output (Path): Requested output path.
        policy (OverwritePolicy): Overwrite policy.

    Raises:
        ValidationError: If policy is fail and target exists.

    Returns:
        Path: Writable output path.
    """
    output = output.expanduser()
    if not output.exists():
        return output

    if policy == OverwritePolicy.FORCE:
        return output
    if policy == OverwritePolicy.FAIL:
        raise ValidationError(message=f"Output file already exists: {output}")

    return _versioned_path(output)


def _versioned_path(path: Path) -> Path:
    stem = path.stem
    match = re.search(r"\.v(\d+)$", stem)
    index = 2
    if match:
        stem = stem[: match.start()]
        index = int(match.group(1)) + 1

    suffix = path.suffix
    parent = path.parent

    while True:
        candidate = parent / f"{stem}.v{index}{suffix}"
        if not candidate.exists():
            return candidate
        index += 1
