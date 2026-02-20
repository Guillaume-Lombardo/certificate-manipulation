from __future__ import annotations

import pytest

from certificate_manipulation.domain.enums import OverwritePolicy
from certificate_manipulation.exceptions import ValidationError
from certificate_manipulation.services.output_policy_service import resolve_output_path


def test_version_policy_adds_incremented_suffix(tmp_path) -> None:
    base = tmp_path / "bundle.crt"
    base.write_text("x", encoding="utf-8")
    (tmp_path / "bundle.v2.crt").write_text("x", encoding="utf-8")

    resolved = resolve_output_path(base, OverwritePolicy.VERSION)

    assert resolved.name == "bundle.v3.crt"


def test_fail_policy_raises_when_output_exists(tmp_path) -> None:
    base = tmp_path / "bundle.crt"
    base.write_text("x", encoding="utf-8")

    with pytest.raises(ValidationError):
        resolve_output_path(base, OverwritePolicy.FAIL)
