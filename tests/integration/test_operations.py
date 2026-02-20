from __future__ import annotations

import pytest

from certificate_manipulation.domain.enums import (
    InvalidCertPolicy,
    OutputExt,
    OverwritePolicy,
    SortMode,
    SplitNamingStrategy,
)
from certificate_manipulation.domain.models import (
    CombineRequest,
    ConvertRequest,
    SplitRequest,
)
from certificate_manipulation.exceptions import CertificateParseError
from certificate_manipulation.services.bundle_service import combine, convert, split
from tests.cert_factory import make_self_signed_pem


def test_combine_fail_and_skip_invalid(tmp_path) -> None:
    valid = tmp_path / "valid.crt"
    invalid = tmp_path / "invalid.crt"
    valid.write_text(make_self_signed_pem("ca-1"), encoding="utf-8")
    invalid.write_text("broken cert", encoding="utf-8")

    with pytest.raises(CertificateParseError):
        combine(
            CombineRequest(
                inputs=[valid, invalid],
                recursive=False,
                output=tmp_path / "bundle-fail.pem",
                deduplicate=True,
                sort=SortMode.INPUT,
                on_invalid=InvalidCertPolicy.FAIL,
                overwrite=OverwritePolicy.VERSION,
            ),
        )

    result = combine(
        CombineRequest(
            inputs=[valid, invalid],
            recursive=False,
            output=tmp_path / "bundle-skip.pem",
            deduplicate=True,
            sort=SortMode.INPUT,
            on_invalid=InvalidCertPolicy.SKIP,
            overwrite=OverwritePolicy.VERSION,
        ),
    )
    assert result.certificate_count == 1
    assert result.report.invalid_count == 1


def test_split_handles_cn_collisions(tmp_path) -> None:
    pem_a = make_self_signed_pem("core-ca")
    pem_b = make_self_signed_pem("core-ca")
    bundle = tmp_path / "bundle.pem"
    bundle.write_text(f"{pem_a}\n{pem_b}", encoding="utf-8")

    result = split(
        SplitRequest(
            input=bundle,
            output_dir=tmp_path / "split",
            ext=OutputExt.CRT,
            filename_template=SplitNamingStrategy.CN,
            on_invalid=InvalidCertPolicy.FAIL,
            overwrite=OverwritePolicy.VERSION,
        ),
    )

    names = sorted(path.name for path in result.output_paths)
    assert names == ["core-ca-2.crt", "core-ca.crt"]


def test_convert_versions_when_output_exists(tmp_path) -> None:
    source = tmp_path / "source.crt"
    source.write_text(make_self_signed_pem("edge-ca"), encoding="utf-8")
    output = tmp_path / "edge.pem"
    output.write_text("old", encoding="utf-8")

    result = convert(
        ConvertRequest(
            input=source,
            output=output,
            to=OutputExt.PEM,
            overwrite=OverwritePolicy.VERSION,
        ),
    )

    assert result.output_path.name == "edge.v2.pem"
