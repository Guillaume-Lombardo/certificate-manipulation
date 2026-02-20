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
from certificate_manipulation.exceptions import CertificateParseError, ValidationError
from certificate_manipulation.services.bundle_service import (
    combine,
    convert,
    parse_with_policy,
    split,
)
from tests.cert_factory import make_self_signed_pem


def test_combine_deduplicates_by_fingerprint(tmp_path) -> None:
    cert = make_self_signed_pem("switch-a")
    input_a = tmp_path / "a.crt"
    input_b = tmp_path / "b.crt"
    input_a.write_text(cert, encoding="utf-8")
    input_b.write_text(cert, encoding="utf-8")
    output = tmp_path / "bundle.pem"

    result = combine(
        CombineRequest(
            inputs=[input_a, input_b],
            recursive=False,
            output=output,
            deduplicate=True,
            sort=SortMode.INPUT,
            on_invalid=InvalidCertPolicy.FAIL,
            overwrite=OverwritePolicy.VERSION,
        ),
    )

    assert result.certificate_count == 1
    assert result.report.processed == 2
    assert result.report.written == 1
    assert output.exists()


def test_convert_requires_single_certificate(tmp_path) -> None:
    pem_1 = make_self_signed_pem("switch-a")
    pem_2 = make_self_signed_pem("switch-b")
    source = tmp_path / "bundle.pem"
    source.write_text(f"{pem_1}\n{pem_2}", encoding="utf-8")

    with pytest.raises(ValidationError):
        convert(
            ConvertRequest(
                input=source,
                output=tmp_path / "out.pem",
                to=OutputExt.PEM,
                overwrite=OverwritePolicy.VERSION,
            ),
        )


def test_combine_skip_invalid_files(tmp_path) -> None:
    valid = tmp_path / "valid.crt"
    invalid = tmp_path / "invalid.crt"
    valid.write_text(make_self_signed_pem("switch-c"), encoding="utf-8")
    invalid.write_text("broken", encoding="utf-8")

    result = combine(
        CombineRequest(
            inputs=[valid, invalid],
            recursive=False,
            output=tmp_path / "bundle.pem",
            deduplicate=True,
            sort=SortMode.INPUT,
            on_invalid=InvalidCertPolicy.SKIP,
            overwrite=OverwritePolicy.VERSION,
        ),
    )

    assert result.certificate_count == 1
    assert result.report.invalid_count == 1


def test_combine_skip_keeps_valid_blocks_from_partially_invalid_file(tmp_path) -> None:
    valid = make_self_signed_pem("mixed-ca")
    mixed = tmp_path / "mixed.crt"
    mixed.write_text(
        f"{valid}\n-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----\n",
        encoding="utf-8",
    )

    result = combine(
        CombineRequest(
            inputs=[mixed],
            recursive=False,
            output=tmp_path / "bundle-mixed.pem",
            deduplicate=True,
            sort=SortMode.INPUT,
            on_invalid=InvalidCertPolicy.SKIP,
            overwrite=OverwritePolicy.VERSION,
        ),
    )

    assert result.certificate_count == 1
    assert result.report.invalid_count == 1
    assert result.report.warnings


def test_split_writes_two_output_files(tmp_path) -> None:
    bundle = tmp_path / "bundle.pem"
    pem_1 = make_self_signed_pem("edge-1")
    pem_2 = make_self_signed_pem("edge-2")
    bundle.write_text(f"{pem_1}\n{pem_2}", encoding="utf-8")

    result = split(
        SplitRequest(
            input=bundle,
            output_dir=tmp_path / "split",
            ext=OutputExt.CRT,
            filename_template=SplitNamingStrategy.INDEX,
            on_invalid=InvalidCertPolicy.FAIL,
            overwrite=OverwritePolicy.VERSION,
        ),
    )

    assert len(result.output_paths) == 2
    assert {path.name for path in result.output_paths} == {"cert-001.crt", "cert-002.crt"}


def test_convert_success_with_extension_change(tmp_path) -> None:
    source = tmp_path / "single.crt"
    source.write_text(make_self_signed_pem("single-ca"), encoding="utf-8")

    result = convert(
        ConvertRequest(
            input=source,
            output=tmp_path / "single-output.crt",
            to=OutputExt.PEM,
            overwrite=OverwritePolicy.VERSION,
        ),
    )

    assert result.output_path.suffix == ".pem"
    assert result.report.written == 1


def test_parse_with_policy_skip_invalid_blocks() -> None:
    valid = make_self_signed_pem("policy-ca")
    broken_block = "-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----"

    records, warnings, invalid_count = parse_with_policy(
        f"{valid}\n{broken_block}",
        InvalidCertPolicy.SKIP,
    )

    assert len(records) == 1
    assert warnings
    assert invalid_count == 1


def test_parse_with_policy_fail_raises() -> None:
    with pytest.raises(CertificateParseError):
        parse_with_policy("not a certificate", InvalidCertPolicy.FAIL)
