from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from certificate_manipulation.domain.enums import (
    FilterLogicMode,
    InvalidCertPolicy,
    OutputExt,
    OverwritePolicy,
    SortMode,
    SplitNamingStrategy,
)
from certificate_manipulation.domain.models import (
    CertificateRecord,
    CombineRequest,
    ConvertRequest,
    FilterRequest,
    SplitRequest,
)
from certificate_manipulation.exceptions import CertificateParseError, ValidationError
from certificate_manipulation.services.bundle_service import (
    combine,
    convert,
    filter_certificates,
    matches_filter,
    parse_file_with_policy,
    split,
)
from tests.cert_factory import (
    make_pkcs7_bundle_der,
    make_pkcs7_bundle_pem,
    make_self_signed_der,
    make_self_signed_pem,
)


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


def test_parse_file_with_policy_skip_invalid_blocks(tmp_path) -> None:
    valid = make_self_signed_pem("policy-ca")
    broken_block = "-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----"
    bundle = tmp_path / "mixed.pem"
    bundle.write_text(f"{valid}\n{broken_block}", encoding="utf-8")

    records, warnings, invalid_count = parse_file_with_policy(
        bundle,
        InvalidCertPolicy.SKIP,
    )

    assert len(records) == 1
    assert warnings
    assert invalid_count == 1


def test_parse_file_with_policy_fail_raises(tmp_path) -> None:
    invalid = tmp_path / "broken.pem"
    invalid.write_text("not a certificate", encoding="utf-8")

    with pytest.raises(CertificateParseError):
        parse_file_with_policy(invalid, InvalidCertPolicy.FAIL)


def test_split_accepts_der_input(tmp_path) -> None:
    der_input = tmp_path / "single.der"
    der_input.write_bytes(make_self_signed_der("der-input"))

    result = split(
        SplitRequest(
            input=der_input,
            output_dir=tmp_path / "split-der",
            ext=OutputExt.CRT,
            filename_template=SplitNamingStrategy.CN,
            on_invalid=InvalidCertPolicy.FAIL,
            overwrite=OverwritePolicy.VERSION,
        ),
    )

    assert len(result.output_paths) == 1
    content = result.output_paths[0].read_text(encoding="utf-8")
    assert "BEGIN CERTIFICATE" in content


def test_filter_accepts_p7b_input(tmp_path) -> None:
    p7b_input = tmp_path / "bundle.p7b"
    p7b_input.write_text(make_pkcs7_bundle_pem(["p7b-router", "p7b-switch"]), encoding="utf-8")

    result = filter_certificates(
        FilterRequest(
            input=p7b_input,
            output=tmp_path / "p7b-filtered.pem",
            subject_cn="router",
            overwrite=OverwritePolicy.VERSION,
        ),
    )

    assert result.matched_count == 1


def test_parse_file_with_policy_skip_invalid_der_file(tmp_path) -> None:
    invalid_der = tmp_path / "invalid.der"
    invalid_der.write_bytes(b"broken-der")

    records, warnings, invalid_count = parse_file_with_policy(invalid_der, InvalidCertPolicy.SKIP)

    assert records == []
    assert invalid_count == 1
    assert warnings


def test_parse_file_with_policy_skip_invalid_p7b_file(tmp_path) -> None:
    invalid_p7b = tmp_path / "invalid.p7b"
    invalid_p7b.write_bytes(b"broken-p7b")

    records, warnings, invalid_count = parse_file_with_policy(invalid_p7b, InvalidCertPolicy.SKIP)

    assert records == []
    assert invalid_count == 1
    assert warnings


def test_filter_skip_invalid_p7b_raises_validation_error(tmp_path) -> None:
    invalid_p7b = tmp_path / "invalid.p7b"
    invalid_p7b.write_bytes(b"broken-p7b")

    with pytest.raises(ValidationError, match="No valid certificates found in input bundle"):
        filter_certificates(
            FilterRequest(
                input=invalid_p7b,
                output=tmp_path / "filtered.pem",
                on_invalid=InvalidCertPolicy.SKIP,
                overwrite=OverwritePolicy.VERSION,
            ),
        )


def test_filter_accepts_der_encoded_p7b_input(tmp_path) -> None:
    p7b_input = tmp_path / "bundle-der.p7b"
    p7b_input.write_bytes(make_pkcs7_bundle_der(["p7b-der-router", "p7b-der-switch"]))

    result = filter_certificates(
        FilterRequest(
            input=p7b_input,
            output=tmp_path / "p7b-der-filtered.pem",
            subject_cn="router",
            overwrite=OverwritePolicy.VERSION,
        ),
    )

    assert result.matched_count == 1


def test_filter_certificates_by_subject_cn(tmp_path) -> None:
    bundle = tmp_path / "bundle.pem"
    pem_router = make_self_signed_pem("router-edge")
    pem_switch = make_self_signed_pem("switch-core")
    bundle.write_text(f"{pem_router}\n{pem_switch}", encoding="utf-8")

    result = filter_certificates(
        FilterRequest(
            input=bundle,
            output=tmp_path / "filtered.pem",
            subject_cn="router",
            overwrite=OverwritePolicy.VERSION,
        ),
    )

    assert result.matched_count == 1
    assert result.rejected_count == 1


def test_filter_certificates_raises_when_no_match(tmp_path) -> None:
    bundle = tmp_path / "bundle.pem"
    bundle.write_text(make_self_signed_pem("router-edge"), encoding="utf-8")

    with pytest.raises(ValidationError):
        filter_certificates(
            FilterRequest(
                input=bundle,
                output=tmp_path / "filtered.pem",
                subject_cn="firewall",
                overwrite=OverwritePolicy.VERSION,
            ),
        )


def test_filter_certificates_raises_when_no_valid_records(tmp_path) -> None:
    bundle = tmp_path / "bundle.pem"
    bundle.write_text("invalid", encoding="utf-8")

    with pytest.raises(ValidationError, match="No valid certificates found in input bundle"):
        filter_certificates(
            FilterRequest(
                input=bundle,
                output=tmp_path / "filtered.pem",
                on_invalid=InvalidCertPolicy.SKIP,
                overwrite=OverwritePolicy.VERSION,
            ),
        )


def test_matches_filter_excludes_expired_certificates() -> None:
    expired_record = CertificateRecord(
        subject="CN=expired",
        issuer="CN=ca",
        serial="0x1",
        not_before=datetime.now(tz=UTC) - timedelta(days=365),
        not_after=datetime.now(tz=UTC) - timedelta(days=1),
        fingerprint_sha256="abc123",
        pem_text="-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
        subject_common_name="expired",
        issuer_common_name="ca",
    )
    active_record = CertificateRecord(
        subject="CN=active",
        issuer="CN=ca",
        serial="0x2",
        not_before=datetime.now(tz=UTC) - timedelta(days=10),
        not_after=datetime.now(tz=UTC) + timedelta(days=10),
        fingerprint_sha256="def456",
        pem_text="-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
        subject_common_name="active",
        issuer_common_name="ca",
    )
    request = FilterRequest(
        input=Path("in.pem"),
        output=Path("out.pem"),
        exclude_expired=True,
    )

    assert matches_filter(expired_record, request) is False
    assert matches_filter(active_record, request) is True


def test_matches_filter_normalizes_naive_datetime_filters() -> None:
    record = CertificateRecord(
        subject="CN=active",
        issuer="CN=ca",
        serial="0x2",
        not_before=datetime.now(tz=UTC) - timedelta(days=10),
        not_after=datetime.now(tz=UTC) + timedelta(days=10),
        fingerprint_sha256="def456",
        pem_text="-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
        subject_common_name="active",
        issuer_common_name="ca",
    )
    request = FilterRequest(
        input=Path("in.pem"),
        output=Path("out.pem"),
        not_after_lt=datetime(2099, 1, 1, tzinfo=UTC).replace(tzinfo=None),
    )

    assert request.not_after_lt is not None
    assert request.not_after_lt.tzinfo is UTC
    assert matches_filter(record, request) is True


def test_filter_certificates_supports_regex_subject_match(tmp_path) -> None:
    bundle = tmp_path / "bundle.pem"
    pem_router = make_self_signed_pem("router-east")
    pem_switch = make_self_signed_pem("switch-west")
    bundle.write_text(f"{pem_router}\n{pem_switch}", encoding="utf-8")

    result = filter_certificates(
        FilterRequest(
            input=bundle,
            output=tmp_path / "filtered-regex.pem",
            subject_cn_regex="^router-.*",
            overwrite=OverwritePolicy.VERSION,
        ),
    )

    assert result.matched_count == 1
    assert result.rejected_count == 1


def test_filter_certificates_supports_or_logic(tmp_path) -> None:
    bundle = tmp_path / "bundle.pem"
    pem_router = make_self_signed_pem("router-east")
    pem_switch = make_self_signed_pem("switch-west")
    bundle.write_text(f"{pem_router}\n{pem_switch}", encoding="utf-8")

    result = filter_certificates(
        FilterRequest(
            input=bundle,
            output=tmp_path / "filtered-or.pem",
            subject_cn="router",
            issuer_cn="does-not-exist",
            logic=FilterLogicMode.OR,
            overwrite=OverwritePolicy.VERSION,
        ),
    )

    assert result.matched_count == 1
    assert result.rejected_count == 1
