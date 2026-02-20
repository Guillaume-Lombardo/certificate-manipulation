from __future__ import annotations

import pytest

from certificate_manipulation.adapters.x509_parser import load_from_file, parse_many_from_text
from certificate_manipulation.exceptions import CertificateParseError
from tests.cert_factory import (
    make_pkcs7_bundle_der,
    make_pkcs7_bundle_pem,
    make_self_signed_der,
    make_self_signed_pem,
)


def test_parse_many_from_text_with_multiple_certificates() -> None:
    pem_1 = make_self_signed_pem("router-a.internal")
    pem_2 = make_self_signed_pem("router-b.internal")

    records = parse_many_from_text(f"{pem_1}\n{pem_2}")

    assert len(records) == 2
    assert records[0].subject_common_name == "router-a.internal"
    assert records[1].subject_common_name == "router-b.internal"


def test_parse_many_rejects_invalid_payload() -> None:
    with pytest.raises(CertificateParseError):
        parse_many_from_text("not a certificate")


def test_load_from_file_parses_der_certificate(tmp_path) -> None:
    der_path = tmp_path / "edge.der"
    der_path.write_bytes(make_self_signed_der("edge-der"))

    records = load_from_file(der_path)

    assert len(records) == 1
    assert records[0].subject_common_name == "edge-der"


def test_load_from_file_parses_p7b_bundle(tmp_path) -> None:
    p7b_path = tmp_path / "chain.p7b"
    p7b_path.write_text(make_pkcs7_bundle_pem(["p7b-a", "p7b-b"]), encoding="utf-8")

    records = load_from_file(p7b_path)

    assert len(records) == 2
    assert {record.subject_common_name for record in records} == {"p7b-a", "p7b-b"}


def test_load_from_file_parses_der_encoded_p7b_bundle(tmp_path) -> None:
    p7b_path = tmp_path / "chain.p7b"
    p7b_path.write_bytes(make_pkcs7_bundle_der(["p7b-der-a", "p7b-der-b"]))

    records = load_from_file(p7b_path)

    assert len(records) == 2
    assert {record.subject_common_name for record in records} == {"p7b-der-a", "p7b-der-b"}


def test_load_from_file_parses_pem_encoded_cer(tmp_path) -> None:
    cer_path = tmp_path / "leaf.cer"
    cer_path.write_text(make_self_signed_pem("pem-cer"), encoding="utf-8")

    records = load_from_file(cer_path)

    assert len(records) == 1
    assert records[0].subject_common_name == "pem-cer"
