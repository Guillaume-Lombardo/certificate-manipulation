from __future__ import annotations

import pytest

from certificate_manipulation.adapters.x509_parser import parse_many_from_text
from certificate_manipulation.exceptions import CertificateParseError
from tests.cert_factory import make_self_signed_pem


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
