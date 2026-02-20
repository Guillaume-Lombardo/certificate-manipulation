from __future__ import annotations

from datetime import UTC, datetime

from certificate_manipulation.domain.enums import SplitNamingStrategy
from certificate_manipulation.domain.models import CertificateRecord
from certificate_manipulation.services.naming_service import build_filename


def _record(common_name: str | None = None) -> CertificateRecord:
    return CertificateRecord(
        subject="CN=test",
        issuer="CN=test",
        serial="0x1",
        not_before=datetime(2026, 1, 1, tzinfo=UTC),
        not_after=datetime(2027, 1, 1, tzinfo=UTC),
        fingerprint_sha256="deadbeef",
        pem_text="-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
        subject_common_name=common_name,
    )


def test_cn_strategy_sanitizes_name() -> None:
    name = build_filename(_record("Réseau Core/01"), SplitNamingStrategy.CN, 1)

    assert name == "r-seau-core-01"


def test_cn_strategy_falls_back_to_index() -> None:
    name = build_filename(_record(None), SplitNamingStrategy.CN, 3)

    assert name == "cert-003"
