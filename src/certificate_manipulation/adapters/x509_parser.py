"""X.509 PEM parser helpers based on cryptography."""

from __future__ import annotations

import re
from pathlib import Path  # noqa: TC003

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from certificate_manipulation.domain.models import CertificateRecord
from certificate_manipulation.exceptions import CertificateParseError

PEM_BLOCK_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----\s+.+?\s+-----END CERTIFICATE-----",
    re.DOTALL,
)


def extract_pem_blocks(text: str) -> list[str]:
    """Extract PEM certificate blocks from text.

    Args:
        text (str): Raw text potentially containing one or more PEM certificates.

    Returns:
        list[str]: PEM certificate blocks.
    """
    return [block.strip() for block in PEM_BLOCK_RE.findall(text)]


def parse_single_pem(pem_text: str) -> CertificateRecord:
    """Parse one PEM certificate block.

    Args:
        pem_text (str): PEM encoded certificate block.

    Raises:
        CertificateParseError: If parsing fails.

    Returns:
        CertificateRecord: Parsed certificate metadata and canonical PEM.
    """
    try:
        certificate = x509.load_pem_x509_certificate(pem_text.encode("utf-8"))
    except Exception as exc:
        raise CertificateParseError(exc=exc) from exc

    subject_cn = None
    subject_cn_attributes = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if subject_cn_attributes:
        raw_cn = subject_cn_attributes[0].value
        subject_cn = raw_cn.decode("utf-8", errors="replace") if isinstance(raw_cn, bytes) else raw_cn
    issuer_cn = None
    issuer_cn_attributes = certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    if issuer_cn_attributes:
        raw_issuer_cn = issuer_cn_attributes[0].value
        issuer_cn = (
            raw_issuer_cn.decode("utf-8", errors="replace")
            if isinstance(raw_issuer_cn, bytes)
            else raw_issuer_cn
        )

    canonical_pem = certificate.public_bytes(Encoding.PEM).decode("utf-8").strip()
    fingerprint = certificate.fingerprint(hashes.SHA256()).hex()

    return CertificateRecord(
        subject=certificate.subject.rfc4514_string(),
        issuer=certificate.issuer.rfc4514_string(),
        serial=hex(certificate.serial_number),
        not_before=certificate.not_valid_before_utc,
        not_after=certificate.not_valid_after_utc,
        fingerprint_sha256=fingerprint,
        pem_text=canonical_pem,
        subject_common_name=subject_cn,
        issuer_common_name=issuer_cn,
    )


def parse_many_from_text(text: str) -> list[CertificateRecord]:
    """Parse all certificates from raw text.

    Args:
        text (str): Raw text containing PEM certificates.

    Raises:
        CertificateParseError: If no certificates are found or one block is invalid.

    Returns:
        list[CertificateRecord]: Parsed certificates.
    """
    pem_blocks = extract_pem_blocks(text)
    if not pem_blocks:
        raise CertificateParseError(message="No PEM certificates found")
    return [parse_single_pem(block) for block in pem_blocks]


def load_from_file(path: Path) -> list[CertificateRecord]:
    """Load and parse certificates from a UTF-8 file.

    Args:
        path (Path): Input certificate file path.

    Returns:
        list[CertificateRecord]: Parsed certificates.
    """
    text = path.read_text(encoding="utf-8")
    return parse_many_from_text(text)
