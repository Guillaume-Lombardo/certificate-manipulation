"""Filename generation helpers for split outputs."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from certificate_manipulation.domain.enums import SplitNamingStrategy

if TYPE_CHECKING:
    from certificate_manipulation.domain.models import CertificateRecord

_INVALID_FILENAME_CHARS_RE = re.compile(r"[^A-Za-z0-9._-]+")


def build_filename(
    record: CertificateRecord,
    strategy: SplitNamingStrategy,
    index: int,
) -> str:
    """Build a file name stem for a certificate.

    Args:
        record (CertificateRecord): Parsed certificate metadata.
        strategy (SplitNamingStrategy): Naming strategy.
        index (int): 1-based index in split sequence.

    Returns:
        str: File name stem without extension.
    """
    if strategy == SplitNamingStrategy.INDEX:
        return f"cert-{index:03d}"
    if strategy == SplitNamingStrategy.FINGERPRINT:
        return record.fingerprint_sha256

    common_name = record.subject_common_name or f"cert-{index:03d}"
    sanitized = _INVALID_FILENAME_CHARS_RE.sub("-", common_name).strip("-").lower()
    return sanitized or f"cert-{index:03d}"
