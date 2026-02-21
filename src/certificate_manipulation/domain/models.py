"""Domain models for certificate operations."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path  # noqa: TC003

from pydantic import BaseModel, ConfigDict, Field, field_validator

from certificate_manipulation.domain.enums import (
    FilterLogicMode,
    InvalidCertPolicy,
    OutputExt,
    OverwritePolicy,
    SortMode,
    SplitNamingStrategy,
)


class DomainModel(BaseModel):
    """Base model for domain structures."""

    model_config = ConfigDict(frozen=True)


class CertificateRecord(DomainModel):
    """Normalized certificate metadata and PEM payload."""

    subject: str
    issuer: str
    serial: str
    not_before: datetime
    not_after: datetime
    fingerprint_sha256: str
    pem_text: str
    subject_common_name: str | None = None
    issuer_common_name: str | None = None


class OperationReport(DomainModel):
    """Standard report for operation outcomes."""

    processed: int
    written: int
    skipped: int
    invalid_count: int
    warnings: list[str] = Field(default_factory=list)


class CombineRequest(DomainModel):
    """Input contract for combine operation."""

    inputs: list[Path]
    recursive: bool
    output: Path
    deduplicate: bool = True
    sort: SortMode = SortMode.INPUT
    on_invalid: InvalidCertPolicy = InvalidCertPolicy.FAIL
    overwrite: OverwritePolicy = OverwritePolicy.VERSION


class CombineResult(DomainModel):
    """Output contract for combine operation."""

    output_path: Path
    certificate_count: int
    report: OperationReport


class SplitRequest(DomainModel):
    """Input contract for split operation."""

    input: Path
    output_dir: Path
    ext: OutputExt = OutputExt.CRT
    filename_template: SplitNamingStrategy = SplitNamingStrategy.CN
    on_invalid: InvalidCertPolicy = InvalidCertPolicy.FAIL
    overwrite: OverwritePolicy = OverwritePolicy.VERSION


class SplitResult(DomainModel):
    """Output contract for split operation."""

    output_paths: list[Path]
    report: OperationReport


class ConvertRequest(DomainModel):
    """Input contract for convert operation."""

    input: Path
    output: Path
    to: OutputExt
    overwrite: OverwritePolicy = OverwritePolicy.VERSION


class ConvertResult(DomainModel):
    """Output contract for convert operation."""

    output_path: Path
    report: OperationReport


class FilterRequest(DomainModel):
    """Input contract for filter operation."""

    input: Path
    output: Path
    subject_cn: str | None = None
    subject_cn_regex: str | None = None
    issuer_cn: str | None = None
    issuer_cn_regex: str | None = None
    not_after_lt: datetime | None = None
    not_before_gt: datetime | None = None
    fingerprint: str | None = None
    exclude_expired: bool = False
    logic: FilterLogicMode = FilterLogicMode.AND
    on_invalid: InvalidCertPolicy = InvalidCertPolicy.FAIL
    overwrite: OverwritePolicy = OverwritePolicy.VERSION

    @field_validator("not_after_lt", "not_before_gt", mode="after")
    @classmethod
    def normalize_datetime_to_utc(cls, value: datetime | None) -> datetime | None:
        """Normalize optional datetimes to timezone-aware UTC.

        Args:
            value (datetime | None): Optional filter datetime.

        Returns:
            datetime | None: Normalized timezone-aware UTC datetime.
        """
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @field_validator("subject_cn_regex", "issuer_cn_regex", mode="after")
    @classmethod
    def validate_regex_pattern(cls, value: str | None) -> str | None:
        """Validate optional regex patterns used by filter criteria.

        Args:
            value (str | None): Optional regex pattern.

        Returns:
            str | None: Original regex pattern when valid.
        """
        if value is None:
            return None
        re.compile(value)
        return value


class FilterResult(DomainModel):
    """Output contract for filter operation."""

    output_path: Path
    matched_count: int
    rejected_count: int
    report: OperationReport
