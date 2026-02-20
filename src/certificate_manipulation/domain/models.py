"""Domain models for certificate operations."""

from __future__ import annotations

from datetime import datetime  # noqa: TC003
from pathlib import Path  # noqa: TC003

from pydantic import BaseModel, ConfigDict, Field

from certificate_manipulation.domain.enums import (
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
