"""Functional service API for combine/split/convert operations."""

from __future__ import annotations

from typing import TYPE_CHECKING

from certificate_manipulation.adapters.filesystem_io import (
    collect_input_files,
    read_text_file,
    write_text_file,
)
from certificate_manipulation.adapters.x509_parser import (
    extract_pem_blocks,
    load_from_file,
    parse_many_from_text,
    parse_single_pem,
)
from certificate_manipulation.domain.enums import InvalidCertPolicy, SortMode
from certificate_manipulation.domain.models import (
    CertificateRecord,
    CombineRequest,
    CombineResult,
    ConvertRequest,
    ConvertResult,
    OperationReport,
    SplitRequest,
    SplitResult,
)
from certificate_manipulation.exceptions import CertificateParseError, ValidationError
from certificate_manipulation.services.naming_service import build_filename
from certificate_manipulation.services.output_policy_service import resolve_output_path

if TYPE_CHECKING:
    from pathlib import Path


def combine(request: CombineRequest) -> CombineResult:
    """Combine multiple certificate files into a single bundle.

    Args:
        request (CombineRequest): Combine request.

    Raises:
        CertificateParseError: If invalid input is found and policy is fail.
        ValidationError: If there is no valid certificate to write.

    Returns:
        CombineResult: Operation result and report.
    """
    files = collect_input_files(request.inputs, recursive=request.recursive)
    if not files:
        raise ValidationError(message="No certificate files found from --inputs")

    records: list[CertificateRecord] = []
    warnings: list[str] = []
    invalid_count = 0

    for input_file in files:
        try:
            records.extend(load_from_file(input_file))
        except CertificateParseError:
            if request.on_invalid == InvalidCertPolicy.FAIL:
                raise
            invalid_count += 1
            warnings.append(f"Skipped invalid certificate file: {input_file}")

    if not records:
        raise ValidationError(message="No valid certificates found")

    sorted_records = sort_records(records, request.sort)
    if request.deduplicate:
        sorted_records = deduplicate_records(sorted_records)

    output_path = resolve_output_path(request.output, request.overwrite)
    bundle_text = "\n".join(record.pem_text for record in sorted_records).strip() + "\n"
    write_text_file(output_path, bundle_text)

    report = OperationReport(
        processed=len(sorted_records) + invalid_count,
        written=len(sorted_records),
        skipped=invalid_count,
        invalid_count=invalid_count,
        warnings=warnings,
    )
    return CombineResult(
        output_path=output_path,
        certificate_count=len(sorted_records),
        report=report,
    )


def split(request: SplitRequest) -> SplitResult:
    """Split a bundle into one file per certificate.

    Args:
        request (SplitRequest): Split request.

    Raises:
        ValidationError: If no valid certificate can be produced.

    Returns:
        SplitResult: Operation result and report.
    """
    text = read_text_file(request.input)
    records, warnings, invalid_count = parse_with_policy(text, request.on_invalid)
    if not records:
        raise ValidationError(message="No valid certificates found in input bundle")

    output_paths = write_split_outputs(records=records, request=request)
    report = OperationReport(
        processed=len(records) + invalid_count,
        written=len(output_paths),
        skipped=invalid_count,
        invalid_count=invalid_count,
        warnings=warnings,
    )
    return SplitResult(output_paths=output_paths, report=report)


def convert(request: ConvertRequest) -> ConvertResult:
    """Convert a single certificate file to a target extension.

    Args:
        request (ConvertRequest): Convert request.

    Raises:
        ValidationError: If input contains zero or multiple certificates.

    Returns:
        ConvertResult: Operation result and report.
    """
    records = load_from_file(request.input)
    if len(records) != 1:
        raise ValidationError(message="convert expects exactly one certificate in --input")

    output_path = resolve_output_path(request.output, request.overwrite)
    if output_path.suffix.lower() != f".{request.to.value}":
        output_path = output_path.with_suffix(f".{request.to.value}")
        output_path = resolve_output_path(output_path, request.overwrite)

    write_text_file(output_path, records[0].pem_text.strip() + "\n")
    report = OperationReport(
        processed=1,
        written=1,
        skipped=0,
        invalid_count=0,
        warnings=[],
    )
    return ConvertResult(output_path=output_path, report=report)


def write_split_outputs(*, records: list[CertificateRecord], request: SplitRequest) -> list[Path]:
    """Write split outputs to disk.

    Args:
        records (list[CertificateRecord]): Parsed records from input bundle.
        request (SplitRequest): Split request.

    Returns:
        list[Path]: Written output file paths.
    """
    output_paths: list[Path] = []
    collisions: dict[str, int] = {}
    for index, record in enumerate(records, start=1):
        stem = build_filename(record, request.filename_template, index)
        seen = collisions.get(stem, 0)
        collisions[stem] = seen + 1
        if seen > 0:
            stem = f"{stem}-{seen + 1}"

        target = request.output_dir / f"{stem}.{request.ext.value}"
        final_target = resolve_output_path(target, request.overwrite)
        write_text_file(final_target, record.pem_text.strip() + "\n")
        output_paths.append(final_target)
    return output_paths


def sort_records(records: list[CertificateRecord], mode: SortMode) -> list[CertificateRecord]:
    """Sort records according to configured mode.

    Args:
        records (list[CertificateRecord]): Parsed certificate records.
        mode (SortMode): Sort mode.

    Returns:
        list[CertificateRecord]: Sorted records.
    """
    if mode == SortMode.SUBJECT:
        return sorted(records, key=lambda cert: cert.subject.lower())
    if mode == SortMode.NOT_BEFORE:
        return sorted(records, key=lambda cert: cert.not_before)
    return records


def deduplicate_records(records: list[CertificateRecord]) -> list[CertificateRecord]:
    """Deduplicate records by SHA256 fingerprint while preserving order.

    Args:
        records (list[CertificateRecord]): Parsed certificate records.

    Returns:
        list[CertificateRecord]: Deduplicated records.
    """
    seen: set[str] = set()
    deduped: list[CertificateRecord] = []
    for record in records:
        if record.fingerprint_sha256 in seen:
            continue
        seen.add(record.fingerprint_sha256)
        deduped.append(record)
    return deduped


def parse_with_policy(
    text: str,
    policy: InvalidCertPolicy,
) -> tuple[list[CertificateRecord], list[str], int]:
    """Parse bundle text with invalid-certificate policy.

    Args:
        text (str): Bundle content.
        policy (InvalidCertPolicy): Invalid certificate policy.

    Returns:
        tuple[list[CertificateRecord], list[str], int]: Records, warnings, invalid count.
    """
    if policy == InvalidCertPolicy.FAIL:
        return parse_many_from_text(text), [], 0

    records: list[CertificateRecord] = []
    warnings: list[str] = []
    invalid_count = 0
    for block in extract_pem_blocks(text):
        try:
            records.append(parse_single_pem(block))
        except CertificateParseError:
            invalid_count += 1
            warnings.append("Skipped invalid certificate block from input bundle")
    return records, warnings, invalid_count
