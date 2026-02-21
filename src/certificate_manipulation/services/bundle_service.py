"""Functional service API for combine/split/convert operations."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from certificate_manipulation.adapters.filesystem_io import (
    collect_input_files,
    write_text_file,
)
from certificate_manipulation.adapters.x509_parser import (
    extract_pem_blocks,
    load_from_file,
    parse_single_pem,
)
from certificate_manipulation.domain.enums import FilterLogicMode, InvalidCertPolicy, SortMode
from certificate_manipulation.domain.models import (
    CertificateRecord,
    CombineRequest,
    CombineResult,
    ConvertRequest,
    ConvertResult,
    FilterRequest,
    FilterResult,
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
            file_records, file_warnings, file_invalid_count = parse_file_with_policy(
                input_file,
                request.on_invalid,
            )
        except CertificateParseError:
            if request.on_invalid == InvalidCertPolicy.FAIL:
                raise
            invalid_count += 1
            warnings.append(f"Skipped invalid certificate file: {input_file}")
            continue

        records.extend(file_records)
        if not file_records and file_invalid_count == 0:
            invalid_count += 1
            warnings.append(f"Skipped invalid certificate file: {input_file}")
            continue

        invalid_count += file_invalid_count
        warnings.extend(f"{input_file}: {item}" for item in file_warnings)

    if not records:
        raise ValidationError(message="No valid certificates found")

    processed_count = len(records) + invalid_count
    sorted_records = sort_records(records, request.sort)
    if request.deduplicate:
        sorted_records = deduplicate_records(sorted_records)

    output_path = resolve_output_path(request.output, request.overwrite)
    bundle_text = "\n".join(record.pem_text for record in sorted_records).strip() + "\n"
    write_text_file(output_path, bundle_text)

    report = OperationReport(
        processed=processed_count,
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
    records, warnings, invalid_count = parse_file_with_policy(request.input, request.on_invalid)
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


def filter_certificates(request: FilterRequest) -> FilterResult:
    """Filter certificates from an input bundle and write matching ones.

    Args:
        request (FilterRequest): Filter request.

    Raises:
        ValidationError: If no certificate matches filter criteria.

    Returns:
        FilterResult: Filter operation result and report.
    """
    records, warnings, invalid_count = parse_file_with_policy(request.input, request.on_invalid)
    if not records:
        raise ValidationError(message="No valid certificates found in input bundle")

    filtered = [record for record in records if matches_filter(record, request)]
    if not filtered:
        raise ValidationError(message="No certificates matched filter criteria")

    output_path = resolve_output_path(request.output, request.overwrite)
    bundle_text = "\n".join(record.pem_text for record in filtered).strip() + "\n"
    write_text_file(output_path, bundle_text)

    rejected_count = len(records) - len(filtered)
    report = OperationReport(
        processed=len(records) + invalid_count,
        written=len(filtered),
        skipped=rejected_count + invalid_count,
        invalid_count=invalid_count,
        warnings=warnings,
    )
    return FilterResult(
        output_path=output_path,
        matched_count=len(filtered),
        rejected_count=rejected_count,
        report=report,
    )


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


def parse_file_with_policy(
    input_path: Path,
    policy: InvalidCertPolicy,
) -> tuple[list[CertificateRecord], list[str], int]:
    """Parse one input file with invalid-certificate policy.

    Args:
        input_path (Path): Source certificate path.
        policy (InvalidCertPolicy): Invalid certificate policy.

    Returns:
        tuple[list[CertificateRecord], list[str], int]: Records, warnings, invalid count.
    """
    if policy == InvalidCertPolicy.FAIL:
        return load_from_file(input_path), [], 0

    try:
        return load_from_file(input_path), [], 0
    except CertificateParseError:
        if input_path.suffix.lower() in {".der", ".cer", ".p7b", ".p7c"}:
            return [], ["Skipped invalid certificate payload from input file"], 1

    text = input_path.read_text(encoding="utf-8")

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


def matches_filter(record: CertificateRecord, request: FilterRequest) -> bool:
    """Check whether one record matches filter constraints.

    Args:
        record (CertificateRecord): Certificate record to evaluate.
        request (FilterRequest): Filter constraints.

    Returns:
        bool: `True` when record matches all active constraints.
    """
    checks: list[bool] = []
    subject_cn = record.subject_common_name or ""
    issuer_cn = record.issuer_common_name or ""
    checks.extend(
        result
        for enabled, result in [
            (
                request.subject_cn is not None,
                request.subject_cn.lower() in subject_cn.lower() if request.subject_cn is not None else True,
            ),
            (
                request.subject_cn_regex is not None,
                bool(re.search(request.subject_cn_regex, subject_cn, flags=re.IGNORECASE))
                if request.subject_cn_regex is not None
                else True,
            ),
            (
                request.issuer_cn is not None,
                request.issuer_cn.lower() in issuer_cn.lower() if request.issuer_cn is not None else True,
            ),
            (
                request.issuer_cn_regex is not None,
                bool(re.search(request.issuer_cn_regex, issuer_cn, flags=re.IGNORECASE))
                if request.issuer_cn_regex is not None
                else True,
            ),
            (
                request.not_after_lt is not None,
                record.not_after < request.not_after_lt if request.not_after_lt is not None else True,
            ),
            (
                request.not_before_gt is not None,
                record.not_before > request.not_before_gt if request.not_before_gt is not None else True,
            ),
            (
                request.exclude_expired,
                record.not_after > datetime.now(tz=UTC),
            ),
            (
                request.fingerprint is not None,
                request.fingerprint.lower() == record.fingerprint_sha256.lower()
                if request.fingerprint is not None
                else True,
            ),
        ]
        if enabled
    )

    if not checks:
        return True
    if request.logic == FilterLogicMode.OR:
        return any(checks)
    return all(checks)
