"""CLI entry point for certificate-manipulation."""

from __future__ import annotations

import argparse
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, assert_never

from pydantic import BaseModel, Field, field_validator
from pydantic import ValidationError as PydanticValidationError

from certificate_manipulation import __version__
from certificate_manipulation.domain.enums import (
    CliCommand,
    FilterLogicMode,
    InvalidCertPolicy,
    OutputExt,
    OverwritePolicy,
    SortMode,
    SplitNamingStrategy,
)
from certificate_manipulation.domain.models import (
    CombineRequest,
    ConvertRequest,
    FilterRequest,
    OperationReport,
    SplitRequest,
)
from certificate_manipulation.exceptions import CertificateParseError, ValidationError
from certificate_manipulation.logging import OperationLogger, configure_logging, get_logger
from certificate_manipulation.services.bundle_service import (
    combine,
    convert,
    filter_certificates,
    split,
)
from certificate_manipulation.settings import get_settings


class CombineCliArgs(BaseModel):
    """Validated CLI args for combine command."""

    command: Literal[CliCommand.COMBINE]
    inputs: Annotated[list[Path], Field(min_length=1)]
    recursive: bool = False
    output: Path
    deduplicate: bool = True
    sort: SortMode = SortMode.INPUT
    on_invalid: InvalidCertPolicy = InvalidCertPolicy.FAIL
    overwrite: OverwritePolicy = OverwritePolicy.VERSION
    report_json: Path | None = None


class SplitCliArgs(BaseModel):
    """Validated CLI args for split command."""

    command: Literal[CliCommand.SPLIT]
    input: Path
    output_dir: Path
    ext: OutputExt = OutputExt.CRT
    filename_template: SplitNamingStrategy = SplitNamingStrategy.CN
    on_invalid: InvalidCertPolicy = InvalidCertPolicy.FAIL
    overwrite: OverwritePolicy = OverwritePolicy.VERSION
    report_json: Path | None = None


class ConvertCliArgs(BaseModel):
    """Validated CLI args for convert command."""

    command: Literal[CliCommand.CONVERT]
    input: Path
    output: Path
    to: OutputExt
    overwrite: OverwritePolicy = OverwritePolicy.VERSION
    report_json: Path | None = None


class FilterCliArgs(BaseModel):
    """Validated CLI args for filter command."""

    command: Literal[CliCommand.FILTER]
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
    report_json: Path | None = None

    @field_validator("not_after_lt", "not_before_gt", mode="after")
    @classmethod
    def normalize_datetime_to_utc(cls, value: datetime | None) -> datetime | None:
        """Normalize optional filter datetimes to timezone-aware UTC.

        Args:
            value (datetime | None): Optional filter datetime.

        Returns:
            datetime | None: Timezone-aware UTC datetime.
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


ValidatedCliArgs = CombineCliArgs | SplitCliArgs | ConvertCliArgs | FilterCliArgs


def log_operation_summary(
    *,
    command: CliCommand,
    logger: OperationLogger,
    report: OperationReport,
    **extra: object,
) -> None:
    """Log a normalized operation summary for observability.

    Args:
        command (CliCommand): Executed command.
        logger (structlog.BoundLogger): Bound logger used by the CLI.
        report (OperationReport): Operation report to summarize.
        **extra (str | int): Additional command-specific fields.
    """
    logger.info(
        "operation completed",
        command=command.value,
        processed=report.processed,
        written=report.written,
        skipped=report.skipped,
        invalid_count=report.invalid_count,
        warnings_count=len(report.warnings),
        **extra,
    )
    if report.warnings:
        max_warnings_to_log = 50
        warnings = list(report.warnings[:max_warnings_to_log])
        warnings_truncated = max(0, len(report.warnings) - len(warnings))
        logger.warning(
            "operation warnings",
            command=command.value,
            warnings=warnings,
            warnings_total=len(report.warnings),
            warnings_truncated=warnings_truncated,
            **extra,
        )


def write_operation_report_json(
    *,
    report_path: Path,
    command: CliCommand,
    report: OperationReport,
    **extra: object,
) -> None:
    """Write one machine-readable operation report as JSON.

    Args:
        report_path (Path): Target report path.
        command (CliCommand): Executed command.
        report (OperationReport): Operation report payload.
        **extra (object): Additional command-specific metadata.
    """
    payload = {
        "command": command.value,
        "report": report.model_dump(mode="json"),
        "metadata": {key: str(value) if isinstance(value, Path) else value for key, value in extra.items()},
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(f"{json.dumps(payload, indent=2, sort_keys=True)}\n", encoding="utf-8")


def run_combine_command(args: CombineCliArgs, logger: OperationLogger) -> int:
    """Execute combine command from validated CLI args.

    Args:
        args (CombineCliArgs): Validated CLI arguments.
        logger (OperationLogger): Operation logger instance.

    Returns:
        int: CLI exit code for this command.
    """
    result = combine(
        CombineRequest(
            inputs=args.inputs,
            recursive=args.recursive,
            output=args.output,
            deduplicate=args.deduplicate,
            sort=args.sort,
            on_invalid=args.on_invalid,
            overwrite=args.overwrite,
        ),
    )
    log_operation_summary(
        command=CliCommand.COMBINE,
        logger=logger,
        report=result.report,
        output=str(result.output_path),
        certificate_count=result.certificate_count,
    )
    if args.report_json is not None:
        write_operation_report_json(
            report_path=args.report_json,
            command=CliCommand.COMBINE,
            report=result.report,
            output=result.output_path,
            certificate_count=result.certificate_count,
        )
    return 3 if result.report.invalid_count > 0 else 0


def run_split_command(args: SplitCliArgs, logger: OperationLogger) -> int:
    """Execute split command from validated CLI args.

    Args:
        args (SplitCliArgs): Validated CLI arguments.
        logger (OperationLogger): Operation logger instance.

    Returns:
        int: CLI exit code for this command.
    """
    result = split(
        SplitRequest(
            input=args.input,
            output_dir=args.output_dir,
            ext=args.ext,
            filename_template=args.filename_template,
            on_invalid=args.on_invalid,
            overwrite=args.overwrite,
        ),
    )
    log_operation_summary(
        command=CliCommand.SPLIT,
        logger=logger,
        report=result.report,
        output_dir=str(args.output_dir),
        outputs_written=len(result.output_paths),
    )
    if args.report_json is not None:
        write_operation_report_json(
            report_path=args.report_json,
            command=CliCommand.SPLIT,
            report=result.report,
            output_dir=args.output_dir,
            outputs_written=len(result.output_paths),
        )
    return 3 if result.report.invalid_count > 0 else 0


def run_convert_command(args: ConvertCliArgs, logger: OperationLogger) -> int:
    """Execute convert command from validated CLI args.

    Args:
        args (ConvertCliArgs): Validated CLI arguments.
        logger (OperationLogger): Operation logger instance.

    Returns:
        int: CLI exit code for this command.
    """
    result = convert(
        ConvertRequest(
            input=args.input,
            output=args.output,
            to=args.to,
            overwrite=args.overwrite,
        ),
    )
    log_operation_summary(
        command=CliCommand.CONVERT,
        logger=logger,
        report=result.report,
        output=str(result.output_path),
    )
    if args.report_json is not None:
        write_operation_report_json(
            report_path=args.report_json,
            command=CliCommand.CONVERT,
            report=result.report,
            output=result.output_path,
        )
    return 0


def run_filter_command(args: FilterCliArgs, logger: OperationLogger) -> int:
    """Execute filter command from validated CLI args.

    Args:
        args (FilterCliArgs): Validated CLI arguments.
        logger (OperationLogger): Operation logger instance.

    Returns:
        int: CLI exit code for this command.
    """
    result = filter_certificates(
        FilterRequest(
            input=args.input,
            output=args.output,
            subject_cn=args.subject_cn,
            subject_cn_regex=args.subject_cn_regex,
            issuer_cn=args.issuer_cn,
            issuer_cn_regex=args.issuer_cn_regex,
            not_after_lt=args.not_after_lt,
            not_before_gt=args.not_before_gt,
            fingerprint=args.fingerprint,
            exclude_expired=args.exclude_expired,
            logic=args.logic,
            on_invalid=args.on_invalid,
            overwrite=args.overwrite,
        ),
    )
    log_operation_summary(
        command=CliCommand.FILTER,
        logger=logger,
        report=result.report,
        output=str(result.output_path),
        matched=result.matched_count,
        rejected=result.rejected_count,
    )
    if args.report_json is not None:
        write_operation_report_json(
            report_path=args.report_json,
            command=CliCommand.FILTER,
            report=result.report,
            output=result.output_path,
            matched=result.matched_count,
            rejected=result.rejected_count,
        )
    return 3 if result.report.invalid_count > 0 else 0


def dispatch_validated_command(args: ValidatedCliArgs, logger: OperationLogger) -> int:
    """Dispatch validated arguments to the corresponding command runner.

    Args:
        args (ValidatedCliArgs): Validated CLI arguments.
        logger (OperationLogger): Operation logger instance.

    Returns:
        int: CLI exit code for the selected command.
    """
    if isinstance(args, CombineCliArgs):
        return run_combine_command(args, logger)
    if isinstance(args, SplitCliArgs):
        return run_split_command(args, logger)
    if isinstance(args, ConvertCliArgs):
        return run_convert_command(args, logger)
    if isinstance(args, FilterCliArgs):
        return run_filter_command(args, logger)
    assert_never(args)


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line parser.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(prog="certificate-manipulation")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    combine_parser = subparsers.add_parser(
        CliCommand.COMBINE.value,
        help="Combine certificates into a PEM bundle",
    )
    combine_parser.add_argument("--inputs", nargs="+", required=True, help="Input files or directories")
    combine_parser.add_argument("--recursive", action="store_true", help="Traverse directories recursively")
    combine_parser.add_argument("--output", required=True, help="Output bundle file path")
    combine_parser.add_argument(
        "--deduplicate",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Deduplicate certificates by SHA256 fingerprint",
    )
    combine_parser.add_argument(
        "--sort",
        choices=[mode.value for mode in SortMode],
        default=SortMode.INPUT.value,
        help="Sort mode for resulting bundle",
    )
    combine_parser.add_argument(
        "--on-invalid",
        choices=[policy.value for policy in InvalidCertPolicy],
        default=InvalidCertPolicy.FAIL.value,
        help="Policy for invalid certificates",
    )
    combine_parser.add_argument(
        "--overwrite",
        choices=[policy.value for policy in OverwritePolicy],
        default=OverwritePolicy.VERSION.value,
        help="Output collision strategy",
    )
    combine_parser.add_argument(
        "--report-json",
        default=None,
        help="Optional operation report output path (JSON)",
    )

    split_parser = subparsers.add_parser(
        CliCommand.SPLIT.value,
        help="Split bundle into one certificate per file",
    )
    split_parser.add_argument("--input", required=True, help="Input bundle file")
    split_parser.add_argument("--output-dir", required=True, help="Output directory")
    split_parser.add_argument(
        "--ext",
        choices=[ext.value for ext in OutputExt],
        default=OutputExt.CRT.value,
        help="Output extension",
    )
    split_parser.add_argument(
        "--filename-template",
        choices=[strategy.value for strategy in SplitNamingStrategy],
        default=SplitNamingStrategy.CN.value,
        help="Naming strategy for generated files",
    )
    split_parser.add_argument(
        "--on-invalid",
        choices=[policy.value for policy in InvalidCertPolicy],
        default=InvalidCertPolicy.FAIL.value,
        help="Policy for invalid certificates",
    )
    split_parser.add_argument(
        "--overwrite",
        choices=[policy.value for policy in OverwritePolicy],
        default=OverwritePolicy.VERSION.value,
        help="Output collision strategy",
    )
    split_parser.add_argument(
        "--report-json",
        default=None,
        help="Optional operation report output path (JSON)",
    )

    convert_parser = subparsers.add_parser(
        CliCommand.CONVERT.value,
        help="Normalize one certificate and set extension",
    )
    convert_parser.add_argument("--input", required=True, help="Input certificate file")
    convert_parser.add_argument("--output", required=True, help="Output certificate file")
    convert_parser.add_argument(
        "--to",
        required=True,
        choices=[ext.value for ext in OutputExt],
        help="Target extension",
    )
    convert_parser.add_argument(
        "--overwrite",
        choices=[policy.value for policy in OverwritePolicy],
        default=OverwritePolicy.VERSION.value,
        help="Output collision strategy",
    )
    convert_parser.add_argument(
        "--report-json",
        default=None,
        help="Optional operation report output path (JSON)",
    )

    filter_parser = subparsers.add_parser(
        CliCommand.FILTER.value,
        help="Filter certificates from an input bundle",
    )
    filter_parser.add_argument("--input", required=True, help="Input bundle file")
    filter_parser.add_argument("--output", required=True, help="Output bundle file")
    filter_parser.add_argument(
        "--subject-cn",
        default=None,
        help="Case-insensitive contains match on subject CN",
    )
    filter_parser.add_argument(
        "--subject-cn-regex",
        default=None,
        help="Case-insensitive regex match on subject CN",
    )
    filter_parser.add_argument(
        "--issuer-cn",
        default=None,
        help="Case-insensitive contains match on issuer CN",
    )
    filter_parser.add_argument(
        "--issuer-cn-regex",
        default=None,
        help="Case-insensitive regex match on issuer CN",
    )
    filter_parser.add_argument(
        "--not-after-lt",
        default=None,
        help="Keep certs where not_after is lower than this ISO datetime",
    )
    filter_parser.add_argument(
        "--not-before-gt",
        default=None,
        help="Keep certs where not_before is greater than this ISO datetime",
    )
    filter_parser.add_argument(
        "--exclude-expired",
        action="store_true",
        help="Exclude certificates that are already expired",
    )
    filter_parser.add_argument("--fingerprint", default=None, help="Exact SHA256 fingerprint match")
    filter_parser.add_argument(
        "--logic",
        choices=[mode.value for mode in FilterLogicMode],
        default=FilterLogicMode.AND.value,
        help="How to combine active criteria",
    )
    filter_parser.add_argument(
        "--on-invalid",
        choices=[policy.value for policy in InvalidCertPolicy],
        default=InvalidCertPolicy.FAIL.value,
        help="Policy for invalid certificates",
    )
    filter_parser.add_argument(
        "--overwrite",
        choices=[policy.value for policy in OverwritePolicy],
        default=OverwritePolicy.VERSION.value,
        help="Output collision strategy",
    )
    filter_parser.add_argument(
        "--report-json",
        default=None,
        help="Optional operation report output path (JSON)",
    )

    return parser


def validate_cli_args(parsed_args: argparse.Namespace) -> ValidatedCliArgs:
    """Validate raw argparse namespace with Pydantic models.

    Args:
        parsed_args (argparse.Namespace): Parsed argparse namespace.

    Raises:
        ValidationError: If argument payload is invalid.

    Returns:
        ValidatedCliArgs: Strongly typed validated args model.
    """
    raw_args = vars(parsed_args).copy()
    try:
        command = CliCommand(raw_args["command"])
        raw_args["command"] = command
    except Exception as exc:
        raise ValidationError(message=f"Unknown command: {raw_args.get('command')}") from exc

    try:
        if command == CliCommand.COMBINE:
            return CombineCliArgs.model_validate(raw_args)
        if command == CliCommand.SPLIT:
            return SplitCliArgs.model_validate(raw_args)
        if command == CliCommand.CONVERT:
            return ConvertCliArgs.model_validate(raw_args)
        if command == CliCommand.FILTER:
            return FilterCliArgs.model_validate(raw_args)
    except PydanticValidationError as exc:
        raise ValidationError(message=f"Invalid CLI arguments: {exc}") from exc

    raise ValidationError(message=f"Unsupported command: {command}")


def main() -> int:
    """Run the CLI.

    Returns:
        int: Exit code (0 for success).
    """
    parser = build_parser()
    parsed_args = parser.parse_args()
    configure_logging(settings=get_settings())
    logger = get_logger("certificate_manipulation.cli")

    exit_code = 0
    try:
        args = validate_cli_args(parsed_args)
        exit_code = dispatch_validated_command(args, logger)
    except ValidationError as exc:
        logger.exception("validation error", error=str(exc))
        exit_code = 1
    except (CertificateParseError, OSError) as exc:
        logger.exception("operation error", error=str(exc))
        exit_code = 2
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
