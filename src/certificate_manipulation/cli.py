"""CLI entry point for certificate-manipulation."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path  # noqa: TC003
from typing import TYPE_CHECKING, Annotated, Literal, assert_never

from pydantic import BaseModel, Field, field_validator
from pydantic import ValidationError as PydanticValidationError

from certificate_manipulation import __version__
from certificate_manipulation.domain.enums import (
    CliCommand,
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
from certificate_manipulation.logging import configure_logging, get_logger
from certificate_manipulation.services.bundle_service import (
    combine,
    convert,
    filter_certificates,
    split,
)
from certificate_manipulation.settings import get_settings

if TYPE_CHECKING:
    import structlog


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


class SplitCliArgs(BaseModel):
    """Validated CLI args for split command."""

    command: Literal[CliCommand.SPLIT]
    input: Path
    output_dir: Path
    ext: OutputExt = OutputExt.CRT
    filename_template: SplitNamingStrategy = SplitNamingStrategy.CN
    on_invalid: InvalidCertPolicy = InvalidCertPolicy.FAIL
    overwrite: OverwritePolicy = OverwritePolicy.VERSION


class ConvertCliArgs(BaseModel):
    """Validated CLI args for convert command."""

    command: Literal[CliCommand.CONVERT]
    input: Path
    output: Path
    to: OutputExt
    overwrite: OverwritePolicy = OverwritePolicy.VERSION


class FilterCliArgs(BaseModel):
    """Validated CLI args for filter command."""

    command: Literal[CliCommand.FILTER]
    input: Path
    output: Path
    subject_cn: str | None = None
    issuer_cn: str | None = None
    not_after_lt: datetime | None = None
    not_before_gt: datetime | None = None
    fingerprint: str | None = None
    exclude_expired: bool = False
    on_invalid: InvalidCertPolicy = InvalidCertPolicy.FAIL
    overwrite: OverwritePolicy = OverwritePolicy.VERSION

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


ValidatedCliArgs = CombineCliArgs | SplitCliArgs | ConvertCliArgs | FilterCliArgs


def log_operation_summary(
    *,
    command: CliCommand,
    logger: structlog.BoundLogger,
    report: OperationReport,
    **extra: str | int,
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
        "--issuer-cn",
        default=None,
        help="Case-insensitive contains match on issuer CN",
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

    try:
        args = validate_cli_args(parsed_args)
        exit_code = 0

        if isinstance(args, CombineCliArgs):
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
            exit_code = 3 if result.report.invalid_count > 0 else 0
        elif isinstance(args, SplitCliArgs):
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
            exit_code = 3 if result.report.invalid_count > 0 else 0
        elif isinstance(args, ConvertCliArgs):
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
        elif isinstance(args, FilterCliArgs):
            result = filter_certificates(
                FilterRequest(
                    input=args.input,
                    output=args.output,
                    subject_cn=args.subject_cn,
                    issuer_cn=args.issuer_cn,
                    not_after_lt=args.not_after_lt,
                    not_before_gt=args.not_before_gt,
                    fingerprint=args.fingerprint,
                    exclude_expired=args.exclude_expired,
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
            exit_code = 3 if result.report.invalid_count > 0 else 0
        else:
            assert_never(args)
    except ValidationError as exc:
        logger.exception("validation error", error=str(exc))
        return 1
    except (CertificateParseError, OSError) as exc:
        logger.exception("operation error", error=str(exc))
        return 2
    else:
        return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
