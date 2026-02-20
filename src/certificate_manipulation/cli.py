"""CLI entry point for certificate-manipulation."""

from __future__ import annotations

import argparse
from pathlib import Path  # noqa: TC003
from typing import Annotated, Literal

from pydantic import BaseModel, Field
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
from certificate_manipulation.domain.models import CombineRequest, ConvertRequest, SplitRequest
from certificate_manipulation.exceptions import (
    CertificateParseError,
    ValidationError,
)
from certificate_manipulation.logging import configure_logging, get_logger
from certificate_manipulation.services.bundle_service import combine, convert, split
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


ValidatedCliArgs = CombineCliArgs | SplitCliArgs | ConvertCliArgs


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
            logger.info(
                "combine completed",
                output=str(result.output_path),
                certificate_count=result.certificate_count,
                warnings=result.report.warnings,
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
            logger.info(
                "split completed",
                written=len(result.output_paths),
                warnings=result.report.warnings,
            )
            exit_code = 3 if result.report.invalid_count > 0 else 0
        else:
            result = convert(
                ConvertRequest(
                    input=args.input,
                    output=args.output,
                    to=args.to,
                    overwrite=args.overwrite,
                ),
            )
            logger.info("convert completed", output=str(result.output_path))

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
