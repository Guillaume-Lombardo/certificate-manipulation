from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from certificate_manipulation import cli
from certificate_manipulation.domain.enums import (
    CliCommand,
    InvalidCertPolicy,
    OutputExt,
    OverwritePolicy,
    SortMode,
    SplitNamingStrategy,
)
from certificate_manipulation.domain.models import (
    CombineResult,
    ConvertResult,
    OperationReport,
    SplitResult,
)


def test_build_parser_supports_version_flag(capsys) -> None:
    parser = cli.build_parser()

    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["--version"])
    assert exc_info.value.code == 0

    captured = capsys.readouterr()
    assert "0.1.0" in captured.out


def test_main_returns_validation_error_exit_code(mocker) -> None:
    args = argparse.Namespace(
        command="combine",
        inputs=["missing.crt"],
        recursive=False,
        output="bundle.pem",
        deduplicate=True,
        sort="input",
        on_invalid="fail",
        overwrite="version",
    )

    parser = mocker.Mock()
    parser.parse_args.return_value = args
    mocker.patch("certificate_manipulation.cli.build_parser", return_value=parser)
    mocker.patch("certificate_manipulation.cli.configure_logging")
    mock_logger = mocker.patch("certificate_manipulation.cli.get_logger")
    mocker.patch(
        "certificate_manipulation.cli.combine",
        side_effect=cli.ValidationError(message="bad input"),
    )

    result = cli.main()

    assert result == 1
    assert mock_logger.return_value.exception.called


def test_main_returns_operation_error_exit_code(mocker) -> None:
    args = argparse.Namespace(
        command="combine",
        inputs=["valid.crt"],
        recursive=False,
        output="bundle.pem",
        deduplicate=True,
        sort="input",
        on_invalid="fail",
        overwrite="version",
    )
    parser = mocker.Mock()
    parser.parse_args.return_value = args
    mocker.patch("certificate_manipulation.cli.build_parser", return_value=parser)
    mocker.patch("certificate_manipulation.cli.configure_logging")
    mocker.patch("certificate_manipulation.cli.get_logger")
    mocker.patch(
        "certificate_manipulation.cli.combine",
        side_effect=cli.CertificateParseError(message="bad cert"),
    )

    result = cli.main()

    assert result == 2


def test_main_combine_partial_success_returns_three(mocker) -> None:
    args = argparse.Namespace(
        command="combine",
        inputs=["valid.crt"],
        recursive=False,
        output="bundle.pem",
        deduplicate=True,
        sort="input",
        on_invalid="skip",
        overwrite="version",
    )
    parser = mocker.Mock()
    parser.parse_args.return_value = args
    mocker.patch("certificate_manipulation.cli.build_parser", return_value=parser)
    mocker.patch("certificate_manipulation.cli.configure_logging")
    mocker.patch("certificate_manipulation.cli.get_logger")
    mocker.patch(
        "certificate_manipulation.cli.combine",
        return_value=CombineResult(
            output_path=Path("bundle.pem"),
            certificate_count=1,
            report=OperationReport(
                processed=2,
                written=1,
                skipped=1,
                invalid_count=1,
                warnings=["x"],
            ),
        ),
    )

    result = cli.main()

    assert result == 3


def test_main_split_success_returns_zero(mocker) -> None:
    args = argparse.Namespace(
        command="split",
        input="bundle.pem",
        output_dir="out",
        ext="crt",
        filename_template="index",
        on_invalid="fail",
        overwrite="version",
    )
    parser = mocker.Mock()
    parser.parse_args.return_value = args
    mocker.patch("certificate_manipulation.cli.build_parser", return_value=parser)
    mocker.patch("certificate_manipulation.cli.configure_logging")
    mocker.patch("certificate_manipulation.cli.get_logger")
    mocker.patch(
        "certificate_manipulation.cli.split",
        return_value=SplitResult(
            output_paths=[Path("out/cert-001.crt")],
            report=OperationReport(
                processed=1,
                written=1,
                skipped=0,
                invalid_count=0,
                warnings=[],
            ),
        ),
    )

    result = cli.main()

    assert result == 0


def test_main_convert_success_returns_zero(mocker) -> None:
    args = argparse.Namespace(
        command="convert",
        input="a.crt",
        output="a.pem",
        to="pem",
        overwrite="version",
    )
    parser = mocker.Mock()
    parser.parse_args.return_value = args
    mocker.patch("certificate_manipulation.cli.build_parser", return_value=parser)
    mocker.patch("certificate_manipulation.cli.configure_logging")
    mocker.patch("certificate_manipulation.cli.get_logger")
    mocker.patch(
        "certificate_manipulation.cli.convert",
        return_value=ConvertResult(
            output_path=Path("a.pem"),
            report=OperationReport(
                processed=1,
                written=1,
                skipped=0,
                invalid_count=0,
                warnings=[],
            ),
        ),
    )

    result = cli.main()

    assert result == 0


def test_validate_cli_args_for_each_command() -> None:
    combine_args = argparse.Namespace(
        command="combine",
        inputs=["a.crt"],
        recursive=False,
        output="bundle.pem",
        deduplicate=True,
        sort="input",
        on_invalid="fail",
        overwrite="version",
    )
    split_args = argparse.Namespace(
        command="split",
        input="bundle.pem",
        output_dir="out",
        ext="crt",
        filename_template="cn",
        on_invalid="fail",
        overwrite="version",
    )
    convert_args = argparse.Namespace(
        command="convert",
        input="a.crt",
        output="a.pem",
        to="pem",
        overwrite="version",
    )

    parsed_combine = cli.validate_cli_args(combine_args)
    parsed_split = cli.validate_cli_args(split_args)
    parsed_convert = cli.validate_cli_args(convert_args)

    assert isinstance(parsed_combine, cli.CombineCliArgs)
    assert parsed_combine.command == CliCommand.COMBINE
    assert parsed_combine.sort == SortMode.INPUT
    assert parsed_combine.on_invalid == InvalidCertPolicy.FAIL
    assert parsed_combine.overwrite == OverwritePolicy.VERSION

    assert isinstance(parsed_split, cli.SplitCliArgs)
    assert parsed_split.command == CliCommand.SPLIT
    assert parsed_split.filename_template == SplitNamingStrategy.CN
    assert parsed_split.ext == OutputExt.CRT

    assert isinstance(parsed_convert, cli.ConvertCliArgs)
    assert parsed_convert.command == CliCommand.CONVERT
    assert parsed_convert.to == OutputExt.PEM
