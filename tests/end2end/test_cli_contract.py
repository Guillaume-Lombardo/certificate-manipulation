from __future__ import annotations

import sys
from subprocess import run as subprocess_run  # noqa: S404


def run_help(*args: str) -> str:
    """Run CLI help command and return stdout.

    Args:
        *args (str): Additional CLI args.

    Returns:
        str: Help output.
    """
    result = subprocess_run(  # noqa: S603
        [sys.executable, "-m", "certificate_manipulation.cli", *args, "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    return result.stdout


def test_cli_root_contract_has_stable_subcommands() -> None:
    output = run_help()
    for command in ("combine", "split", "convert", "filter"):
        assert command in output


def test_cli_combine_contract_has_stable_options() -> None:
    output = run_help("combine")
    for option in (
        "--inputs",
        "--recursive",
        "--output",
        "--deduplicate",
        "--sort",
        "--on-invalid",
        "--overwrite",
        "--report-json",
    ):
        assert option in output


def test_cli_split_contract_has_stable_options() -> None:
    output = run_help("split")
    for option in (
        "--input",
        "--output-dir",
        "--ext",
        "--filename-template",
        "--on-invalid",
        "--overwrite",
        "--report-json",
    ):
        assert option in output


def test_cli_convert_contract_has_stable_options() -> None:
    output = run_help("convert")
    for option in ("--input", "--output", "--to", "--overwrite", "--report-json"):
        assert option in output


def test_cli_filter_contract_has_stable_options() -> None:
    output = run_help("filter")
    for option in (
        "--input",
        "--output",
        "--subject-cn",
        "--subject-cn-regex",
        "--issuer-cn",
        "--issuer-cn-regex",
        "--not-after-lt",
        "--not-before-gt",
        "--fingerprint",
        "--exclude-expired",
        "--logic",
        "--on-invalid",
        "--overwrite",
        "--report-json",
    ):
        assert option in output
