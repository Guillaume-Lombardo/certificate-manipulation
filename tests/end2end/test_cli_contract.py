from __future__ import annotations

import re
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
    assert result.returncode == 0, (
        f"CLI help command failed with return code {result.returncode}\n"
        f"STDOUT:\n{result.stdout}\n"
        f"STDERR:\n{result.stderr}"
    )
    return result.stdout


def test_cli_root_contract_has_stable_subcommands() -> None:
    output = run_help()
    match = re.search(r"\{([^}]+)\}", output)
    assert match is not None
    subcommands = {item.strip() for item in match.group(1).split(",")}
    assert subcommands == {"combine", "split", "convert", "filter"}


def extract_option_tokens(output: str) -> set[str]:
    """Extract long option tokens from one argparse help output.

    Args:
        output (str): CLI help output.

    Returns:
        set[str]: Long option tokens.
    """
    return set(re.findall(r"--[a-z0-9][a-z0-9-]*", output))


def test_cli_combine_contract_has_stable_options() -> None:
    output = run_help("combine")
    options = extract_option_tokens(output)
    assert options == {
        "--inputs",
        "--recursive",
        "--output",
        "--deduplicate",
        "--no-deduplicate",
        "--sort",
        "--on-invalid",
        "--overwrite",
        "--report-json",
        "--help",
    }


def test_cli_split_contract_has_stable_options() -> None:
    output = run_help("split")
    options = extract_option_tokens(output)
    assert options == {
        "--input",
        "--output-dir",
        "--ext",
        "--filename-template",
        "--on-invalid",
        "--overwrite",
        "--report-json",
        "--help",
    }


def test_cli_convert_contract_has_stable_options() -> None:
    output = run_help("convert")
    options = extract_option_tokens(output)
    assert options == {
        "--input",
        "--output",
        "--to",
        "--overwrite",
        "--report-json",
        "--help",
    }


def test_cli_filter_contract_has_stable_options() -> None:
    output = run_help("filter")
    options = extract_option_tokens(output)
    assert options == {
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
        "--help",
    }
