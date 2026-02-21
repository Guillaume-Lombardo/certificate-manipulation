from __future__ import annotations

import sys
from collections import Counter
from datetime import UTC, datetime, timedelta
from subprocess import CompletedProcess  # noqa: S404
from subprocess import run as subprocess_run  # noqa: S404

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from certificate_manipulation.adapters.x509_parser import parse_many_from_text
from tests.cert_factory import make_self_signed_der, make_self_signed_pem


def run_cli(args: list[str]) -> CompletedProcess[str]:
    """Run the CLI module command and capture outputs.

    Args:
        args (list[str]): CLI arguments excluding the Python module prefix.

    Returns:
        CompletedProcess[str]: Subprocess result object.
    """
    return subprocess_run(  # noqa: S603
        [sys.executable, "-m", "certificate_manipulation.cli", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def make_expired_self_signed_pem(common_name: str) -> str:
    private_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(tz=UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    certificate = (
        x509
        .CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=30))
        .not_valid_after(now - timedelta(days=1))
        .sign(private_key=private_key, algorithm=hashes.SHA256())
    )
    return certificate.public_bytes(Encoding.PEM).decode("utf-8")


def test_cli_combine_split_recombine_flow(tmp_path) -> None:
    cert_a = tmp_path / "a.crt"
    cert_b = tmp_path / "b.crt"
    cert_c = tmp_path / "c.crt"
    cert_a.write_text(make_self_signed_pem("router-a"), encoding="utf-8")
    cert_b.write_text(make_self_signed_pem("router-b"), encoding="utf-8")
    cert_c.write_text(make_self_signed_pem("router-c"), encoding="utf-8")

    bundle = tmp_path / "bundle.pem"
    combine = run_cli(
        [
            "combine",
            "--inputs",
            str(cert_a),
            str(cert_b),
            str(cert_c),
            "--output",
            str(bundle),
        ],
    )
    assert combine.returncode == 0
    assert bundle.exists()

    out_dir = tmp_path / "split"
    split = run_cli(
        [
            "split",
            "--input",
            str(bundle),
            "--output-dir",
            str(out_dir),
            "--filename-template",
            "index",
        ],
    )
    assert split.returncode == 0

    split_files = sorted(out_dir.glob("*.crt"))
    assert len(split_files) == 3

    recombined = tmp_path / "recombined.pem"
    recombine = run_cli(
        [
            "combine",
            "--inputs",
            *[str(path) for path in split_files],
            "--output",
            str(recombined),
        ],
    )
    assert recombine.returncode == 0

    original_records = parse_many_from_text(bundle.read_text(encoding="utf-8"))
    recombined_records = parse_many_from_text(recombined.read_text(encoding="utf-8"))
    original_fingerprints = Counter(item.fingerprint_sha256 for item in original_records)
    recombined_fingerprints = Counter(item.fingerprint_sha256 for item in recombined_records)
    assert original_fingerprints == recombined_fingerprints


def test_cli_combine_skip_invalid_returns_partial_success(tmp_path) -> None:
    valid_cert = tmp_path / "valid.crt"
    invalid_cert = tmp_path / "invalid.crt"
    valid_cert.write_text(make_self_signed_pem("edge-router"), encoding="utf-8")
    invalid_cert.write_text("not-a-certificate", encoding="utf-8")

    bundle = tmp_path / "bundle.pem"
    combine = run_cli(
        [
            "combine",
            "--inputs",
            str(valid_cert),
            str(invalid_cert),
            "--output",
            str(bundle),
            "--on-invalid",
            "skip",
        ],
    )
    assert combine.returncode == 3
    records = parse_many_from_text(bundle.read_text(encoding="utf-8"))
    assert len(records) == 1


def test_cli_filter_exclude_expired(tmp_path) -> None:
    active = make_self_signed_pem("core-active", valid_days=365)
    expired = make_expired_self_signed_pem("core-expired")
    bundle = tmp_path / "bundle.pem"
    bundle.write_text(f"{active}\n{expired}", encoding="utf-8")

    filtered = tmp_path / "filtered.pem"
    filter_result = run_cli(
        [
            "filter",
            "--input",
            str(bundle),
            "--output",
            str(filtered),
            "--exclude-expired",
        ],
    )
    assert filter_result.returncode == 0

    filtered_records = parse_many_from_text(filtered.read_text(encoding="utf-8"))
    assert len(filtered_records) == 1
    assert filtered_records[0].subject_common_name == "core-active"


def test_cli_combine_accepts_der_input(tmp_path) -> None:
    cert_pem = tmp_path / "a.crt"
    cert_der = tmp_path / "b.der"
    cert_pem.write_text(make_self_signed_pem("router-pem"), encoding="utf-8")
    cert_der.write_bytes(make_self_signed_der("router-der"))

    bundle = tmp_path / "bundle.pem"
    combine = run_cli(
        [
            "combine",
            "--inputs",
            str(cert_pem),
            str(cert_der),
            "--output",
            str(bundle),
        ],
    )

    assert combine.returncode == 0
    records = parse_many_from_text(bundle.read_text(encoding="utf-8"))
    assert len(records) == 2


def test_cli_filter_supports_regex_and_or_logic(tmp_path) -> None:
    cert_a = tmp_path / "a.crt"
    cert_b = tmp_path / "b.crt"
    cert_a.write_text(make_self_signed_pem("router-edge"), encoding="utf-8")
    cert_b.write_text(make_self_signed_pem("switch-core"), encoding="utf-8")
    bundle = tmp_path / "bundle.pem"
    combine = run_cli(
        [
            "combine",
            "--inputs",
            str(cert_a),
            str(cert_b),
            "--output",
            str(bundle),
        ],
    )
    assert combine.returncode == 0

    regex_output = tmp_path / "regex.pem"
    regex_filter = run_cli(
        [
            "filter",
            "--input",
            str(bundle),
            "--output",
            str(regex_output),
            "--subject-cn-regex",
            "^router-.*",
        ],
    )
    assert regex_filter.returncode == 0
    regex_records = parse_many_from_text(regex_output.read_text(encoding="utf-8"))
    assert len(regex_records) == 1

    or_output = tmp_path / "or.pem"
    or_filter = run_cli(
        [
            "filter",
            "--input",
            str(bundle),
            "--output",
            str(or_output),
            "--subject-cn",
            "router",
            "--issuer-cn",
            "nope",
            "--logic",
            "or",
        ],
    )
    assert or_filter.returncode == 0
    or_records = parse_many_from_text(or_output.read_text(encoding="utf-8"))
    assert len(or_records) == 1
