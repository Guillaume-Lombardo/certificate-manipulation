#!/usr/bin/env python3
"""Run a basic local benchmark for large certificate bundles.

This script generates self-signed certificates, then measures CLI command timings
for combine, split, and filter operations.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess  # noqa: S404
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments.

    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser(description="Benchmark certificate-manipulation CLI")
    parser.add_argument("--cert-count", type=int, default=200, help="Number of generated certificates")
    parser.add_argument(
        "--workdir",
        type=Path,
        default=Path(".benchmarks") / "phase3",
        help="Working directory for generated artifacts",
    )
    return parser.parse_args()


def make_self_signed_pem(common_name: str) -> str:
    """Build one self-signed PEM certificate.

    Args:
        common_name (str): Common Name for subject and issuer.

    Returns:
        str: PEM-encoded certificate.
    """
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
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(private_key=private_key, algorithm=hashes.SHA256())
    )
    return certificate.public_bytes(Encoding.PEM).decode("utf-8")


def run_cli(*args: str) -> float:
    """Run the package CLI command and return elapsed seconds.

    Args:
        *args (str): CLI arguments.

    Raises:
        RuntimeError: If the command fails.

    Returns:
        float: Elapsed execution time in seconds.
    """
    start = perf_counter()
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "certificate_manipulation.cli", *args],
        capture_output=True,
        text=True,
        check=False,
    )
    elapsed = perf_counter() - start
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
    return elapsed


def write_input_certs(*, cert_count: int, input_dir: Path) -> None:
    """Generate benchmark certificates under one directory.

    Args:
        cert_count (int): Number of certificates to create.
        input_dir (Path): Destination directory.
    """
    input_dir.mkdir(parents=True, exist_ok=True)
    for index in range(1, cert_count + 1):
        cert_path = input_dir / f"cert-{index:04d}.crt"
        cert_path.write_text(make_self_signed_pem(f"bench-{index:04d}"), encoding="utf-8")


def main() -> int:
    """Entrypoint for benchmark execution.

    Returns:
        int: Process exit code.
    """
    args = parse_args()
    workdir = args.workdir

    if workdir.exists():
        shutil.rmtree(workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    input_dir = workdir / "input"
    split_dir = workdir / "split"
    bundle = workdir / "bundle.pem"
    filtered = workdir / "filtered.pem"

    write_input_certs(cert_count=args.cert_count, input_dir=input_dir)

    combine_elapsed = run_cli("combine", "--inputs", str(input_dir), "--recursive", "--output", str(bundle))
    split_elapsed = run_cli(
        "split",
        "--input",
        str(bundle),
        "--output-dir",
        str(split_dir),
        "--filename-template",
        "index",
    )
    filter_elapsed = run_cli(
        "filter",
        "--input",
        str(bundle),
        "--output",
        str(filtered),
        "--subject-cn",
        "bench-0",
    )

    payload = {
        "cert_count": args.cert_count,
        "timings_seconds": {
            "combine": round(combine_elapsed, 4),
            "split": round(split_elapsed, 4),
            "filter": round(filter_elapsed, 4),
        },
        "artifacts": {
            "workdir": str(workdir),
            "bundle": str(bundle),
            "split_dir": str(split_dir),
            "filtered": str(filtered),
        },
    }
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
