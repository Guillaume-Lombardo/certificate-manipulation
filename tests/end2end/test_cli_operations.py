from __future__ import annotations

import sys
from subprocess import run as subprocess_run  # noqa: S404

from certificate_manipulation.adapters.x509_parser import parse_many_from_text
from tests.cert_factory import make_self_signed_pem


def test_cli_combine_and_split_flow(tmp_path) -> None:
    cert_a = tmp_path / "a.crt"
    cert_b = tmp_path / "b.crt"
    cert_a.write_text(make_self_signed_pem("router-a"), encoding="utf-8")
    cert_b.write_text(make_self_signed_pem("router-b"), encoding="utf-8")

    bundle = tmp_path / "bundle.pem"
    combine = subprocess_run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "certificate_manipulation.cli",
            "combine",
            "--inputs",
            str(cert_a),
            str(cert_b),
            "--output",
            str(bundle),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert combine.returncode == 0
    assert bundle.exists()

    out_dir = tmp_path / "split"
    split = subprocess_run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "certificate_manipulation.cli",
            "split",
            "--input",
            str(bundle),
            "--output-dir",
            str(out_dir),
            "--filename-template",
            "index",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert split.returncode == 0

    split_files = sorted(out_dir.glob("*.crt"))
    assert len(split_files) == 2

    split_bundle_text = "\n".join(path.read_text(encoding="utf-8") for path in split_files)
    records = parse_many_from_text(split_bundle_text)
    assert len(records) == 2
