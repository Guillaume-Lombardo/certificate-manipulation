from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

import pytest


def load_benchmark_module():
    """Load the benchmark script as a Python module.

    Returns:
        object: Loaded benchmark module object.
    """
    module_path = Path(__file__).resolve().parents[2] / "scripts" / "benchmark_large_bundle.py"
    spec = importlib.util.spec_from_file_location("benchmark_large_bundle", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["benchmark_large_bundle"] = module
    spec.loader.exec_module(module)
    return module


def test_evaluate_thresholds_reports_violations() -> None:
    module = load_benchmark_module()
    report = module.BenchmarkReport.model_validate(
        {
            "cert_count": 10,
            "timings_seconds": {"combine": 3.2, "split": 1.5, "filter": 2.1},
            "artifacts": {
                "workdir": "/workspace/workdir",
                "bundle": "/workspace/workdir/bundle.pem",
                "split_dir": "/workspace/workdir/split",
                "filtered": "/workspace/workdir/filtered.pem",
            },
        },
    )
    thresholds = module.BenchmarkThresholds(
        combine_max_seconds=3.0,
        split_max_seconds=2.0,
        filter_max_seconds=2.0,
    )

    failures = module.evaluate_thresholds(report=report, thresholds=thresholds)

    assert len(failures) == 2
    assert "combine exceeded threshold" in failures[0]
    assert "filter exceeded threshold" in failures[1]


def test_load_thresholds_cli_overrides_file(tmp_path: Path) -> None:
    module = load_benchmark_module()
    threshold_file = tmp_path / "thresholds.json"
    threshold_file.write_text(
        '{"combine_max_seconds": 5.0, "split_max_seconds": 6.0, "filter_max_seconds": 7.0}',
        encoding="utf-8",
    )
    args = argparse.Namespace(
        thresholds_file=threshold_file,
        assert_max_combine_seconds=4.0,
        assert_max_split_seconds=None,
        assert_max_filter_seconds=6.5,
    )

    thresholds = module.load_thresholds(args)

    assert thresholds.combine_max_seconds == pytest.approx(4.0)
    assert thresholds.split_max_seconds == pytest.approx(6.0)
    assert thresholds.filter_max_seconds == pytest.approx(6.5)
