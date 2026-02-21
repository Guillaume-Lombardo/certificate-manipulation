from __future__ import annotations

import certificate_manipulation as cm


def test_public_api_contract_exports_expected_symbols() -> None:
    expected_symbols = {
        "AsyncExecutionError",
        "CertificateParseError",
        "CertificateRecord",
        "CliCommand",
        "CombineRequest",
        "CombineResult",
        "ConvertRequest",
        "ConvertResult",
        "FilterLogicMode",
        "FilterRequest",
        "FilterResult",
        "InvalidCertPolicy",
        "OperationError",
        "OperationReport",
        "OutputExt",
        "OverwritePolicy",
        "PackageError",
        "Settings",
        "SettingsError",
        "SortMode",
        "SplitNamingStrategy",
        "SplitRequest",
        "SplitResult",
        "ValidationError",
        "__version__",
        "combine",
        "configure_logging",
        "convert",
        "filter_certificates",
        "get_logger",
        "get_settings",
        "run_async",
        "split",
    }

    assert set(cm.__all__) == expected_symbols
    for symbol in expected_symbols:
        assert hasattr(cm, symbol)
