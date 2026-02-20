from certificate_manipulation.exceptions import (
    AsyncExecutionError,
    CertificateParseError,
    OperationError,
    PackageError,
    SettingsError,
    ValidationError,
)


def test_root_exception_hierarchy() -> None:
    assert issubclass(SettingsError, PackageError)
    assert issubclass(AsyncExecutionError, PackageError)
    assert issubclass(CertificateParseError, PackageError)
    assert issubclass(ValidationError, PackageError)
    assert issubclass(OperationError, PackageError)
