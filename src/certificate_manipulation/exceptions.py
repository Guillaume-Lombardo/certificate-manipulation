"""Package exceptions."""

from __future__ import annotations

from dataclasses import dataclass


class PackageError(Exception):
    """Root exception for the package."""


@dataclass(frozen=True)
class SettingsError(PackageError):
    """Raised when settings cannot be loaded or validated."""

    message: str = "Failed to load settings"
    exc: Exception | None = None

    def __str__(self) -> str:
        """Return error message payload."""
        return f"{self.message}: {self.exc}" if self.exc else self.message


@dataclass(frozen=True)
class AsyncExecutionError(PackageError):
    """Raised when an async operation fails in compatibility runner."""

    result: BaseException
    message: str = "Async operation failed"

    def __str__(self) -> str:
        """Return error message payload."""
        return f"{self.message}: {self.result}"


@dataclass(frozen=True)
class CertificateParseError(PackageError):
    """Raised when a certificate payload cannot be parsed."""

    message: str = "Failed to parse certificate"
    exc: Exception | None = None

    def __str__(self) -> str:
        """Return error message payload."""
        return f"{self.message}: {self.exc}" if self.exc else self.message


@dataclass(frozen=True)
class ValidationError(PackageError):
    """Raised when inputs are invalid for an operation."""

    message: str

    def __str__(self) -> str:
        """Return error message payload."""
        return self.message


@dataclass(frozen=True)
class OperationError(PackageError):
    """Raised when an operation fails at runtime."""

    message: str
    exc: Exception | None = None

    def __str__(self) -> str:
        """Return error message payload."""
        return f"{self.message}: {self.exc}" if self.exc else self.message
