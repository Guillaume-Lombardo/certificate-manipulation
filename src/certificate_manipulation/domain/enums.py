"""Domain enums for public user-facing choices."""

from __future__ import annotations

from enum import StrEnum


class OutputExt(StrEnum):
    """Supported output extensions."""

    PEM = "pem"
    CRT = "crt"


class OverwritePolicy(StrEnum):
    """How output collisions are handled."""

    VERSION = "version"
    FORCE = "force"
    FAIL = "fail"


class InvalidCertPolicy(StrEnum):
    """How invalid certificates are handled."""

    FAIL = "fail"
    SKIP = "skip"


class SplitNamingStrategy(StrEnum):
    """Naming strategy for certificates written by split."""

    CN = "cn"
    INDEX = "index"
    FINGERPRINT = "fingerprint"


class SortMode(StrEnum):
    """Sort order when combining certificates."""

    INPUT = "input"
    SUBJECT = "subject"
    NOT_BEFORE = "not_before"


class CliCommand(StrEnum):
    """CLI subcommand names."""

    COMBINE = "combine"
    SPLIT = "split"
    CONVERT = "convert"
