"""Filesystem helpers for certificate operations."""

from __future__ import annotations

from typing import TYPE_CHECKING

from certificate_manipulation.exceptions import ValidationError

if TYPE_CHECKING:
    from pathlib import Path

SUPPORTED_EXTENSIONS = {".pem", ".crt"}


def collect_input_files(inputs: list[Path], *, recursive: bool) -> list[Path]:
    """Collect certificate files from explicit files and directories.

    Args:
        inputs (list[Path]): Input file and directory paths.
        recursive (bool): Whether directory traversal is recursive.

    Raises:
        ValidationError: If any input path does not exist.

    Returns:
        list[Path]: Collected certificate files in deterministic order.
    """
    files: list[Path] = []
    for input_path in inputs:
        path = input_path.expanduser()
        if not path.exists():
            raise ValidationError(message=f"Input path does not exist: {path}")
        if path.is_file():
            if path.suffix.lower() in SUPPORTED_EXTENSIONS:
                files.append(path)
            continue

        iterator = path.rglob("*") if recursive else path.glob("*")
        files.extend(
            child for child in iterator if child.is_file() and child.suffix.lower() in SUPPORTED_EXTENSIONS
        )

    # Stable order for deterministic output.
    return sorted(dict.fromkeys(files))


def read_text_file(path: Path) -> str:
    """Read UTF-8 text file.

    Args:
        path (Path): File path.

    Returns:
        str: File content.
    """
    return path.read_text(encoding="utf-8")


def write_text_file(path: Path, content: str) -> None:
    """Write UTF-8 text file, creating parent directories.

    Args:
        path (Path): File path.
        content (str): Text content to write.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
