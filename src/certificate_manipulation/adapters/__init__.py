"""Adapters for external I/O and certificate parsing."""

from certificate_manipulation.adapters.filesystem_io import (
    collect_input_files,
    read_text_file,
    write_text_file,
)
from certificate_manipulation.adapters.x509_parser import (
    extract_pem_blocks,
    load_from_file,
    parse_many_from_text,
    parse_single_pem,
)

__all__ = [
    "collect_input_files",
    "extract_pem_blocks",
    "load_from_file",
    "parse_many_from_text",
    "parse_single_pem",
    "read_text_file",
    "write_text_file",
]
