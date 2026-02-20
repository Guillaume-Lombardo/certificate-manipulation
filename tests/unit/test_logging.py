from __future__ import annotations

from certificate_manipulation.logging import configure_logging, get_logger
from certificate_manipulation.settings import Settings


def test_structlog_logger_is_configured(capsys) -> None:
    configure_logging(settings=Settings(log_json=False, log_level="INFO"), force=True)
    logger = get_logger("tests")
    logger.info("hello")

    captured = capsys.readouterr()
    assert "hello" in captured.err.lower()
