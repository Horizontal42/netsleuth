"""Netsleuth - Cross-platform CLI for deep network diagnostics.

Provides ISP/VPN/ASN identity, latency, path and bandwidth analysis
with comprehensive reporting in multiple formats.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

__version__ = "0.1.0"

# Configure structured logging with JSON formatter when available
logger = logging.getLogger(__name__)


def setup_logging(
    level: int = logging.INFO,
    log_file: Path | None = None,
    json_format: bool = False,
) -> None:
    """Configure structured logging for netsleuth.

    Args:
        level: Logging level (default: INFO)
        log_file: Optional file path for log output
        json_format: If True, use JSON formatting for structured logs
    """
    handlers: list[logging.Handler] = []

    # Console handler with rich formatting
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)

    if json_format:
        try:
            from pythonjsonlogger import jsonlogger

            json_formatter = jsonlogger.JsonFormatter(
                fmt="%(asctime)s %(name)s %(levelname)s %(message)s %(filename)s %(lineno)d",
                datefmt="%Y-%m-%dT%H:%M:%S%z",
            )
            console_handler.setFormatter(json_formatter)
        except ImportError:
            # Fallback to basic format if python-json-logger not installed
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            console_handler.setFormatter(formatter)
    else:
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        console_handler.setFormatter(formatter)

    handlers.append(console_handler)

    # File handler if requested
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(level)
        if json_format:
            try:
                from pythonjsonlogger import jsonlogger

                json_formatter = jsonlogger.JsonFormatter(
                    fmt="%(asctime)s %(name)s %(levelname)s %(message)s %(filename)s %(lineno)d",
                    datefmt="%Y-%m-%dT%H:%M:%S%z",
                )
                file_handler.setFormatter(json_formatter)
            except ImportError:
                formatter = logging.Formatter(
                    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                )
                file_handler.setFormatter(formatter)
        else:
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            file_handler.setFormatter(formatter)
        handlers.append(file_handler)

    logging.basicConfig(level=level, handlers=handlers, force=True)
    logger.debug("Logging configured: level=%s, file=%s, json=%s", level, log_file, json_format)
