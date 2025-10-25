# Licensed under the GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""Logging configuration and utilities for VISM components."""

import os
import logging
import re
from dataclasses import dataclass
from logging.handlers import RotatingFileHandler


@dataclass
class LoggingConfig:
    """Configuration for logging system."""

    log_root: str = "logs"
    log_file: str = "app.log"
    error_file: str = "error.log"
    log_level: str = "INFO"


class SensitiveDataFilter(logging.Filter): # pylint: disable=too-few-public-methods
    """Filter to mask sensitive data in log messages."""

    SENSITIVE_PATTERNS = set()

    def filter(self, record):
        """Filter and mask sensitive data in log record."""
        for _pattern_name, pattern in self.SENSITIVE_PATTERNS:
            if isinstance(record.msg, str):
                record.msg = re.sub(
                    pattern,
                    r'\1***REDACTED***',
                    record.msg
                )
            if record.args:
                record.args = tuple(
                    re.sub(pattern, r'\1***REDACTED***', str(arg))
                    if isinstance(arg, str) else arg
                    for arg in record.args
                )
        return True


class ColoredFormatter(logging.Formatter):  # pylint: disable=too-few-public-methods
    """Formatter that adds color codes to log messages."""


@dataclass
class LoggingHandlers:
    """Container for logging handlers."""

    console_handler: logging.Handler
    file_handler: logging.Handler
    error_handler: logging.Handler


def setup_logger(config: LoggingConfig):
    """
    Set up logging configuration with handlers and formatters.

    Args:
        config: Logging configuration
    """
    # Create log directory if it doesn't exist
    os.makedirs(config.log_root, exist_ok=True)

    # Define log format
    log_format = (
        '%(asctime)s - %(name)s - %(levelname)s - '
        '%(filename)s:%(lineno)d - %(message)s'
    )

    # Create formatters
    formatter = logging.Formatter(log_format)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(SensitiveDataFilter())

    # File handler for all logs
    file_handler = RotatingFileHandler(
        f'{config.log_root}/{config.log_file}',
        maxBytes=10485760,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    file_handler.addFilter(SensitiveDataFilter())

    # Error file handler
    error_handler = RotatingFileHandler(
        f'{config.log_root}/{config.error_file}',
        maxBytes=10485760,  # 10MB
        backupCount=5
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(formatter)
    error_handler.addFilter(SensitiveDataFilter())

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, config.log_level.upper()))

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Add new handlers
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(error_handler)

    # Log initialization
    logging.info("Logging system initialized")
