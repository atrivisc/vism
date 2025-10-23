import logging
import logging.config
import os
import sys

from pydantic.dataclasses import dataclass


@dataclass
class LoggingConfig:
    log_root: str
    log_file: str
    error_file: str
    verbose: bool = False
    log_dir: str = "./logs/"
    log_level: str = "INFO"


class SensitiveDataFilter(logging.Filter):
    SENSITIVE_PATTERNS = {}

    def sanitize(self, text):
        for name, pattern in self.SENSITIVE_PATTERNS.items():
            text = pattern['pattern'].sub(pattern['replace'], text)
        return text

    def filter(self, record):
        if isinstance(record.msg, str):
            record.msg = self.sanitize(record.msg)

        if record.args:
            record.args = tuple(
                self.sanitize(arg) if isinstance(arg, str) else arg
                for arg in record.args
            )

        return True

class ErrorFilter(logging.Filter):
    def filter(self, record):
        return record.levelno <= logging.WARNING

class ColoredFormatter(logging.Formatter):
    RED = '\033[91m'
    RESET = '\033[0m'

    def format(self, record):
        formatted = super().format(record)
        if record.levelno >= logging.ERROR:
            formatted = f"{self.RED}{formatted}{self.RESET}"

        return formatted

def setup_logger(config: LoggingConfig):
    if not os.path.exists(config.log_dir):
        raise ValueError(f"Log directory {config.log_dir} does not exist.")

    logging_config = {
        'version': 1,
        'disable_existing_loggers': False,
        'filters': {
            'sensitive_data': {
                '()': SensitiveDataFilter,
            },
            'info_debug_only': {
                '()': ErrorFilter,
            }
        },
        'formatters': {
            'verbose': {
                '()': ColoredFormatter,
                'format': '%(asctime)s [%(name)-30s] [%(levelname)-8s] %(message)s',
                'datefmt': '%Y-%m-%d %H:%M:%S',
            },
            'simple': {
                '()': ColoredFormatter,
                'format': '%(asctime)s [%(levelname)-8s] %(message)s',
                'datefmt': '%Y-%m-%d %H:%M:%S',
            },
        },
        'handlers': {
            'file': {
                'level': f"{config.log_level}",
                'class': 'logging.FileHandler',
                'formatter': 'simple' if not config.verbose else 'verbose',
                'filename': f'{config.log_dir.rstrip("/")}/{config.log_file}',
                'encoding': 'utf8',
                'filters': ['sensitive_data', 'info_debug_only']
            },
            "uvicorn": {
                "level": "INFO",
                "class": "logging.StreamHandler",
                "formatter": 'simple' if not config.verbose else 'verbose',
                "stream": sys.stdout,
            },
            "uvicorn_error": {
                "level": "INFO",
                "class": "logging.StreamHandler",
                "formatter": 'simple' if not config.verbose else 'verbose',
                "stream": sys.stderr,
            },
            'error_file': {
                'level': f"ERROR",
                'class': 'logging.FileHandler',
                'formatter': 'simple' if not config.verbose else 'verbose',
                'filename': f'{config.log_dir.rstrip("/")}/{config.error_file}',
                'encoding': 'utf8',
                'filters': ['sensitive_data']
            },
        },
        'loggers': {
            f'{config.log_root}': {
                'level': config.log_level,
                'handlers': ['file', 'error_file'],
                "propagate": False,
            },
            'shared': {
                'level': config.log_level,
                'handlers': ['file', 'error_file'],
                "propagate": False,
            },
            'module': {
                'level': config.log_level,
                'handlers': ['file', 'error_file'],
                "propagate": False,
            },
            "uvicorn": {
                "handlers": ["uvicorn"],
                "level": "INFO",
                "propagate": False,
            },
            "uvicorn.error": {
                "handlers": ["uvicorn_error"],
                "level": "INFO",
                "propagate": False,
            },
            "uvicorn.access": {
                "handlers": ["uvicorn"],
                "level": "INFO",
                "propagate": False,
            },
        }
    }

    logging.config.dictConfig(logging_config)
    logging.debug("Logging is set up and ready")