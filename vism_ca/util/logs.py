import logging
import logging.config
import sys

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

class ColoredFormatter(logging.Formatter):
    RED = '\033[91m'
    RESET = '\033[0m'

    def format(self, record):
        formatted = super().format(record)
        if record.levelno >= logging.ERROR:
            formatted = f"{self.RED}{formatted}{self.RESET}"

        return formatted

def setup_logger(loglevel: str = "INFO", verbose: bool = False):
    logging_config = {
        'version': 1,
        'disable_existing_loggers': False,
        'filters': {
            'sensitive_data': {
                '()': SensitiveDataFilter,
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
            'console': {
                'level': loglevel if not verbose else 'DEBUG',
                'class': 'logging.StreamHandler',
                'formatter': 'verbose' if verbose else 'simple',
                'stream': sys.stdout,
                'filters': ['sensitive_data']
            }
        },
        'loggers': {
            '': {
                'level': loglevel if not verbose else 'DEBUG',
                'handlers': ['console']
            }
        }
    }

    logging.config.dictConfig(logging_config)
    logging.debug("Logging is set up and ready")