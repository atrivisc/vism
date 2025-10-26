# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""Shared exception classes for VISM components."""

import logging

shared_logger = logging.getLogger("vism_shared")


class VismBreakingException(SystemExit):
    """Critical exception that causes system exit."""

    log_level = logging.CRITICAL
    include_traceback = True

    def __init__(self, message: str, *args):
        super().__init__(message, *args)
        self._log_error(message, *args)

    def _log_error(self, message: str, *args):
        shared_logger.log(
            self.log_level,
            "%s: %s",
            self.__class__.__name__,
            message,
            exc_info=self.include_traceback,
            *args
        )


class VismException(RuntimeError):
    """Base exception class for VISM errors."""

    log_level = logging.ERROR
    include_traceback = False

    def __init__(self, message: str, *args):
        super().__init__(message, *args)
        self._log_error(message, *args)

    def _log_error(self, message: str, *args):
        shared_logger.log(
            self.log_level,
            "%s: %s",
            self.__class__.__name__,
            message,
            exc_info=self.include_traceback,
            *args
        )


class VismDatabaseException(VismException):
    """Exception raised for database-related errors."""


class ChrootWriteFileExists(VismException):
    """Exception raised when attempting to write to an existing file."""


class ChrootWriteToFileException(VismException):
    """Exception raised when writing to a file fails."""


class ChrootOpenFileException(VismException):
    """Exception raised when opening a file fails."""
