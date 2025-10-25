# Licensed under the GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""OpenSSL module exception classes."""

import inspect
import logging


class OpensslException(Exception):
    """Base exception class for OpenSSL module errors."""

    log_level = logging.ERROR
    include_traceback = False

    def __init__(self, message: str, *args, context: dict = None):
        super().__init__(message, *args)
        self.context = context or {}
        self._log_error(message)

    def _log_error(self, message: str):
        frame = inspect.currentframe()
        try:
            caller_frame = frame.f_back.f_back
            caller_module = inspect.getmodule(caller_frame)
            logger_name = (
                caller_module.__name__ if caller_module else __name__
            )
        finally:
            del frame

        logger = logging.getLogger(logger_name)
        logger.log(
            self.log_level,
            "%s: %s",
            self.__class__.__name__,
            message,
            exc_info=self.include_traceback
        )


class ProfileNotFound(OpensslException):
    """Exception raised when OpenSSL profile is not found."""


class MultipleProfilesFound(OpensslException):
    """Exception raised when multiple profiles match the search."""
