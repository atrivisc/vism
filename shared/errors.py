import logging
from shared import shared_logger

class VismBreakingException(SystemExit):
    log_level = logging.CRITICAL
    include_traceback = True

    def __init__(self, message: str, context: dict = None, *args):
        super().__init__(message, *args)
        self.context = context or {}
        self._log_error(message)

    def _log_error(self, message: str):
        shared_logger.log(
            self.log_level,
            f"{self.__class__.__name__}: {message}",
            exc_info=self.include_traceback
        )

class VismException(RuntimeError):
    log_level = logging.ERROR
    include_traceback = False

    def __init__(self, message: str, context: dict = None, *args):
        super().__init__(message, *args)
        self.context = context or {}
        self._log_error(message)

    def _log_error(self, message: str):
        shared_logger.log(
            self.log_level,
            f"{self.__class__.__name__}: {message}",
            exc_info=self.include_traceback
        )


class VismDatabaseException(VismException):
    pass

class ChrootWriteFileExists(VismException):
    pass

class ChrootWriteToFileException(VismException):
    pass

class ChrootOpenFileException(VismException):
    pass
