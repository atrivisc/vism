import inspect
import logging


class VismException(RuntimeError):
    log_level = logging.ERROR
    include_traceback = False

    def __init__(self, message: str, context: dict = None, *args):
        super().__init__(message, *args)
        self.context = context or {}
        self._log_error(message)

    def _log_error(self, message: str):
        frame = inspect.currentframe()
        try:
            caller_frame = frame.f_back.f_back
            caller_module = inspect.getmodule(caller_frame)
            logger_name = caller_module.__name__ if caller_module else __name__
        finally:
            del frame

        logger = logging.getLogger(logger_name)
        logger.log(
            self.log_level,
            f"{self.__class__.__name__}: {message}",
            exc_info=self.include_traceback
        )


class ChrootWriteFileExists(VismException):
    pass

class ChrootWriteToFileException(VismException):
    pass

class ChrootOpenFileException(VismException):
    pass

class GenCertException(VismException):
    pass

class GenCSRException(VismException):
    pass

class GenPKEYException(VismException):
    pass

class GenCRLException(VismException):
    pass
