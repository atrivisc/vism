import inspect
import logging

from vism.util.errors import VismException


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

class CertConfigNotFound(VismException):
    pass
