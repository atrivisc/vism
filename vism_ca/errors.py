from shared.errors import VismException


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
