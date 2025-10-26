# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html

"""Set of Vism CA specific exceptions"""

from shared.errors import VismException


class GenCertException(VismException):
    """Raised when a certificate cannot be generated."""

class GenCSRException(VismException):
    """Raised when a CSR cannot be generated."""

class GenPKEYException(VismException):
    """Raised when a PKEY cannot be generated."""

class GenCRLException(VismException):
    """Raised when a CRL cannot be generated."""

class CertConfigNotFound(VismException):
    """Raised when a certificate config cannot be found."""
