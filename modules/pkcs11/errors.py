# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""PKCS#11 module exception classes."""

from shared.errors import VismException


class PKCS11Error(VismException):
    """Base exception class for PKCS#11 errors."""


class PKCS11KeyNotFound(VismException):
    """Exception raised when a PKCS#11 key is not found."""


class PKCS11FailedToSignData(VismException):
    """Exception raised when signing data fails."""


class PKCS11FailedToVerifySignature(VismException):
    """Exception raised when signature verification fails."""


class PKCS11FailedToGetPublicKey(VismException):
    """Exception raised when retrieving public key fails."""


class PKCS11FailedToEncryptData(VismException):
    """Exception raised when data encryption fails."""


class PKCS11FailedToDecryptData(VismException):
    """Exception raised when data decryption fails."""
