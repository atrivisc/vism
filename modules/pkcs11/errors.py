from shared.errors import VismException

class PKCS11Error(VismException):
    pass

class PKCS11KeyNotFound(VismException):
    pass

class PKCS11FailedToSignData(VismException):
    pass

class PKCS11FailedToVerifySignature(VismException):
    pass

class PKCS11FailedToGetPublicKey(VismException):
    pass

class PKCS11FailedToEncryptData(VismException):
    pass

class PKCS11FailedToDecryptData(VismException):
    pass