from pydantic import BaseModel

class ErrorResponse(BaseModel):
    err: str
    detail: str = None
    traceback: str = None

class CertificateResponse(BaseModel):
    name: str
    crt_pem: str
    crl_pem: str = None

class CreatedCertificatesResponse(BaseModel):
    certificates: list[CertificateResponse]

class CertificateStatusResponse(BaseModel):
    name: str
    status: str

class CertificateStatusesResponse(BaseModel):
    statuses: list[CertificateStatusResponse]