from pydantic import BaseModel

class CreateCertificatesRequest(BaseModel):
    certificate_names: list[str]
