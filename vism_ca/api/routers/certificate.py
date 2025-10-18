import logging
import traceback

from fastapi import APIRouter
from starlette.responses import JSONResponse

from vism_ca.api.schema.requests import CreateCertificatesRequest
from vism_ca.api.schema.responses import CertificateResponse, CreatedCertificatesResponse, ErrorResponse, \
    CertificateStatusResponse, CertificateStatusesResponse
from vism_ca.ca import VismCA
from vism_ca.ca.crypto.certificate import Certificate
from vism_ca.errors import CertConfigNotFound, GenCertException

logger = logging.getLogger(__name__)

class CertificateRouter:
    def __init__(self, ca: VismCA):
        self.ca = ca
        self.router = APIRouter()

        self.router.get("/status")(self.cert_status)
        self.router.post("/create")(self.create_certificates)
        self.router.get("/{certificate_name}")(self.get_certificate)

    def get_certificate(self, certificate_name: str):
        cert_entity = self.ca.database.get_cert_by_name(name=certificate_name)
        if not cert_entity:
            return JSONResponse(
                status_code=404,
                content={"err": "Certificate not found."},
                headers={
                    "Content-Type": "application/json",
                }
            )
        return JSONResponse(
            status_code=200,
            content=CertificateResponse(**cert_entity.cert_data()).model_dump(),
            headers={}
        )

    def cert_status(self):
        certificate_statuses = []
        for cert_config in self.ca.config.x509_certificates:
            cert = self.ca.database.get_cert_by_name(name=cert_config.name)
            cert_status = CertificateStatusResponse(
                name=cert_config.name,
                status='not_created' if not cert else 'created'
            )
            certificate_statuses.append(cert_status)

        return JSONResponse(
            status_code=200,
            content=CertificateStatusesResponse(statuses=certificate_statuses).model_dump(),
            headers={
                "Content-Type": "application/json",
            }
        )

    def create_certificates(self, data: CreateCertificatesRequest):
        logger.debug(f"Received request to create certificates: {' | '.join(data.certificate_names)}")

        if len(data.certificate_names) == 0:
            return JSONResponse(
                status_code=400,
                content={"err": "No certificates requested to create."},
                headers={
                    "Content-Type": "application/json",
                }
            )

        certificate_responses = []
        for certificate_name in data.certificate_names:
            try:
                cert = Certificate(self.ca, certificate_name)
                certificate_responses.append(
                    CertificateResponse(**cert.create().__dict__())
                )
            except CertConfigNotFound as e:
                error_response = ErrorResponse(err=e.__class__.__name__, detail=str(e), traceback=traceback.format_exc())
                return JSONResponse(
                    status_code=400,
                    content=error_response.model_dump(),
                    headers={
                        "Content-Type": "application/json",
                    }
                )
            except Exception as e:
                error_response = ErrorResponse(err=e.__class__.__name__, detail=str(e), traceback=traceback.format_exc())
                return JSONResponse(
                    status_code=500,
                    content=error_response.model_dump(),
                )


        response_data = CreatedCertificatesResponse(certificates=certificate_responses)

        return JSONResponse(
            status_code=201,
            content=response_data.model_dump(),
            headers={
                "Content-Type": "application/json",
            }
        )
