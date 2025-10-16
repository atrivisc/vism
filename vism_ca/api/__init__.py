import os

from fastapi import FastAPI

from vism_ca.api.routers import CertificateRouter
from vism_ca.ca import VismCA
from vism_ca.config import APIConfig


class VismCAApi:
    def __init__(self):
        config_file_path = os.environ.get('CONFIG_FILE_PATH', './config.yaml')
        self.config = APIConfig(config_file_path)

        self.ca = VismCA()
        self.api = FastAPI()
        self.setup_routes()

    def setup_routes(self):
        cert_router = CertificateRouter(self.ca)
        self.api.include_router(
            cert_router.router,
            prefix="/certificates",
            tags=["certificates"]
        )

vism_ca_api = VismCAApi()
app = vism_ca_api.api