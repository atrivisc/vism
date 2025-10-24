import asyncio
import os
import re
from contextlib import asynccontextmanager
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from starlette.responses import JSONResponse

from shared.data.exchange import DataExchange, DataExchangeCertMessage
from shared.data.validation import Data
from shared.errors import VismException
from vism_acme.config import AcmeConfig, acme_logger
from vism_acme.db import VismAcmeDatabase
from vism_acme.db.authz import AuthzStatus
from vism_acme.db.error import ErrorEntity
from vism_acme.db.order import OrderStatus
from vism_acme.middleware import JWSMiddleware
from vism_acme.middleware.acme_request import AcmeAccountMiddleware
from vism_acme.schema.response import ACMEProblemResponse
from vism_acme.util.nonce import NonceManager


class VismACMEController:
    def __init__(self):
        config_file_path = os.environ.get('CONFIG_FILE_PATH', './acme_config.yaml')

        self.config = AcmeConfig(config_file_path)
        self.validation_module = self.setup_validation_module()
        self.encryption_module = self.setup_encryption_module()
        self.data_exchange_module = self.setup_data_exchange_module()
        self.database = VismAcmeDatabase(self.config.database, self.validation_module)
        self.nonce_manager = NonceManager(self.config)
        self.api = FastAPI(lifespan=self.lifespan)
        self.setup_exception_handlers()
        self.setup_middleware()
        self.setup_routes()

    async def handle_chain_from_ca(self, cert_message: DataExchangeCertMessage):
        order = self.database.get_order_by_id(cert_message.order_id)

        if order is None:
            acme_logger.error(f"Order {cert_message.order_id} not found")
            return None

        if order.status != OrderStatus.PROCESSING:
            detail = f"Order {cert_message.order_id} is not in processing state"
            error = ErrorEntity(type="invalidOrder", title="Failed to validate CA csr response", detail=detail)
            order.set_error(error)
            self.database.save_to_db(order)
            acme_logger.error(detail)
            return None

        try:
            certificates = x509.load_pem_x509_certificates(cert_message.chain.encode("utf-8"))
        except Exception as e:
            error = ErrorEntity(type="invalidOrder", title="Failed to validate CA csr response", detail=str(e))
            order.set_error(error)
            self.database.save_to_db(order)
            acme_logger.error(f"Failed to load certificates from chain: {e}")
            return None

        authz_entities = self.database.get_authz_by_order_id(cert_message.order_id)
        if authz_entities is None:
            error_detail = f"Authz entities for order {cert_message.order_id} not found"
            error = ErrorEntity(type="invalidOrder", title="Failed to validate CA csr response", detail=error_detail)
            order.set_error(error)
            self.database.save_to_db(order)
            acme_logger.error(error_detail)
            return None

        order_expired = order.status == OrderStatus.EXPIRED
        if not order_expired:
            order_expired = datetime.fromisoformat(order.expires) < datetime.now()
            if order_expired:
                order.status = OrderStatus.EXPIRED
                self.database.save_to_db(order)
                acme_logger.error(f"Order {cert_message.order_id} expired, can not accept certificate")
                return None

        ca_profile = self.config.get_profile_by_name(cert_message.profile_name)
        if ca_profile is None:
            acme_logger.error(f"CA profile {cert_message.profile_name} not found")
            return None

        try:
            issuer_x509 = x509.load_pem_x509_certificate(ca_profile.ca_pem.encode("utf-8"))
        except Exception as e:
            error = ErrorEntity(type="invalidOrder", title="Failed to validate CA csr response", detail=str(e))
            order.set_error(error)
            self.database.save_to_db(order)
            acme_logger.error(f"Failed to load {cert_message.ca_name} certificate: {e}")
            return None

        ordered_cert = certificates[0]

        try:
            ordered_cert.verify_directly_issued_by(issuer_x509)
        except Exception as e:
            error_detail = f"Failed to verify certificate for order {cert_message.order_id}: {e}"
            error = ErrorEntity(type="invalidOrder", title="Failed to validate CA csr response", detail=str(e))
            order.set_error(error)
            acme_logger.error(error_detail)
            return None

        csr = x509.load_pem_x509_csr(order.csr_pem.encode("utf-8"))
        cert_san = ordered_cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)
        csr_san = csr.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)

        public_key_matches = csr.public_key() == ordered_cert.public_key()
        subject_matches = csr.subject == ordered_cert.subject
        san_matches = csr_san.value == cert_san.value

        if not (public_key_matches and subject_matches and san_matches):
            acme_logger.error(f"CSR and certificate do not match for order {cert_message.order_id}")
            acme_logger.debug(f"public_key_matches: {public_key_matches} | subject_matches: {subject_matches} | san_matches: {san_matches}")
            order.status = OrderStatus.INVALID
            order.error = ErrorEntity(type="invalidOrder", title="Failed to validate CA csr response", detail="CSR and certificate do not match")
            self.database.save_to_db(order)
            return None

        acme_logger.info(f"Certificate for order {cert_message.order_id} accepted.")
        order.status = OrderStatus.VALID
        order.crt_pem = cert_message.chain
        self.database.save_to_db(order)
        return None

    @asynccontextmanager
    async def lifespan(self, api: FastAPI):
        asyncio.create_task(self.data_exchange_module.receive_cert())
        yield
        self.validation_module.cleanup(full=True)
        self.encryption_module.cleanup(full=True)
        await self.data_exchange_module.cleanup(full=True)

    def setup_encryption_module(self) -> Data:
        encryption_module_imports = __import__(f'modules.{self.config.security.data_validation.module}', fromlist=['Module', 'ModuleConfig'])
        encryption_module = encryption_module_imports.Module(
            encryption_key=self.config.security.data_encryption.encryption_key,
            validation_key=self.config.security.data_validation.validation_key
        )
        encryption_module.load_config(self.config.raw_config_data)

        return encryption_module

    def setup_data_exchange_module(self) -> DataExchange:
        data_exchange_module_imports = __import__(f'modules.{self.config.data_exchange.module}', fromlist=['Module', 'ModuleConfig'])
        data_exchange_module = data_exchange_module_imports.Module(self)
        data_exchange_module.load_config(self.config.raw_config_data)

        return data_exchange_module

    def setup_validation_module(self) -> Data:
        validation_module_imports = __import__(f'modules.{self.config.security.data_validation.module}', fromlist=['Module', 'ModuleConfig'])
        validation_module = validation_module_imports.Module(
            encryption_key=self.config.security.data_encryption.encryption_key,
            validation_key=self.config.security.data_validation.validation_key
        )
        validation_module.load_config(self.config.raw_config_data)

        return validation_module

    def setup_middleware(self):
        self.api.add_middleware(
            AcmeAccountMiddleware,
            jwk_paths=["/new-account", "/revoke-cert"],
            kid_paths=["/account/", "/new-order", "/authz"],
            controller=self,
        )

        self.api.add_middleware(
            JWSMiddleware,
            skip_paths=["/directory", "/new-nonce", "/health"],
            controller=self,
        )

    def setup_exception_handlers(self):
        @self.api.exception_handler(ACMEProblemResponse)
        async def acme_problem_response_handler(request, exc: ACMEProblemResponse):
            return JSONResponse(
                status_code=exc.status_code,
                content=exc.error_json,
                headers={"Content-Type": "application/problem+json"}
            )
        @self.api.exception_handler(VismException)
        async def acme_problem_response_handler(request, exc: VismException):
            return JSONResponse(
                status_code=500,
                content={
                    "type": "urn:ietf:params:acme:error:serverInternal",
                    "title": "An internal server error occurred",
                },
                headers={"Content-Type": "application/problem+json"}
            )

    def setup_routes(self):
        from vism_acme.routers.account import AccountRouter
        from vism_acme.routers.base import BaseRouter
        from vism_acme.routers.nonce import NonceRouter
        from vism_acme.routers.order import OrderRouter
        from vism_acme.routers.authz import AuthzRouter

        base_router = BaseRouter(self)
        nonce_router = NonceRouter(self)
        account_router = AccountRouter(self)
        order_router = OrderRouter(self)
        authz_router = AuthzRouter(self)

        self.api.include_router(account_router.router)
        self.api.include_router(nonce_router.router)
        self.api.include_router(base_router.router)
        self.api.include_router(order_router.router)
        self.api.include_router(authz_router.router)

controller = VismACMEController()
app = controller.api
