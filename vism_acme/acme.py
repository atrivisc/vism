# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""VISM ACME Controller module for handling ACME protocol operations."""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from fastapi import FastAPI
from starlette.responses import JSONResponse
from shared.controller import Controller
from shared.data.exchange import DataExchangeCertMessage
from shared.errors import VismException
from vism_acme import AcmeConfig, acme_logger, ACMEProblemResponse
from vism_acme.db import VismAcmeDatabase, ErrorEntity, OrderStatus, OrderEntity
from vism_acme.middleware import AcmeAccountMiddleware, JWSMiddleware
from vism_acme.util import NonceManager


class VismACMEController(Controller):
    """Controller class for VISM ACME server operations."""

    configClass = AcmeConfig
    databaseClass = VismAcmeDatabase

    def __init__(self):
        super().__init__()
        self.nonce_manager = NonceManager(self.config)
        self.api = FastAPI(lifespan=self.lifespan)

        self.setup_exception_handlers()
        self.setup_middleware()
        self.setup_routes()

    async def _get_order_for_csr(self, order_id: str) -> OrderEntity:
        """Get and validate order for CSR processing."""
        order = self.database.get_order_by_id(order_id)

        if order is None:
            raise VismException(
                f"Order {order_id} not found"
            )

        order_expired = order.status == OrderStatus.EXPIRED
        if not order_expired:
            order_expired = (
                datetime.fromisoformat(order.expires) < datetime.now()
            )

        if order_expired:
            order.status = OrderStatus.EXPIRED
            self.database.save_to_db(order)
            raise VismException(
                f"Order {order_id} expired, can not accept certificate"
            )

        if order.status != OrderStatus.PROCESSING:
            detail = (
                f"Order {order_id} is not in processing state"
            )
            error = ErrorEntity(
                type="invalidOrder",
                title="Failed to validate CA csr response",
                detail=detail
            )
            order.set_error(error)
            self.database.save_to_db(order)
            raise VismException(detail)

        return order

    async def handle_chain_from_ca(
            self,
            cert_message: DataExchangeCertMessage
    ):  # pylint: disable=too-many-locals
        """Handle certificate chain received from CA."""
        order = await self._get_order_for_csr(cert_message.order_id)
        if order is None:
            return None

        try:
            certificates = x509.load_pem_x509_certificates(
                cert_message.chain.encode("utf-8")
            )
        except ValueError as exc:
            error = ErrorEntity(
                type="invalidOrder",
                title="Failed to validate CA csr response",
                detail=str(exc)
            )
            order.set_error(error)
            self.database.save_to_db(order)
            raise VismException(
                f"Failed to load certificates from chain: {exc}"
            ) from exc

        ca_profile = self.config.get_profile_by_name(
            cert_message.profile_name
        )
        if ca_profile is None:
            raise VismException(
                f"CA profile {cert_message.profile_name} not found"
            )

        try:
            issuer_x509 = x509.load_pem_x509_certificate(
                ca_profile.ca_pem.encode("utf-8")
            )
        except ValueError as exc:
            error = ErrorEntity(
                type="invalidOrder",
                title="Failed to validate CA csr response",
                detail=str(exc)
            )
            order.set_error(error)
            self.database.save_to_db(order)
            raise VismException(
                f"Failed to load {cert_message.ca_name} certificate: {exc}"
            ) from exc

        ordered_cert = certificates[0]

        try:
            ordered_cert.verify_directly_issued_by(issuer_x509)
        except (ValueError, TypeError, InvalidSignature) as exc:
            error_detail = (
                f"Failed to verify certificate for order "
                f"{cert_message.order_id}: {exc}"
            )
            error = ErrorEntity(
                type="invalidOrder",
                title="Failed to validate CA csr response",
                detail=error_detail
            )
            order.set_error(error)
            raise VismException(error_detail) from exc

        try:
            csr = x509.load_pem_x509_csr(order.csr_pem.encode("utf-8"))
        except ValueError as exc:
            error = ErrorEntity(
                type="invalidOrder",
                title="Failed to validate csr",
                detail=str(exc)
            )
            order.set_error(error)
            self.database.save_to_db(order)
            raise VismException(
                f"Failed to verify csr: {exc}"
            ) from exc

        cert_san = ordered_cert.extensions.get_extension_for_oid(
            x509.OID_SUBJECT_ALTERNATIVE_NAME
        )
        csr_san = csr.extensions.get_extension_for_oid(
            x509.OID_SUBJECT_ALTERNATIVE_NAME
        )

        public_key_matches = csr.public_key() == ordered_cert.public_key()
        subject_matches = csr.subject == ordered_cert.subject
        san_matches = csr_san.value == cert_san.value

        if not (public_key_matches and subject_matches and san_matches):
            order.status = OrderStatus.INVALID
            order.error = ErrorEntity(
                type="invalidOrder",
                title="Failed to validate CA csr response",
                detail="CSR and certificate do not match"
            )
            self.database.save_to_db(order)
            raise VismException(
                f"CSR and certificate do not match for order "
                f"{cert_message.order_id}"
            )

        acme_logger.info(
            "Certificate for order %s accepted.", cert_message.order_id
        )
        order.status = OrderStatus.VALID
        order.crt_pem = cert_message.chain
        self.database.save_to_db(order)
        return None

    @asynccontextmanager
    async def lifespan(self, _api: FastAPI):
        """Manage application lifespan with async context manager."""
        asyncio.create_task(self.data_exchange_module.receive_cert())
        yield
        self.validation_module.cleanup(full=True)
        self.encryption_module.cleanup(full=True)
        await self.data_exchange_module.cleanup(full=True)

    def setup_middleware(self):
        """Configure middleware for the FastAPI application."""
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
        """Set up exception handlers for the FastAPI application."""
        @self.api.exception_handler(ACMEProblemResponse)
        async def acme_problem_response_handler(_request, exc: ACMEProblemResponse):
            return JSONResponse(
                status_code=exc.status_code,
                content=exc.error_json,
                headers={"Content-Type": "application/problem+json"}
            )

        @self.api.exception_handler(VismException)
        async def vism_exception_handler(_request, _exc: VismException):
            return JSONResponse(
                status_code=500,
                content={
                    "type": "urn:ietf:params:acme:error:serverInternal",
                    "title": "An internal server error occurred",
                },
                headers={"Content-Type": "application/problem+json"}
            )

    def setup_routes(self):
        """Set up routes for the FastAPI application."""
        # Import routers here to avoid circular imports
        from vism_acme.routers import AccountRouter  # pylint: disable=import-outside-toplevel
        from vism_acme.routers import BaseRouter  # pylint: disable=import-outside-toplevel
        from vism_acme.routers import OrderRouter  # pylint: disable=import-outside-toplevel
        from vism_acme.routers import AuthzRouter  # pylint: disable=import-outside-toplevel

        base_router = BaseRouter(self)
        account_router = AccountRouter(self)
        order_router = OrderRouter(self)
        authz_router = AuthzRouter(self)

        self.api.include_router(account_router.router)
        self.api.include_router(base_router.router)
        self.api.include_router(order_router.router)
        self.api.include_router(authz_router.router)


controller = VismACMEController()
app = controller.api
