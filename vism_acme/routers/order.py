# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""Router for ACME order operations."""

import secrets
from typing import Any

from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter
from starlette.responses import JSONResponse, Response
from shared.data.exchange import DataExchangeCSRMessage
from shared.util import absolute_url, get_client_ip
from vism_acme import ACMEProblemResponse
from vism_acme.config import acme_logger
from vism_acme.db.authz import (
    ChallengeEntity,
    AuthzEntity,
    AuthzStatus,
    ChallengeStatus
)
from vism_acme.db.order import OrderEntity, OrderStatus
from vism_acme.acme import VismACMEController
from vism_acme.routers import AcmeRequest


class OrderRouter:
    """Router for handling ACME order endpoints."""

    def __init__(self, controller: VismACMEController):
        self.controller = controller

        self.router = APIRouter()
        self.router.post("/new-order")(self.new_order)
        self.router.post("/orders/{account_kid}")(self.account_orders)
        self.router.post("/order/{order_id}")(self.order)
        self.router.post("/order/{order_id}/finalize")(self.order_finalize)
        self.router.post("/order/{order_id}/certificate")(
            self.order_certificate
        )

    async def order_certificate(self, request: AcmeRequest, order_id: str):
        """Retrieve the certificate for a completed order."""
        acme_logger.info(
            "Received request to get order %s certificate.", order_id
        )
        order = await self._validate_order_request(order_id, request)
        if order.status != OrderStatus.VALID:
            raise ACMEProblemResponse(
                error_type="orderNotReady",
                title="Order is not ready.",
                status_code=403
            )

        return Response(
            content=order.crt_pem,
            headers={
                "Content-Type": "application/pem-certificate-chain",
            },
            status_code=200,
            media_type="application/pem-certificate-chain",
        )

    async def order_finalize(self, request: AcmeRequest, order_id: str):
        """Finalize an order by submitting a CSR."""
        acme_logger.info("Received request to finalize order %s.", order_id)
        order = await self._validate_order_request(order_id, request)

        if order.status != "ready":
            order_authz_entities = (
                self.controller.database.get_authz_by_order_id(order_id)
            )
            order_ready = all(
                authz.status == AuthzStatus.VALID
                for authz in order_authz_entities
            )
            if order_ready:
                acme_logger.info("Order %s is ready.", order_id)
                order.status = "ready"
                order = self.controller.database.save_to_db(order)

        if order.status != "ready":
            raise ACMEProblemResponse(
                error_type="orderNotReady",
                title="Order is not ready.",
                status_code=403
            )

        csr_der_b64 = request.state.jws_envelope.payload.csr
        order_authz_entities = (
            self.controller.database.get_authz_by_order_id(order_id)
        )
        domains = [authz.identifier_value for authz in order_authz_entities]

        profile = self.controller.config.get_profile_by_name(
            order.profile_name
        )
        csr = profile.validate_csr(csr_der_b64, domains)
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)

        order.csr_pem = csr_pem.decode("utf-8")
        order.status = OrderStatus.PROCESSING
        order = self.controller.database.save_to_db(order)

        acme_logger.info(
            "Validated order %s finalization. Sending CSR to RabbitMQ.",
            order_id
        )

        rabbitmq_message = DataExchangeCSRMessage(
            csr_pem=csr_pem.decode("utf-8"),
            ca_name=profile.ca,
            profile_name=profile.name,
            module_args=profile.module_args,
            order_id=order_id,
        )

        try:
            await self.controller.data_exchange_module.send_csr(
                rabbitmq_message
            )
            acme_logger.info("Sent CSR to RabbitMQ.")
        except Exception as exc:
            acme_logger.error("Failed to send CSR to RabbitMQ: %s", exc)
            raise ACMEProblemResponse(
                error_type="serverInternal",
                title="Internal error.",
                status_code=500
            ) from exc

        return await self._order_json_response(
            order, order_authz_entities, request, 200
        )

    async def order(self, request: AcmeRequest, order_id: str):
        """Get the status of an order."""
        acme_logger.info("Received request to get order %s.", order_id)
        order = await self._validate_order_request(order_id, request)

        authz_entities = self.controller.database.get_authz_by_order_id(
            order_id
        )
        return await self._order_json_response(
            order, authz_entities, request, 200
        )

    async def _validate_order_request(
            self,
            order_id: str,
            request: AcmeRequest
    ) -> OrderEntity | None:
        """Validate that an order exists and belongs to the account."""
        order = self.controller.database.get_order_by_id(order_id)
        if not order:
            raise ACMEProblemResponse(
                error_type="malformed",
                title="Invalid order ID.",
                status_code=404
            )

        if order.account.id != request.state.account.id:
            raise ACMEProblemResponse(
                error_type="unauthorized",
                title="Account is not authorized to access this order.",
                status_code=403
            )
        return order

    async def account_orders(self, request: AcmeRequest, account_kid: str):
        """Get all orders for an account."""
        if account_kid != request.state.account.kid:
            raise ACMEProblemResponse(
                error_type="unauthorized",
                title="Account is not authorized.",
                status_code=403
            )

        account_orders = self.controller.database.get_orders_by_account_kid(
            account_kid
        )
        return JSONResponse(
            content={
                "orders": [
                    absolute_url(request, f"/order/{order.id}")
                    for order in account_orders
                ]
            },
            status_code=200,
            headers={
                "Content-Type": "application/json",
                "Replay-Nonce": (
                    await self.controller.nonce_manager.new_nonce(
                        request.state.account.id
                    )
                ),
            }
        )

    async def new_order(self, request: AcmeRequest):
        """Create a new order."""
        acme_logger.info("Received request to create new order.")
        profile = self.controller.config.get_profile_by_name(
            request.state.jws_envelope.payload.profile
        )

        errors = []
        client_ip = get_client_ip(request)
        for identifier in request.state.jws_envelope.payload.identifiers:
            try:
                await profile.validate_client(client_ip, identifier.value)
            except ACMEProblemResponse as exc:
                errors.append(exc)

        if errors:
            raise ACMEProblemResponse(
                error_type="malformed",
                title="One or more identifiers are invalid.",
                subproblems=errors
            )

        order = OrderEntity(
            account=request.state.account,
            status="pending",
            profile_name=profile.name,
            not_before=request.state.jws_envelope.payload.not_before,
            not_after=request.state.jws_envelope.payload.not_after
        )

        order = self.controller.database.save_to_db(order)

        authz_entities = []
        for identifier in request.state.jws_envelope.payload.identifiers:
            authz_entity = AuthzEntity(
                identifier_type=identifier.type,
                identifier_value=identifier.value,
                status=AuthzStatus.PENDING,
                wildcard=False,
                order=order,
            )
            authz_entity = self.controller.database.save_to_db(authz_entity)
            authz_entities.append(authz_entity)

            for challenge_type in profile.supported_challenge_types:
                token = secrets.token_urlsafe(32)
                key_authorization = (
                    token + "." + request.state.account.jwk.thumbprint()
                )
                challenge = ChallengeEntity(
                    type=challenge_type,
                    status=ChallengeStatus.PENDING,
                    key_authorization=key_authorization,
                    authz=authz_entity,
                )
                self.controller.database.save_to_db(challenge)

        return await self._order_json_response(
            order, authz_entities, request, 201
        )

    async def _order_json_response(
            self,
            order: OrderEntity,
            order_authz_entities: list[AuthzEntity],
            request: AcmeRequest,
            status_code: int
    ) -> JSONResponse:
        """Build JSON response for order endpoints."""
        response: dict[str, Any] = {
            "status": order.status,
            "expires": order.expires,
            "notBefore": order.not_before,
            "notAfter": order.not_after,
            "identifiers": [
                {
                    "type": authz.identifier_type,
                    "value": authz.identifier_value
                }
                for authz in order_authz_entities
            ],
            "authorizations": [
                absolute_url(request, f"/authz/{authz.id}")
                for authz in order_authz_entities
            ],
            "finalize": absolute_url(
                request, f"/order/{order.id}/finalize"
            ),
            "certificate": (
                absolute_url(request, f"/order/{order.id}/certificate")
                if order.crt_pem else None
            )
        }

        if order.status == OrderStatus.INVALID and order.error:
            status_code = 400
            response["error"] = {
                "type": f"urn:ietf:params:acme:error:{order.error.type}",
                "title": order.error.title,
                "detail": order.error.detail,
            }

        return JSONResponse(
            content=response,
            status_code=status_code,
            headers={
                "Content-Type": "application/json",
                "Location": absolute_url(request, f"/order/{order.id}"),
                "Replay-Nonce": (
                    await self.controller.nonce_manager.new_nonce(
                        request.state.account.id
                    )
                ),
            }
        )
