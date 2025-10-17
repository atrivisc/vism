import secrets
import socket
from typing import Optional
from fastapi import APIRouter
from starlette.responses import JSONResponse

from vism_acme.config import Profile
from vism_acme.db.challenge import ChallengeEntry, AuthzEntry, AuthzStatus, ChallengeStatus
from vism_acme.db.order import OrderEntry
from vism_acme import VismACMEController
from vism_acme.routers import AcmeRequest
from vism_acme.schema.response import ACMEProblemResponse
from vism_acme.util import get_client_ip, absolute_url


class OrderRouter:
    def __init__(self, controller: VismACMEController):
        self.controller = controller

        self.router = APIRouter()
        self.router.post("/new-order")(self.new_order)
        self.router.post("/orders/{account_kid}")(self.account_orders)
        self.router.post("/order/{order_id}")(self.order)

    async def order(self, request: AcmeRequest, order_id: str):
        order = self.controller.database.get_order_by_id(order_id)
        if not order:
            raise ACMEProblemResponse(type="malformed", title="Invalid order ID.")

        if order.account.id != request.state.account.id:
            raise ACMEProblemResponse(type="unauthorized", title="Account is not authorized to access this order.")

        authz_entries = self.controller.database.get_authz_by_order_id(order_id)

        return JSONResponse(
            content={
                "status": order.status,
                "expires": order.expires,
                "notBefore": order.not_before,
                "notAfter": order.not_after,
                "identifiers": [identifier.to_dict() for identifier in request.state.jws_envelope.payload.identifiers],
                "authorizations": [absolute_url(request, f"/authz/{authz.id}") for authz in authz_entries],
                "finalize": absolute_url(request, f"/order/{order.id}/finalize"),
                "certificate": absolute_url(request, f"/order/{order.id}/certificate") if order.cert_pem else None
            },
            status_code=201,
            headers={
                "Content-Type": "application/json",
                "Location": absolute_url(request, f"/order/{order.id}"),
                "Replay-Nonce": await self.controller.nonce_manager.new_nonce(request.state.account.id),
            }
        )

    async def account_orders(self, request: AcmeRequest, account_kid: str):
        if account_kid != request.state.account.kid:
            raise ACMEProblemResponse(type="unauthorized", title="Account is not authorized.")

        account_orders = self.controller.database.get_orders_by_account_kid(account_kid)
        return JSONResponse(
            content={
                "orders": [absolute_url(request, f"/order/{order.id}") for order in account_orders]
            },
            status_code=200,
            headers={
                "Content-Type": "application/json",
                "Replay-Nonce": await self.controller.nonce_manager.new_nonce(request.state.account.id),
            }
        )

    async def new_order(self, request: AcmeRequest):
        profile = self.controller.config.get_profile_by_name(request.state.jws_envelope.payload.profile)

        errors = []
        client_ip = get_client_ip(request)
        for identifier in request.state.jws_envelope.payload.identifiers:
            err = await self._validate_client(profile, client_ip, identifier.value)
            if err:
                errors.append(err)
                continue

        if errors:
            raise ACMEProblemResponse(
                type="malformed",
                title="One or more identifiers are invalid.",
                subproblems=errors
            )

        order = OrderEntry(
            account=request.state.account,
            status="pending",
            profile_name=profile.name,
            not_before=request.state.jws_envelope.payload.notBefore,
            not_after=request.state.jws_envelope.payload.notAfter
        )

        order = self.controller.database.save_to_db(order)

        authz_urls = []
        for identifier in request.state.jws_envelope.payload.identifiers:
            authz_entry = AuthzEntry(
                identifier_type=identifier.type,
                identifier_value=identifier.value,
                status=AuthzStatus.PENDING,
                wildcard=False,
                order=order,
            )
            authz_entry = self.controller.database.save_to_db(authz_entry)
            authz_urls.append(absolute_url(request, f"/authz/{authz_entry.id}"))

            for challenge_type in profile.supported_challenge_types:
                token = secrets.token_urlsafe(32)
                key_authorization = token + "." + request.state.account.jwk.thumbprint()
                challenge = ChallengeEntry(
                    type=challenge_type,
                    status=ChallengeStatus.PENDING,
                    key_authorization=key_authorization,
                    authz=authz_entry,
                )
                self.controller.database.save_to_db(challenge)

        return JSONResponse(
            content={
                "status": order.status,
                "expires": order.expires,
                "identifiers": [identifier.to_dict() for identifier in request.state.jws_envelope.payload.identifiers],
                "authorizations": authz_urls,
                "finalize": absolute_url(request, f"/order/{order.id}/finalize")
            },
            status_code=201,
            headers={
                "Content-Type": "application/json",
                "Location": absolute_url(request, f"/order/{order.id}"),
                "Replay-Nonce": await self.controller.nonce_manager.new_nonce(request.state.account.id),
            }
        )

    async def _validate_client(self, profile: Profile, client_ip: str, domain: str) -> Optional[ACMEProblemResponse]:
        try:
            domain_ips = set([x[4][0] for x in socket.getaddrinfo(domain, None)])
        except socket.gaierror as e:
            return ACMEProblemResponse(
                type="malformed",
                title=f"Domain {domain} does not exist",
                detail=str(e)
            )
        except Exception as e:
            return ACMEProblemResponse(
                type="serverInternal",
                title=f"Unknown error occurred while validating domain",
                detail=str(e)
            )

        if len(domain_ips) == 0:
            return ACMEProblemResponse(
                type="malformed",
                title=f"Domain exists but has no IPs",
            )

        pre_validated = profile.client_is_valid(client_ip, domain)
        client_allowed = profile.client_is_allowed(client_ip, domain)

        if not pre_validated and not client_allowed and client_ip not in domain_ips:
            return ACMEProblemResponse(
                type="unauthorized",
                title=f"Client IP '{client_ip}' has not authority over '{domain}'",
                detail=f"Pre-validated: {pre_validated}, Client Allowed: {client_allowed}",
            )

        return None
