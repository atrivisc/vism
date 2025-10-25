# Licensed under the GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""Router for ACME account operations."""

import secrets

from fastapi import APIRouter
from starlette.responses import JSONResponse

from shared.util import absolute_url
from vism_acme import ACMEProblemResponse
from vism_acme.db import AccountEntity, JWKEntity
from vism_acme.acme import VismACMEController
from vism_acme.routers import AcmeRequest


class AccountRouter:
    """Router for handling ACME account endpoints."""

    def __init__(self, controller: VismACMEController):
        self.controller = controller

        self.router = APIRouter()
        self.router.post("/new-account")(self.new_account)
        self.router.post("/account/{account_kid}")(self.update_account)

    async def update_account(self, request: AcmeRequest, account_kid: str):
        """Update an existing ACME account."""
        if not request.state.jws_envelope.payload:
            raise ACMEProblemResponse(
                error_type="malformed",
                title="No fields provided in request body."
            )

        if request.state.jws_envelope.payload.contact:
            request.state.account.contact = ','.join(
                request.state.jws_envelope.payload.contact
            )

        if request.state.jws_envelope.payload.status:
            request.state.account.status = (
                request.state.jws_envelope.payload.status
            )

        account = self.controller.database.save_to_db(
            request.state.account
        )
        location = absolute_url(
            request, f"/account/{request.state.account.kid}"
        )
        return JSONResponse(
            content={
                # required for acme.sh, not explicitly in RFC
                "id": account.kid,
                "status": account.status,
                "contact": (
                    account.contact.split(",") if account.contact else []
                ),
                "orders": absolute_url(request, f"/orders/{account_kid}"),
            },
            status_code=200,
            headers={
                "Content-Type": "application/json",
                "Location": location,
                "Replay-Nonce": (
                    await self.controller.nonce_manager.new_nonce(
                        request.state.account.id
                    )
                ),
            },
        )

    async def new_account(self, request: AcmeRequest):
        """Create a new ACME account or return existing one."""
        if (not hasattr(request.state, "account") and
                request.state.jws_envelope.payload.only_return_existing):
            raise ACMEProblemResponse(
                error_type="accountDoesNotExist",
                title="Provided JWK is not linked to an account."
            )

        if not request.state.account:
            kid = "acct-" + secrets.token_hex(12)
            status = "valid"

            jwk = JWKEntity(**request.state.jws_envelope.headers.jwk)
            jwk = self.controller.database.save_to_db(jwk)
            account = AccountEntity(
                kid=kid,
                status=status,
                _jwk=jwk,
            )
            if request.state.jws_envelope.payload.contact:
                account.contact = ','.join(
                    request.state.jws_envelope.payload.contact
                )

            self.controller.database.save_to_db(account)
            return_code = 201
        else:
            account = request.state.account
            return_code = 200

        location = absolute_url(request, f"/account/{account.kid}")
        return JSONResponse(
            content={
                # required for acme.sh, not explicitly in RFC
                "id": account.kid,
                "status": account.status,
                "contact": (
                    account.contact.split(",") if account.contact else []
                ),
                "orders": absolute_url(request, f"/orders/{account.kid}"),
            },
            status_code=return_code,
            headers={
                "Content-Type": "application/json",
                "Location": location,
                "Replay-Nonce": (
                    await self.controller.nonce_manager.new_nonce(
                        account.id
                    )
                ),
            },
        )
