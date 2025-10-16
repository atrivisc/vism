import secrets

from fastapi import APIRouter
from starlette.responses import JSONResponse

from vism_acme.db import AccountEntry, JWKEntry
from vism_acme.main import VismACMEController
from vism_acme.routers import AcmeRequest
from vism_acme.schema.response import ACMEProblemResponse
from vism_acme.util import absolute_url


class AccountRouter:
    def __init__(self, controller: VismACMEController):
        self.controller = controller

        self.router = APIRouter()
        self.router.post("/new-account")(self.new_account)
        self.router.post("/account/{account_kid}")(self.update_account)

    async def update_account(self, request: AcmeRequest, account_kid: str):
        if not request.state.jws_envelope.decoded_payload:
            raise ACMEProblemResponse(type="malformed", title=f"No fields provided in request body.")

        if request.state.jws_envelope.decoded_payload.contact:
            request.state.account.contact = ','.join(request.state.jws_envelope.decoded_payload.contact)

        if request.state.jws_envelope.decoded_payload.status:
            request.state.account.status = request.state.jws_envelope.decoded_payload.status

        self.controller.database.save_to_db(request.state.account)
        location = absolute_url(request, f"/account/{request.state.account.kid}")
        return JSONResponse(
            content={"status": request.state.account.status},
            status_code=200,
            headers={
                "Content-Type": "application/json",
                "Location": location,
                "Replay-Nonce": await self.controller.nonce_manager.new_nonce(request.state.account.id),
            },
        )

    async def new_account(self, request: AcmeRequest):
        if not request.state.account and request.state.jws_envelope.decoded_payload.only_return_existing:
            raise ACMEProblemResponse(type="accountDoesNotExist", title=f"Provided JWK is not linked to an account.")

        if not request.state.account:
            kid = "acct-" + secrets.token_hex(12)
            status = "valid"

            jwk = JWKEntry(
                n=request.state.jws_envelope.decoded_headers.jwk['n'],
                e=request.state.jws_envelope.decoded_headers.jwk['e'],
                kty=request.state.jws_envelope.decoded_headers.jwk['kty'],
            )
            jwk = self.controller.database.save_to_db(jwk)
            account = AccountEntry(
                kid=kid,
                jwk_id=jwk.id,
                contact=','.join(request.state.jws_envelope.decoded_payload.contact) if request.state.jws_envelope.decoded_payload.contact else None,
                status=status,
                jwk=jwk,
            )
            self.controller.database.save_to_db(account)
            return_code = 201
        else:
            account = request.state.account
            if account.status != "valid":
                raise ACMEProblemResponse(type="unauthorized", title=f"Account status is {account.status}.")
            return_code = 200

        location = absolute_url(request, f"/account/{account.kid}")
        return JSONResponse(
            content={"status": account.status},
            status_code=return_code,
            headers={
                "Content-Type": "application/json",
                "Location": location,
                "Replay-Nonce": await self.controller.nonce_manager.new_nonce(account.id),
            },
        )
