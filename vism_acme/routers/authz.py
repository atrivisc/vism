from datetime import datetime
from fastapi import APIRouter, BackgroundTasks
from starlette.responses import JSONResponse

from vism_acme.db.authz import AuthzStatus, ChallengeStatus
from vism_acme.db.order import OrderStatus
from vism_acme import VismACMEController
from vism_acme.routers import AcmeRequest
from vism_acme.schema.response import ACMEProblemResponse
from vism_acme.validators.http_01 import Http01Validator


class AuthzRouter:
    def __init__(self, controller: VismACMEController):
        self.controller = controller

        self.router = APIRouter()
        self.router.post("/authz/{authz_id}")(self.authz)
        self.router.post("/challenge/{challenge_id}")(self.challenge)

    async def challenge(self, request: AcmeRequest, background_tasks: BackgroundTasks, challenge_id: str):
        challenge_entity = self.controller.database.get_challenge_by_id(challenge_id)
        if not challenge_entity:
            raise ACMEProblemResponse(type="malformed", title="Invalid challenge ID.")

        if challenge_entity.authz.order.account.id != request.state.account.id:
            raise ACMEProblemResponse(type="unauthorized", title="Account is not authorized to access this challenge.")

        authz_expired = challenge_entity.authz.status == AuthzStatus.EXPIRED
        if not authz_expired:
            authz_expired = datetime.fromisoformat(challenge_entity.authz.expires) < datetime.now()
            if authz_expired:
                challenge_entity.authz.status = AuthzStatus.EXPIRED
                challenge_entity.authz = self.controller.database.save_to_db(challenge_entity.authz)
                challenge_entity.status = ChallengeStatus.INVALID
                challenge_entity = self.controller.database.save_to_db(challenge_entity)

        if not authz_expired and not challenge_entity.status == ChallengeStatus.VALID:
            challenge_entity.status = ChallengeStatus.PROCESSING
            challenge_entity = self.controller.database.save_to_db(challenge_entity)

            validator = Http01Validator(self.controller, challenge_entity)
            background_tasks.add_task(validator.validate)

        return JSONResponse(
            status_code=200,
            content={
                "status": challenge_entity.status,
                "type": challenge_entity.type,
                "token": challenge_entity.key_authorization.split(".")[0],
            },
            headers={
                "Content-Type": "application/json",
                "Replay-Nonce": await self.controller.nonce_manager.new_nonce(request.state.account.id),
                "Retry-After": self.controller.config.retry_after_seconds
            }
        )

    async def authz(self, request: AcmeRequest, authz_id: str):
        authz_entity = self.controller.database.get_authz_by_id(authz_id)
        if not authz_entity:
            raise ACMEProblemResponse(type="malformed", title="Invalid authz ID.")

        if authz_entity.order.account.id != request.state.account.id:
            raise ACMEProblemResponse(type="unauthorized", title="Account is not authorized to access this authz.")

        authz_expired = authz_entity.status == AuthzStatus.EXPIRED
        if not authz_expired:
            authz_expired = datetime.fromisoformat(authz_entity.expires) < datetime.now()
            if authz_expired:
                authz_entity.status = AuthzStatus.EXPIRED
                authz_entity = self.controller.database.save_to_db(authz_entity)

        order_expired = authz_entity.order.status == OrderStatus.EXPIRED
        if not order_expired:
            order_expiry = datetime.fromisoformat(authz_entity.order.expires)
            order_expired = datetime.now() > order_expiry
            if order_expired:
                authz_entity.order.status = OrderStatus.EXPIRED
                authz_entity.order = self.controller.database.save_to_db(authz_entity.order)

        authz_challenges = self.controller.database.get_challenges_by_authz_id(authz_entity.id)

        response_code = 200
        response = {
            "status": authz_entity.status,
            "expires": authz_entity.expires,
            "identifier": {
                "type": authz_entity.identifier_type,
                "value": authz_entity.identifier_value
            },
            "challenges": [challenge.to_dict(request) for challenge in authz_challenges],
        }

        if authz_entity.error:
            response_code = 400
            response["error"] = {
                "type": f"urn:ietf:params:acme:error:{authz_entity.error.type}",
                "title": authz_entity.error.title,
                "detail": authz_entity.error.detail,
            }

        return JSONResponse(
            status_code=response_code,
            content=response,
            headers={
                "Content-Type": "application/json",
                "Replay-Nonce": await self.controller.nonce_manager.new_nonce(request.state.account.id),
                "Retry-After": self.controller.config.retry_after_seconds
            }
        )

