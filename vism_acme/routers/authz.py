from datetime import datetime

from fastapi import APIRouter, BackgroundTasks
from starlette.responses import JSONResponse

from vism_acme.db.challenge import ChallengeStatus, AuthzStatus
from vism_acme.db.order import OrderStatus
from vism_acme import VismACMEController
from vism_acme.routers import AcmeRequest
from vism_acme.schema.response import ACMEProblemResponse


class AuthzRouter:
    def __init__(self, controller: VismACMEController):
        self.controller = controller

        self.router = APIRouter()
        self.router.post("/authz/{authz_id}")(self.authz)
        self.router.post("/challenge/{challenge_id}")(self.challenge)

    def challenge(self, request: AcmeRequest, background_tasks: BackgroundTasks, challenge_id: str):
        challenge_entry = self.controller.database.get_challenge_by_id(challenge_id)
        if not challenge_entry:
            raise ACMEProblemResponse(type="malformed", title="Invalid challenge ID.")

        authz_expired = challenge_entry.authz.status == AuthzStatus.EXPIRED
        if not authz_expired:
            authz_expired = datetime.fromisoformat(challenge_entry.authz.expires) < datetime.now()
            if authz_expired:
                challenge_entry.authz.status = AuthzStatus.EXPIRED
                challenge_entry.authz = self.controller.database.save_to_db(challenge_entry.authz)
                challenge_entry.status = ChallengeStatus.INVALID
                challenge_entry = self.controller.database.save_to_db(challenge_entry)

        if not authz_expired and not challenge_entry.status == ChallengeStatus.VALID:
            challenge_entry.status = ChallengeStatus.PROCESSING
            challenge_entry = self.controller.database.save_to_db(challenge_entry)

            background_tasks.add_task()



    def authz(self, request: AcmeRequest, authz_id: str):
        authz_entry = self.controller.database.get_authz_by_id(authz_id)
        if not authz_entry:
            raise ACMEProblemResponse(type="malformed", title="Invalid authz ID.")

        if authz_entry.order.account.id != request.state.account.id:
            raise ACMEProblemResponse(type="unauthorized", title="Account is not authorized to access this authz.")

        authz_expired = authz_entry.status == AuthzStatus.EXPIRED
        if not authz_expired:
            authz_expired = datetime.fromisoformat(authz_entry.expires) < datetime.now()
            if authz_expired:
                authz_entry.status = AuthzStatus.EXPIRED
                authz_entry = self.controller.database.save_to_db(authz_entry)

        order_expired = authz_entry.order.status == OrderStatus.EXPIRED
        if not order_expired:
            order_expiry = datetime.fromisoformat(authz_entry.order.expires)
            order_expired = datetime.now() > order_expiry
            if order_expired:
                authz_entry.order.status = OrderStatus.EXPIRED
                authz_entry.order = self.controller.database.save_to_db(authz_entry.order)

        authz_challenges = self.controller.database.get_challenges_by_authz_id(authz_entry.id)

        # if not order_expired and not authz_expired:
        #     for challenge in authz_challenges:
        #         if identifier_challenge.id == challenge_entry.id:
        #             challenge_entry.status = "valid"
        #             challenge_entry = self.controller.database.save_to_db(challenge_entry)
        #         else:
        #             identifier_challenge.status = "invalid"
        #             self.controller.database.save_to_db(identifier_challenge)
        #
        #     order_identifiers = self.controller.database.get_identifiers_by_order_id(challenge_entry.order.id)
        #     for identifier in order_identifiers:
        #         if identifier.id == challenge_entry.identifier_id:
        #             challenge_entry.identifier.status = "valid"
        #             challenge_entry.identifier = self.controller.database.save_to_db(challenge_entry.identifier)
        #
        #     if all(identifier.status == "valid" for identifier in order_identifiers):
        #         challenge_entry.order.status = "valid"
        #         challenge_entry.order = self.controller.database.save_to_db(challenge_entry.order)

        return JSONResponse(
            status_code=200,
            content={
                "status": authz_entry.status,
                "expires": authz_entry.expires,
                "identifier": {
                    "type": authz_entry.identifier_type,
                    "value": authz_entry.identifier_value
                },
                "challenges": [challenge.to_dict(request) for challenge in authz_challenges]
            }
        )

