from fastapi import APIRouter
from starlette.requests import Request
from starlette.responses import JSONResponse
from vism_acme.main import VismACMEController
from vism_acme.routers import AcmeRequest


class BaseRouter:
    def __init__(self, controller: VismACMEController):
        self.controller = controller
        self.router = APIRouter()
        self.router.get("/directory")(self.directory)

    async def directory(self, request: AcmeRequest):
        base = str(request.base_url).rstrip("/")
        dir_obj = {
            "newNonce": f"{base}/new-nonce",
            "newAccount": f"{base}/new-account",
            "newOrder": f"{base}/new-order",
            "revokeCert": f"{base}/revoke-cert",
            "keyChange": None,
            "meta": {
                "profiles": {profile.name: profile.__dict__ for profile in self.controller.config.profiles}
            }
        }
        return JSONResponse(dir_obj)
