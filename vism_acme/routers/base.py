# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""Router for ACME base operations."""
from fastapi import APIRouter
from starlette.responses import JSONResponse, Response

from vism_acme import acme_logger
from vism_acme.acme import VismACMEController
from vism_acme.routers import AcmeRequest


class BaseRouter:
    """Router for handling ACME base endpoints like directory."""

    def __init__(self, controller: VismACMEController):
        self.controller = controller
        self.router = APIRouter()
        self.router.get("/directory")(self.directory)
        self.router.head("/new-nonce")(self.new_nonce)
        self.router.get("/new-nonce")(self.new_nonce)

    async def new_nonce(self):
        """Return new nonce."""
        acme_logger.info("Received request to create new nonce.")
        nonce = await self.controller.nonce_manager.new_nonce()
        return Response(status_code=200, headers={"Replay-Nonce": nonce})

    async def directory(self, request: AcmeRequest):
        """Return the ACME directory with service endpoints and metadata."""
        base = request.base_url
        base = str(base.replace(scheme="https")).rstrip("/")
        dir_obj = {
            "newNonce": f"{base}/new-nonce",
            "newAccount": f"{base}/new-account",
            "newOrder": f"{base}/new-order",
            "revokeCert": f"{base}/revoke-cert",
            "keyChange": None,
            "meta": {
                "profiles": {
                    profile.name: profile.to_dict()
                    for profile in self.controller.config.profiles
                }
            }
        }
        return JSONResponse(dir_obj)
