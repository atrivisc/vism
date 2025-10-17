from fastapi import APIRouter
from starlette.responses import Response
from vism_acme import VismACMEController


class NonceRouter:
    def __init__(self, controller: VismACMEController):
        self.controller = controller

        self.router = APIRouter()
        self.router.head("/new-nonce")(self.new_nonce)
        self.router.get("/new-nonce")(self.new_nonce)

    async def new_nonce(self):
        nonce = await self.controller.nonce_manager.new_nonce()
        return Response(status_code=200, headers={"Replay-Nonce": nonce})
