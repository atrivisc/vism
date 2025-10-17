import os
from fastapi import FastAPI
from starlette.responses import JSONResponse

from vism.util.errors import VismException
from vism_acme.config import AcmeConfig
from vism_acme.db import VismDatabase
from vism_acme.middleware import JWSMiddleware
from vism_acme.middleware.acme_request import AcmeAccountMiddleware
from vism_acme.schema.response import ACMEProblemResponse
from vism_acme.util.nonce import NonceManager


class VismACMEController:
    def __init__(self):
        config_file_path = os.environ.get('CONFIG_FILE_PATH', './acme_config.yaml')

        self.config = AcmeConfig(config_file_path)
        self.database = VismDatabase(self.config.database)
        self.nonce_manager = NonceManager(self.config)
        self.api = FastAPI()
        self.setup_exception_handlers()
        self.setup_middleware()
        self.setup_routes()

    def setup_middleware(self):
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
        @self.api.exception_handler(ACMEProblemResponse)
        async def acme_problem_response_handler(request, exc: ACMEProblemResponse):
            return JSONResponse(
                status_code=exc.status_code,
                content=exc.error_json,
                headers={"Content-Type": "application/problem+json"}
            )
        @self.api.exception_handler(VismException)
        async def acme_problem_response_handler(request, exc: VismException):
            return JSONResponse(
                status_code=500,
                content={
                    "type": "urn:ietf:params:acme:error:serverInternal",
                    "title": "An internal server error occurred",
                },
                headers={"Content-Type": "application/problem+json"}
            )

    def setup_routes(self):
        from vism_acme.routers.account import AccountRouter
        from vism_acme.routers.base import BaseRouter
        from vism_acme.routers.nonce import NonceRouter
        from vism_acme.routers.order import OrderRouter
        from vism_acme.routers.authz import AuthzRouter

        base_router = BaseRouter(self)
        nonce_router = NonceRouter(self)
        account_router = AccountRouter(self)
        order_router = OrderRouter(self)
        authz_router = AuthzRouter(self)

        self.api.include_router(account_router.router)
        self.api.include_router(nonce_router.router)
        self.api.include_router(base_router.router)
        self.api.include_router(order_router.router)
        self.api.include_router(authz_router.router)

controller = VismACMEController()
app = controller.api
