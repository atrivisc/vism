import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from starlette.responses import JSONResponse

from shared.data.validation import Data
from shared.errors import VismException
from shared.rabbitmq.producer import RabbitMQProducer
from vism_acme.config import AcmeConfig
from vism_acme.db import VismAcmeDatabase
from vism_acme.middleware import JWSMiddleware
from vism_acme.middleware.acme_request import AcmeAccountMiddleware
from vism_acme.schema.response import ACMEProblemResponse
from vism_acme.util.nonce import NonceManager


class VismACMEController:
    def __init__(self):
        config_file_path = os.environ.get('CONFIG_FILE_PATH', './acme_config.yaml')

        self.config = AcmeConfig(config_file_path)
        self.validation_module = self.setup_validation_module()
        self.encryption_module = self.setup_encryption_module()
        self.database = VismAcmeDatabase(self.config.database, self.validation_module)
        self.nonce_manager = NonceManager(self.config)
        self.rabbitmq_producer = RabbitMQProducer(self.config.raw_config_data)
        self.api = FastAPI(lifespan=self.lifespan)
        self.setup_exception_handlers()
        self.setup_middleware()
        self.setup_routes()

    @asynccontextmanager
    async def lifespan(self, api: FastAPI):
        yield
        self.validation_module.cleanup(full=True)
        self.encryption_module.cleanup(full=True)
        await self.rabbitmq_producer.close_all_connections()

    def setup_encryption_module(self) -> Data:
        encryption_module_imports = __import__(f'modules.{self.config.security.data_validation.module}', fromlist=['Module', 'ModuleConfig'])
        encryption_module = encryption_module_imports.Module(
            encryption_key=self.config.security.data_encryption.encryption_key,
            validation_key=self.config.security.data_validation.validation_key
        )
        encryption_module.load_config(self.config.raw_config_data)

        return encryption_module

    def setup_validation_module(self) -> Data:
        validation_module_imports = __import__(f'modules.{self.config.security.data_validation.module}', fromlist=['Module', 'ModuleConfig'])
        validation_module = validation_module_imports.Module(
            encryption_key=self.config.security.data_encryption.encryption_key,
            validation_key=self.config.security.data_validation.validation_key
        )
        validation_module.load_config(self.config.raw_config_data)

        return validation_module

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
