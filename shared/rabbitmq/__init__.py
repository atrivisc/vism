from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncGenerator

import aio_pika
from aio_pika.abc import AbstractRobustChannel

from shared import shared_logger
from shared.data.validation import Data
from shared.errors import VismException
from shared.rabbitmq.errors import RabbitMQError


@dataclass
class RabbitMQConfig:
    host: str
    port: int
    user: str
    password: str
    vhost: str

    data_encryption_key: str
    data_encryption_module: str
    data_validation_key: str
    data_validation_module: str

class RabbitMQ:
    config: RabbitMQConfig
    open_connections = {}

    def __init__(self, config_data: dict):
        self.raw_config_data = config_data
        if self.config is None:
            raise VismException("Config wasn't set before super().__init__")

        self.encryption_module = self.setup_encryption_module()
        self.validation_module = self.setup_validation_module()

    def setup_encryption_module(self) -> Data:
        encryption_module_imports = __import__(f'modules.{self.config.data_encryption_module}', fromlist=['Module', 'ModuleConfig'])
        encryption_module = encryption_module_imports.Module(
            encryption_key=self.config.data_encryption_key,
        )
        encryption_module.load_config(self.raw_config_data)

        return encryption_module

    def setup_validation_module(self) -> Data:
        validation_module_imports = __import__(f'modules.{self.config.data_encryption_module}', fromlist=['Module', 'ModuleConfig'])
        validation_module = validation_module_imports.Module(
            validation_key=self.config.data_validation_key,
        )
        validation_module.load_config(self.raw_config_data)

        return validation_module

    async def close_all_connections(self):
        for connection in self.open_connections.values():
            await connection.close()
        self.open_connections = {}

    @asynccontextmanager
    async def _get_channel(self, **kwargs) -> AsyncGenerator[AbstractRobustChannel]:
        shared_logger.debug("Opening a RabbitMQ connection")
        connection = await aio_pika.connect_robust(
            host=self.config.host,
            port=self.config.port,
            login=self.config.user,
            password=self.config.password,
            virtualhost=self.config.vhost,
        )
        connection_id = id(connection)
        self.open_connections[connection_id] = connection
        try:
            channel = connection.channel(**kwargs)
            yield channel
        except Exception as e:
            if not connection.closed():
                self.open_connections.pop(connection_id)
                await connection.close()
            raise RabbitMQError(f"Failed to connect to RabbitMQ: {e}")
        finally:
            if not connection.closed():
                self.open_connections.pop(connection_id)
                await connection.close()
            shared_logger.debug("RabbitMQ Connection closed")