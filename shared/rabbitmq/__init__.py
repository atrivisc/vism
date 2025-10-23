from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncGenerator

import aio_pika
from aio_pika.abc import AbstractRobustChannel

from shared import shared_logger
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

    @asynccontextmanager
    async def _get_channel(self) -> AsyncGenerator[AbstractRobustChannel]:
        shared_logger.debug("Opening a RabbitMQ connection")
        connection = await aio_pika.connect_robust(
            host=self.config.host,
            port=self.config.port,
            login=self.config.user,
            password=self.config.password,
            virtual_host=self.config.vhost,
        )
        try:
            channel = connection.channel()
            yield channel
        except Exception as e:
            if not connection.closed():
                await connection.close()
            raise RabbitMQError(f"Failed to connect to RabbitMQ: {e}")
        finally:
            if not connection.closed():
                await connection.close()
            shared_logger.debug("RabbitMQ Connection closed")