import asyncio
import os
import socket

import aio_pika
from dataclasses import dataclass

from aio_pika.abc import AbstractRobustChannel, AbstractExchange, AbstractQueue, AbstractIncomingMessage
from aiormq import AMQPConnectionError

from shared.config import shared_logger
from shared.rabbitmq import RabbitMQConfig, RabbitMQ


@dataclass
class RabbitMQConsumerConfig(RabbitMQConfig):
    csr_queue: str
    cert_queue: str

    producer_validation_public_key_pem: str

    max_retries: int = 5
    retry_delay_seconds: int = 1


class RabbitMQConsumer(RabbitMQ):
    def __init__(self, ca, config_data: dict):
        self.ca = ca
        self.config: RabbitMQConsumerConfig = RabbitMQConsumerConfig(**config_data.get("rabbitmq_consumer", {}))

    async def consume_csr(self, retry_count: int = 0):
        async with self._get_channel() as channel:
            queue: AbstractQueue = await channel.get_queue(self.config.csr_queue)

            retry_count = 0
            try:
                await queue.consume(self.handle_message, consumer_tag=socket.gethostname(), no_ack=True)
            except aio_pika.exceptions.QueueEmpty:
                await asyncio.sleep(self.config.retry_delay_seconds)
                return self.consume_csr()
            except AMQPConnectionError:
                if retry_count >= self.config.max_retries:
                    raise
                await asyncio.sleep(self.config.retry_delay_seconds)
                return self.consume_csr(retry_count + 1)
            except Exception:
                raise

    async def handle_message(self, message: AbstractIncomingMessage):
        shared_logger.info(f"Received CSR message from RabbitMQ.")
        async with message.process():
            print(message.body)
