import asyncio
import socket
from dataclasses import dataclass
from aio_pika.abc import AbstractQueue, AbstractIncomingMessage
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
        super().__init__(config_data)

    async def consume_csr(self, retry_count: int = 0):
        async with self._get_channel() as channel:
            await channel.initialize(timeout=30)
            await channel.set_qos(prefetch_count=1)
            queue: AbstractQueue = await channel.get_queue(self.config.csr_queue)

            try:
                await queue.consume(self.handle_message, consumer_tag=socket.gethostname(), no_ack=True)
            except AMQPConnectionError:
                if retry_count >= self.config.max_retries:
                    raise
                await asyncio.sleep(self.config.retry_delay_seconds)
                return self.consume_csr(retry_count + 1)

    async def handle_message(self, message: AbstractIncomingMessage):
        shared_logger.info(f"Received CSR message from RabbitMQ.")
        async with message.process(requeue=True):
            print(message.body)
