import base64
import json
from dataclasses import dataclass

from aio_pika import RobustExchange, Message

from shared import shared_logger
from shared.rabbitmq import RabbitMQConfig, RabbitMQ
from shared.rabbitmq.message import RabbitMQMessage


@dataclass
class RabbitMQProducerConfig(RabbitMQConfig):
    csr_exchange: str
    cert_exchange: str
    consumer_encryption_public_key_pem: str

    max_retries: int = 5
    retry_delay_seconds: int = 1


class RabbitMQProducer(RabbitMQ):
    def __init__(self, config_data: dict):
        self.config: RabbitMQProducerConfig = RabbitMQProducerConfig(**config_data.get("rabbitmq_producer", {}))
        super().__init__(config_data)

    async def send_message(self, message: RabbitMQMessage, exchange: str, routing_key: str):
        shared_logger.debug(f"Sending message to RabbitMQ exchange '{exchange}' with routing key '{routing_key}'")
        message_body = json.dumps(message.to_dict())
        message_signature = self.validation_module.sign(message_body)
        encrypted_message_body = self.encryption_module.encrypt_for_peer(message_body, self.config.consumer_encryption_public_key_pem)

        async with self._get_channel() as channel:
            await channel.initialize(timeout=30)
            await channel.set_qos(prefetch_count=1)
            exchange: RobustExchange = await channel.get_exchange(exchange)

            message: Message = Message(
                body=encrypted_message_body,
                headers={
                    "X-Vism-Signature": base64.urlsafe_b64encode(message_signature).decode("utf-8"),
                }
            )

            await exchange.publish(
                message=message,
                routing_key=routing_key,
            )
