from dataclasses import dataclass
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

    async def send_message(self, message: RabbitMQMessage, exchange: str, routing_key: str):
        shared_logger.debug(f"Sending message to RabbitMQ exchange '{exchange}' with routing key '{routing_key}'")
        with self._get_channel() as channel:
            await channel.basic_publish(
                exchange=exchange,
                routing_key=routing_key,
                body=message.get_encrypted_message_body(self.config.consumer_encryption_public_key_pem),
            )
