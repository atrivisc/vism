# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""RabbitMQ module for secure message exchange in VISM."""

import asyncio
import base64
import json
import socket
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

import aio_pika
from aio_pika import Message
from aio_pika.abc import AbstractRobustChannel, AbstractIncomingMessage
from aiormq import AMQPConnectionError

from modules import module_logger
from modules.rabbitmq.config import RabbitMQConfig
from modules.rabbitmq.errors import RabbitMQError
from shared.data.exchange import (
    DataExchange,
    DataExchangeCSRMessage,
    DataExchangeMessage,
    DataExchangeCertMessage
)
from vism_ca import Certificate


# pylint: disable=too-many-instance-attributes
class RabbitMQ(DataExchange):
    """RabbitMQ implementation of DataExchange."""
    configClass = RabbitMQConfig
    config: RabbitMQConfig

    def __init__(self, *args, **kwargs):
        module_logger.debug("Initializing RabbitMQ module")
        super().__init__(*args, **kwargs)
        self.connection: Optional[aio_pika.Connection] = None

    async def cleanup(self, full: bool = False):
        """Clean up RabbitMQ resources."""
        module_logger.debug("Cleaning up RabbitMQ")
        if self.connection is not None:
            if not self.connection.closed():
                await self.connection.close()
            self.connection = None

    async def send_message(
        self, message: DataExchangeMessage, exchange: str,
        message_type: str, routing_key: str
    ):
        """Send data to RabbitMQ exchange."""
        module_logger.info(
            "Sending message to RabbitMQ exchange '%s'", exchange
        )

        data_json = message.to_json().encode("utf-8")
        encrypted_message_body = self.encryption_module.encrypt_for_peer(
            data_json, self.config.peer_encryption_public_key_pem
        )
        encrypted_message_signature = self.validation_module.sign(
            encrypted_message_body
        )

        async with self._get_channel() as channel:
            await channel.initialize(timeout=30)
            await channel.set_qos(prefetch_count=1)
            exchange_obj = await channel.get_exchange(exchange)

            rabbitmq_message: Message = Message(
                body=encrypted_message_body,
                headers={
                    "X-Vism-Message-Type": message_type,
                    "X-Vism-Signature": base64.urlsafe_b64encode(
                        encrypted_message_signature
                    ).decode("utf-8"),
                    "Content-Type": "application/octet-stream",
                }
            )

            await exchange_obj.publish(
                message=rabbitmq_message,
                routing_key=routing_key,
            )

    async def send_cert(self, message: DataExchangeCertMessage):
        """Send certificate message."""
        await self.send_message(message, self.config.cert_exchange, "cert", "cert")

    async def send_csr(self, message: DataExchangeCSRMessage):
        """Send CSR message."""
        await self.send_message(message, self.config.csr_exchange, "csr", "csr")

    async def receive_cert(self, *, retry_count: int = 0):
        """Receive certificate messages from queue."""
        module_logger.info(
            "Starting listening for messages from RabbitMQ queue '%s'",
            self.config.cert_queue
        )
        async with self._get_channel() as channel:
            await channel.initialize(timeout=30)
            await channel.set_qos(prefetch_count=1)
            queue = await channel.get_queue(self.config.cert_queue)

            try:
                consumer_tag = socket.gethostname()
                await queue.consume(self.handle_message, consumer_tag=consumer_tag)
            except AMQPConnectionError:
                if retry_count >= self.config.max_retries:
                    raise
                await asyncio.sleep(self.config.retry_delay_seconds)
                return await self.receive_cert(retry_count=retry_count + 1)

    async def receive_csr(self, *, retry_count: int = 0):
        """Receive CSR messages from queue."""
        module_logger.info(
            "Starting listening for messages from RabbitMQ queue '%s'",
            self.config.csr_queue
        )
        async with self._get_channel() as channel:
            await channel.initialize(timeout=30)
            await channel.set_qos(prefetch_count=1)
            queue = await channel.get_queue(self.config.csr_queue)

            try:
                consumer_tag = socket.gethostname()
                await queue.consume(self.handle_message, consumer_tag=consumer_tag)
            except AMQPConnectionError:
                if retry_count >= self.config.max_retries:
                    raise
                await asyncio.sleep(self.config.retry_delay_seconds)
                return await self.receive_csr(retry_count=retry_count + 1)

    async def handle_message(self, message: AbstractIncomingMessage):
        """Handle incoming RabbitMQ message."""
        module_logger.info("Received message from RabbitMQ.")
        async with message.process():
            message_type = message.headers.get("X-Vism-Message-Type", None)
            if not message_type:
                module_logger.error(
                    "No message type found in message headers: %s",
                    message.headers
                )
                return None

            module_logger.info(
                "Processing message from RabbitMQ of type '%s'.",
                message_type
            )
            module_logger.debug(
                "Message body: %s | Signature: %s",
                message.body, message.headers['X-Vism-Signature']
            )

            self.validation_module.verify(
                message.body,
                message.headers["X-Vism-Signature"]
            )
            decrypted_body = self.encryption_module.decrypt(message.body)

            if message.headers["X-Vism-Message-Type"] == "csr":
                csr_message = DataExchangeCSRMessage(
                    **json.loads(decrypted_body)
                )
                ca_obj = Certificate(self.controller, csr_message.ca_name)
                chain = ca_obj.sign_csr(
                    csr_message.csr_pem, csr_message.module_args, acme=True
                )

                cert_message = DataExchangeCertMessage(
                    chain=chain,
                    order_id=csr_message.order_id,
                    ca_name=csr_message.ca_name,
                    profile_name=csr_message.profile_name,
                    original_signature_b64=message.headers["X-Vism-Signature"],
                    original_encrypted_b64=base64.urlsafe_b64encode(
                        message.body
                    ).decode("utf-8"),
                )
                await self.send_cert(cert_message)
            elif message.headers["X-Vism-Message-Type"] == "cert":
                cert_message = DataExchangeCertMessage(
                    **json.loads(decrypted_body)
                )
                original_encrypted = base64.urlsafe_b64decode(
                    cert_message.original_encrypted_b64
                )
                self.validation_module.verify(
                    original_encrypted,
                    cert_message.original_signature_b64
                )
                await self.controller.handle_chain_from_ca(cert_message)

            return None

    @asynccontextmanager
    async def _get_channel(self, **kwargs) -> AsyncGenerator[AbstractRobustChannel]:
        """Get a RabbitMQ channel."""
        module_logger.debug("Opening a RabbitMQ connection")
        if self.connection is None:
            self.connection = await aio_pika.connect_robust(
                host=self.config.host,
                port=self.config.port,
                login=self.config.user,
                password=self.config.password,
                virtualhost=self.config.vhost,
            )
        try:
            channel = self.connection.channel(**kwargs)
            yield channel
        except Exception as e:
            await self.cleanup()
            raise RabbitMQError(
                f"Failed to connect to RabbitMQ: {e}"
            ) from e
        finally:
            await self.cleanup()
            module_logger.debug("RabbitMQ Connection closed")
