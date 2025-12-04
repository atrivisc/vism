# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""RabbitMQ module for secure message exchange in VISM."""

import asyncio
import base64
import json
import socket
from typing import Optional

import aio_pika
from aio_pika import Message
from aio_pika.abc import AbstractIncomingMessage, AbstractRobustConnection
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
        self._connection: Optional[aio_pika.Connection] = None

    async def cleanup(self, full: bool = False):
        """Clean up RabbitMQ resources."""
        module_logger.debug("Cleaning up RabbitMQ")
        if full:
            self.validation_module.async_cleanup(full=True)
            self.encryption_module.async_cleanup(full=True)

        conn = await self.connection
        if conn is not None:
            if not conn.is_closed:
                await conn.close()
            self._connection = None

    async def send_message(
        self, message: DataExchangeMessage, exchange: str,
        message_type: str, routing_key: str
    ):
        """Send data to RabbitMQ exchange."""
        module_logger.info(
            "Sending message to RabbitMQ exchange '%s'", exchange
        )

        data_json = message.to_json().encode("utf-8")
        message_signature = self.validation_module.sign(data_json)

        connection = await self.connection
        async with connection.channel(on_return_raises=True) as channel:
            if not channel.is_initialized:
                await channel.initialize(timeout=30)

            exchange_obj = await channel.get_exchange(exchange)

            rabbitmq_message: Message = Message(
                body=data_json,
                headers={
                    "X-Vism-Message-Type": message_type,
                    "X-Vism-Signature": base64.urlsafe_b64encode(
                        message_signature
                    ).decode("utf-8"),
                    "Content-Type": "application/octet-stream",
                }
            )

            try:
                await exchange_obj.publish(
                    message=rabbitmq_message,
                    routing_key=routing_key,
                )
            except Exception as e:
                module_logger.error(f"Failed to publish message: {e}")
                raise RuntimeError from e

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
        connection = await self.connection
        async with connection.channel(on_return_raises=True) as channel:
            if not channel.is_initialized:
                await channel.initialize(timeout=30)
            await channel.set_qos(prefetch_count=1)
            queue = await channel.declare_queue(
                name=self.config.cert_queue,
                passive=True,
                durable=True,
                robust=True,
            )

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
        connection = await self.connection
        async with connection.channel(on_return_raises=True) as channel:
            if not channel.is_initialized:
                await channel.initialize(timeout=30)

            queue = await channel.declare_queue(
                name=self.config.csr_queue,
                passive=True,
                durable=True,
                robust=True,
            )

            try:
                consumer_tag = socket.gethostname()
                await queue.consume(self.handle_message, consumer_tag=consumer_tag)
            except AMQPConnectionError as e:
                if retry_count >= self.config.max_retries:
                    raise e
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

            if message.headers["X-Vism-Message-Type"] == "csr":
                csr_message = DataExchangeCSRMessage(
                    **json.loads(message.body)
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
                )
                await self.send_cert(cert_message)
            elif message.headers["X-Vism-Message-Type"] == "cert":
                cert_message = DataExchangeCertMessage(
                    **json.loads(message.body)
                )
                self.validation_module.verify(
                    message.body,
                    cert_message.original_signature_b64
                )
                await self.controller.handle_chain_from_ca(cert_message)

            return None

    @property
    async def connection(self) -> AbstractRobustConnection:
        if self._connection is None:
            try:
                self._connection = await aio_pika.connect_robust(
                    host=self.config.host,
                    port=self.config.port,
                    login=self.config.user,
                    password=self.config.password,
                    virtualhost=self.config.vhost,
                )
            except AMQPConnectionError as e:
                raise RabbitMQError(
                    f"Failed to connect to RabbitMQ: {e}"
                ) from e
        return self._connection
