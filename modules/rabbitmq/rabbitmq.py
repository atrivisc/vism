import asyncio
import base64
import json
import socket
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncGenerator, Optional

import aio_pika
from aio_pika import Message
from aio_pika.abc import AbstractRobustChannel, AbstractIncomingMessage
from aiormq import AMQPConnectionError

from modules import module_logger
from shared.data.exchange import DataExchange, DataExchangeConfig, DataExchangeCSRMessage, DataExchangeMessage, \
    DataExchangeCertMessage
from shared.data.validation import Data
from modules.rabbitmq.errors import RabbitMQError
from vism_ca import Certificate


@dataclass
class RabbitMQConfig(DataExchangeConfig):
    host: str
    port: int
    user: str
    password: str
    vhost: str

    data_encryption_key: str
    data_encryption_module: str
    data_validation_key: str
    data_validation_module: str

    peer_encryption_public_key_pem: str
    peer_validation_public_key_pem: str

    csr_queue: str = None
    cert_queue: str = None
    csr_exchange: str = None
    cert_exchange: str = None

    max_retries: int = 5
    retry_delay_seconds: int = 1

class RabbitMQ(DataExchange):
    configClass = RabbitMQConfig
    config_path: str = "rabbitmq"

    config: RabbitMQConfig

    def __init__(self, *args, **kwargs):
        module_logger.debug(f"Initializing RabbitMQ module")
        super().__init__(*args, **kwargs)
        self.encryption_module: Optional[Data] = None
        self.validation_module: Optional[Data] = None
        self.connection: Optional[aio_pika.Connection] = None

    def load_config(self, config_data: dict) -> None:
        module_logger.debug(f"Loading config for RabbitMQ module")
        super().load_config(config_data)
        self.encryption_module = self._setup_encryption_module()
        self.validation_module = self._setup_validation_module()

    def _setup_encryption_module(self) -> Data:
        encryption_module_imports = __import__(f'modules.{self.config.data_encryption_module}', fromlist=['Module', 'ModuleConfig'])
        encryption_module = encryption_module_imports.Module(
            encryption_key=self.config.data_encryption_key,
        )
        encryption_module.load_config(self.raw_config)

        return encryption_module

    def _setup_validation_module(self) -> Data:
        validation_module_imports = __import__(f'modules.{self.config.data_validation_module}', fromlist=['Module', 'ModuleConfig'])
        validation_module = validation_module_imports.Module(
            validation_key=self.config.data_validation_key,
        )
        validation_module.load_config(self.raw_config)

        return validation_module

    async def cleanup(self, full: bool = False):
        module_logger.debug("Cleaning up RabbitMQ")
        if self.connection is not None:
            if not self.connection.closed():
                await self.connection.close()
            self.connection = None

    async def send_data(self, message: DataExchangeMessage, exchange: str, message_type: str, routing_key: str):
        module_logger.info(f"Sending message to RabbitMQ exchange '{exchange}'")

        data_json = message.to_json().encode("utf-8")
        encrypted_message_body = self.encryption_module.encrypt_for_peer(data_json, self.config.peer_encryption_public_key_pem)
        encrypted_message_signature = self.validation_module.sign(encrypted_message_body)

        async with self._get_channel() as channel:
            await channel.initialize(timeout=30)
            await channel.set_qos(prefetch_count=1)
            exchange = await channel.get_exchange(exchange)

            message: Message = Message(
                body=encrypted_message_body,
                headers={
                    "X-Vism-Message-Type": message_type,
                    "X-Vism-Signature": base64.urlsafe_b64encode(encrypted_message_signature).decode("utf-8"),
                    "Content-Type": "application/octet-stream",
                }
            )

            await exchange.publish(
                message=message,
                routing_key=routing_key,
            )

    async def send_cert(self, message: DataExchangeCertMessage):
        await self.send_data(message, self.config.cert_exchange, "cert", "cert")

    async def send_csr(self, message: DataExchangeCSRMessage):
        await self.send_data(message, self.config.csr_exchange, "csr", "csr")

    async def receive_cert(self, *, retry_count: int = 0):
        module_logger.info(f"Starting listening for messages from RabbitMQ queue '{self.config.cert_queue}'")
        async with self._get_channel() as channel:
            await channel.initialize(timeout=30)
            await channel.set_qos(prefetch_count=1)
            queue = await channel.get_queue(self.config.cert_queue)

            try:
                await queue.consume(self.handle_message, consumer_tag=socket.gethostname())
            except AMQPConnectionError:
                if retry_count >= self.config.max_retries:
                    raise
                await asyncio.sleep(self.config.retry_delay_seconds)
                return await self.receive_cert(retry_count=retry_count + 1)

    async def receive_csr(self, *, retry_count: int = 0):
        module_logger.info(f"Starting listening for messages from RabbitMQ queue '{self.config.csr_queue}'")
        async with self._get_channel() as channel:
            await channel.initialize(timeout=30)
            await channel.set_qos(prefetch_count=1)
            queue = await channel.get_queue(self.config.csr_queue)

            try:
                await queue.consume(self.handle_message, consumer_tag=socket.gethostname())
            except AMQPConnectionError:
                if retry_count >= self.config.max_retries:
                    raise
                await asyncio.sleep(self.config.retry_delay_seconds)
                return await self.receive_csr(retry_count=retry_count + 1)

    async def handle_message(self, message: AbstractIncomingMessage):
        module_logger.info(f"Received message from RabbitMQ.")
        async with message.process():
            message_type = message.headers.get("X-Vism-Message-Type", None)
            if not message_type:
                module_logger.error(f"No message type found in message headers: {message.headers}")
                return None

            module_logger.info(f"Processing message from RabbitMQ of type '{message_type}'.")
            module_logger.debug(f"Message body: {message.body} | Signature: {message.headers['X-Vism-Signature']}")
            
            self.validation_module.verify(message.body, message.headers["X-Vism-Signature"])
            decrypted_body = self.encryption_module.decrypt(message.body)

            if message.headers["X-Vism-Message-Type"] == "csr":
                csr_message = DataExchangeCSRMessage(**json.loads(decrypted_body))
                ca = Certificate(self.controller, csr_message.ca_name)
                chain = ca.sign_csr(csr_message.csr_pem, csr_message.module_args, acme=True)

                cert_message = DataExchangeCertMessage(
                    chain=chain,
                    order_id=csr_message.order_id,
                    ca_name=csr_message.ca_name,
                    profile_name=csr_message.profile_name,
                    original_signature_b64=message.headers["X-Vism-Signature"],
                    original_encrypted_b64=base64.urlsafe_b64encode(message.body).decode("utf-8"),
                )
                await self.send_cert(cert_message)
            elif message.headers["X-Vism-Message-Type"] == "cert":
                cert_message = DataExchangeCertMessage(**json.loads(decrypted_body))
                original_encrypted = base64.urlsafe_b64decode(cert_message.original_encrypted_b64)
                self.validation_module.verify(original_encrypted, cert_message.original_signature_b64)
                await self.controller.handle_chain_from_ca(cert_message)
                
            return None

    @asynccontextmanager
    async def _get_channel(self, **kwargs) -> AsyncGenerator[AbstractRobustChannel]:
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
            raise RabbitMQError(f"Failed to connect to RabbitMQ: {e}")
        finally:
            await self.cleanup()
            module_logger.debug("RabbitMQ Connection closed")