import base64
import json
import os
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from shared import shared_logger
from shared.rabbitmq.errors import RabbitMQError


@dataclass
class RabbitMQMessage:
    def to_dict(self):
        raise NotImplementedError()

@dataclass
class RabbitmqCSRMessage(RabbitMQMessage):
    csr_pem: str = None
    module_args: dict = None

    def to_dict(self):
        return {
            "csr_pem": self.csr_pem,
            "module_args": self.module_args,
        }