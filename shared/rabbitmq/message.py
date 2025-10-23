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

    def get_encrypted_message_body(self, public_key_pem: str) -> str:
        shared_logger.debug("Encrypting rabbitmq message body")
        aes_key = os.urandom(32)
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(os.urandom(12)))
        encryptor = cipher.encryptor()
        data = json.dumps(self.to_dict()).encode()
        ciphertext = encryptor.update(data) + encryptor.finalize()

        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        if isinstance(public_key, rsa.RSAPublicKey):
            encrypted_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        else:
            raise RabbitMQError(f"Unsupported public key type: {type(public_key)}")

        return json.dumps({
            "ciphertext": base64.urlsafe_b64encode(ciphertext).decode(),
            "encrypted_key": base64.urlsafe_b64encode(encrypted_key).decode(),
        })


@dataclass
class RabbitmqCSRMessage(RabbitMQMessage):
    csr_pem: str = None
    module_args: dict = None

    def to_dict(self):
        return {
            "csr_pem": self.csr_pem,
            "module_args": self.module_args,
        }