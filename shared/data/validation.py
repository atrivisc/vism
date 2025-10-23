import json
import os
from dataclasses import dataclass
from typing import Optional, Tuple
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec, ed25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from shared import shared_logger
from shared.errors import VismException

class DataError(VismException):
    pass

@dataclass
class DataModuleConfig:
    pass

@dataclass
class DataConfig:
    pass

class Data:
    configClass = DataConfig
    config_path: str = None

    def __init__(self, encryption_key: str, validation_key: str):
        self.config: Optional[DataConfig] = None
        self.encryption_key = encryption_key
        self.validation_key = validation_key

    def load_config(self, config_data: dict) -> None:
        self.config = self.configClass(**config_data.get(self.config_path, {}))

    def decrypt(self, data: str) -> str:
        raise NotImplemented()

    def encrypt(self, data: str) -> str:
        raise NotImplemented()

    def sign(self, data: str) -> str:
        raise NotImplemented()

    def verify(self, data: str, signature: str) -> bool:
        raise NotImplemented()