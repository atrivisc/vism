from dataclasses import dataclass
from typing import Optional
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

    def __init__(self, *, encryption_key: str = None, validation_key: str = None):
        self.config: Optional[DataConfig] = None
        self.encryption_key = encryption_key
        self.validation_key = validation_key

    def load_config(self, config_data: dict) -> None:
        self.config = self.configClass(**config_data.get(self.config_path, {}))

    def decrypt(self, data: bytes) -> bytes:
        raise NotImplemented()

    def decrypt_for_peer(self, data: bytes, peer_public_key_pem: str) -> bytes:
        raise NotImplemented()

    def encrypt(self, data: bytes) -> bytes:
        raise NotImplemented()

    def encrypt_for_peer(self, data: bytes, peer_public_key_pem: str) -> bytes:
        raise NotImplemented()

    def sign(self, data: bytes) -> bytes:
        raise NotImplemented()

    def verify(self, data: bytes, signature_b64u: str) -> bool:
        raise NotImplemented()

    def cleanup(self, full: bool = False) -> None:
        pass