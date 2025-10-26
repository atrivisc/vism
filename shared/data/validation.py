# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""Data validation and cryptography module interfaces."""

from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from typing import Optional
from shared import shared_logger
from shared.config import Config
from shared.errors import VismException


class DataError(VismException):
    """Exception raised for data validation/encryption errors."""


@dataclass
class DataModuleConfig:
    """Base configuration class for data modules."""


@dataclass
class DataConfig(Config):
    """Configuration class for data operations."""


class Data(metaclass=ABCMeta):
    """Abstract base class for data validation and encryption modules."""

    configClass = DataConfig

    def __init__(
            self,
            *,
            encryption_key: str = None,
            validation_key: str = None
    ):
        shared_logger.info("Initializing Data module: %s", self.__class__.__name__)
        self.config: Optional[DataConfig] = self.configClass.load()
        self.encryption_key = encryption_key
        self.validation_key = validation_key

    @abstractmethod
    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data using the module's encryption key."""
        raise NotImplementedError()

    @abstractmethod
    def decrypt_for_peer(
            self,
            data: bytes,
            peer_public_key_pem: str
    ) -> bytes:
        """Decrypt data encrypted for a specific peer."""
        raise NotImplementedError()

    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data using the module's encryption key."""
        raise NotImplementedError()

    @abstractmethod
    def encrypt_for_peer(
            self,
            data: bytes,
            peer_public_key_pem: str
    ) -> bytes:
        """Encrypt data for a specific peer."""
        raise NotImplementedError()

    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        """Sign data using the module's validation key."""
        raise NotImplementedError()

    @abstractmethod
    def verify(self, data: bytes, signature_b64u: str) -> bool:
        """Verify data signature using the module's validation key."""
        raise NotImplementedError()

    def cleanup(self, full: bool = False) -> None:
        """Clean up resources used by the data module."""
