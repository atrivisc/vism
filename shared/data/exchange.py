# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""Data exchange module for inter-component communication."""

import json
from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from shared import shared_logger
from shared.config import Config
from shared.data.validation import Data


@dataclass
class DataExchangeConfig(Config):
    """Base configuration class for data exchange modules."""
    data_encryption_module: str
    data_encryption_key: str
    data_validation_module: str
    data_validation_key: str

@dataclass
class DataExchangeMessage:
    """Base class for data exchange messages."""

    def to_json(self) -> str:
        """Convert message to JSON string."""
        raise NotImplementedError()


@dataclass
class DataExchangeCSRMessage(DataExchangeMessage):
    """Message containing Certificate Signing Request data."""

    csr_pem: str
    ca_name: str
    profile_name: str
    module_args: dict
    order_id: str

    def to_json(self) -> str:
        """Convert CSR message to JSON string."""
        return json.dumps({
            "csr_pem": self.csr_pem,
            "ca_name": self.ca_name,
            "profile_name": self.profile_name,
            "module_args": self.module_args,
            "order_id": self.order_id,
        })


@dataclass
class DataExchangeCertMessage(DataExchangeMessage):
    """Message containing certificate chain data."""

    chain: str
    order_id: str
    ca_name: str
    profile_name: str
    original_signature_b64: str

    def to_json(self) -> str:
        """Convert certificate message to JSON string."""
        return json.dumps({
            "chain": self.chain,
            "order_id": self.order_id,
            "ca_name": self.ca_name,
            "profile_name": self.profile_name,
            "original_signature_b64": self.original_signature_b64,
        })


class DataExchange(metaclass=ABCMeta):
    """Abstract base class for data exchange implementations."""

    configClass = DataExchangeConfig

    def __init__(self, controller):
        shared_logger.info(
            "Initializing DataExchange module: %s",
            self.__class__.__name__
        )
        self.controller = controller
        self.config: DataExchangeConfig = self.configClass.load()
        self.encryption_module = self._setup_encryption_module()
        self.validation_module = self._setup_validation_module()

    def _setup_encryption_module(self) -> Data:
        module_name = f'modules.{self.config.data_encryption_module}'
        encryption_module_imports = __import__(
            module_name,
            fromlist=['Module', 'ModuleConfig']
        )
        encryption_module = encryption_module_imports.Module(
            encryption_key=self.config.data_encryption_key,
        )
        return encryption_module

    def _setup_validation_module(self) -> Data:
        module_name = f'modules.{self.config.data_validation_module}'
        validation_module_imports = __import__(
            module_name,
            fromlist=['Module', 'ModuleConfig']
        )
        validation_module = validation_module_imports.Module(
            validation_key=self.config.data_validation_key,
        )
        return validation_module

    async def cleanup(self, full: bool = False):
        """Clean up resources used by the data exchange module."""

    @abstractmethod
    async def send_csr(self, message: DataExchangeCSRMessage):
        """Send a CSR message to the CA."""
        raise NotImplementedError()

    @abstractmethod
    async def send_cert(self, message: DataExchangeCertMessage):
        """Send certificate data."""
        raise NotImplementedError()

    @abstractmethod
    async def receive_csr(self) -> None:
        """Receive CSR data from clients."""
        raise NotImplementedError()

    @abstractmethod
    async def receive_cert(self) -> None:
        """Receive certificate data from CA."""
        raise NotImplementedError()
