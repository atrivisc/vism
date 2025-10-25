"""Data exchange module for inter-component communication."""
# Licensed under the GPL 3: https://www.gnu.org/licenses/gpl-3.0.html

import json
from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from typing import Optional

from shared import shared_logger


@dataclass
class DataExchangeConfig:
    """Base configuration class for data exchange modules."""


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
    original_encrypted_b64: str

    def to_json(self) -> str:
        """Convert certificate message to JSON string."""
        return json.dumps({
            "chain": self.chain,
            "order_id": self.order_id,
            "ca_name": self.ca_name,
            "profile_name": self.profile_name,
            "original_signature_b64": self.original_signature_b64,
            "original_encrypted_b64": self.original_encrypted_b64,
        })


class DataExchange(metaclass=ABCMeta):
    """Abstract base class for data exchange implementations."""

    configClass = DataExchangeConfig
    config_path: str = None

    def __init__(self, controller):
        shared_logger.info(
            "Initializing DataExchange module: %s",
            self.__class__.__name__
        )
        self.controller = controller
        self.raw_config: Optional[dict] = None
        self.config: Optional[DataExchangeConfig] = None

    def load_config(self, config_data: dict) -> None:
        """Load configuration from config data dictionary."""
        self.raw_config = config_data
        self.config = self.configClass(
            **config_data.get(self.config_path, {})
        )

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
