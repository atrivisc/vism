import json
from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from typing import Optional

from shared import shared_logger


@dataclass
class DataExchangeConfig:
    pass

@dataclass
class DataExchangeMessage:
    def to_json(self) -> str:
        raise NotImplementedError()

@dataclass
class DataExchangeCSRMessage(DataExchangeMessage):
    csr_pem: str
    ca_name: str
    profile_name: str
    module_args: dict
    order_id: str

    def to_json(self) -> str:
        return json.dumps({
            "csr_pem": self.csr_pem,
            "ca_name": self.ca_name,
            "profile_name": self.profile_name,
            "module_args": self.module_args,
            "order_id": self.order_id,
        })

@dataclass
class DataExchangeCertMessage(DataExchangeMessage):
    chain: str
    order_id: str
    ca_name: str
    profile_name: str
    original_signature_b64: str
    original_encrypted_b64: str

    def to_json(self) -> str:
        return json.dumps({
            "chain": self.chain,
            "order_id": self.order_id,
            "ca_name": self.ca_name,
            "profile_name": self.profile_name,
            "original_signature_b64": self.original_signature_b64,
            "original_encrypted_b64": self.original_encrypted_b64,
        })

class DataExchange(metaclass=ABCMeta):
    configClass = DataExchangeConfig
    config_path: str = None

    def __init__(self, controller):
        shared_logger.info(f"Initializing DataExchange module: {self.__class__.__name__}")
        self.controller = controller
        self.raw_config: Optional[dict] = None
        self.config: Optional[DataExchangeConfig] = None

    def load_config(self, config_data: dict) -> None:
        self.raw_config = config_data
        self.config = self.configClass(**config_data.get(self.config_path, {}))

    async def cleanup(self, full: bool = False):
        pass

    @abstractmethod
    async def send_csr(self, message: DataExchangeCSRMessage):
        raise NotImplementedError()

    @abstractmethod
    async def send_cert(self, data: bytes):
        raise NotImplementedError()

    @abstractmethod
    async def receive_csr(self) -> bytes:
        raise NotImplementedError()

    @abstractmethod
    async def receive_cert(self) -> bytes:
        raise NotImplementedError()