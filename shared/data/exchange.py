from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class DataExchangeConfig:
    pass

class DataExchange(metaclass=ABCMeta):
    configClass = DataExchangeConfig
    config_path: str = None

    def __init__(self, controller):
        self.controller = controller
        self.raw_config: Optional[dict] = None
        self.config: Optional[DataExchangeConfig] = None

    def load_config(self, config_data: dict) -> None:
        self.raw_config = config_data
        self.config = self.configClass(**config_data.get(self.config_path, {}))

    @abstractmethod
    async def cleanup(self, full: bool = False):
        pass

    @abstractmethod
    async def send_csr(self, data: bytes):
        raise NotImplementedError()

    @abstractmethod
    async def receive_csr(self) -> bytes:
        raise NotImplementedError()