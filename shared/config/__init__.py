import logging
import yaml
from typing import Optional, Any
from pydantic.dataclasses import dataclass

from shared import logs
from shared.logs import LoggingConfig

shared_logger = logging.getLogger("shared")

@dataclass
class DataValidation:
    enabled: bool = False
    module: str = None
    validation_key: str = None

@dataclass
class DataEncryption:
    enabled: bool = False
    module: str = None
    encryption_key: str = None

@dataclass
class Security:
    data_validation: DataValidation = None
    data_encryption: DataEncryption = None
    chroot_base_dir: str = None

class Config:
    log_conf = {}
    conf_path: str = ""
    def __init__(self, config_file_path: str):
        self.config_file_path = config_file_path
        self.raw_config_data: Optional[dict] = self.read_config_file()
        self.setup_logging()

        path_conf = self.raw_config_data.get(self.conf_path, {})
        self.security = Security(**path_conf.get("security", {}))

    def setup_logging(self):
        logs.setup_logger(
            LoggingConfig(**dict(self.log_conf, **self.raw_config_data.get("logging", {})))
        )

    def read_config_file(self) -> dict[str, Any]:
        with open(self.config_file_path, 'r') as file:
            return yaml.safe_load(file)

@dataclass
class ModuleArgsConfig:
    pass