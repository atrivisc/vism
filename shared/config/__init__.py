# Licensed under the GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""Shared configuration classes for VISM components."""

from typing import Optional, Any

import yaml
from pydantic.dataclasses import dataclass

from shared import logs, shared_logger
from shared.logs import LoggingConfig

@dataclass
class DataValidation:
    """Configuration for data validation module."""

    enabled: bool = False
    module: str = None
    validation_key: str = None


@dataclass
class DataEncryption:
    """Configuration for data encryption module."""

    enabled: bool = False
    module: str = None
    encryption_key: str = None


@dataclass
class Security:
    """Security configuration including validation and encryption."""

    data_validation: DataValidation = None
    data_encryption: DataEncryption = None
    chroot_base_dir: str = None


@dataclass
class DataExchange:
    """Configuration for data exchange module."""

    module: str


class Config:
    """Base configuration class for VISM components."""

    log_conf = {}
    conf_path: str = ""

    def __init__(self, config_file_path: str):
        self.config_file_path = config_file_path
        self.raw_config_data: Optional[dict] = self.read_config_file()
        self.setup_logging()

        path_conf = self.raw_config_data.get(self.conf_path, {})
        self.security = Security(**path_conf.get("security", {}))
        self.data_exchange = DataExchange(
            **path_conf.get("data_exchange", {})
        )

    def setup_logging(self):
        """Set up logging configuration."""
        shared_logger.info("Setting up logging")
        logs.setup_logger(
            LoggingConfig(
                **dict(
                    self.log_conf,
                    **self.raw_config_data.get("logging", {})
                )
            )
        )

    def read_config_file(self) -> dict[str, Any]:
        """Read and parse YAML configuration file."""
        shared_logger.info(
            "Reading config file from %s", self.config_file_path
        )
        with open(self.config_file_path, 'r', encoding='utf-8') as file:
            return yaml.safe_load(file)


class ModuleArgsConfig:  # pylint: disable=too-few-public-methods
    """Base class for module argument configuration."""
