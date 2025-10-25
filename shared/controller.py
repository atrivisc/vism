# Licensed under the GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""Base controller class for VISM components."""

import asyncio
from shared.config import Config
from shared.data.exchange import DataExchange
from shared.data.validation import Data


class Controller:
    """Base controller class for managing modules and configuration."""

    config_file_path: str = ""
    configClass = Config

    def __init__(self):
        self.config = self.configClass(self.config_file_path)
        self.data_exchange_module = self.setup_data_exchange_module()
        self.encryption_module = self.setup_encryption_module()
        self.validation_module = self.setup_validation_module()

        self._shutdown_event = asyncio.Event()

    def setup_data_exchange_module(self) -> DataExchange:
        """Set up the data exchange module from configuration."""
        data_exchange_module_imports = __import__(
            f'modules.{self.config.data_exchange.module}',
            fromlist=['Module', 'ModuleConfig']
        )
        data_exchange_module = data_exchange_module_imports.Module(self)

        data_exchange_module.load_config(self.config.raw_config_data)
        return data_exchange_module

    def setup_encryption_module(self) -> Data:
        """Set up the encryption module from configuration."""
        encryption_module_imports = __import__(
            f'modules.{self.config.security.data_encryption.module}',
            fromlist=['Module', 'ModuleConfig']
        )
        encryption_module = encryption_module_imports.Module(
            encryption_key=self.config.security.data_encryption.encryption_key,
        )

        encryption_module.load_config(self.config.raw_config_data)
        return encryption_module

    def setup_validation_module(self) -> Data:
        """Set up the validation module from configuration."""
        validation_module_imports = __import__(
            f'modules.{self.config.security.data_validation.module}',
            fromlist=['Module', 'ModuleConfig']
        )
        validation_module = validation_module_imports.Module(
            validation_key=self.config.security.data_validation.validation_key
        )

        validation_module.load_config(self.config.raw_config_data)
        return validation_module
