# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""Base controller class for VISM components."""

import asyncio
from shared.config import Config, shared_logger
from shared.data.exchange import DataExchange
from shared.data.validation import Data
from shared.db import VismDatabase
from shared.logs import setup_logger, SensitiveDataFilter
from shared.s3 import AsyncS3Client


class Controller:
    """Base controller class for managing modules and configuration."""

    configClass = Config
    databaseClass = VismDatabase

    def __init__(self):
        self.config = self.configClass.load()
        self.setup_logging()
        self.data_exchange_module = self.setup_data_exchange_module()
        self.encryption_module = self.setup_encryption_module()
        self.validation_module = self.setup_validation_module()
        self.database = self.databaseClass(self.config.database, self.validation_module)
        self.s3 = AsyncS3Client(self.config.s3)

        self._shutdown_event = asyncio.Event()

    def __post_init__(self):
        self.setup_logging()

    def setup_logging(self):
        """Set up logging configuration."""
        shared_logger.info("Setting up logging")
        setup_logger(self.config.logging)

    def shutdown(self):
        """Initiates shutdown of the CA."""
        shared_logger.info("Received shutdown signal, shutting down")
        self._shutdown_event.set()

    def setup_data_exchange_module(self) -> DataExchange:
        """Set up the data exchange module from configuration."""
        data_exchange_module_imports = __import__(
            f'modules.{self.config.security.data_exchange.module}',
            fromlist=['Module', 'ModuleConfig']
        )

        SensitiveDataFilter.SENSITIVE_PATTERNS.update(
            data_exchange_module_imports.LOGGING_SENSITIVE_PATTERNS
        )

        return data_exchange_module_imports.Module(self)

    def setup_encryption_module(self) -> Data:
        """Set up the encryption module from configuration."""
        encryption_module_imports = __import__(
            f'modules.{self.config.security.data_encryption.module}',
            fromlist=['Module', 'ModuleConfig']
        )

        SensitiveDataFilter.SENSITIVE_PATTERNS.update(
            encryption_module_imports.LOGGING_SENSITIVE_PATTERNS
        )

        return encryption_module_imports.Module(
            encryption_key=self.config.security.data_encryption.encryption_key,
        )

    def setup_validation_module(self) -> Data:
        """Set up the validation module from configuration."""
        validation_module_imports = __import__(
            f'modules.{self.config.security.data_validation.module}',
            fromlist=['Module', 'ModuleConfig', 'LOGGING_SENSITIVE_PATTERNS']
        )

        SensitiveDataFilter.SENSITIVE_PATTERNS.update(
            validation_module_imports.LOGGING_SENSITIVE_PATTERNS
        )

        return validation_module_imports.Module(
            validation_key=self.config.security.data_validation.validation_key
        )
