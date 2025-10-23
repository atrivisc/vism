import asyncio
import logging
import os
from asyncio import futures, tasks
from asyncio.base_events import _run_until_complete_cb  # type: ignore[attr-defined]

from shared.data.validation import Data
from shared.rabbitmq.consumer import RabbitMQConsumer
from vism_ca.ca.crypto import CryptoModule
from vism_ca.ca.crypto.certificate import Certificate
from vism_ca.config import CAConfig
from vism_ca.ca.db import VismCADatabase, CertificateEntity

ca_logger = logging.getLogger("vism_ca")

class VismCA:
    def __init__(self):
        config_file_path = os.environ.get('CONFIG_FILE_PATH', './config.yaml')
        self.config = CAConfig(config_file_path)

        self.validation_module: Data = self.setup_validation_module()
        self.encryption_module: Data = self.setup_encryption_module()

        self.database = VismCADatabase(self.config.database, self.validation_module)

        self.rabbitmq_consumer = RabbitMQConsumer(self, self.config.raw_config_data)

    async def run(self):
        try:
            await self.init_certificates()
            await self.rabbitmq_consumer.consume_csr()
        except asyncio.CancelledError:
            ca_logger.info("Ca shutting down")

        try:
            await asyncio.Future()
        finally:
            pass

    def setup_encryption_module(self):
        encryption_module_imports = __import__(f'modules.{self.config.security.data_validation.module}', fromlist=['Module', 'ModuleConfig'])
        encryption_module = encryption_module_imports.Module(
            encryption_key=self.config.security.data_encryption.encryption_key,
            validation_key=self.config.security.data_validation.validation_key
        )
        encryption_module.load_config(self.config.raw_config_data)

        return encryption_module

    def setup_validation_module(self):
        validation_module_imports = __import__(f'modules.{self.config.security.data_validation.module}', fromlist=['Module', 'ModuleConfig'])
        validation_module = validation_module_imports.Module(
            encryption_key=self.config.security.data_encryption.encryption_key,
            validation_key=self.config.security.data_validation.validation_key
        )
        validation_module.load_config(self.config.raw_config_data)

        return validation_module

    async def init_certificates(self):
        for certificate in self.config.x509_certificates:
            cert = None
            try:
                cert = Certificate(self, certificate.name)
                cert.create()
            except Exception as e:
                if cert is not None:
                    cert.crypto_module.cleanup(full=True)
                raise
            finally:
                if cert is not None:
                    cert.crypto_module.cleanup(full=True)


def main():
    ca = VismCA()
    loop = asyncio.new_event_loop()
    future = tasks.ensure_future(ca.run(), loop=loop)
    try:
        loop.run_until_complete(future)
    except KeyboardInterrupt:
        pass
    finally:
        if not future.done():
            future.cancel()
        if loop.is_running():
            loop.close()

if __name__ == '__main__':
    main()