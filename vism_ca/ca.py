import asyncio
import logging
import os
import aiocron
from random import randint
from shared.controller import Controller
from shared.errors import VismBreakingException
from vism_ca import VismCADatabase, CAConfig, Certificate

ca_logger = logging.getLogger("vism_ca")

class VismCA(Controller):
    databaseClass = VismCADatabase
    configClass = CAConfig
    config_file_path = os.environ.get('CONFIG_FILE_PATH', './config.yaml')
    config: CAConfig = None

    def __init__(self):
        super().__init__()
        self.database = self.databaseClass(self.config.database, self.validation_module)

    def shutdown(self):
        ca_logger.info("Received shutdown signal, shutting down")
        self._shutdown_event.set()

    @aiocron.crontab(f'{randint(0, 60)} {randint(0, 23)} * * *')
    async def _update_crl(self):
        ca_logger.info("Updating CRLs for internally managed certificates")
        for cert_config in self.config.x509_certificates:
            if cert_config.externally_managed:
                continue

            cert = Certificate(self, cert_config.name)
            cert.update_crl()

    async def run(self):
        ca_logger.info("Starting CA")
        try:
            await self.init_certificates()
            await self.data_exchange_module.receive_csr()
            await self._shutdown_event.wait()
        except asyncio.CancelledError:
            ca_logger.info("CA shutting down")

        try:
            await asyncio.shield(self.data_exchange_module.cleanup(full=True))
            self.encryption_module.cleanup(full=True)
            self.validation_module.cleanup(full=True)
        except Exception as e:
            ca_logger.exception(f"Failed to cleanup data exchange module during shutdown: {e}")

    async def init_certificates(self):
        ca_logger.info("Creating CA certificates")
        for cert_config in self.config.x509_certificates:
            cert = None
            try:
                cert = Certificate(self, cert_config.name)
                cert.create()
            except Exception as e:
                if cert is not None:
                    cert.crypto_module.cleanup(full=True)
                raise VismBreakingException(f"Failed to create CA certificate '{cert_config.name}': {e}")
            finally:
                ca_logger.info(f"Created CA certificate '{cert_config.name}'")
                if cert is not None:
                    cert.crypto_module.cleanup(full=True)
        ca_logger.info("CA certificates created")

def main():
    ca = VismCA()
    try:
        asyncio.run(ca.run())
    except KeyboardInterrupt:
        ca.shutdown()

if __name__ == '__main__':
    main()