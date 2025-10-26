# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""Main Vism CA class and entrypoint."""

import asyncio
import logging
from random import randint
import aiocron
from shared.controller import Controller
from shared.errors import VismBreakingException, VismException
from vism_ca import VismCADatabase, CAConfig, Certificate

ca_logger = logging.getLogger("vism")

class VismCA(Controller):
    """
    Handles the operations and configuration for a CA within the Vism framework.

    Provides functionality to initialize and manage certificates, update Certificate Revocation
    Lists (CRLs), and handle shutdown. The class integrates configuration and database
    models specific to the CA and allows periodic or event-driven tasks related to CA operation.

    :ivar databaseClass: The database class to be used for CA operations.
    :type databaseClass: Type[Database]
    :ivar configClass: The configuration class for the CA.
    :type configClass: Type[Config]
    """

    databaseClass = VismCADatabase
    configClass = CAConfig
    config: CAConfig

    @aiocron.crontab(f'{randint(0, 60)} {randint(0, 23)} * * *')
    async def _update_crl(self):
        """Periodically updates CRLs for all certificates managed by the CA."""
        ca_logger.info("Updating CRLs for internally managed certificates")
        for cert_config in self.config.x509_certificates:
            if cert_config.externally_managed:
                continue

            cert = Certificate(self, cert_config.name)
            cert.update_crl()

    async def run(self):
        """Entrypoint for the CA. Initializes and manages the CA lifecycle."""
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
        except VismException as e:
            ca_logger.exception("Failed to cleanup data exchange module during shutdown: %s", e)

    async def init_certificates(self):
        """Creates and manages certificates for the CA."""
        ca_logger.info("Creating CA certificates")
        for cert_config in self.config.x509_certificates:
            cert = None
            try:
                cert = Certificate(self, cert_config.name)
                cert.create()
                ca_logger.info("Created CA certificate '%s'", cert_config.name)
            except Exception as e:
                if cert is not None:
                    cert.crypto_module.cleanup(full=True)
                raise VismBreakingException(
                    f"Failed to create CA certificate '{cert_config.name}': {e}"
                ) from e
            finally:
                if cert is not None:
                    cert.crypto_module.cleanup(full=True)
        ca_logger.info("CA certificates created")

def main():
    """Async entrypoint for the CA."""
    ca = VismCA()
    try:
        asyncio.run(ca.run())
    except KeyboardInterrupt:
        ca.shutdown()

if __name__ == '__main__':
    main()
