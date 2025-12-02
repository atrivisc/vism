# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""Main Vism CA class and entrypoint."""

import asyncio
import logging
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

    async def update_crl(self):
        """Updates CRLs for all certificates managed by the CA."""
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
            ca_logger.info("CA shutting down.")
        except Exception as e:
            ca_logger.critical(f"CA encountered a fatal error: {e}")
            raise e
        finally:
            self.encryption_module.cleanup(full=True)
            self.validation_module.cleanup(full=True)
            await asyncio.shield(self.data_exchange_module.cleanup(full=True))

    async def init_certificates(self):
        """Creates and manages certificates for the CA."""
        ca_logger.info("Creating CA certificates")
        for cert_config in self.config.x509_certificates:
            cert = None
            try:
                cert = Certificate(self, cert_config.name)
                cert.create()
                ca_logger.info("Created CA certificate '%s'", cert_config.name)
                cert.cleanup()
            except Exception as e:
                if cert is not None:
                    cert.cleanup()
                raise VismBreakingException(
                    f"Failed to create CA certificate '{cert_config.name}': {e}"
                ) from e
        ca_logger.info("CA certificates created")

def main(function: str = None):
    """Async entrypoint for the CA."""
    ca = VismCA()
    try:
        if function is None:
            asyncio.run(ca.run())
        if function == "update_crl":
            asyncio.run(ca.update_crl())
    except KeyboardInterrupt:
        ca.shutdown()

if __name__ == '__main__':
    main()
