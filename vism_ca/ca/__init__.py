import logging
import logging.config
import os
from typing import Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from vism.util import aes256_decrypt, aes256_encrypt
from vism.util.errors import VismException
from vism_ca.ca.crypto import CryptoModule
from vism_ca.errors import CertConfigNotFound
from vism_ca.logs import setup_logger
from vism_ca.config import CAConfig
from vism_ca.ca.db import VismDatabase, CertificateEntry

logger = logging.getLogger("vism_ca")

class VismCA:
    def __init__(self):
        config_file_path = os.environ.get('CONFIG_FILE_PATH', './config.yaml' )
        self.config = CAConfig(config_file_path)
        self.database = VismDatabase(self.config.database)
        setup_logger()

    def sign_csr(self, csr_path: str, ca_cert_name: str, module_args: dict[str, str]):
        csr_pem = None
        try:
            with open(csr_path, 'r') as csr_file:
                csr_pem = csr_file.read()
        except Exception as e:
            logger.error(f"Error reading csr file '{csr_path}': {e}")

        if not csr_pem:
            return logger.error(f"CSR file '{csr_path}' is empty.")

        try:
            x509.load_pem_x509_csr(csr_pem.encode(), backend=default_backend())
        except Exception as e:
            return logger.error(f"Error loading csr file '{csr_path}': {e}")

        ca_cert_config = self._get_certificate_config(ca_cert_name)
        if not ca_cert_config:
            return logger.error(f"Certificate '{ca_cert_name}' not found in config.")

        ca_crypto_module = self._get_crypto_module_by_name(ca_cert_config.module)
        crypto_module_imports = __import__(f'modules.{ca_cert_config.module}', fromlist=['ModuleArgsConfig'])
        module_args = crypto_module_imports.ModuleArgsConfig(**module_args)

        signing_cert = CertificateEntry.get_by_name(ca_cert_config.name)
        if not signing_cert:
            return logger.error(f"Signing certificate '{ca_cert_config.name}' not found in database.")

        if not signing_cert.private_key_pem:
            return logger.error(f"Signing certificate '{ca_cert_config.name}' has no private key.")

        if not signing_cert.certificate_pem:
            return logger.error(f"Signing certificate '{ca_cert_config.name}' has no certificate.")

        if self.config.security.data_encryption.enabled:
            unencrypted_private_key = aes256_decrypt(signing_cert.private_key_pem, self.config.security.data_encryption.password)
        else:
            unencrypted_private_key = signing_cert.private_key_pem

        crt_pem = ca_crypto_module.sign_csr(ca_cert_config, signing_cert.certificate_pem, unencrypted_private_key, csr_pem, module_args)
        ca_crypto_module.cleanup(full=True)

        return crt_pem
