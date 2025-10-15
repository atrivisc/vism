import logging
import logging.config
import sys
from argparse import Namespace
from typing import Optional
from vism_ca.config import Config, CertificateConfig
from vism_ca.crypto import Crypto
from vism_ca.db import VismDatabase, Certificate
from vism_ca.util import aes256_encrypt, aes256_decrypt
from vism_ca.util.logs import setup_logger, SensitiveDataFilter

logger = logging.getLogger("vism_ca")

class VismCA:
    def __init__(self, cli_args: Namespace):
        self.cli_args = cli_args
        self.config: Config = self.load_config()
        self.database = VismDatabase(self.config.database)

        setup_logger(self.config.logging.level, self.cli_args.verbose)

    def get_crypto_module(self, cert_config: CertificateConfig) -> Crypto:
        logging.debug(f"Loading crypto module {cert_config.module} for '{cert_config.name}'.")
        crypto_module_imports = __import__(f'modules.{cert_config.module}', fromlist=['Module', 'ModuleConfig', 'ModuleData', 'LOGGING_SENSITIVE_PATTERNS'])
        crypto_module = crypto_module_imports.Module(self.config.security.chroot_base_dir)
        crypto_module.load_config(self.config.raw_config_data)
        crypto_module.create_chroot_environment()

        SensitiveDataFilter.SENSITIVE_PATTERNS.update(crypto_module_imports.LOGGING_SENSITIVE_PATTERNS)
        self.database.create_module_tables(crypto_module_imports.ModuleData)

        return crypto_module

    def create_certificates(self, certificate_names: list[str]) -> None:
        for certificate_name in certificate_names:
            self.create_certificate(certificate_name)

    def _get_certificate_config(self, certificate_name: str) -> Optional[CertificateConfig]:
        cert_configs = list(filter(lambda conf: conf.name == certificate_name, self.config.x509_certificates))
        if not cert_configs:
            return logger.error(f"Certificate with name {certificate_name} not found in config.")
        if len(cert_configs) > 1:
            return logger.error(f"Multiple certificates found with the name: {certificate_name}")

        return cert_configs[0]

    def create_certificate(self, certificate_name: str) -> Optional[Certificate]:
        cert_config = self._get_certificate_config(certificate_name)
        logging.info(f"Creating certificate '{cert_config.name}'")
        cert = Certificate.get_by_name(cert_config.name)
        if cert:
            return logging.warn(f"Certificate '{cert_config.name}' already exists. Skipping.")

        cert = Certificate(name=cert_config.name, externally_managed=cert_config.externally_managed, module=cert_config.module)
        if cert.externally_managed:
            logging.info(f"Certificate '{cert_config.name}' is externally managed. Adding data directly to database.")
            cert.certificate_pem = cert_config.certificate_pem
            cert.crl_pem = cert_config.crl_pem
            cert.save_to_db()
        else:
            crypto_module = self.get_crypto_module(cert_config)
            logging.info(f"Generating certificate '{cert_config.name}'")
            unencrypted_private_key, cert.public_key_pem = crypto_module.generate_private_key(cert_config)
            cert.csr_pem = crypto_module.generate_csr(cert_config, unencrypted_private_key)

            if cert_config.signed_by is not None:
                signing_cert_config = self._get_certificate_config(cert_config.signed_by)
                if signing_cert_config.externally_managed:
                    return logging.error(f"Signing certificate '{signing_cert_config.name}' is externally managed. Please sign the certificate manually.")

                signing_cert = Certificate.get_by_name(signing_cert_config.name)

                if not signing_cert:
                    return logging.error(f"Signing certificate '{signing_cert_config.name}' not found in database.")

                signing_private_key_encrypted = signing_cert.private_key_pem
                if self.config.security.data_encryption.enabled:
                    signing_private_key_decrypted = aes256_decrypt(signing_private_key_encrypted, self.config.security.data_encryption.password)
                else:
                    signing_private_key_decrypted = signing_private_key_encrypted

                cert.certificate_pem = crypto_module.sign_ca_certificate(
                    cert_config,
                    signing_cert_config,
                    signing_cert.certificate_pem,
                    signing_private_key_decrypted,
                    cert.csr_pem
                )
                del signing_private_key_decrypted
                del signing_private_key_encrypted
            else:
                cert.certificate_pem = crypto_module.generate_ca_certificate(cert_config, unencrypted_private_key, cert.csr_pem)

            cert.crl_pem = crypto_module.generate_crl(cert_config, unencrypted_private_key, cert.certificate_pem)

            if self.config.security.data_encryption.enabled:
                logging.info(f"Encrypting private key for '{cert_config.name}' with aes256.")
                cert.private_key_pem = aes256_encrypt(unencrypted_private_key, self.config.security.data_encryption.password)
            else:
                cert.private_key_pem = unencrypted_private_key

            del unencrypted_private_key

            cert.save_to_db()

        return cert

    def ca_status(self) -> dict:
        logging.debug(f"Generating status for all certificates")
        certificates = {}
        for cert_config in self.config.x509_certificates:
            certificates[cert_config.name] = {}
            cert = Certificate.get_by_name(name=cert_config.name)
            if not cert:
                certificates[cert_config.name]['status'] = 'not_created'
            else:
                certificates[cert_config.name]['status'] = 'created'

        return certificates

    def load_config(self) -> Config:
        logging.debug(f"Loading configuration from {self.cli_args.config}.")
        return Config(self.cli_args.config)

