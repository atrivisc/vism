import logging
from dataclasses import dataclass
from typing import Optional

from vism.util import aes256_decrypt, aes256_encrypt
from vism_ca.ca import CertificateEntry, CryptoModule, VismCA
from vism_ca.config import CertificateConfig
from vism_ca.errors import GenCertException

logger = logging.getLogger(__name__)

@dataclass
class CertificateData:
    name: str
    crt_pem: str
    crl_pem: str = None

    def __dict__(self):
        return {
            "name": self.name,
            "crt_pem": self.crt_pem,
            "crl_pem": self.crl_pem
        }

class Certificate:
    def __init__(self, ca: VismCA, name: str):
        self.ca = ca

        self.name = name
        self.config: CertificateConfig = self.ca.config.get_cert_config_by_name(self.name)
        self.crypto_module = CryptoModule.load_crypto_module(self.config.module, self.ca)

        self.signing_cert: Optional['Certificate'] = None
        if self.config.signed_by is not None:
            self.signing_cert = Certificate(ca, self.config.signed_by)

        self.db_entry: Optional['CertificateEntry'] = self.ca.database.get_cert_by_name(self.name)

    def create(self) -> CertificateData:
        try:
            return self._create()
        finally:
            self.crypto_module.cleanup(full=True)

    def _create(self) -> 'CertificateData':
        logger.info(f"Creating certificate '{self.name}'")

        if self.db_entry:
            logger.warning(f"Certificate '{self.name}' already exists. Skipping.")
            return CertificateData(
                name=self.name,
                crt_pem=self.db_entry.crt_pem,
                crl_pem=self.db_entry.crl_pem
            )

        if self.config.externally_managed:
            logger.info(f"Certificate '{self.name}' is externally managed. Adding data directly to database.")
            if self.config.crl_pem is None or self.config.certificate_pem is None:
                response = f"Externally managed certificate '{self.name}' must have certificate and crl pem defined in the config."
                logger.error(response)
                raise GenCertException(response)

            cert_data = CertificateData(
                name=self.name,
                crt_pem=self.config.certificate_pem,
                crl_pem=self.config.crl_pem
            )
            self.ca.database.save_to_db(CertificateEntry(name=cert_data.name, crt_pem=cert_data.crt_pem, crl_pem=cert_data.crl_pem))
            return cert_data

        unencrypted_private_key, public_key_pem = self.crypto_module.generate_private_key(self.config)
        csr_pem = self.crypto_module.generate_csr(self.config, unencrypted_private_key)

        if self.signing_cert is not None:
            if self.signing_cert.config.externally_managed and self.config.externally_managed is None and self.config.crl_pem is None:
                raise GenCertException(f"Signing certificate '{self.signing_cert.name}' is externally managed. Please sign '{self.name}' certificate manually.")

            if self.signing_cert.db_entry is None:
                raise GenCertException(f"Signing certificate '{self.signing_cert.name}' not found in database.")

            signing_private_key_encrypted = self.signing_cert.db_entry.pkey_pem
            if self.ca.config.security.data_encryption.enabled:
                signing_private_key_decrypted = aes256_decrypt(signing_private_key_encrypted, self.ca.config.security.data_encryption.password)
            else:
                signing_private_key_decrypted = signing_private_key_encrypted

            crt_pem = self.signing_cert.crypto_module.sign_ca_certificate(
                self.config,
                self.signing_cert.config,
                self.signing_cert.db_entry.crt_pem,
                signing_private_key_decrypted,
                csr_pem
            )
            del signing_private_key_decrypted
            del signing_private_key_encrypted
        else:
            crt_pem = self.crypto_module.generate_ca_certificate(self.config, unencrypted_private_key, csr_pem)

        crl_pem = self.crypto_module.generate_crl(self.config, unencrypted_private_key, crt_pem)

        if self.ca.config.security.data_encryption.enabled:
            logging.info(f"Encrypting private key for '{self.name}' with aes256.")
            private_key_pem = aes256_encrypt(unencrypted_private_key, self.ca.config.security.data_encryption.password)
        else:
            private_key_pem = unencrypted_private_key

        db_entry = CertificateEntry(
            name=self.name,
            crt_pem=crt_pem,
            csr_pem=csr_pem,
            pkey_pem=private_key_pem,
            pubkey_pem=public_key_pem,
            crl_pem=crl_pem,
            externally_managed=self.config.externally_managed,
            module=self.config.module,
        )
        self.ca.database.save_to_db(db_entry)

        return CertificateData(
            name=self.name,
            crt_pem=crt_pem,
            crl_pem=crl_pem
        )