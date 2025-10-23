import base64
import logging
from dataclasses import dataclass
from typing import Optional

from vism_ca.ca.crypto import CryptoModule
from vism_ca.ca.db import CertificateEntity
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
    def __init__(self, ca: "VismCA", name: str):
        self.ca = ca

        self.name = name
        self.config: CertificateConfig = self.ca.config.get_cert_config_by_name(self.name)
        self.crypto_module = CryptoModule.load_crypto_module(self.config.module, self.ca)

        self.signing_cert: Optional['Certificate'] = None
        if self.config.signed_by is not None:
            self.signing_cert = Certificate(ca, self.config.signed_by)

        self.db_entity: Optional['CertificateEntity'] = self.ca.database.get_cert_by_name(self.name)

    def create(self) -> CertificateEntity:
        try:
            return self._create()
        except Exception as e:
            self.crypto_module.cleanup(full=True)
            raise
        finally:
            self.crypto_module.cleanup()

    def _create(self) -> 'CertificateEntity':
        logger.info(f"Creating certificate '{self.name}'")

        if self.db_entity:
            logger.warning(f"Certificate '{self.name}' already exists. Skipping create.")
            return self.db_entity

        if self.config.externally_managed:
            logger.info(f"Certificate '{self.name}' is externally managed. Adding data directly to database.")
            if self.config.crl_pem is None or self.config.certificate_pem is None:
                response = f"Externally managed certificate '{self.name}' must have certificate and crl pem defined in the config."
                logger.error(response)
                raise GenCertException(response)

            cert_entity = CertificateEntity(
                name=self.name,
                crt_pem=self.config.certificate_pem,
                crl_pem=self.config.crl_pem,
                externally_managed=self.config.externally_managed,
            )
            cert_entity = self.ca.database.save_to_db(cert_entity)
            return cert_entity

        unencrypted_private_key, public_key_pem = self.crypto_module.generate_private_key(self.config)
        csr_pem = self.crypto_module.generate_csr(self.config, unencrypted_private_key)

        if self.signing_cert is not None:
            if self.signing_cert.config.externally_managed and self.config.externally_managed is None and self.config.crl_pem is None:
                raise GenCertException(f"Signing certificate '{self.signing_cert.name}' is externally managed. Please sign '{self.name}' certificate manually.")

            if self.signing_cert.db_entity is None:
                raise GenCertException(f"Signing certificate '{self.signing_cert.name}' not found in database.")

            signing_private_key_encrypted = self.signing_cert.db_entity.pkey_pem
            signing_private_key_decrypted = self.ca.encryption_module.decrypt(signing_private_key_encrypted).decode("utf-8")

            crt_pem = self.signing_cert.crypto_module.sign_ca_certificate(
                self.config,
                self.signing_cert.config,
                self.signing_cert.db_entity.crt_pem,
                signing_private_key_decrypted,
                csr_pem
            )
            del signing_private_key_decrypted
            del signing_private_key_encrypted
        else:
            crt_pem = self.crypto_module.generate_ca_certificate(self.config, unencrypted_private_key, csr_pem)

        crl_pem = self.crypto_module.generate_crl(self.config, unencrypted_private_key, crt_pem)
        private_key_pem_encrypted = self.ca.encryption_module.encrypt(unencrypted_private_key)
        private_key_pem = base64.urlsafe_b64encode(private_key_pem_encrypted).decode("utf-8")
        db_entity = CertificateEntity(
            name=self.name,
            crt_pem=crt_pem,
            csr_pem=csr_pem,
            pkey_pem=private_key_pem,
            pubkey_pem=public_key_pem,
            crl_pem=crl_pem,
            externally_managed=self.config.externally_managed,
            module=self.config.module,
        )
        db_entity = self.ca.database.save_to_db(db_entity)
        return db_entity
