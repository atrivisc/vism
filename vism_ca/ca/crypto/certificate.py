import base64
import logging
from dataclasses import dataclass
from typing import Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from shared.config import ModuleArgsConfig
from shared.errors import VismException
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

    def sign_csr(self, csr_pem: str, module_args_dict: dict, acme: bool = False) -> str:
        csr = x509.load_pem_x509_csr(data=csr_pem.encode("utf-8"), backend=default_backend())

        if isinstance(csr.public_key(), rsa.RSAPublicKey):
            if csr.public_key().key_size < 2048:
                raise VismException(f"RSA key size must be at least 2048 bits, got {csr.public_key().key_size}")

        if not csr.is_signature_valid:
            raise VismException("Invalid CSR signature.")

        signing_crt_pem = self.db_entity.crt_pem
        encrypted_signing_key_pem_b64 = self.db_entity.pkey_pem
        encrypted_signing_key_pem = base64.urlsafe_b64decode(encrypted_signing_key_pem_b64)
        unencrypted_key = self.ca.encryption_module.decrypt(encrypted_signing_key_pem).decode("utf-8")

        module_args: ModuleArgsConfig = self.crypto_module.moduleArgsClass(**module_args_dict)

        cert = self.crypto_module.sign_csr(self.config, signing_crt_pem, unencrypted_key, csr_pem, module_args)
        chain = self.get_chain(acme)

        return f"{cert}\n{chain}"

    def get_chain(self, acme: bool = False) -> str:
        if self.signing_cert is not None:
            chain = (self.db_entity.crt_pem + self.signing_cert.get_chain(acme))
        else:
            chain = self.db_entity.crt_pem if not acme else ""

        return chain

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
            signing_private_key_decrypted = self.ca.encryption_module.decrypt(signing_private_key_encrypted.encode("utf-8")).decode("utf-8")

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
        private_key_pem_encrypted = self.ca.encryption_module.encrypt(unencrypted_private_key.encode("utf-8"))
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
