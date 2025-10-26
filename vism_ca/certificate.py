# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html

"""
This module provides an abstraction layer for managing certificates within the Vism CA
controller. It handles certificate issuance, signing, and revocation functionalities,
making it easier to interface with the crypto module, CA database, and other components.

Classes:
    Certificate: Represents a certificate and provides methods for operations such as
                 generating, signing, and managing CRLs.
"""

import base64
from typing import Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from shared.config import ModuleArgsConfig
from shared.errors import VismException, VismBreakingException
from vism_ca import CryptoModule, ca_logger, CertificateEntity
from vism_ca.errors import GenCertException, GenCRLException


class Certificate:
    """
    Represents a certificate and provides methods for operations such as
    generating, signing, and managing CRLs.
    """

    def __init__(self, ca, name: str):
        self.ca = ca

        self.name = name
        self.config = self.ca.config.get_cert_config_by_name(self.name)
        self.crypto_module = CryptoModule.load_crypto_module(
            self.config.module, self.ca
        )

        self.signing_cert: Optional['Certificate'] = None
        if self.config.signed_by is not None:
            self.signing_cert = Certificate(ca, self.config.signed_by)

        self.db_entity: Optional['CertificateEntity'] = (
            self.ca.database.get_cert_by_name(self.name)
        )

        if self.db_entity is not None:
            self.cryptoCert = self.crypto_module.cryptoCertClass.from_cert_entity(self.db_entity)
            self.cryptoCert.config = self.config
        else:
            self.cryptoCert = self.crypto_module.cryptoCertClass(config=self.config)

    def update_crl(self):
        """Update CRL for certificate."""
        if self.db_entity is None:
            raise GenCertException(
                f"Certificate '{self.name}' not found in database."
            )

        if self.config.externally_managed:
            raise GenCRLException(
                f"Certificate '{self.name}' is externally managed. "
                f"CRL cannot be updated."
            )

        encrypted_private_key_b64u = self.db_entity.pkey_pem
        encrypted_private_key = base64.urlsafe_b64decode(
            encrypted_private_key_b64u
        )
        private_key = self.ca.encryption_module.decrypt(
            encrypted_private_key
        ).decode("utf-8")

        try:
            crl_pem = self.crypto_module.generate_crl(
                self.config, private_key, self.db_entity.crt_pem
            )
        finally:
            del private_key

        self.db_entity.crl_pem = crl_pem
        self.db_entity = self.ca.database.save_to_db(self.db_entity)

    def sign_csr(
        self, csr_pem: str, module_args_dict: dict, acme: bool = False
    ) -> str:
        """Sign a CSR and return the certificate with chain."""
        csr = x509.load_pem_x509_csr(
            data=csr_pem.encode("utf-8"), backend=default_backend()
        )

        if isinstance(csr.public_key(), rsa.RSAPublicKey):
            if csr.public_key().key_size < 2048:
                raise VismException(
                    f"RSA key size must be at least 2048 bits, "
                    f"got {csr.public_key().key_size}"
                )

        if not csr.is_signature_valid:
            raise VismException("Invalid CSR signature.")

        if self.db_entity is None:
            raise VismException(
                f"Certificate '{self.name}' not found in database."
            )

        encrypted_signing_key_pem_b64 = str(self.db_entity.pkey_pem)
        encrypted_signing_key_pem = base64.urlsafe_b64decode(
            encrypted_signing_key_pem_b64
        )
        unencrypted_key = self.ca.encryption_module.decrypt(
            encrypted_signing_key_pem
        ).decode("utf-8")
        self.cryptoCert.key_pem = unencrypted_key

        module_args: ModuleArgsConfig = (
            self.crypto_module.moduleArgsClass(**module_args_dict)
        )

        crypto_cert = self.crypto_module.cryptoCertClass(csr_pem=csr_pem)
        crypto_cert = self.crypto_module.sign_csr(crypto_cert, self.cryptoCert, module_args)
        chain = self.get_chain(acme)

        del unencrypted_key
        self.cryptoCert.key_pem = self.db_entity.pkey_pem

        return f"{crypto_cert.crt_pem}\n{chain}"

    def get_chain(self, acme: bool = False) -> str:
        """Recursively get chain of certificates."""
        if self.db_entity is None:
            return ""

        if self.signing_cert is not None:
            chain = self.db_entity.crt_pem + self.signing_cert.get_chain(acme)
        else:
            chain = self.db_entity.crt_pem if not acme else ""

        return chain

    def create(self) -> 'CertificateEntity':
        """Create certificate."""
        ca_logger.info("Creating certificate '%s'", self.name)

        if self.db_entity:
            ca_logger.info(
                "Certificate '%s' already exists. Skipping create.", self.name
            )
            return self.db_entity

        if self.config.externally_managed:
            ca_logger.info(
                "Certificate '%s' is externally managed. "
                "Adding data directly to database.",
                self.name
            )
            if self.config.crl_pem is None or self.config.certificate_pem is None:
                raise VismBreakingException(
                    f"Externally managed certificate '{self.name}' "
                    f"must have certificate and crl pem defined in the config."
                )

            cert_entity = CertificateEntity(
                name=self.name,
                crt_pem=self.config.certificate_pem,
                crl_pem=self.config.crl_pem,
                externally_managed=self.config.externally_managed,
            )
            cert_entity = self.ca.database.save_to_db(cert_entity)
            return cert_entity

        self.cryptoCert = self.crypto_module.generate_private_key(self.cryptoCert)

        try:
            self.cryptoCert = self.crypto_module.generate_csr(self.cryptoCert)
        except:
            self.crypto_module.cleanup(full=True)
            del self.cryptoCert
            raise

        if self.signing_cert is not None:
            if self.signing_cert.config.externally_managed and (self.config.certificate_pem is None or self.config.crl_pem is None):
                del self.cryptoCert
                raise VismBreakingException(
                    f"Signing certificate '{self.signing_cert.name}' "
                    f"is externally managed. "
                    f"Please sign '{self.name}' certificate manually."
                )

            if self.signing_cert.db_entity is None:
                del self.cryptoCert
                raise VismBreakingException(
                    f"Signing certificate '{self.signing_cert.name}' "
                    f"not found in database."
                )

            signing_pkey_encrypted_b64 = self.signing_cert.db_entity.pkey_pem
            signing_pkey_encrypted = base64.urlsafe_b64decode(signing_pkey_encrypted_b64)
            signing_pkey_decrypted = self.ca.encryption_module.decrypt(
                signing_pkey_encrypted
            ).decode("utf-8")

            self.signing_cert.cryptoCert.key_pem = signing_pkey_decrypted

            try:
                self.cryptoCert = self.signing_cert.crypto_module.sign_ca_certificate(self.cryptoCert, self.signing_cert.cryptoCert)
            except:
                self.crypto_module.cleanup(full=True)
                del self.cryptoCert
                raise
            finally:
                del signing_pkey_encrypted
                del signing_pkey_decrypted
                del self.signing_cert.cryptoCert
        else:
            try:
                self.cryptoCert = self.crypto_module.generate_ca_certificate(self.cryptoCert)
            except:
                self.crypto_module.cleanup(full=True)
                del self.cryptoCert
                raise

        try:
            self.cryptoCert = self.crypto_module.generate_crl(self.cryptoCert)
        except:
            self.crypto_module.cleanup(full=True)
            del self.cryptoCert
            raise

        cert_entity = self.cryptoCert.to_cert_entity()
        private_key_pem_encrypted = self.ca.encryption_module.encrypt(self.cryptoCert.key_pem.encode("utf-8"))
        private_key_pem_encrypted_b64u = base64.urlsafe_b64encode(private_key_pem_encrypted).decode("utf-8")
        cert_entity.pkey_pem = private_key_pem_encrypted_b64u

        cert_entity = self.ca.database.save_to_db(cert_entity)
        return cert_entity
