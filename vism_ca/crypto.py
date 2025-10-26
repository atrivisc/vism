# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html

"""
Cryptography module for Vism CA.

This module provides the base classes and interfaces for cryptographic operations
including key generation, CSR creation, certificate signing, and CRL generation.
"""

from dataclasses import dataclass
from typing import Self

from shared.chroot import Chroot
from shared.config import ModuleArgsConfig, Config
from shared.logs import SensitiveDataFilter
from vism_ca import CertificateConfig, ca_logger, CertificateEntity


@dataclass
class CryptoConfig(Config):
    """Base configuration class for crypto modules."""

@dataclass
class CryptoCert:
    """Data class for crypto module data."""

    crt_pem: str = None
    key_pem: str = None
    pub_key_pem: str = None
    csr_pem: str = None
    crl_pem: str = None
    config: 'CertificateConfig' = None

    def to_cert_entity(self):
        """Populate data from CryptoCert."""
        return CertificateEntity(
            name=self.config.name,
            crt_pem=self.crt_pem,
            csr_pem=self.csr_pem,
            pkey_pem=self.key_pem,
            pubkey_pem=self.pub_key_pem,
            crl_pem=self.crl_pem,
            externally_managed=self.config.externally_managed,
        )

    @classmethod
    def from_cert_entity(cls, cert_entity: CertificateEntity) -> Self:
        """Populate data from CertificateEntity."""
        return cls(
            crt_pem=cert_entity.crt_pem,
            key_pem=cert_entity.pkey_pem,
            pub_key_pem=cert_entity.pubkey_pem,
            csr_pem=cert_entity.csr_pem,
            crl_pem=cert_entity.crl_pem,
        )


class CryptoModule:
    """
    Base class for cryptographic modules.

    Provides interfaces for certificate operations including key generation,
    CSR creation, certificate signing, and CRL management.
    """

    configClass = CryptoConfig
    cryptoCertClass = CryptoCert
    moduleArgsClass = ModuleArgsConfig

    def __init__(self, chroot_dir: str):
        self.chroot = Chroot(chroot_dir)
        self.config = self.configClass.load()

    def cleanup(self, full: bool = False):
        """Clean up temporary files and resources."""
        raise NotImplementedError()

    def create_chroot_environment(self) -> None:
        """Create and configure the chroot environment."""
        raise NotImplementedError()

    def generate_private_key(self, cert: CryptoCert) -> CryptoCert:
        """Generate a private key and return private and public key PEMs."""
        raise NotImplementedError()

    def generate_csr(self, cert: CryptoCert) -> CryptoCert:
        """Generate a Certificate Signing Request."""
        raise NotImplementedError()

    def generate_ca_certificate(self, cert: CryptoCert) -> CryptoCert:
        """Generate a CA certificate."""
        raise NotImplementedError()

    def generate_crl(self, cert: CryptoCert) -> CryptoCert:
        """Generate a Certificate Revocation List."""
        raise NotImplementedError()

    def sign_ca_certificate(
        self,
        cert: CryptoCert,
        signing_cert: CryptoCert,
    ) -> CryptoCert:
        """
        Sign a CA certificate with another CA certificate.

        Args:
            cert: Configuration for the to be signed certificate
            signing_cert: Configuration for the signing certificate

        Returns:
            str: PEM of the signed certificate
        """

    def sign_csr(
        self,
        cert: CryptoCert,
        signing_cert: CryptoCert,
        module_args: ModuleArgsConfig
    ) -> CryptoCert:
        """
        Sign a Certificate Signing Request.

        Args:
            cert: Configuration for the to be signed certificate
            signing_cert: Configuration for the signing certificate
            module_args: Module-specific arguments for signing

        Returns:
            str: PEM of the signed certificate
        """

    @classmethod
    def load_crypto_module(cls, module_name: str, ca) -> 'Self':
        """
        Load and initialize a crypto module by name.

        Args:
            module_name: Name of the module to load
            ca: VismCA instance

        Returns:
            CryptoModule: Initialized crypto module instance
        """
        ca_logger.debug(
            "Loading crypto module %s for '%s'.", module_name, module_name
        )
        crypto_module_imports = CryptoModule.get_crypto_module_imports(
            module_name
        )
        crypto_module = crypto_module_imports.Module(
            ca.config.security.chroot_base_dir, ca.database
        )
        crypto_module.create_chroot_environment()

        SensitiveDataFilter.SENSITIVE_PATTERNS.update(
            crypto_module_imports.LOGGING_SENSITIVE_PATTERNS
        )

        return crypto_module

    @classmethod
    def get_crypto_module_imports(cls, module_name: str):
        """
        Import and return crypto module components.

        Args:
            module_name: Name of the module to import

        Returns:
            Module with Module, ModuleConfig, ModuleData, and
            LOGGING_SENSITIVE_PATTERNS
        """
        return __import__(
            f'modules.{module_name}',
            fromlist=[
                'Module',
                'ModuleConfig',
                'ModuleData',
                'LOGGING_SENSITIVE_PATTERNS'
            ]
        )
