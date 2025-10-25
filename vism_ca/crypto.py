# Licensed under the GPL 3: https://www.gnu.org/licenses/gpl-3.0.html

"""
Cryptography module for Vism CA.

This module provides the base classes and interfaces for cryptographic operations
including key generation, CSR creation, certificate signing, and CRL generation.
"""

from dataclasses import dataclass
from typing import Optional
from shared.chroot import Chroot
from shared.config import ModuleArgsConfig
from shared.logs import SensitiveDataFilter
from vism_ca import CertificateConfig, ca_logger, CertificateEntity


@dataclass
class CryptoConfig:
    """Base configuration class for crypto modules."""

@dataclass
class CryptoCert:
    """Data class for crypto module data."""

    crt_pem: str = None
    key_pem: str = None
    csr_pem: str = None
    crl_pem: str = None

    @classmethod
    def from_cert_entity(cls, cert_entity: CertificateEntity):
        """Populate data from CertificateEntity."""
        return CryptoCert(
            crt_pem=cert_entity.crt_pem,
            key_pem=cert_entity.pkey_pem,
            csr_pem=cert_entity.csr_pem,
            crl_pem=cert_entity.crl_pem,
        )


class CryptoModule:
    """
    Base class for cryptographic modules.

    Provides interfaces for certificate operations including key generation,
    CSR creation, certificate signing, and CRL management.
    """

    config_path: str = ""
    configClass = CryptoConfig
    moduleArgsClass = ModuleArgsConfig

    def __init__(self, chroot_dir: str):
        self.chroot = Chroot(chroot_dir)
        self.config: Optional[CryptoConfig] = None

    def load_config(self, config_data: dict) -> None:
        """Load configuration from config data dictionary."""
        self.config = self.configClass(**config_data.get(self.config_path, {}))

    def cleanup(self, full: bool = False):
        """Clean up temporary files and resources."""
        raise NotImplementedError()

    def generate_private_key(
        self, cert_config: CertificateConfig
    ) -> tuple[str, str]:
        """Generate a private key and return private and public key PEMs."""
        raise NotImplementedError()

    def generate_csr(
        self, cert_config: CertificateConfig, key_pem: str
    ) -> str:
        """Generate a Certificate Signing Request."""
        raise NotImplementedError()

    def create_chroot_environment(self) -> None:
        """Create and configure the chroot environment."""
        raise NotImplementedError()

    def generate_ca_certificate(
        self, cert_config: CertificateConfig, key_pem: str, csr_pem: str
    ) -> str:
        """Generate a CA certificate."""
        raise NotImplementedError()

    def generate_crl(
        self, cert_config: CertificateConfig, key_pem: str, crt_pem: str
    ):
        """Generate a Certificate Revocation List."""
        raise NotImplementedError()

    def sign_ca_certificate( # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        cert_config: CertificateConfig,
        signing_cert_config: CertificateConfig,
        signing_crt_pem: str,
        signing_key_pem: str,
        csr_pem: str
    ) -> str:
        """
        Sign a CA certificate with another CA certificate.

        Args:
            cert_config: Configuration for the certificate to be signed
            signing_cert_config: Configuration for the signing certificate
            signing_crt_pem: PEM of the signing certificate
            signing_key_pem: PEM of the signing private key
            csr_pem: PEM of the Certificate Signing Request

        Returns:
            str: PEM of the signed certificate
        """

    def sign_csr( # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        signing_cert_config: CertificateConfig,
        signing_crt_pem: str,
        signing_key_pem: str,
        csr_pem: str,
        module_args: ModuleArgsConfig
    ) -> str:
        """
        Sign a Certificate Signing Request.

        Args:
            signing_cert_config: Configuration for the signing certificate
            signing_crt_pem: PEM of the signing certificate
            signing_key_pem: PEM of the signing private key
            csr_pem: PEM of the Certificate Signing Request
            module_args: Module-specific arguments for signing

        Returns:
            str: PEM of the signed certificate
        """

    @classmethod
    def load_crypto_module(cls, module_name: str, ca) -> 'CryptoModule':
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
        crypto_module.load_config(ca.config.raw_config_data)
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
