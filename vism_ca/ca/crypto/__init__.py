import logging
from dataclasses import dataclass
from typing import Optional

from vism_ca.config import CertificateConfig, ModuleArgsConfig, CAConfig
from vism_ca.ca.crypto.chroot import Chroot
from vism_ca.logs import SensitiveDataFilter

logger = logging.getLogger("crypto")

@dataclass
class CryptoConfig:
    pass

class CryptoModule:
    config_path: str
    configClass: CryptoConfig

    def __init__(self, chroot_dir: str):
        self.chroot = Chroot(chroot_dir)
        self.config: Optional[CryptoConfig] = None

    def load_config(self, config_data: dict) -> None:
        self.config = self.configClass(**config_data.get(self.config_path, {}))

    def cleanup(self, full: bool = False):
        raise NotImplemented()

    def generate_private_key(self, cert_config: CertificateConfig) -> tuple[str, str]:
        raise NotImplemented()

    def generate_csr(self, cert_config: CertificateConfig, key_pem: str) -> str:
        raise NotImplemented()

    def create_chroot_environment(self) -> None:
        raise NotImplemented()

    def generate_ca_certificate(self, cert_config: CertificateConfig, key_pem: str, csr_pem: str) -> str:
        raise NotImplemented()

    def generate_crl(self, cert_config: CertificateConfig, key_pem: str, crt_pem: str):
        raise NotImplemented()

    def sign_ca_certificate(self, cert_config: CertificateConfig, signing_cert_config: CertificateConfig, signing_crt_pem: str, signing_key_pem: str, csr_pem: str) -> str:
        pass

    def sign_csr(self, signing_cert_config: CertificateConfig, signing_crt_pem: str, signing_key_pem: str, csr_pem: str, module_args: ModuleArgsConfig) -> str:
        pass

    @classmethod
    def load_crypto_module(cls, module_name: str, ca) -> 'CryptoModule':
        logger.debug(f"Loading crypto module {module_name} for '{module_name}'.")
        crypto_module_imports = CryptoModule.get_crypto_module_imports(module_name)
        crypto_module = crypto_module_imports.Module(ca.config.security.chroot_base_dir, ca.database)
        crypto_module.load_config(ca.config.raw_config_data)
        crypto_module.create_chroot_environment()
        ca.database.create_module_tables(crypto_module_imports.ModuleData)

        SensitiveDataFilter.SENSITIVE_PATTERNS.update(crypto_module_imports.LOGGING_SENSITIVE_PATTERNS)

        return crypto_module

    @classmethod
    def get_crypto_module_imports(cls, module_name: str):
        return __import__(f'modules.{module_name}', fromlist=['Module', 'ModuleConfig', 'ModuleData', 'LOGGING_SENSITIVE_PATTERNS'])