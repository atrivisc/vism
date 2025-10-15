from dataclasses import dataclass
from typing import Optional
from vism_ca.config import CertificateConfig
from vism_ca.crypto.chroot import Chroot


@dataclass
class CryptoConfig:
    pass

class Crypto:
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