import logging
from dataclasses import dataclass
from shared.config import ModuleArgsConfig, Config
from vism_ca import CertConfigNotFound

logger = logging.getLogger(__name__)

@dataclass
class Database:
    host: str
    port: int
    database: str
    username: str
    password: str

@dataclass
class CertificateConfig:
    name: str
    module: str
    module_args: ModuleArgsConfig

    signed_by: str = None
    externally_managed: bool = False
    certificate_pem: str = None
    crl_pem: str = None

    def __post_init__(self):
        module_import = __import__(f'modules.{self.module}', fromlist=['ModuleArgsConfig'])
        self.module_args = module_import.ModuleArgsConfig(**self.module_args)

ca_logger = logging.getLogger("vism_ca")

class CAConfig(Config):
    log_conf = {
        "log_root": "vism_ca",
        "log_file": "vism_ca.log",
        "error_file": "vism_ca_error.log",
    }
    conf_path = "vism_ca"
    def __init__(self, config_file_path: str):
        super().__init__(config_file_path)

        ca_config = self.raw_config_data.get(self.conf_path, {})
        self.database = Database(**ca_config.get("database", {}))
        self.x509_certificates: list[CertificateConfig] = [CertificateConfig(**cert) for cert in ca_config.get("x509_certificates", [])]

    def get_cert_config_by_name(self, cert_name: str) -> CertificateConfig:
        cert_configs = list(filter(lambda conf: conf.name == cert_name, self.x509_certificates))
        if not cert_configs:
            raise CertConfigNotFound(f"Certificate with name '{cert_name}' not found in config.")
        if len(cert_configs) > 1:
            raise ValueError(f"Multiple certificates found with the name: '{cert_name}'")

        return cert_configs[0]
