import logging
import logging.config
import sys
from argparse import Namespace
from vism_ca.config import Config
from vism_ca.crypto.crypto import Crypto
from vism_ca.db.database import Certificate, VismDatabase
from vism_ca.x509.certificate import CertificateConfig


class VismCA:
    def __init__(self, cli_args: Namespace):
        self.cli_args = cli_args
        self.config: Config = self.load_config()
        self.setup_logger()
        self.database = VismDatabase(self.config.database)

    def test(self):
        cert_config = self.config.x509_certificates[0]
        
        self.crypto_module: Crypto = __import__(f'modules.{cert_config.module}', fromlist=['Module', 'ModuleConfig']).Module(self.config.security.chroot_base_dir)
        self.crypto_module.load_config(self.config.raw_config_data)
    
        self.crypto_module.generate_chroot_environment()

        try:
            priv_key_pem, pub_key_pem = self.crypto_module.generate_private_key(cert_config)
            csr_pem = self.crypto_module.generate_csr(cert_config, priv_key_pem)
            crt_pem = self.crypto_module.generate_ca_certificate(cert_config, priv_key_pem, csr_pem)
            print(crt_pem)
        except:
            self.crypto_module.cleanup(full=True)

    def get_crypto_module(self, cert_config: CertificateConfig) -> Crypto:
        crypto_module_imports = __import__(f'modules.{cert_config.module}', fromlist=['Module', 'ModuleConfig', 'ModuleData'])
        crypto_module = crypto_module_imports.Module(self.config.security.chroot_base_dir)
        crypto_module.load_config(self.config.raw_config_data)
        crypto_module.generate_chroot_environment()

        self.database.create_module_tables(crypto_module_imports.ModuleData)

        return crypto_module

    def create_crl(self, cert_config: CertificateConfig):
        crypto_module = self.get_crypto_module(cert_config)

    def create_certificate(self, cert_config: CertificateConfig) -> Certificate:
        crypto_module = self.get_crypto_module(cert_config)

        cert = Certificate.get_by_name(cert_config.name)
        if cert:
            return cert

        cert = Certificate(name=cert_config.name, externally_managed=cert_config.externally_managed, module=cert_config.module)
        if cert.externally_managed:
            cert.certificate_pem = cert_config.certificate_pem
            cert.crl_pem = cert_config.crl_pem
            cert.save_to_db()
        else:
            cert.private_key_pem, cert.public_key_pem = crypto_module.generate_private_key(cert_config)
            cert.csr_pem = crypto_module.generate_csr(cert_config, cert.private_key_pem)
            cert.certificate_pem = crypto_module.generate_ca_certificate(cert_config, cert.private_key_pem, cert.csr_pem)
            cert.save_to_db()

        return cert

    def load_config(self) -> Config:
        return Config(self.cli_args.config)

    def setup_logger(self):
        verbose = self.cli_args.verbose or self.config.logging.verbose
        logging_config = {
            'version': 1,
            'disable_existing_loggers': False,
            'formatters': {
                'verbose': {'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'},
                'simple': {'format': '%(message)s'},
            },
            'handlers': {
                'console': {
                    'level': self.config.logging.level if not verbose else 'DEBUG',
                    'class': 'logging.StreamHandler',
                    'formatter': 'verbose' if verbose else 'simple',
                    'stream': sys.stdout
                }
            },
            'loggers': {
                '': {
                    'level': self.config.logging.level if not verbose else 'DEBUG',
                    'handlers': ['console']
                }
            }
        }

        logging.config.dictConfig(logging_config)
        logging.debug("Logging is set up and ready")
