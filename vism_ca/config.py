from dataclasses import dataclass, fields
from typing import Optional

import yaml
import logging

from vism_ca.x509.certificate import CertificateConfig

logger = logging.getLogger(__name__)

@dataclass
class Database:
    host: str = ""
    port: int = 3306
    database: str = ""
    username: str = ""
    password: str = ""

@dataclass
class DataEncryption:
    enabled: bool = False
    password: str = ""

@dataclass
class Security:
    chroot_base_dir: str
    data_encryption: DataEncryption

    def __post_init__(self):
        self.data_encryption = DataEncryption(**self.data_encryption)

@dataclass
class Logging:
    directory: str = "./logs/"
    level: str = "INFO"
    verbose: bool = False

def load_dataclass(obj):
    parsed_data = {}

    if hasattr(obj, "__dataclass_fields__"):
        for field in fields(obj):
            value = getattr(obj, field.name)
            if hasattr(value, "__dataclass_fields__"):  # If the value is a dataclass, recursively parse it
                parsed_data[field.name] = load_dataclass(value)
            else:
                parsed_data[field.name] = value

    return parsed_data


class Config:
    def __init__(self, config_file):
        self.config_file = config_file

        self.raw_config_data: Optional[dict] = None

        self.database: Optional[Database] = None
        self.logging: Optional[Logging] = None
        self.x509_certificates: Optional[list[CertificateConfig]] = None
        self.security: Optional[Security] = None

        self.load()

    def load(self):
        try:
            with open(self.config_file, 'r') as file:
                config_data = yaml.safe_load(file)
                self.raw_config_data = config_data

                self.database = Database(**config_data['database'])
                self.logging = Logging(**config_data['logging'])
                self.security = Security(**config_data['security'])
                self.x509_certificates = [CertificateConfig(**cert) for cert in config_data.get('x509_certificates', [])]

            logger.debug(f"Configuration file '{self.config_file}' loaded successfully.")
        except FileNotFoundError:
            logger.error(f"Error: The file '{self.config_file}' was not found.")
        except yaml.YAMLError as e:
            logger.error(f"Error: There was an issue with parsing the YAML file: {e}")

