from pydantic.dataclasses import dataclass
from typing import Optional

import yaml
import logging

from vism import Config

logger = logging.getLogger(__name__)

@dataclass
class Database:
    host: str = ""
    port: int = 3306
    database: str = ""
    username: str = ""
    password: str = ""

@dataclass
class Logging:
    directory: str = "./logs/"
    level: str = "INFO"
    verbose: bool = False

@dataclass
class Profile:
    name: str
    ca: str
    module_args: dict = None
    enabled: bool = True

@dataclass
class API:
    host: str = "0.0.0.0"
    port: int = 8080

class AcmeConfig(Config):
    def __init__(self, config_file_path: str):
        super().__init__(config_file_path)

        acme_config = self.raw_config_data.get("vism_acme", {})
        self.database = Database(**acme_config.get("database", {}))
        self.logging = Logging(**acme_config.get("logging", {}))
        self.profiles = [Profile(**profile) for profile in acme_config.get("profiles", {})]
        self.server = API(**acme_config.get("server", {}))
        self.nonce_ttl_seconds = acme_config.get("nonce_ttl_seconds", 300)
        self.retry_after_seconds = acme_config.get("retry_after_seconds", 60)
