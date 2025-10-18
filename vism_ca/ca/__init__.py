import logging.config
import os
from vism_ca.ca.crypto import CryptoModule
from vism_ca.logs import setup_logger
from vism_ca.config import CAConfig
from vism_ca.ca.db import VismDatabase, CertificateEntity

logger = logging.getLogger("vism_ca")

class VismCA:
    def __init__(self):
        config_file_path = os.environ.get('CONFIG_FILE_PATH', './config.yaml' )
        self.config = CAConfig(config_file_path)
        self.database = VismDatabase(self.config.database)
        setup_logger()

