import yaml
from typing import Optional, Any

class Config:
    def __init__(self, config_file_path: str):
        self.config_file_path = config_file_path
        self.raw_config_data: Optional[dict] = self.read_config_file()

    def read_config_file(self) -> dict[str, Any]:
        with open(self.config_file_path, 'r') as file:
            return yaml.safe_load(file)
