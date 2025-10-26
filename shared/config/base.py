# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""Base configuration module."""
import logging
import os
from dataclasses import field
from typing import Any
import yaml
from cachetools import TTLCache
from pydantic.dataclasses import dataclass
from shared.errors import VismBreakingException

_file_cache = TTLCache(ttl=30, maxsize=10)
shared_logger = logging.getLogger("vism_shared")

def read_file_cached(path: str) -> str:
    """
    Cached file reading function.
    Implemented be because switched to vism_config decorator.
    """
    if path not in _file_cache:
        with open(path, 'r', encoding='utf-8') as f:
            _file_cache[path] = f.read()

    return _file_cache[path]

def vism_config(conf_path: str, config_file: str = None, load: bool = True):
    """Decorator function for specifying configuration attributes."""

    if conf_path is None:
        raise VismBreakingException("conf_path attribute is required for vism_config decorator")

    if config_file is None:
        config_file = os.environ.get('CONFIG_FILE', './vism.yaml')

    def read_config_file(config_file_path: str) -> dict[str, Any]:
        """Read and parse YAML configuration file."""
        shared_logger.debug(
            "Reading config file from %s", config_file_path
        )
        return yaml.safe_load(read_file_cached(config_file_path))

    def decorator(cls):
        cls = dataclass(cls)
        setattr(cls, "is_vism_config", True)

        if not hasattr(cls, "config_file"):
            setattr(cls, "config_file", config_file)

        if not hasattr(cls, "conf_path"):
            setattr(cls, "conf_path", conf_path)

        if not hasattr(cls, "load"):
            setattr(cls, "load", load)

        if not getattr(cls, "load", False):
            return cls

        raw_config_data = read_config_file(getattr(cls, "config_file"))
        own_config = raw_config_data.get(getattr(cls, "conf_path"), {})

        if not own_config:
            return cls

        for field_name, field_value in cls.__dataclass_fields__.items():
            if own_config.get(field_name, {}):
                if getattr(field_value.type, "is_vism_config", False):
                    setattr(cls, field_name, field(
                        **dict(
                            field_value.metadata,
                            init=False,
                            default=field_value.type(**own_config[field_name])
                        )
                    ))
                else:
                    setattr(cls, field_name, field(
                        **dict(
                            field_value.metadata,
                            init=False,
                            default=own_config[field_name]
                        )
                    ))

        return cls
    return decorator


# @vism_config(conf_path="")
# class BaseConfig:
#     """Base configuration class."""
