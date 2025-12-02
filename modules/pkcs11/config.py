# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""PKCS#11 module configuration classes."""
import os
import re
from enum import Enum
from typing import ClassVar

from pydantic.dataclasses import dataclass
from shared.data.validation import DataConfig


class SignatureAlgorithmsName(Enum):
    """Supported signature algorithms for PKCS#11."""

    ECDSA = "ECDSA"


class HashingAlgorithmsName(Enum):
    """Supported hashing algorithms for PKCS#11."""

    SHA256 = "SHA256"
    SHA512 = "SHA512"
    SHA3_256 = "SHA3-256"
    SHA3_512 = "SHA3-512"


@dataclass
class PKCS11KeyConfig:
    """Configuration for a PKCS#11 key."""

    label: str
    id: str
    pubkey_label: str
    slot: str
    slot_pin: str
    signature_algorithm: SignatureAlgorithmsName = None
    hashing_algorithm: HashingAlgorithmsName = None


@dataclass
class PKCS11Config(DataConfig):
    """Main configuration for PKCS#11 module."""

    __path__: ClassVar[str] = "pkcs11"
    __config_dir__: ClassVar[str] = f"{os.getenv("CONFIG_DIR", os.getcwd()).rstrip("/")}"
    __config_file__: ClassVar[str] = f"{__config_dir__}/pkcs11.yaml"

    private_keys: list[PKCS11KeyConfig]

    chroot_dir: str = "/tmp/chroot"
    lib_path: str = '/usr/local/lib/softhsm/libsofthsm2.so'
    bin_path: str = '/usr/bin/pkcs11-tool'

    additional_chroot_files: list[str] = None
    additional_chroot_dirs: list[str] = None


LOGGING_SENSITIVE_PATTERNS = {
    'pkcs11_pin': {
        'pattern': re.compile(r'(--pin\s)\S+'),
        'replace': r'\1[REDACTED]'
    }
}
