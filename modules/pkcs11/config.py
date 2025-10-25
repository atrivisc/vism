# Licensed under the GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""PKCS#11 module configuration classes."""

from enum import Enum
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
    slot: str
    slot_pin: str
    signature_algorithm: SignatureAlgorithmsName = None
    hashing_algorithm: HashingAlgorithmsName = None


@dataclass
class PKCS11Config(DataConfig):
    """Main configuration for PKCS#11 module."""

    private_keys: list[PKCS11KeyConfig]

    chroot_dir: str = "/tmp/chroot"
    lib_path: str = '/usr/local/lib/softhsm/libsofthsm2.so'
    bin_path: str = '/usr/bin/pkcs11-tool'

    additional_chroot_files: list[str] = None
    additional_chroot_dirs: list[str] = None
