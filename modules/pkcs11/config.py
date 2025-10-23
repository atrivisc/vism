from enum import Enum
from pydantic.dataclasses import dataclass
from shared.data.validation import DataConfig


class SignatureAlgorithmsName(Enum):
    ECDSA = "ECDSA"

class HashingAlgorithmsName(Enum):
    SHA256 = "SHA256"
    SHA512 = "SHA512"
    SHA3_256 = "SHA3-256"
    SHA3_512 = "SHA3-512"

@dataclass
class PKCS11KeyConfig:
    label: str
    slot: str
    slot_pin: str
    signature_algorithm: SignatureAlgorithmsName = None
    hashing_algorithm: HashingAlgorithmsName = None

@dataclass
class PKCS11Config(DataConfig):
    private_keys: list[PKCS11KeyConfig]

    chroot_dir: str = "/tmp/chroot"
    lib_path: str = '/usr/local/lib/softhsm/libsofthsm2.so'
    bin_path: str = '/usr/bin/pkcs11-tool'

    additional_chroot_files: list[str] = None
    additional_chroot_dirs: list[str] = None
