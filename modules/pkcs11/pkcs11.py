import base64
import logging
import os
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Union
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from modules import module_logger
from modules.pkcs11.config import PKCS11Config, SignatureAlgorithmsName, HashingAlgorithmsName, PKCS11KeyConfig
from modules.pkcs11.errors import PKCS11FailedToSignData, PKCS11FailedToVerifySignature, PKCS11KeyNotFound, PKCS11FailedToGetPublicKey, PKCS11FailedToEncryptData, PKCS11Error
from shared.chroot import Chroot
from shared.data.validation import Data
from shared.errors import VismException
from shared.util import get_needed_libraries
from cryptography.hazmat.primitives.asymmetric import utils as asymmetric_crypto_utils

logger = logging.getLogger("pkcs11")

class PKCS11MechanismCapability(Enum):
    sign = "sign"
    verify = "verify"
    wrap = "wrap"
    unwrap = "unwrap"
    decrypt = "decrypt"
    encrypt = "encrypt"
    derive = "derive"
    generate = "generate"

    @classmethod
    def get(cls, name: str):
        try:
            return cls(name)
        except ValueError:
            return None

@dataclass
class PKCS11Mechanism:
    name: str
    capabilities: list[PKCS11MechanismCapability]

@dataclass
class PKCS11Key:
    chroot: Chroot
    bin: str
    config: PKCS11KeyConfig
    key_id: str = None
    key_label: str = None
    slot: str = None
    slot_pin: str = None
    additional_args: list[str] = None
    module: str = "/usr/local/lib/softhsm/libsofthsm2.so"

    supported_mechanisms: list[PKCS11Mechanism] = None
    public_key: PublicKeyTypes = None

    def __post_init__(self):
        self.supported_mechanisms = self.get_supported_mechanisms()
        self.public_key = self.get_public_key()

    def derive_ec_shared_secret(self, peer_public_key_der: bytes) -> bytes:
        ecdh_mechanisms = self.get_supported_mechanisms_by_name("ECDH")
        if ecdh_mechanisms is None or len(ecdh_mechanisms) == 0:
            raise PKCS11Error(f"ECDH encryption is not supported for module: {self.module}")
        else:
            ecdh_mechanism = ecdh_mechanisms[-1]

        self.chroot.write_file("/tmp/peer_pub.der", peer_public_key_der)
        result = self.chroot.run_command(
            f"{self.bin} --derive "
            f"--mechanism {ecdh_mechanism.name} "
            f"-i /tmp/peer_pub.der "
            f"--key-type AES:32 "
            f"-o /tmp/aes_key.der "
            f"{self.to_command_args()}"
        )
        if result.returncode != 0:
            raise PKCS11Error(f"Failed to derive key: {result.stderr}")

        shared_secret = self.chroot.read_file_bytes("/tmp/aes_key.der")
        return shared_secret

    def to_command_args(self, args_to_skip: list[str] = None):
        if args_to_skip is None:
            args_to_skip = []

        args = [f"--module {self.module}"] + (self.additional_args if self.additional_args else [])

        if self.key_id and 'key_id' not in args_to_skip:
            args.append(f"--id {self.key_id}")
        if self.key_label and 'key_label' not in args_to_skip:
            args.append(f"--label {self.key_label}")
        if self.slot and 'slot' not in args_to_skip:
            args.append(f"--slot {self.slot}")
        if self.slot_pin and 'slot_pin' not in args_to_skip:
            args.append(f"--pin {self.slot_pin}")

        return " ".join(args)

    def get_supported_mechanisms(self) -> list[PKCS11Mechanism]:
        result = self.chroot.run_command(
            f"{self.bin} --module {self.module} -M"
        )
        if result.returncode != 0:
            raise PKCS11Error(f"Failed to list mechanisms: {result.stderr}")

        mechanisms: list[PKCS11Mechanism] = []
        for line in result.stdout.splitlines() :
            line: str = line.strip()
            line_parts = line.split(", ")
            if len(line_parts) < 2:
                continue

            if line_parts[1].startswith("keySize="):
                line_parts.pop(1)

            capabilities = [PKCS11MechanismCapability.get(name) for name in line_parts[1:]]
            mechanisms.append(PKCS11Mechanism(line_parts[0], capabilities))

        return mechanisms

    def get_supported_mechanisms_by_name(self, mechanism_name: str) -> list[PKCS11Mechanism]:
        mechanisms = []
        for mechanism in self.supported_mechanisms:
            if mechanism.name.startswith(mechanism_name):
                mechanisms.append(mechanism)
        return mechanisms

    def get_public_key(self) -> PublicKeyTypes:
        result = self.chroot.run_command(
            f"{self.bin} -r --type pubkey "
            f"-o /tmp/pubkey.der "
            f"{self.to_command_args()}"
        )
        if result.returncode != 0:
            raise PKCS11FailedToGetPublicKey(f"Failed to load public key: {result.stderr}")

        public_key_der = self.chroot.read_file_bytes("/tmp/pubkey.der")
        public_key = serialization.load_der_public_key(public_key_der)
        return public_key

    @staticmethod
    def get_digest(data: bytes, hashing_algorithm: HashAlgorithm) -> bytes:
        hash_alg = hashes.Hash(hashing_algorithm)
        buffer = data[:]
        hash_alg.update(buffer)
        digest = hash_alg.finalize()
        return digest

    def encrypt(self, data: bytes, encryption_algorithm: Union[ec.ECDH]):
        if isinstance(encryption_algorithm, ec.ECDH):
            public_key_der = self.public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            return self.encrypt_for_peer(data, encryption_algorithm, public_key_der)
        else:
            raise PKCS11Error(f"Unsupported encryption algorithm: {encryption_algorithm}")

    def decrypt(self, data: bytes, encryption_algorithm: Union[ec.ECDH]):
        if isinstance(encryption_algorithm, ec.ECDH):
            public_key_der = self.public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            return self.decrypt_for_peer(data, encryption_algorithm, public_key_der)
        else:
            raise PKCS11Error(f"Unsupported encryption algorithm: {encryption_algorithm}")

    def decrypt_for_peer(self, data: bytes, encryption_algorithm: Union[ec.ECDH], derive_peer_public_key_der: bytes):
        if isinstance(encryption_algorithm, ec.ECDH):
            if derive_peer_public_key_der is None:
                raise PKCS11Error("derive_peer_public_key_der is required for ec.ECDH encryption")
            else:
                try:
                    serialization.load_der_public_key(derive_peer_public_key_der)
                except Exception as e:
                    raise PKCS11Error(f"Failed to load peer public key: {e}")

            shared_secret = self.derive_ec_shared_secret(derive_peer_public_key_der)
            aes_key = self.get_digest(shared_secret, hashes.SHA256())
            iv, ciphertext = data[:12], data[12:]
            tag = b'\x19W6p\xa5\xbfJ\xec\xcf\xa4\x81\x80E\x96\xe8\x85'
            aesgcm = AESGCM(aes_key)
            decrypted = aesgcm.decrypt(iv, ciphertext, tag)
            return decrypted
        else:
            raise PKCS11Error(f"Unsupported encryption algorithm: {encryption_algorithm}")

    def encrypt_for_peer(self, data: bytes, encryption_algorithm: Union[ec.ECDH], derive_peer_public_key_der: bytes):
        if isinstance(encryption_algorithm, ec.ECDH):
            if derive_peer_public_key_der is None:
                raise PKCS11Error("derive_peer_public_key_der is required for ec.ECDH encryption")
            else:
                try:
                    serialization.load_der_public_key(derive_peer_public_key_der)
                except Exception as e:
                    raise PKCS11Error(f"Failed to load peer public key: {e}")

            shared_secret = self.derive_ec_shared_secret(derive_peer_public_key_der)
            aes_key = self.get_digest(shared_secret, hashes.SHA256())
            aesgcm = AESGCM(aes_key)
            iv = os.urandom(12)

            tag = b'\x19W6p\xa5\xbfJ\xec\xcf\xa4\x81\x80E\x96\xe8\x85'
            ciphertext = aesgcm.encrypt(iv, data, tag)
            combined = iv + ciphertext

            return combined
        else:
            raise PKCS11Error(f"Unsupported encryption algorithm: {encryption_algorithm}")

    def validate_signature(self, data: bytes, signature_der: bytes, signature_algorithm: Union[ec.ECDSA]):
        data_digest = self.get_digest(data, signature_algorithm.algorithm)
        self.chroot.write_file("/tmp/data.in", data_digest)

        if isinstance(signature_algorithm, ec.ECDSA):
            self.chroot.write_file("/tmp/sig.in", signature_der)
            self.chroot.write_file("/tmp/sig_data.in", data_digest)
            method = f"ECDSA-{signature_algorithm.algorithm.name.upper()}"
            result = self.chroot.run_command(
                f"{self.bin} --verify "
                f"--mechanism {method} "
                f"--signature-file /tmp/sig.in "
                f"--signature-format sequence "
                f"-i /tmp/sig_data.in "
                f"{self.to_command_args()}"
            )
            if result.returncode != 0:
                raise PKCS11Error(f"Failed to verify signature: {result.stderr}")
        else:
            raise PKCS11Error(f"Unsupported signature algorithm: {signature_algorithm}")

    def sign(self, data: bytes, signature_algorithm: Union[ec.ECDSA]) -> bytes:
        data_digest = self.get_digest(data, signature_algorithm.algorithm)
        self.chroot.write_file("/tmp/data.in", data_digest)

        if isinstance(signature_algorithm, ec.ECDSA):
            method = f"ECDSA-{signature_algorithm.algorithm.name.upper()}"
        else:
            raise PKCS11Error(f"Unsupported signature algorithm: {signature_algorithm}")

        result = self.chroot.run_command(
            f"{self.bin} "
            f"--mechanism {method} "
            f"-i /tmp/data.in "
            f"-o /tmp/sig.out "
            f"{self.to_command_args()} -s"
        )
        if result.returncode != 0:
            raise PKCS11Error(f"Failed to sign data: {result.stderr}")

        sig_bytes = self.chroot.read_file_bytes("/tmp/sig.out")
        curve_bits = self.public_key.curve.key_size
        r_s_len = (curve_bits + 7) // 8

        r = int.from_bytes(sig_bytes[:r_s_len], 'big')
        s = int.from_bytes(sig_bytes[r_s_len:], 'big')
        signature_der = asymmetric_crypto_utils.encode_dss_signature(r, s)
        return signature_der

class PKCS11(Data):
    configClass = PKCS11Config
    config_path: str = "pkcs11"

    def __init__(self, *args, **kwargs):
        module_logger.debug(f"Initializing PKCS11 module")
        super().__init__(*args, **kwargs)
        self.config: Optional[PKCS11Config] = None
        self.chroot: Optional[Chroot] = None

    @staticmethod
    def _get_hashing_algorithm(key: PKCS11KeyConfig) -> hashes.HashAlgorithm:
        match key.hashing_algorithm:
            case HashingAlgorithmsName.SHA256:
                return hashes.SHA256()
            case HashingAlgorithmsName.SHA512:
                return hashes.SHA512()
            case HashingAlgorithmsName.SHA3_256:
                return hashes.SHA3_256()
            case HashingAlgorithmsName.SHA3_512:
                return hashes.SHA3_512()

    def load_config(self, config_data: dict) -> None:
        module_logger.debug(f"Loading config for PKCS11 module")
        super().load_config(config_data)
        self.create_chroot_environment()

    def get_key_config_by_label(self, label: str) -> Optional[PKCS11KeyConfig]:
        for key in self.config.private_keys:
            if key.label == label:
                return key
        return None

    def get_key_by_label(self, label: str):
        key_config = self.get_key_config_by_label(label)
        if not key_config:
            raise PKCS11KeyNotFound(f"No key found with the given label: {label}")

        return PKCS11Key(
            self.chroot,
            self.config.bin_path,
            config=key_config,
            key_label=key_config.label,
            slot=key_config.slot,
            slot_pin=key_config.slot_pin,
            module=self.config.lib_path
        )

    def verify(self, data: bytes, signature_b64: str) -> None:
        module_logger.info(f"PKCS11: Verifying signature with '{self.validation_key}'")
        if signature_b64 is None:
            raise PKCS11FailedToVerifySignature("Signature is missing")

        with self._get_key(self.validation_key) as key:
            signature_der = base64.urlsafe_b64decode(signature_b64)

            if key.config.signature_algorithm == SignatureAlgorithmsName.ECDSA:
                signature_algorithm = ec.ECDSA(self._get_hashing_algorithm(key.config))
                key.validate_signature(data, signature_der, signature_algorithm)
            else:
                raise PKCS11FailedToSignData(f"Unsupported signature algorithm: {key.config.signature_algorithm}")

    def decrypt(self, data: bytes) -> bytes:
        module_logger.info(f"PKCS11: Decrypting data with '{self.encryption_key}'")
        with self._get_key(self.encryption_key) as key:
            if isinstance(key.public_key, ec.EllipticCurvePublicKey):
                encryption_algorithm = ec.ECDH()
                decrypted_data = key.decrypt(data, encryption_algorithm)
            return decrypted_data

    def decrypt_for_peer(self, data: bytes, peer_public_key_pem: str = None) -> bytes:
        module_logger.info(f"PKCS11: Decrypting data for peer with '{self.encryption_key}'")
        with self._get_key(self.encryption_key) as key:
            if isinstance(key.public_key, ec.EllipticCurvePublicKey):
                encryption_algorithm = ec.ECDH()
                peer_public_key_der = serialization.load_pem_public_key(peer_public_key_pem.encode("utf-8")).public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                decrypted_data = key.decrypt_for_peer(data, encryption_algorithm, peer_public_key_der)
            return decrypted_data

    def encrypt(self, data: bytes) -> bytes:
        module_logger.info(f"PKCS11: Encrypting data with '{self.encryption_key}'")
        with self._get_key(self.encryption_key) as key:
            if isinstance(key.public_key, ec.EllipticCurvePublicKey):
                encryption_algorithm = ec.ECDH()
                encrypted_data = key.encrypt(data, encryption_algorithm)
            return encrypted_data

    def encrypt_for_peer(self, data: bytes, peer_public_key_pem: str = None) -> bytes:
        module_logger.info(f"PKCS11: fEncrypting data for peer with '{self.encryption_key}'")
        with self._get_key(self.encryption_key) as key:
            if isinstance(key.public_key, ec.EllipticCurvePublicKey):
                encryption_algorithm = ec.ECDH()
                if not peer_public_key_pem:
                    raise PKCS11FailedToEncryptData("peer_public_key_pem is required for ec.ECDH encryption")

                peer_public_key_der = serialization.load_pem_public_key(peer_public_key_pem.encode("utf-8")).public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                encrypted_data = key.encrypt_for_peer(data, encryption_algorithm, peer_public_key_der)

            return encrypted_data

    @contextmanager
    def _get_key(self, key_label: str):
        self.cleanup()
        try:
            key = self.get_key_by_label(key_label)
            yield key
        except Exception as e:
            self.cleanup()
            raise VismException(f"Failed to load key: {e}")
        finally:
            self.cleanup()

    def sign(self, data: bytes) -> bytes:
        module_logger.info(f"PKCS11: Signing data with '{self.validation_key}'")
        with self._get_key(self.validation_key) as key:
            if key.config.signature_algorithm == SignatureAlgorithmsName.ECDSA:
                signature_algorithm = ec.ECDSA(self._get_hashing_algorithm(key.config))
                signature_der = key.sign(data, signature_algorithm)
            else:
                raise PKCS11FailedToSignData(f"Unsupported signature algorithm: {key.config.signature_algorithm}")

            return signature_der

    def cleanup(self, full: bool = False):
        module_logger.debug(f"Cleaning up PKCS11 environment. Full: {full}")
        self.chroot.delete_folder_contents("/tmp")

        if full:
            self.chroot.delete_folder_contents("/")
            self.chroot = None

    def create_chroot_environment(self):
        module_logger.debug("Creating chroot environment for PKCS11 module.")
        if self.chroot is None:
            self.chroot = Chroot(self.config.chroot_dir)

        bin_libraries = get_needed_libraries(self.config.bin_path)
        lib_libraries = get_needed_libraries(self.config.lib_path)
        self.chroot.create_folder("/tmp")

        for library in lib_libraries + bin_libraries:
            self.chroot.copy_file(library)

        self.chroot.copy_file(self.config.lib_path)
        self.chroot.copy_file(self.config.bin_path)

        if self.config.additional_chroot_dirs:
            for directory in self.config.additional_chroot_dirs:
                self.chroot.copy_folder(directory)

        if self.config.additional_chroot_files:
            for file in self.config.additional_chroot_files:
                self.chroot.copy_file(file)