import os
import shutil
import subprocess
from dataclasses import dataclass
from subprocess import CompletedProcess
from typing import Optional

from vism_ca.config import CertificateConfig
from vism_ca.util.errors import ChrootWriteFileExists, ChrootWriteToFileException, ChrootOpenFileException


@dataclass
class CryptoConfig:
    pass

class Crypto:
    config_path: str
    configClass: CryptoConfig

    def __init__(self, chroot_dir: str):
        self.chroot_dir = chroot_dir.rstrip("/")
        self.unshare_cmd = ['unshare', '-muinpUCT', '-r', 'chroot', chroot_dir]
        self.config: Optional[CryptoConfig] = None

    def load_config(self, config_data: dict) -> None:
        self.config = self.configClass(**config_data.get(self.config_path, {}))

    def generate_private_key(self, cert_config: CertificateConfig) -> tuple[str, str]:
        raise NotImplemented()

    def generate_csr(self, cert_config: CertificateConfig, key_pem: str) -> str:
        raise NotImplemented()

    def generate_chroot_environment(self) -> None:
        raise NotImplemented()

    def generate_ca_certificate(self, cert_config: CertificateConfig, key_pem: str, csr_pem: str) -> str:
        raise NotImplemented()

    def generate_crl(self, cert_config: CertificateConfig):
        raise NotImplemented()

    def cleanup(self, full: bool = False):
        raise NotImplemented()

    def delete_folder_in_chroot(self, folder: str):
        shutil.rmtree(f'{self.chroot_dir}/{folder.lstrip("/")}')

    def create_folder_in_chroot(self, folder: str):
        os.makedirs(f'{self.chroot_dir}/{folder.lstrip("/")}', exist_ok=True)

    def copy_file_to_chroot(self, src: str):
        self.create_folder_in_chroot(os.path.dirname(src))
        dest = f'{self.chroot_dir}/{src.lstrip("/")}'
        shutil.copy(src, dest, follow_symlinks=True)

    def write_file_in_chroot(self, path: str, contents: bytes):
        directory = os.path.dirname(f'{self.chroot_dir}/{path.lstrip('/')}')
        os.makedirs(directory, exist_ok=True)

        real_path = f"{self.chroot_dir}/{path.lstrip('/')}"
        if os.path.exists(real_path):
            raise ChrootWriteFileExists(f"Can not write to {real_path}, file already exists")

        try:
            fd = os.open(real_path, os.O_CREAT | os.O_WRONLY, mode=0o600)
        except Exception as e:
            raise ChrootOpenFileException(f"Failed to create or open file {real_path}: {e}")

        try:
            os.write(fd, contents)
            os.close(fd)
        except Exception as e:
            os.close(fd)
            raise ChrootWriteToFileException(f"Failed to write to file {real_path}: {e}")

    def delete_file_in_chroot(self, path):
        real_path = f"{self.chroot_dir}/{path.lstrip('/')}"
        if os.path.exists(real_path):
            os.remove(real_path)

    def run_command_in_chroot(self, command: str, stdin: str = None, environment: dict = None) -> CompletedProcess:
        result = subprocess.run(
            self.unshare_cmd + command.split(" "),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            input=stdin,
            text=True,
            env=environment
        )
        self.cleanup()
        return result
