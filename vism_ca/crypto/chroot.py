import logging
import os
import shutil
import subprocess
from vism_ca.util.errors import ChrootWriteFileExists, ChrootOpenFileException, ChrootWriteToFileException

logger = logging.getLogger(__name__)

class Chroot:
    def __init__(self, chroot_dir: str):
        self.unshare_cmd = ['unshare', '-muinpUCT', '-r', 'chroot', chroot_dir]
        self.chroot_dir = chroot_dir.rstrip("/")

    def read_file(self, path: str) -> str:
        logger.debug(f"Reading file: {path}")
        with open(f'{self.chroot_dir}/{path.lstrip("/")}', 'r') as file:
            return file.read()

    def delete_folder(self, folder: str):
        logger.debug(f"Deleting folder: {folder}")
        shutil.rmtree(f'{self.chroot_dir}/{folder.lstrip("/")}')

    def create_folder(self, folder: str):
        logger.debug(f"Creating folder: {folder}")
        os.makedirs(f'{self.chroot_dir}/{folder.lstrip("/")}', exist_ok=True)

    def copy_file(self, src: str):
        logger.debug(f"Copying file: {src}")
        self.create_folder(os.path.dirname(src))
        dest = f'{self.chroot_dir}/{src.lstrip("/")}'
        shutil.copy(src, dest, follow_symlinks=True)

    def write_file(self, path: str, contents: bytes):
        logger.debug(f"Writing file: {path}")
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

    def delete_file(self, path):
        logger.debug(f"Deleting file: {path}")
        real_path = f"{self.chroot_dir}/{path.lstrip('/')}"
        if os.path.exists(real_path):
            os.remove(real_path)

    def run_command(self, command: str, stdin: str = None, environment: dict = None) -> subprocess.CompletedProcess:
        logger.debug(f"Running command: {command}")
        result = subprocess.run(
            self.unshare_cmd + command.split(" "),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            input=stdin,
            text=True,
            env=environment
        )
        return result