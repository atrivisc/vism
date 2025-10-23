import os
import shutil
import subprocess

from shared import shared_logger
from shared.errors import ChrootWriteFileExists, ChrootOpenFileException, ChrootWriteToFileException

class Chroot:
    def __init__(self, chroot_dir: str):
        self.unshare_cmd = ['unshare', '-muinpUCT', '-r', 'chroot', chroot_dir]
        self.chroot_dir = chroot_dir.rstrip("/")

    def read_file_bytes(self, path: str) -> bytes:
        shared_logger.debug(f"Reading file: {path}")
        with open(f'{self.chroot_dir}/{path.lstrip("/")}', 'rb') as file:
            return file.read()

    def read_file(self, path: str) -> str:
        shared_logger.debug(f"Reading file: {path}")
        with open(f'{self.chroot_dir}/{path.lstrip("/")}', 'r') as file:
            return file.read()

    def delete_folder_contents(self, folder: str):
        shared_logger.debug(f"Deleting folder contents: {folder}")
        shutil.rmtree(f'{self.chroot_dir}/{folder.lstrip("/")}', ignore_errors=True)
        self.create_folder(folder)

    def delete_folder(self, folder: str):
        shared_logger.debug(f"Deleting folder: {folder}")
        try:
            shutil.rmtree(f'{self.chroot_dir}/{folder.lstrip("/")}')
        except FileNotFoundError:
            pass

    def create_folder(self, folder: str):
        shared_logger.debug(f"Creating folder: {folder}")
        os.makedirs(f'{self.chroot_dir}/{folder.lstrip("/")}', exist_ok=True)

    def copy_folder(self, src: str):
        shared_logger.debug(f"Copying folder: {src}")
        shutil.copytree(src, f'{self.chroot_dir}/{src.lstrip("/")}', dirs_exist_ok=True)

    def copy_file(self, src: str):
        shared_logger.debug(f"Copying file: {src}")
        self.create_folder(os.path.dirname(src))
        dest = f'{self.chroot_dir}/{src.lstrip("/")}'
        shutil.copy(src, dest, follow_symlinks=True)

    def write_file(self, path: str, contents: bytes):
        shared_logger.debug(f"Writing file: {path} | {contents}")
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
        shared_logger.debug(f"Deleting file: {path}")
        real_path = f"{self.chroot_dir}/{path.lstrip('/')}"
        if os.path.exists(real_path):
            os.remove(real_path)

    def run_command(self, command: str, stdin: str = None, environment: dict = None) -> subprocess.CompletedProcess:
        print(command)
        shared_logger.debug(f"Running command: {command}")
        result = subprocess.run(
            self.unshare_cmd + command.split(" "),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            input=stdin,
            text=True,
            env=environment
        )
        return result