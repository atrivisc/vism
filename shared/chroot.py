# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""Chroot utility for isolated filesystem operations."""

import os
import shutil
import subprocess
import uuid

from shared import shared_logger
from shared.errors import (
    ChrootWriteFileExists,
    ChrootOpenFileException,
    ChrootWriteToFileException
)


class Chroot:
    """Chroot environment for isolated file operations."""

    def __init__(self, chroot_dir: str):
        self.chroot_dir = f"{chroot_dir.rstrip(' / ')}/{uuid.uuid4()}"
        self.unshare_cmd = [
            'unshare', '-fmuipUCT', '-r', 'chroot', self.chroot_dir
        ]

    def read_file_bytes(self, path: str) -> bytes:
        """Read file contents as bytes."""
        shared_logger.debug("Reading file: %s", path)
        with open(
            f'{self.chroot_dir}/{path.lstrip("/")}',
            'rb',
            encoding=None
        ) as file:
            return file.read()

    def read_file(self, path: str) -> str:
        """Read file contents as string."""
        shared_logger.debug("Reading file: %s", path)
        with open(
            f'{self.chroot_dir}/{path.lstrip("/")}',
            'r',
            encoding='utf-8'
        ) as file:
            return file.read()

    def delete_folder_contents(self, folder: str):
        """Delete all contents of a folder."""
        shared_logger.debug("Deleting folder contents: %s", folder)
        shutil.rmtree(
            f'{self.chroot_dir}/{folder.lstrip("/")}',
            ignore_errors=True
        )
        self.create_folder(folder)

    def delete_folder(self, folder: str):
        """Delete a folder."""
        shared_logger.debug("Deleting folder: %s", folder)
        try:
            shutil.rmtree(f'{self.chroot_dir}/{folder.lstrip("/")}')
        except FileNotFoundError:
            pass

    def create_folder(self, folder: str):
        """Create a folder."""
        shared_logger.debug("Creating folder: %s", folder)
        os.makedirs(
            f'{self.chroot_dir}/{folder.lstrip("/")}',
            exist_ok=True,
            mode=0o700
        )

    def copy_folder(self, src: str):
        """Copy a folder into chroot."""
        shared_logger.debug("Copying folder: %s", src)
        shutil.copytree(
            src,
            f'{self.chroot_dir}/{src.lstrip("/")}',
            dirs_exist_ok=True
        )
        os.chmod(f'{self.chroot_dir}/{src.lstrip("/")}', 0o700)

    def copy_file(self, src: str):
        """Copy a file into chroot."""
        shared_logger.debug("Copying file: %s", src)
        self.create_folder(os.path.dirname(src))
        dest = f'{self.chroot_dir}/{src.lstrip("/")}'
        shutil.copy2(src, dest, follow_symlinks=True)

    def write_file(self, path: str, contents: bytes):
        """Write contents to a file in chroot."""
        shared_logger.debug("Writing file: %s", path)
        directory = os.path.dirname(
            f'{self.chroot_dir}/{path.lstrip("/")}'
        )
        os.makedirs(directory, exist_ok=True, mode=0o700)

        real_path = f"{self.chroot_dir}/{path.lstrip('/')}"
        if os.path.exists(real_path):
            raise ChrootWriteFileExists(
                f"Can not write to {real_path}, file already exists"
            )

        try:
            fd = os.open(real_path, os.O_CREAT | os.O_WRONLY, mode=0o600)
        except Exception as exc:
            raise ChrootOpenFileException(
                f"Failed to create or open file {real_path}: {exc}"
            ) from exc

        try:
            os.write(fd, contents)
            os.close(fd)
        except Exception as exc:
            os.close(fd)
            raise ChrootWriteToFileException(
                f"Failed to write to file {real_path}: {exc}"
            ) from exc

    def delete_file(self, path):
        """Delete a file from chroot."""
        shared_logger.debug("Deleting file: %s", path)
        real_path = f"{self.chroot_dir}/{path.lstrip('/')}"
        if os.path.exists(real_path):
            os.remove(real_path)

    def run_command(
            self,
            command: str,
            stdin: str = None,
            environment: dict = None
    ) -> subprocess.CompletedProcess:
        """Run a command in the chroot environment."""
        shared_logger.debug("Running command: %s", command)
        result = subprocess.run(
            self.unshare_cmd + command.split(" "),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            input=stdin,
            text=True,
            env=environment,
            check=False,
            timeout=60,
        )
        return result
