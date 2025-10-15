import logging
import shutil
import textwrap
from dataclasses import dataclass

from typing import Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from modules.openssl.config import OpenSSLConfig, CAProfile, OpenSSLModuleArgs
from modules.openssl.db import OpenSSLData
from modules.openssl.errors import ProfileNotFound, MultipleProfilesFound, OpensslException
from vism_ca.config import CertificateConfig
from vism_ca.crypto import Crypto
from vism_ca.util import get_needed_libraries
from vism_ca.util.errors import GenCertException, GenCSRException, GenPKEYException, GenCRLException
from jinja2 import Template, StrictUndefined

logger = logging.getLogger("modules.openssl")

@dataclass
class OpenSSLCertConfig(CertificateConfig):
    module_args: OpenSSLModuleArgs

class OpenSSL(Crypto):
    config_path: str = "openssl"
    configClass: OpenSSLConfig = OpenSSLConfig

    def __init__(self, chroot_dir: str):
        self.config: Optional[OpenSSLConfig] = None
        super().__init__(chroot_dir)

    @property
    def openssl_path(self):
        return self.config.bin or shutil.which("openssl")

    def _write_openssl_config(self, cert_config: OpenSSLCertConfig):
        openssl_config_template_path = cert_config.module_args.config_template or self.config.default_config_template

        config_template = ""
        with open(f'modules/openssl/templates/{openssl_config_template_path}', 'r') as f:
            config_template = f.read()

        profile = self.config.get_profile_by_name(cert_config.module_args.profile)

        template = Template(
            textwrap.dedent(config_template),
            trim_blocks=True,
            lstrip_blocks=True,
            undefined=StrictUndefined
        ).render({'certificate': cert_config, 'ca_profile': profile})

        self.chroot.write_file(f"/tmp/{cert_config.name}/{cert_config.name}.conf", template.encode("utf-8"))

    def _create_crt_environment(self, cert_config: OpenSSLCertConfig, key_pem: str = None, csr_pem: str = None, crt_pem: str = None) -> None:
        logger.debug(f"Creating crt environment for '{cert_config.name}'"),
        self._write_openssl_config(cert_config)

        if key_pem:
            key_path = f"/tmp/{cert_config.name}/{cert_config.name}.key"
            self.chroot.write_file(key_path, key_pem.encode("utf-8"))
        if csr_pem:
            csr_path = f"/tmp/{cert_config.name}/{cert_config.name}.csr"
            self.chroot.write_file(csr_path, csr_pem.encode("utf-8"))
        if crt_pem:
            crt_path = f"/tmp/{cert_config.name}/{cert_config.name}.crt"
            self.chroot.write_file(crt_path, crt_pem.encode("utf-8"))

    def _create_ca_environment(self, cert_config: OpenSSLCertConfig, key_pem: str = None, csr_pem: str = None, crt_pem: str = None):
        logger.debug(f"Creating ca environment for '{cert_config.name}'"),

        self._create_crt_environment(cert_config, key_pem, csr_pem, crt_pem)
        openssl_data = OpenSSLData.get_by_cert_name(cert_config.name)
        if not openssl_data and crt_pem:
            cert = x509.load_pem_x509_certificate(crt_pem.encode(), default_backend())
            cert_serial = format(cert.serial_number, 'x')
            openssl_data = OpenSSLData.get_by_cert_serial(cert_serial)

        if not openssl_data:
            openssl_data = OpenSSLData(cert_name=cert_config.name)

        if openssl_data:
            if not openssl_data.database:
                openssl_data.database = ""
            if not openssl_data.serial:
                openssl_data.serial = "01"
            if not openssl_data.crlnumber:
                openssl_data.crlnumber = "01"

            database_path = f"/tmp/{cert_config.name}/{cert_config.name}.db"
            serial_path = f"/tmp/{cert_config.name}/serial"
            crl_number_path = f"/tmp/{cert_config.name}/crlnumber"

            self.chroot.write_file(database_path, openssl_data.database.encode("utf-8"))
            self.chroot.write_file(serial_path, openssl_data.serial.encode("utf-8"))
            self.chroot.write_file(crl_number_path, openssl_data.crlnumber.encode("utf-8"))

        self.chroot.create_folder(f"/tmp/{cert_config.name}/certs")

        return openssl_data

    def create_chroot_environment(self):
        logger.info("Generating chroot environment for openssl module."),
        libraries = get_needed_libraries(self.openssl_path)
        self.chroot.create_folder("/tmp")

        for library in libraries:
            self.chroot.copy_file(library)

        self.chroot.copy_file(self.openssl_path)

    def generate_crl(self, cert_config: OpenSSLCertConfig, key_pem: str, crt_pem: str):
        logger.info(f"Generating crl for '{cert_config.name}'"),
        openssl_data = self._create_ca_environment(cert_config, key_pem, crt_pem=crt_pem)

        if not openssl_data:
            self.cleanup()
            raise GenCRLException(f"Cannot generate CRL before certificate.")

        command = (f"{self.openssl_path} ca -batch "
                   f"-keyfile /tmp/{cert_config.name}/{cert_config.name}.key "
                   f"-config /tmp/{cert_config.name}/{cert_config.name}.conf "
                   f"-gencrl "
                   f"-out -")

        if cert_config.module_args.key.password:
            command += f" -passin pass:{cert_config.module_args.key.password}"

        output = self.chroot.run_command(command)
        if output.returncode != 0:
            self.cleanup()
            raise GenCRLException(f"Failed to generate crl: {output.stderr}")

        openssl_data.crlnumber = self.chroot.read_file(f"/tmp/{cert_config.name}/crlnumber")
        openssl_data.serial = self.chroot.read_file(f"/tmp/{cert_config.name}/serial")
        openssl_data.database = self.chroot.read_file(f"/tmp/{cert_config.name}/{cert_config.name}.db")

        openssl_data.save_to_db()
        self.cleanup()

        return output.stdout

    def generate_csr(self, cert_config: OpenSSLCertConfig, key_pem: str) -> str:
        logger.info(f"Generating csr for '{cert_config.name}'"),

        self._create_crt_environment(cert_config, key_pem)

        key_path = f"/tmp/{cert_config.name}/{cert_config.name}.key"
        command = f"{self.openssl_path} req -batch -new -config /tmp/{cert_config.name}/{cert_config.name}.conf -key {key_path}"
        if cert_config.module_args.key.password:
            command += f" -passin pass:{cert_config.module_args.key.password}"

        output = self.chroot.run_command(command)
        if output.returncode != 0:
            self.cleanup()
            raise GenCSRException(f"Failed to generate csr: {output.stderr}")

        self.cleanup()

        return output.stdout

    def generate_private_key(self, cert_config: OpenSSLCertConfig) -> tuple[str, str]:
        logger.info(f"Generating private key for '{cert_config.name} 'with password."),
        self._create_crt_environment(cert_config)

        key_config = cert_config.module_args.key

        command = f"{self.openssl_path} genpkey -config /tmp/{cert_config.name}/{cert_config.name}.conf -algorithm {key_config.algorithm}"
        if key_config.algorithm == "RSA" and key_config.bits:
            command += f" -pkeyopt rsa_keygen_bits:{key_config.bits}"
        if key_config.password:
            command += f" -aes-256-cbc -pass pass:{key_config.password}"

        output = self.chroot.run_command(command)

        if output.returncode != 0:
            self.cleanup()
            raise GenPKEYException(f"Failed to generate private key: {output.stderr}")

        try:
            private_key_pem = output.stdout
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=key_config.password.encode("utf-8") if key_config.password else None,
                backend=default_backend()
            )

            public_key = private_key.public_key()
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode("utf-8")
        except Exception as e:
            self.cleanup()
            raise GenPKEYException(f"Failed to generate private key: {e}")

        self.cleanup()
        return private_key_pem, public_key_pem

    def cleanup(self, full: bool = False):
        self.chroot.delete_folder("/tmp")
        if full:
            self.chroot.delete_folder("/")

    def generate_ca_certificate(self, cert_config: OpenSSLCertConfig, key_pem: str, csr_pem: str) -> str:
        logger.info(f"Generating ca certificate for '{cert_config.name}'")

        openssl_data = self._create_ca_environment(cert_config, key_pem, csr_pem)
        command = self._build_ca_sign_command(cert_config)

        cert_pem = self._execute_ca_sign(command)
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        cert_serial = format(cert.serial_number, 'x')

        openssl_data.cert_serial = cert_serial
        openssl_data.crlnumber = self.chroot.read_file(f"/tmp/{cert_config.name}/crlnumber")
        openssl_data.serial = self.chroot.read_file(f"/tmp/{cert_config.name}/serial")
        openssl_data.database = self.chroot.read_file(f"/tmp/{cert_config.name}/{cert_config.name}.db")

        openssl_data.save_to_db()
        self.cleanup()

        return cert_pem

    def sign_ca_certificate(self, cert_config: OpenSSLCertConfig, signing_cert_config: OpenSSLCertConfig, signing_crt_pem: str, signing_key_pem: str, csr_pem: str) -> str:
        logger.info(f"Signing ca certificate for '{cert_config.name}' with '{signing_cert_config.name}'")

        signing_openssl_data = self._create_ca_environment(signing_cert_config, crt_pem=signing_crt_pem, key_pem=signing_key_pem)
        openssl_data = self._create_ca_environment(cert_config, csr_pem=csr_pem)
        command = self._build_ca_sign_command(cert_config, signing_cert_config)

        cert_pem = self._execute_ca_sign(command)
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        cert_serial = format(cert.serial_number, 'x')

        openssl_data.cert_serial = cert_serial
        openssl_data.crlnumber = self.chroot.read_file(f"/tmp/{cert_config.name}/crlnumber")
        openssl_data.serial = self.chroot.read_file(f"/tmp/{cert_config.name}/serial")
        openssl_data.database = self.chroot.read_file(f"/tmp/{cert_config.name}/{cert_config.name}.db")

        signing_openssl_data.crlnumber = self.chroot.read_file(f"/tmp/{signing_cert_config.name}/crlnumber")
        signing_openssl_data.serial = self.chroot.read_file(f"/tmp/{signing_cert_config.name}/serial")
        signing_openssl_data.database = self.chroot.read_file(f"/tmp/{signing_cert_config.name}/{signing_cert_config.name}.db")

        openssl_data.save_to_db()
        signing_openssl_data.save_to_db()
        self.cleanup()

        return cert_pem

    def _build_ca_sign_command(self, cert_config: OpenSSLCertConfig, parent_cert_config: OpenSSLCertConfig = None) -> str:
        signing_key_path = f"/tmp/{cert_config.name}/{cert_config.name}.key" if parent_cert_config is None else f"/tmp/{parent_cert_config.name}/{parent_cert_config.name}.key"
        config_path = f"/tmp/{cert_config.name}/{cert_config.name}.conf" if parent_cert_config is None else f"/tmp/{parent_cert_config.name}/{parent_cert_config.name}.conf"
        csr_path = f"/tmp/{cert_config.name}/{cert_config.name}.csr"

        command = (f"{self.openssl_path} ca -batch "
                   f"-keyfile {signing_key_path} "
                   f"-config {config_path} "
                   f"-in {csr_path} "
                   f"-out -")

        if cert_config.module_args.days:
            command += f" -days {cert_config.module_args.days}"

        if cert_config.module_args.extension:
            command += f' -extensions {cert_config.module_args.extension}'

        if parent_cert_config is None and cert_config.signed_by is None:
            command += " -selfsign"

        key_config = cert_config.module_args.key if parent_cert_config is None else parent_cert_config.module_args.key
        if key_config.password:
            command += f" -passin pass:{key_config.password}"

        return command

    def _execute_ca_sign(self, command: str) -> str:
        output = self.chroot.run_command(command)

        if output.returncode != 0:
            self.cleanup()
            raise GenCertException(f"Failed to generate certificate: {output.stderr}")

        return output.stdout