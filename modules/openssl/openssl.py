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
from modules.openssl.errors import ProfileNotFound, MultipleProfilesFound
from vism_ca.config import CertificateConfig
from vism_ca.db.database import Certificate
from vism_ca.util.errors import GenCertException, GenCSRException, GenPKEYException, GenCRLException
from vism_ca.util.util import get_needed_libraries
from jinja2 import Template, StrictUndefined
from vism_ca.crypto.crypto import Crypto

logger = logging.getLogger(__name__)

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

    def get_profile(self, cert: OpenSSLCertConfig) -> CAProfile:
        profiles = list(filter(lambda profile: profile.name == cert.module_args.profile, self.config.ca_profiles))
        if len(profiles) == 0:
            raise ProfileNotFound(f"OpenSSL profile {cert.module_args.profile} not found.")

        if len(profiles) > 1:
            raise MultipleProfilesFound(f"Multiple profiles found with the name: {cert.module_args.profile}")

        return profiles[0]

    def write_openssl_config(self, certificate: OpenSSLCertConfig, profile: CAProfile):
        openssl_config_template_path = certificate.module_args.config_template or self.config.default_config_template

        config_template = ""
        with open(f'modules/openssl/templates/{openssl_config_template_path}', 'r') as f:
            config_template = f.read()

        template = Template(textwrap.dedent(config_template), trim_blocks=True, lstrip_blocks=True, undefined=StrictUndefined)
        data = {
            'certificate': certificate,
            'ca_profile': profile
        }

        output = template.render(data)

        self.chroot.write_file(f"/tmp/{certificate.name}/{certificate.name}.conf", output.encode("utf-8"))

    def generate_chroot_environment(self):
        libraries = get_needed_libraries(self.openssl_path)
        self.chroot.create_folder("/tmp")

        for library in libraries:
            self.chroot.copy_file(library)

        self.chroot.copy_file(self.openssl_path)

    def create_ca_environment(self, cert_config: OpenSSLCertConfig, key_pem: str, csr_pem: str = None, crt_pem: str = None, openssl_data: OpenSSLData = None):
        key_path = f"/tmp/{cert_config.name}/{cert_config.name}.key"
        self.chroot.write_file(key_path, key_pem.encode("utf-8"))

        if csr_pem:
            csr_path = f"/tmp/{cert_config.name}/{cert_config.name}.csr"
            self.chroot.write_file(csr_path, csr_pem.encode("utf-8"))

        if crt_pem:
            crt_path = f"/tmp/{cert_config.name}/{cert_config.name}.crt"
            self.chroot.write_file(crt_path, crt_pem.encode("utf-8"))

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

    def generate_crl(self, cert_config: OpenSSLCertConfig, key_pem: str, crt_pem: str):
        profile = self.get_profile(cert_config)
        self.write_openssl_config(cert_config, profile)

        cert = x509.load_pem_x509_certificate(crt_pem.encode(), default_backend())
        cert_serial = format(cert.serial_number, 'x')
        openssl_data = OpenSSLData.get_by_cert_serial(cert_serial)
        if not openssl_data:
            raise GenCRLException(f"Cannot generate CRL before certificate.")

        self.create_ca_environment(cert_config, key_pem, crt_pem=crt_pem, openssl_data=openssl_data)

        key_config = cert_config.module_args.key
        key_path = f"/tmp/{cert_config.name}/{cert_config.name}.key"

        command = (f"{self.openssl_path} ca -batch "
                   f"-keyfile {key_path} "
                   f"-config /tmp/{cert_config.name}/{cert_config.name}.conf "
                   f"-gencrl "
                   f"-out -")

        if key_config.password:
            command += f" -passin pass:{key_config.password}"

        output = self.chroot.run_command(command)
        if output.returncode != 0:
            raise GenCRLException(f"Failed to generate crl: {output.stderr}")

        openssl_data.crlnumber = self.chroot.read_file(f"/tmp/{cert_config.name}/crlnumber")
        openssl_data.serial = self.chroot.read_file(f"/tmp/{cert_config.name}/serial")
        openssl_data.database = self.chroot.read_file(f"/tmp/{cert_config.name}/{cert_config.name}.db")

        openssl_data.save_to_db()
        self.cleanup()

        return output.stdout

    def generate_ca_certificate(self, cert_config: OpenSSLCertConfig, key_pem: str, csr_pem: str) -> Certificate:
        profile = self.get_profile(cert_config)
        self.write_openssl_config(cert_config, profile)

        openssl_data = OpenSSLData.get_by_cert_name(cert_config.name)
        if openssl_data:
            raise GenCertException(f"Certificate with name {cert_config.name} already exists.")

        openssl_data = OpenSSLData(cert_name=cert_config.name)

        self.create_ca_environment(cert_config, key_pem, csr_pem=csr_pem, openssl_data=openssl_data)

        key_config = cert_config.module_args.key
        key_path = f"/tmp/{cert_config.name}/{cert_config.name}.key"
        csr_path = f"/tmp/{cert_config.name}/{cert_config.name}.csr"
        cert_days = profile.default_ca.default_days
        if cert_config.module_args.days:
            cert_days = cert_config.module_args.days

        command = (f"{self.openssl_path} ca -batch "
                   f"-keyfile {key_path} "
                   f"-config /tmp/{cert_config.name}/{cert_config.name}.conf "
                   f"-in {csr_path} "
                   f"-days {cert_days} "
                   f"-out -")

        if cert_config.module_args.extension:
            command += f' -extensions {cert_config.module_args.extension}'

        if cert_config.signed_by is None:
            command += f" -selfsign"

        if key_config.password:
            command += f" -passin pass:{key_config.password}"

        output = self.chroot.run_command(command)

        if output.returncode != 0:
            raise GenCertException(f"Failed to generate certificate: {output.stderr}")

        cert = x509.load_pem_x509_certificate(output.stdout.encode(), default_backend())
        cert_serial = format(cert.serial_number, 'x')

        openssl_data.cert_serial = cert_serial
        openssl_data.crlnumber = self.chroot.read_file(f"/tmp/{cert_config.name}/crlnumber")
        openssl_data.serial = self.chroot.read_file(f"/tmp/{cert_config.name}/serial")
        openssl_data.database = self.chroot.read_file(f"/tmp/{cert_config.name}/{cert_config.name}.db")

        openssl_data.save_to_db()
        self.cleanup()

        return output.stdout

    def generate_csr(self, cert_config: OpenSSLCertConfig, key_pem: str) -> Certificate:
        profile = self.get_profile(cert_config)
        self.write_openssl_config(cert_config, profile)
        self.create_ca_environment(cert_config, key_pem)

        key_path = f"/tmp/{cert_config.name}/{cert_config.name}.key"
        command = f"{self.openssl_path} req -batch -new -config /tmp/{cert_config.name}/{cert_config.name}.conf -key {key_path}"
        if cert_config.module_args.key.password:
            command += f" -passin pass:{cert_config.module_args.key.password}"

        output = self.chroot.run_command(command)
        if output.returncode != 0:
            raise GenCSRException(f"Failed to generate csr: {output.stderr}")

        self.cleanup()

        return output.stdout

    def cleanup(self, full: bool = False):
        self.chroot.delete_folder("/tmp")
        if full:
            self.chroot.delete_folder("/")

    def generate_private_key(self, cert_config: OpenSSLCertConfig) -> tuple[str, str]:
        profile = self.get_profile(cert_config)
        self.write_openssl_config(cert_config, profile)

        key_config = cert_config.module_args.key

        command = f"{self.openssl_path} genpkey -config /tmp/{cert_config.name}/{cert_config.name}.conf -algorithm {key_config.algorithm}"
        if key_config.algorithm == "RSA" and key_config.bits:
            command += f" -pkeyopt rsa_keygen_bits:{key_config.bits}"
        if key_config.password:
            command += f" -aes-256-cbc -pass pass:{key_config.password}"

        output = self.chroot.run_command(command)

        if output.returncode != 0:
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
            raise GenPKEYException(f"Failed to generate private key: {e}")

        self.cleanup()

        return private_key_pem, public_key_pem