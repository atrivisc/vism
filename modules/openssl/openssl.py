import logging
import shutil
import textwrap

from typing import Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from modules.openssl.config import OpenSSLConfig, CAProfile, OpenSSLKeyConfig, OpenSSLModuleArgs
from modules.openssl.errors import ProfileNotFound, MultipleProfilesFound
from vism_ca.config import CertificateConfig
from vism_ca.db.database import Certificate
from vism_ca.util.errors import GenCertException, GenCSRException
from vism_ca.util.util import get_needed_libraries
from jinja2 import Template, StrictUndefined
from vism_ca.crypto.crypto import Crypto

logger = logging.getLogger(__name__)


class OpenSSL(Crypto):
    config_path: str = "openssl"
    configClass: OpenSSLConfig = OpenSSLConfig

    def __init__(self, chroot_dir: str):
        self.config: Optional[OpenSSLConfig] = None
        super().__init__(chroot_dir)

    @property
    def openssl_path(self):
        return self.config.bin or shutil.which("openssl")

    def get_profile(self, cert: CertificateConfig) -> CAProfile:
        profiles = list(filter(lambda profile: profile.name == cert.module_args.profile, self.config.ca_profiles))
        if len(profiles) == 0:
            raise ProfileNotFound(f"OpenSSL profile {cert.module_args.profile} not found.")

        if len(profiles) > 1:
            raise MultipleProfilesFound(f"Multiple profiles found with the name: {cert.module_args.profile}")

        return profiles[0]

    def write_openssl_config(self, certificate: CertificateConfig, profile: CAProfile):
        openssl_config_template_path = certificate.module_args.config_template or self.config.default_config_template

        config_template = ""
        with open(f'modules/openssl/templates/{openssl_config_template_path}', 'r') as f:
            config_template = f.read()

        template = Template(textwrap.dedent(config_template), trim_blocks=True, lstrip_blocks=True, undefined=StrictUndefined)
        data = {
            'certificate': certificate,
            'ca_profile': profile,
            'chroot_dir': self.chroot_dir
        }

        output = template.render(data)

        self.write_file_in_chroot(f"/tmp/{certificate.name}/{certificate.name}.conf", output.encode("utf-8"))

    def generate_chroot_environment(self):
        libraries = get_needed_libraries(self.openssl_path)
        self.create_folder_in_chroot("/tmp")

        for library in libraries:
            self.copy_file_to_chroot(library)

        self.copy_file_to_chroot(self.openssl_path)

    def generate_ca_certificate(self, cert_config: CertificateConfig, key_pem: str, csr_pem: str) -> Certificate:
        profile = self.get_profile(cert_config)
        self.write_openssl_config(cert_config, profile)

        key_path = f"/tmp/{cert_config.name}/{cert_config.name}.key"
        self.write_file_in_chroot(key_path, key_pem.encode("utf-8"))

        csr_path = f"/tmp/{cert_config.name}/{cert_config.name}.csr"
        self.write_file_in_chroot(csr_path, csr_pem.encode("utf-8"))

        module_args: OpenSSLModuleArgs = cert_config.module_args
        key: OpenSSLKeyConfig = cert_config.module_args.key

        password = None
        if key.password:
            password = key.password

        cert_days = profile.default_ca.default_days
        if module_args.days:
            cert_days = module_args.days

        command = (f"{self.openssl_path} ca -batch "
                   f"-keyfile {key_path} "
                   f"-config /tmp/{cert_config.name}/{cert_config.name}.conf "
                   f"-in {csr_path} "
                   f"-days {cert_days} "
                   f"-out -")

        if module_args.extension:
            command += f' -extensions {module_args.extension}'

        if password:
            command += f" -passin pass:{password}"

        output = self.run_command_in_chroot(command)

        if output.returncode != 0:
            raise GenCertException(f"Failed to generate certificate: {output.stderr}")

        return output.stdout

    def generate_csr(self, cert_config: CertificateConfig, key_pem: str) -> Certificate:
        profile = self.get_profile(cert_config)
        self.write_openssl_config(cert_config, profile)

        key_path = f"/tmp/{cert_config.name}/{cert_config.name}.key"
        self.write_file_in_chroot(key_path, key_pem.encode("utf-8"))

        key: OpenSSLKeyConfig = cert_config.module_args.key

        password = None
        if key.password:
            password = key.password

        command = f"{self.openssl_path} req -batch -new -config /tmp/{cert_config.name}/{cert_config.name}.conf -key {key_path}"
        if password:
            command += f" -passin pass:{password}"

        output = self.run_command_in_chroot(command)

        if output.returncode != 0:
            raise GenCSRException(f"Failed to generate csr: {output.stderr}")

        return output.stdout

    def cleanup(self, full: bool = False):
        self.delete_folder_in_chroot("/tmp")
        if full:
            self.delete_folder_in_chroot("/")


    def generate_private_key(self, cert_config: CertificateConfig) -> tuple[str, str]:
        profile = self.get_profile(cert_config)
        self.write_openssl_config(cert_config, profile)

        key: OpenSSLKeyConfig = cert_config.module_args.key

        password = None
        if key.password:
            password = key.password

        command = f"{self.openssl_path} genpkey -config /tmp/{cert_config.name}/{cert_config.name}.conf -algorithm {key.algorithm}"
        if key.algorithm == "RSA" and key.bits:
            command += f" -pkeyopt rsa_keygen_bits:{key.bits}"

        if password:
            command += f" -aes-256-cbc -pass pass:{password}"

        output = self.run_command_in_chroot(command)

        if output.returncode != 0:
            raise GenCSRException(f"Failed to generate csr: {output.stderr}")

        private_key_pem = output.stdout

        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=password.encode("utf-8") if password else None,
            backend=default_backend()
        )

        public_key = private_key.public_key()

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

        return private_key_pem, public_key_pem