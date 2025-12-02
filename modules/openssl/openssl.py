"""OpenSSL cryptographic module implementation."""
import re
# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html

import shutil
import textwrap
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from jinja2 import Template, StrictUndefined

from modules import module_logger
from modules.openssl.config import OpenSSLConfig, OpenSSLModuleArgs, OpenSSLSupportedEngines, GemEngineArgs, \
    OpenSSLEngineArgs
from modules.openssl.db import OpenSSLData
from shared.util import get_needed_libraries
from vism_ca import VismCADatabase, CertificateConfig, CryptoModule
from vism_ca.crypto import CryptoCert
from vism_ca.errors import (
    GenCertException,
    GenCSRException,
    GenPKEYException,
    GenCRLException
)


@dataclass
class OpenSSLCertConfig(CertificateConfig):
    """Certificate configuration for OpenSSL module."""

    module_args: OpenSSLModuleArgs


@dataclass
class OpenSSLCryptoCert(CryptoCert):
    """Certificate for OpenSSL module."""
    config: OpenSSLCertConfig

    @property
    def config_path(self):
        return f"/tmp/{self.config.name}/{self.config.name}.conf"

    @property
    def key_path(self):
        return f"/tmp/{self.config.name}/{self.config.name}.key"

    @property
    def pub_key_path(self):
        return f"/tmp/{self.config.name}/{self.config.name}_pub.key"

    @property
    def csr_path(self):
        return f"/tmp/{self.config.name}/{self.config.name}.csr"

    @property
    def cert_path(self):
        return f"/tmp/{self.config.name}/{self.config.name}.crt"

    @property
    def crl_path(self):
        return f"/tmp/{self.config.name}/{self.config.name}.crl"

    @property
    def database_path(self):
        return f"/tmp/{self.config.name}/{self.config.name}.db"

    @property
    def serial_path(self):
        return f"/tmp/{self.config.name}/serial"

    @property
    def crlnumber_path(self):
        return f"/tmp/{self.config.name}/crlnumber"

    @property
    def certs_path(self):
        return f"/tmp/{self.config.name}/certs"
    

class OpenSSL(CryptoModule):
    """OpenSSL implementation of cryptographic module."""

    config_path: str = "openssl"
    configClass: OpenSSLConfig = OpenSSLConfig
    moduleArgsClass = OpenSSLModuleArgs
    cryptoCertClass = OpenSSLCryptoCert
    config: OpenSSLConfig

    def __init__(self, chroot_dir: str, database: VismCADatabase):
        module_logger.debug("Initializing OpenSSL module")
        self.database = database
        super().__init__(chroot_dir)

    @property
    def openssl_path(self):
        """Get path to openssl binary."""
        return self.config.bin or shutil.which("openssl")

    def _write_openssl_config(self, cert: OpenSSLCryptoCert):
        """Write OpenSSL configuration file to chroot."""
        openssl_config_template_path = (
            cert.config.module_args.config_template or
            self.config.default_config_template
        )

        config_template = ""
        template_path = (
            f'modules/openssl/templates/{openssl_config_template_path}'
        )
        with open(template_path, 'r', encoding='utf-8') as f:
            config_template = f.read()

        profile = self.config.get_profile_by_name(
            cert.config.module_args.profile
        )

        template = Template(
            textwrap.dedent(config_template),
            trim_blocks=True,
            lstrip_blocks=True,
            undefined=StrictUndefined
        ).render({'certificate': cert.config, 'ca_profile': profile})

        self.chroot.write_file(cert.config_path, template.encode("utf-8"))

    def _create_crt_environment(self, cert: OpenSSLCryptoCert) -> None:
        """Create certificate environment in chroot."""
        module_logger.debug(
            "Creating crt environment for '%s'",
            cert.config.name
        )
        self._write_openssl_config(cert)

        if cert.key_pem:
            self.chroot.write_file(cert.key_path, cert.key_pem.encode("utf-8"))
        if cert.pub_key_pem:
            self.chroot.write_file(cert.pub_key_path, cert.pub_key_pem.encode("utf-8"))
        if cert.csr_pem:
            self.chroot.write_file(cert.csr_path, cert.csr_pem.encode("utf-8"))
        if cert.crt_pem:
            self.chroot.write_file(cert.cert_path, cert.crt_pem.encode("utf-8"))

    def _create_ca_environment(self, cert: OpenSSLCryptoCert):
        """Create CA environment in chroot."""
        module_logger.debug(
            "Creating ca environment for '%s'",
            cert.config.name
        )

        self._create_crt_environment(cert)
        openssl_data = self.database.get(
            OpenSSLData,
            OpenSSLData.cert_name == cert.config.name
        )

        if not openssl_data:
            openssl_data = OpenSSLData(cert_name=cert.config.name)

        if openssl_data:
            if not openssl_data.database:
                openssl_data.database = ""
            if not openssl_data.serial:
                openssl_data.serial = "01"
            if not openssl_data.crlnumber:
                openssl_data.crlnumber = "01"

            self.chroot.write_file(
                cert.database_path,
                openssl_data.database.encode("utf-8")
            )
            self.chroot.write_file(
                cert.serial_path,
                openssl_data.serial.encode("utf-8")
            )
            self.chroot.write_file(
                cert.crlnumber_path,
                openssl_data.crlnumber.encode("utf-8")
            )

        self.chroot.create_folder(f"/tmp/{cert.config.name}/certs")

        return openssl_data

    def create_chroot_environment(self):
        """Create chroot environment for OpenSSL."""
        module_logger.debug(
            "Generating chroot environment for openssl module."
        )
        libraries = get_needed_libraries(self.openssl_path)
        self.chroot.create_folder("/tmp")

        for library in libraries:
            self.chroot.copy_file(library)

        self.chroot.copy_file(self.openssl_path)

        if self.config.additional_chroot_dirs:
            for directory in self.config.additional_chroot_dirs:
                self.chroot.copy_folder(directory)

        if self.config.additional_chroot_files:
            for file in self.config.additional_chroot_files:
                self.chroot.copy_file(file)

        if self.config.additional_chroot_libraries:
            for file in self.config.additional_chroot_libraries:
                libraries = get_needed_libraries(file)
                for library in libraries:
                    self.chroot.copy_file(library)
                self.chroot.copy_file(file)

    def _build_csr_sign_command(
            self,
            signing_cert: OpenSSLCryptoCert,
            module_args: OpenSSLModuleArgs
    ) -> str:
        """Build command for signing a CSR."""
        csr_path = "/tmp/to_sign.csr"

        command = (
            f"{self.openssl_path} ca -batch "
            f"-keyfile {signing_cert.key_path} "
            f"-config {signing_cert.config_path} "
            f"-in {csr_path} "
            f"-out -"
        )

        if module_args.days:
            command += f" -days {module_args.days}"

        if module_args.extension:
            command += f' -extensions {module_args.extension}'

        key_config = signing_cert.config.module_args.key
        if key_config.password:
            command += f" -passin pass:{key_config.password}"

        return command

    def _build_ca_sign_command(
            self,
            cert: OpenSSLCryptoCert,
            signing_cert: OpenSSLCryptoCert = None
    ) -> str:
        """Build command for signing a CA certificate."""
        if signing_cert is None:
            signing_key_path = cert.key_path
            config_path = cert.config_path
        else:
            signing_key_path = signing_cert.key_path
            config_path = signing_cert.config_path

        command = (
            f"{self.openssl_path} ca -batch "
            f"-keyfile {signing_key_path} "
            f"-config {config_path} "
            f"-in {cert.csr_path} "
            f"-out -"
        )

        if cert.config.module_args.days:
            command += f" -days {cert.config.module_args.days}"

        if cert.config.module_args.extension:
            command += f' -extensions {cert.config.module_args.extension}'

        if signing_cert is None and cert.config.signed_by is None:
            command += " -selfsign"

        key_config = (
            cert.config.module_args.key if signing_cert is None
            else signing_cert.config.module_args.key
        )
        if key_config.password:
            command += f" -passin pass:{key_config.password}"

        return command

    def _execute_ca_sign(
            self,
            command: str,
            openssl_data: OpenSSLData = None,
            signing_cert: OpenSSLCryptoCert = None
    ) -> str:
        """Execute CA signing command."""
        output = self.chroot.run_command(command)

        if output.returncode != 0:
            self.cleanup()
            raise GenCertException(
                f"Failed to generate certificate: {output.stderr}"
            )

        if openssl_data and signing_cert.config:
            openssl_data.crlnumber = self.chroot.read_file(signing_cert.crlnumber_path)
            openssl_data.serial = self.chroot.read_file(signing_cert.serial_path)
            openssl_data.database = self.chroot.read_file(signing_cert.database_path)
            self.database.save_to_db(openssl_data)

        return output.stdout

    def generate_crl(self, cert: OpenSSLCryptoCert) -> OpenSSLCryptoCert:
        """Generate Certificate Revocation List."""
        module_logger.info(
            "Generating crl for '%s'",
            cert.config.name
        )
        openssl_data = self._create_ca_environment(cert)

        if not openssl_data:
            self.cleanup()
            raise GenCRLException("Cannot generate CRL before certificate.")

        if cert.config.module_args.engine is None:
            command = (
                f"{self.openssl_path} ca -batch "
                f"-keyfile {cert.key_path} "
                f"-config {cert.config_path} "
                f"-gencrl "
                f"-out -"
            )
            password = cert.config.module_args.key.password
            if password:
                command += f" -passin pass:{password}"
        elif cert.config.module_args.engine == OpenSSLSupportedEngines.gem.value:
            command = (
                f"{self.openssl_path} ca -engine gem -batch "
                f"-key {cert.key_pem} -keyform engine -keyfile {cert.pub_key_path} "
                f"-config {cert.config_path} "
                f"-gencrl "
                f"-out -"
            )
        else:
            self.cleanup()
            raise GenPKEYException(
                f"Invalid engine value in config: {cert.config.module_args.engine}"
            )

        output = self.chroot.run_command(command)
        acceptable_rc = [0]
        if cert.config.module_args.engine == OpenSSLSupportedEngines.gem.value:
            acceptable_rc = [139, 0, -11]
        if output.returncode not in acceptable_rc:
            self.cleanup()
            raise GenCRLException(
                f"Failed to generate crl: "
                f"\nrc: {output.returncode}"
                f"\nstderr: {output.stderr}"
                f"\nstdout: {output.stdout}"
            )

        openssl_data.crlnumber = self.chroot.read_file(cert.crlnumber_path)
        openssl_data.serial = self.chroot.read_file(cert.serial_path)
        openssl_data.database = self.chroot.read_file(cert.database_path)

        self.database.save_to_db(openssl_data)
        self.cleanup()

        cert.crl_pem = output.stdout

        return cert

    def generate_csr(self, cert: OpenSSLCryptoCert) -> OpenSSLCryptoCert:
        """Generate Certificate Signing Request."""
        module_logger.info(
            "Generating csr for '%s'",
            cert.config.name
        )

        self._create_crt_environment(cert)

        if cert.config.module_args.engine is None:
            command = (
                f"{self.openssl_path} req -batch -new "
                f"-config {cert.config_path} -key {cert.key_path}"
            )
            password = cert.config.module_args.key.password
            if password:
                command += f" -passin pass:{password}"
        elif cert.config.module_args.engine == OpenSSLSupportedEngines.gem.value:
            command = (
                f"{self.openssl_path} req -engine gem -config {cert.config_path} -batch -new "
                f"-key {cert.key_path} -keyform engine -out /tmp/csr.pem"
            )
            engine_args: Optional[GemEngineArgs] = cert.config.module_args.engine_args
            if engine_args:
                self.chroot.write_file(engine_args.pin_file, engine_args.pin.encode("utf-8"))
        else:
            self.cleanup()
            raise GenPKEYException(
                f"Invalid engine value in config: {cert.config.module_args.engine}"
            )

        output = self.chroot.run_command(command)
        acceptable_rc = [0]
        if cert.config.module_args.engine == OpenSSLSupportedEngines.gem.value:
            acceptable_rc = [139, 0, -11]

        if output.returncode not in acceptable_rc:
            self.cleanup()
            raise GenCSRException(f"Failed to generate csr: {output.stderr}")

        csr_pem = self.chroot.read_file("/tmp/csr.pem")
        self.cleanup()
        cert.csr_pem = csr_pem
        return cert

    def generate_private_key(self, cert: OpenSSLCryptoCert) -> OpenSSLCryptoCert:
        """Generate private key and return private and public key PEMs."""
        module_logger.info(
            "Generating private key for '%s'.",
            cert.config.name
        )
        self._create_crt_environment(cert)

        key_config = cert.config.module_args.key

        if cert.config.module_args.engine is None:
            command = (
                f"{self.openssl_path} genpkey -config {cert.config_path} "
                f"-algorithm {key_config.algorithm}"
            )
            if key_config.password:
                command += f" -aes-256-cbc -pass pass:{key_config.password}"
        elif cert.config.module_args.engine == OpenSSLSupportedEngines.gem.value:
            command = (
                f"{self.openssl_path} genpkey -engine gem -config {cert.config_path} "
                f"-algorithm {key_config.algorithm} -out {cert.pub_key_path}"
            )
            engine_args: Optional[GemEngineArgs] = cert.config.module_args.engine_args
            if engine_args:
                self.chroot.write_file(engine_args.pin_file, engine_args.pin.encode("utf-8"))

        else:
            self.cleanup()
            raise GenPKEYException(
                f"Invalid engine value in config: {cert.config.module_args.engine}"
            )

        if key_config.algorithm == "RSA" and key_config.bits:
            command += f" -pkeyopt rsa_keygen_bits:{key_config.bits}"

        output = self.chroot.run_command(command)
        acceptable_rc = [0]
        if cert.config.module_args.engine == OpenSSLSupportedEngines.gem.value:
            acceptable_rc = [139, 0, -11]

        if output.returncode not in acceptable_rc:
            self.cleanup()
            raise GenPKEYException(
                "Failed to generate private key:"
                f"\nrc: {output.returncode}"
                f"\nstderr:{output.stderr}"
            )

        if 'CKA_ID: ' not in output.stderr:
            raise GenPKEYException(
                "CKA_ID not found in command stderr stream."
                "Ensure the LogLevel is set to 6 and that you're using the modified gem engine code."
            )

        if cert.config.module_args.engine == OpenSSLSupportedEngines.gem.value:
            stderr_cka_id = [
                match.group(1) for line in output.stderr.splitlines() if "CKA_ID" in line
                for match in [re.search(r'"([^"]+)"', line)] if match
            ]
            private_key_label = stderr_cka_id[0]
            private_key_pem = private_key_label
            public_key_pem = self.chroot.read_file(cert.pub_key_path)
        else:
            try:
                private_key_pem = output.stdout
                password_bytes = (
                    key_config.password.encode("utf-8")
                    if key_config.password else None
                )
                private_key = serialization.load_pem_private_key(
                    private_key_pem.encode(),
                    password=password_bytes,
                    backend=default_backend()
                )

                public_key = private_key.public_key()
                public_key_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode("utf-8")
            except Exception as exc:
                self.cleanup()
                raise GenPKEYException(
                    f"Failed to generate private key: {exc}"
                ) from exc

        self.cleanup()

        cert.key_pem = private_key_pem
        cert.pub_key_pem = public_key_pem

        return cert

    def cleanup(self, full: bool = False):
        """Clean up temporary files in chroot."""
        try:
            self.chroot.delete_folder("/tmp")
        except FileNotFoundError:
            pass

        if full:
            self.chroot.delete_folder("/")

    def generate_ca_certificate(self, cert: OpenSSLCryptoCert) -> OpenSSLCryptoCert:
        """Generate CA certificate."""
        module_logger.info(
            "Generating ca certificate for '%s'",
            cert.config.name
        )

        openssl_data = self._create_ca_environment(cert)
        command = self._build_ca_sign_command(cert)
        cert_pem = self._execute_ca_sign(command, openssl_data, cert)

        self.cleanup()
        cert.crt_pem = cert_pem
        return cert

    def sign_csr(
        self,
        cert: OpenSSLCryptoCert,
        signing_cert: OpenSSLCryptoCert,
        module_args: OpenSSLModuleArgs
    ) -> OpenSSLCryptoCert:
        """Sign a Certificate Signing Request."""
        module_logger.info("Signing csr with '%s'", signing_cert.config.name)
        signing_openssl_data = self._create_ca_environment(signing_cert)

        self.chroot.write_file("/tmp/to_sign.csr", cert.csr_pem.encode("utf-8"))
        command = self._build_csr_sign_command(signing_cert, module_args)

        cert_pem = self._execute_ca_sign(command, signing_openssl_data, signing_cert)
        self.cleanup()

        cert.crt_pem = cert_pem
        return cert

    def sign_ca_certificate(
        self,
        cert: OpenSSLCryptoCert,
        signing_cert: OpenSSLCryptoCert,
    ) -> OpenSSLCryptoCert:
        """Sign a CA certificate with another CA certificate."""
        module_logger.info(
            "Signing ca certificate for '%s' with '%s'",
            cert.config.name,
            signing_cert.config.name
        )

        signing_openssl_data = self._create_ca_environment(signing_cert)
        openssl_data = self._create_ca_environment(cert)
        command = self._build_ca_sign_command(cert, signing_cert)
        cert_pem = self._execute_ca_sign(command, signing_openssl_data, signing_cert)

        openssl_data.crlnumber = self.chroot.read_file(cert.crlnumber_path)
        openssl_data.serial = self.chroot.read_file(cert.serial_path)
        openssl_data.database = self.chroot.read_file(cert.database_path)

        self.database.save_to_db(openssl_data)
        self.cleanup()

        cert.crt_pem = cert_pem
        return cert