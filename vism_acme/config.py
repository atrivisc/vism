"""Configuration module for VISM ACME server."""
# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html

import base64
import os
import socket
import ipaddress
import logging
from dataclasses import field
from typing import Optional, ClassVar

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import CertificateSigningRequest, Extension
from pydantic import field_validator
from pydantic.dataclasses import dataclass

from shared.config import VismConfig
from shared.util import (
    is_valid_subnet,
    snake_to_camel,
    fix_base64_padding
)
from vism_acme import ACMEProblemResponse


@dataclass
class DomainValidation:
    """Domain validation configuration for access control."""

    domain: str = None
    clients: list[str] = None

    def to_dict(self):
        """Convert domain validation to dictionary."""
        return {
            "domain": self.domain,
            "clients": self.clients,
        }


@dataclass
class Profile:  # pylint: disable=too-many-instance-attributes
    """ACME profile configuration."""

    name: str
    ca: str
    ca_pem: str
    module_args: dict = None
    enabled: bool = True
    default: bool = False

    allowed_extension_oids: list[str] = None
    allowed_basic_constraints: list[str] = None
    allowed_key_usage: list[str] = None
    allowed_extended_key_usage_oids: list[str] = None

    supported_challenge_types: list[str] = None
    pre_validated: list[DomainValidation] = None
    acl: list[DomainValidation] = None
    cluster: list[str] = None

    def validate_csr(
            self,
            csr_der_b64: str,
            ordered_identifiers: list[str]
    ) -> CertificateSigningRequest:
        # pylint: disable=too-many-branches
        """Validate a Certificate Signing Request."""
        try:
            csr_data = base64.urlsafe_b64decode(
                fix_base64_padding(csr_der_b64)
            )
            csr = x509.load_der_x509_csr(
                data=csr_data,
                backend=default_backend()
            )
        except Exception as exc:
            raise ACMEProblemResponse(
                error_type="badCSR",
                title="Invalid CSR.",
                detail=str(exc)
            ) from exc

        if isinstance(csr.public_key(), rsa.RSAPublicKey):
            if csr.public_key().key_size < 2048:
                raise ACMEProblemResponse(
                    error_type="badCSR",
                    title="RSA key too small.",
                    detail=(
                        f"RSA key size must be at least 2048 bits, "
                        f"got {csr.public_key().key_size}"
                    )
                )

        if not csr.is_signature_valid:
            raise ACMEProblemResponse(
                error_type="badCSR",
                title="Invalid CSR signature."
            )

        try:
            csr_domains = [
                str(name.value) for name in
                csr.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value
            ]
        except Exception as exc:
            raise ACMEProblemResponse(
                error_type="badCSR",
                title="Failed to extract alt names from CSR.",
                detail=str(exc)
            ) from exc

        if set(csr_domains) != set(ordered_identifiers):
            raise ACMEProblemResponse(
                error_type="badCSR",
                title="CSR identifiers don't match authorized identifiers.",
                detail=(
                    f"CSR domains: {csr_domains}, "
                    f"Authorized domains: {ordered_identifiers}"
                )
            )

        self._validate_csr_extensions(csr)

        return csr

    def _validate_csr_extensions(self, csr: CertificateSigningRequest):
        csr_extensions: list[x509.Extension] = list(iter(csr.extensions))
        for ext in csr_extensions:
            if ext.oid.dotted_string not in self.allowed_extension_oids:
                raise ACMEProblemResponse(
                    error_type="badCSR",
                    title=(
                        f"CSR contains forbidden extension: {ext.oid}."
                    )
                )

            if ext.oid == x509.oid.ExtensionOID.BASIC_CONSTRAINTS:
                self._validate_csr_basic_constraint(ext)

            if ext.oid == x509.oid.ExtensionOID.KEY_USAGE:
                self._validate_csr_key_usage(ext)

            if ext.oid == x509.oid.ExtensionOID.EXTENDED_KEY_USAGE:
                self._validate_extended_key_usage(ext)

            if ext.oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                self._validate_csr_san(ext)

    @staticmethod
    def _validate_csr_san(ext: Extension):
        for name in ext.value:
            if type(name) not in [x509.DNSName, x509.IPAddress]:
                raise ACMEProblemResponse(
                    error_type="badCSR",
                    title=(
                        f"CSR contains forbidden alt name: "
                        f"{name.value}."
                    )
                )

    def _validate_extended_key_usage(self, ext: Extension):
        for ext_key_usage in ext.value:
            if (ext_key_usage.dotted_string not in
                    self.allowed_extended_key_usage_oids):
                # pylint: disable=protected-access
                raise ACMEProblemResponse(
                    error_type="badCSR",
                    title=(
                        f"CSR contains forbidden extended key "
                        f"usage: {ext_key_usage._name}."
                    )
                )

    def _validate_csr_key_usage(self, ext: Extension):
        for key, value in vars(ext.value).items():
            if not value:
                continue

            key_usage = snake_to_camel(key.lstrip('_'))
            if key_usage not in self.allowed_key_usage:
                raise ACMEProblemResponse(
                    error_type="badCSR",
                    title=(
                        f"CSR contains forbidden key usage: "
                        f"{key_usage}."
                    )
                )

    def _validate_csr_basic_constraint(self, ext: Extension):
        if ext.value.ca:
            raise ACMEProblemResponse(
                error_type="badCSR",
                title="CSR must not be for a CA certificate."
            )
        if ext.value.path_length and ext.value.path_length != 0:
            raise ACMEProblemResponse(
                error_type="badCSR",
                title="CSR must have a path length of 0."
            )
        if not ext.critical:
            raise ACMEProblemResponse(
                error_type="badCSR",
                title="Basic Constraints extension must be critical."
            )

    async def validate_client(
            self,
            client_ip: str,
            domain: str
    ) -> None:
        """Validate that a client has authority over a domain."""
        try:
            domain_ips = {
                x[4][0] for x in socket.getaddrinfo(domain, None)
            }
        except socket.gaierror as exc:
            raise ACMEProblemResponse(
                error_type="dns",
                title=f"Domain {domain} does not exist",
                detail=str(exc)
            ) from exc
        except Exception as exc:
            raise ACMEProblemResponse(
                error_type="serverInternal",
                title="Unknown error occurred while validating domain",
                detail=str(exc)
            ) from exc

        if len(domain_ips) == 0:
            raise ACMEProblemResponse(
                error_type="dns",
                title="Domain exists but has no IPs",
            )

        pre_validated = self._client_is_valid(client_ip, domain)
        client_allowed = self._client_is_allowed(client_ip, domain)
        client_in_cluster = self._client_in_cluster(client_ip)

        if (not pre_validated and not client_allowed and
                client_ip not in domain_ips and not client_in_cluster):
            raise ACMEProblemResponse(
                error_type="unauthorized",
                title=(
                    f"Client IP '{client_ip}' has not authority over "
                    f"'{domain}'"
                ),
                detail=(
                    f"Pre-validated: {pre_validated}, "
                    f"Client Allowed: {client_allowed}"
                ),
            )

    def to_dict(self):
        """Convert profile to dictionary."""
        return {
            "name": self.name,
            "ca": self.ca,
            "module_args": self.module_args,
            "enabled": self.enabled,
            "default": self.default,
            "supported_challenge_types": self.supported_challenge_types,
            "pre_validated": (
                [dv.to_dict() for dv in self.pre_validated]
                if self.pre_validated else None
            ),
            "acl": (
                [dv.to_dict() for dv in self.acl]
                if self.acl else None
            ),
            "cluster": self.cluster,
        }

    @field_validator("supported_challenge_types")
    @classmethod
    def challenge_types_must_be_valid(cls, v):
        """Validate challenge types."""
        if v and not isinstance(v, list):
            raise ValueError("Profile challenge types must be a list.")

        if v and "http-01" not in v and "dns-01" not in v:
            raise ValueError(
                "Profile challenge types must contain 'http-01' or 'dns-01'."
            )

        return v

    def _client_is_valid(self, client_ip: str, domain: str) -> bool:
        """Check if client is pre-validated for a domain."""
        if not self.pre_validated:
            return False

        for domain_validation in self.pre_validated:
            if domain_validation.domain == domain:
                return self._client_in_dv(client_ip, domain_validation)

        return False

    def _client_in_cluster(
            self,
            client_ip: str
    ) -> bool | ACMEProblemResponse:
        """Check if client is in the cluster."""
        if not self.cluster:
            return False

        client_hostnames = []
        try:
            host_by_addr = socket.gethostbyaddr(client_ip)
            client_hostnames.append(host_by_addr[0])
            client_hostnames += host_by_addr[1]
        except socket.herror:
            pass  # No PTR so we skip
        except Exception as exc:  # pylint: disable=broad-exception-caught
            return ACMEProblemResponse(
                error_type="serverInternal",
                title="Unknown error occurred while validating domain",
                detail=str(exc)
            )

        subnets = [
            subnet for subnet in self.cluster if is_valid_subnet(subnet)
        ]
        client_ip_in_subnets = False
        for subnet in subnets:
            if client_ip in subnet:
                client_ip_in_subnets = True
                break

        return (set(client_hostnames) & set(self.cluster) or
                client_ip in self.cluster or
                client_ip_in_subnets)

    def _client_in_dv(
            self,
            client_ip: str,
            domain: DomainValidation
    ) -> bool | ACMEProblemResponse:
        """Check if client is in domain validation list."""
        client_hostnames = []
        try:
            host_by_addr = socket.gethostbyaddr(client_ip)
            client_hostnames.append(host_by_addr[0])
            client_hostnames += host_by_addr[1]
        except socket.herror:
            pass  # No PTR so we skip
        except Exception as exc:  # pylint: disable=broad-exception-caught
            return ACMEProblemResponse(
                error_type="serverInternal",
                title="Unknown error occurred while validating domain",
                detail=str(exc)
            )

        subnets = [
            subnet for subnet in domain.clients if is_valid_subnet(subnet)
        ]
        client_ip_in_subnets = False
        for subnet in subnets:
            if client_ip in subnet:
                client_ip_in_subnets = True
                break

        return (set(client_hostnames) & set(domain.clients) or
                domain.clients == ["*"] or
                client_ip in domain.clients or
                client_ip_in_subnets)

    def _client_is_allowed(
            self,
            client_ip: str,
            domain: str
    ) -> bool | ACMEProblemResponse:
        """Check if client is allowed for a domain via ACL."""
        if not self.acl:
            return False

        for domain_validation in self.acl:
            if domain_validation.domain == domain:
                return self._client_in_dv(client_ip, domain_validation)

        return False

    def __post_init__(self):
        if self.supported_challenge_types is None:
            self.supported_challenge_types = ["http-01"]

        if self.allowed_extension_oids is None:
            self.allowed_extension_oids = [
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME.dotted_string,
                x509.oid.ExtensionOID.BASIC_CONSTRAINTS.dotted_string,
                x509.oid.ExtensionOID.KEY_USAGE.dotted_string,
                x509.oid.ExtensionOID.EXTENDED_KEY_USAGE.dotted_string,
            ]

        if self.allowed_basic_constraints is None:
            self.allowed_basic_constraints = [
                "CA:FALSE",
                "pathlen:0"
            ]

        if self.allowed_key_usage is None:
            self.allowed_key_usage = [
                "digitalSignature",
                "keyEncipherment",
                "keyAgreement",
                "dataEncipherment"
            ]

        if self.allowed_extended_key_usage_oids is None:
            self.allowed_extended_key_usage_oids = [
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH.dotted_string,
            ]


@dataclass
class Http01:
    """HTTP-01 challenge configuration."""

    port: int = 28080
    follow_redirect: bool = True
    timeout_seconds: int = 2
    retries: int = 1
    retry_delay_seconds: int = 0.1

    @field_validator("port")
    @classmethod
    def port_must_be_valid(cls, v):
        """Validate port number."""
        if v < 1 or v > 65535:
            raise ValueError("Port must be between 1 and 65535")
        return v


@dataclass
class API:
    """API server configuration."""

    host: str = "0.0.0.0"
    port: int = 8080

    @field_validator("port")
    @classmethod
    def port_must_be_valid(cls, v):
        """Validate port number."""
        if v < 1 or v > 65535:
            raise ValueError("Port must be between 1 and 65535")
        return v

    @field_validator("host")
    @classmethod
    def host_must_be_valid(cls, v):
        """Validate host is a valid IP address."""
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError as exc:
            raise ValueError("Host must be a valid IP address") from exc


acme_logger = logging.getLogger("vism_acme")


@dataclass
class AcmeConfig(VismConfig):
    """Main configuration class for VISM ACME server."""

    __path__: ClassVar[str] = "vism_acme"
    __config_dir__: ClassVar[str] = f"{os.getenv("CONFIG_DIR", os.getcwd()).rstrip("/")}"
    __config_file__: ClassVar[str] = f"{__config_dir__}/vism_acme.yaml"

    profiles: list[Profile] = field(default_factory=list)
    http01: Http01 = field(default_factory=Http01)
    api: API = field(default_factory=API)
    nonce_ttl_seconds: str = "300"
    retry_after_seconds: str = "5"
    default_profile: Profile = field(init=False)

    def __post_init__(self):
        self.validate_config()

    def validate_config(self):
        """Validate the ACME configuration."""
        acme_logger.info("Validating ACME config")
        if not self.profiles:
            raise ValueError("No profiles found in config.")

        default_profiles = list(
            filter(lambda profile: profile.default, self.profiles)
        )
        if len(default_profiles) > 1:
            raise ValueError("Multiple default profiles found.")

        if not default_profiles:
            raise ValueError("No default profile found.")

        self.default_profile = default_profiles[0]

    def get_profile_by_name(self, name: str) -> Optional[Profile]:
        """Get profile by name, or return default if name is empty."""
        acme_logger.debug("Getting profile '%s'", name)
        if not name:
            return self.default_profile

        profiles = list(
            filter(lambda profile: profile.name == name, self.profiles)
        )
        if len(profiles) == 0:
            raise ACMEProblemResponse(
                error_type="invalidProfile",
                title=f"Profile '{name}' not found."
            )
        if len(profiles) > 1:
            raise ACMEProblemResponse(
                error_type="invalidProfile",
                title=f"Multiple profiles found with the name: '{name}'"
            )

        # juuuuii8u9 | Comment from my cat

        profile = profiles[0]
        if not profile.enabled:
            raise ACMEProblemResponse(
                error_type="invalidProfile",
                title=f"Profile '{name}' is disabled."
            )

        return profile
