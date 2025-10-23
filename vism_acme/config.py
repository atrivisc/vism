import base64
import socket
import ipaddress
import logging
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import CertificateSigningRequest
from pydantic import field_validator
from pydantic.dataclasses import dataclass
from typing import Optional

from shared.config import Config
from shared.util import is_valid_subnet, snake_to_camel
from vism_acme.schema.response import ACMEProblemResponse
from vism_acme.util import fix_base64_padding

logger = logging.getLogger(__name__)

@dataclass
class DomainValidation:
    domain: str = None
    clients: list[str] = None

    def to_dict(self):
        return {
            "domain": self.domain,
            "clients": self.clients,
        }

@dataclass
class Profile:
    name: str
    ca: str
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

    def validate_csr(self, csr_der_b64: str, ordered_identifiers: list[str]) -> CertificateSigningRequest:
        try:
            csr_data = base64.urlsafe_b64decode(fix_base64_padding(csr_der_b64))
            csr = x509.load_der_x509_csr(data=csr_data, backend=default_backend())
        except Exception as e:
            raise ACMEProblemResponse(type="badCSR", title="Invalid CSR.", detail=str(e))

        if isinstance(csr.public_key(), rsa.RSAPublicKey):
            if csr.public_key().key_size < 2048:
                raise ACMEProblemResponse(type="badCSR", title="RSA key too small.", detail=f"RSA key size must be at least 2048 bits, got {csr.public_key().key_size}")

        if not csr.is_signature_valid:
            raise ACMEProblemResponse(type="badCSR", title="Invalid CSR signature.")

        try:
            csr_domains = [str(name.value) for name in
                           csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]
        except Exception as e:
            raise ACMEProblemResponse(type="badCSR", title="Failed to extract alt names from CSR.", detail=str(e))

        if set(csr_domains) != set(ordered_identifiers):
            raise ACMEProblemResponse(
                type="badCSR",
                title="CSR identifiers don't match authorized identifiers.",
                detail=f"CSR domains: {csr_domains}, Authorized domains: {ordered_identifiers}"
            )

        csr_extensions: list[x509.Extension] = csr.extensions.__iter__()
        for ext in csr_extensions:
            if ext.oid.dotted_string not in self.allowed_extension_oids:
                raise ACMEProblemResponse(type="badCSR", title=f"CSR contains forbidden extension: {ext.oid}.")

            if ext.oid == x509.oid.ExtensionOID.BASIC_CONSTRAINTS:
                if ext.value.ca:
                    raise ACMEProblemResponse(type="badCSR", title="CSR must not be for a CA certificate.")
                if ext.value.path_length and ext.value.path_length != 0:
                    raise ACMEProblemResponse(type="badCSR", title="CSR must have a path length of 0.")
                if not ext.critical:
                    raise ACMEProblemResponse(type="badCSR", title="Basic Constraints extension must be critical.")

            if ext.oid == x509.oid.ExtensionOID.KEY_USAGE:
                for key, value in vars(ext.value).items():
                    if not value:
                        continue

                    key_usage = snake_to_camel(key.lstrip('_'))
                    if key_usage not in self.allowed_key_usage:
                        raise ACMEProblemResponse(type="badCSR", title=f"CSR contains forbidden key usage: {key_usage}.")

            if ext.oid == x509.oid.ExtensionOID.EXTENDED_KEY_USAGE:
                for ext_key_usage in ext.value:
                    if ext_key_usage.dotted_string not in self.allowed_extended_key_usage_oids:
                        raise ACMEProblemResponse(type="badCSR", title=f"CSR contains forbidden extended key usage: {ext_key_usage._name}.")

            if ext.oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                for name in ext.value:
                    if type(name) not in [x509.DNSName, x509.IPAddress]:
                        raise ACMEProblemResponse(type="badCSR", title=f"CSR contains forbidden alt name: {name.value}.")

        return csr

    async def validate_client(self, client_ip: str, domain: str) -> None:
        try:
            domain_ips = set([x[4][0] for x in socket.getaddrinfo(domain, None)])
        except socket.gaierror as e:
            raise ACMEProblemResponse(
                type="dns",
                title=f"Domain {domain} does not exist",
                detail=str(e)
            )
        except Exception as e:
            raise ACMEProblemResponse(
                type="serverInternal",
                title=f"Unknown error occurred while validating domain",
                detail=str(e)
            )

        if len(domain_ips) == 0:
            raise ACMEProblemResponse(
                type="dns",
                title=f"Domain exists but has no IPs",
            )

        pre_validated = self._client_is_valid(client_ip, domain)
        client_allowed = self._client_is_allowed(client_ip, domain)
        client_in_cluster = self._client_in_cluster(client_ip)

        if not pre_validated and not client_allowed and client_ip not in domain_ips and not client_in_cluster:
            raise ACMEProblemResponse(
                type="unauthorized",
                title=f"Client IP '{client_ip}' has not authority over '{domain}'",
                detail=f"Pre-validated: {pre_validated}, Client Allowed: {client_allowed}",
            )

    def to_dict(self):
        return {
            "name": self.name,
            "ca": self.ca,
            "module_args": self.module_args,
            "enabled": self.enabled,
            "default": self.default,
            "supported_challenge_types": self.supported_challenge_types,
            "pre_validated": [dv.to_dict() for dv in self.pre_validated] if self.pre_validated else None,
            "acl": [dv.to_dict() for dv in self.acl] if self.acl else None,
            "cluster": self.cluster,
        }

    @field_validator("supported_challenge_types")
    @classmethod
    def challenge_types_must_be_valid(cls, v):
        if v and not isinstance(v, list):
            raise ValueError("Profile challenge types must be a list.")

        if v and "http-01" not in v and "dns-01" not in v:
            raise ValueError("Profile challenge types must contain 'http-01' or 'dns-01'.")

        return v

    def _client_is_valid(self, client_ip: str, domain: str) -> bool:
        if not self.pre_validated:
            return False

        for domain_validation in self.pre_validated:
            if domain_validation.domain == domain:
                return self._client_in_dv(client_ip, domain_validation)

        return False

    def _client_in_cluster(self, client_ip: str) -> bool | ACMEProblemResponse:
        if not self.cluster:
            return False

        client_hostnames = []
        try:
            host_by_addr = socket.gethostbyaddr(client_ip)
            client_hostnames.append(host_by_addr[0])
            client_hostnames += host_by_addr[1]
        except socket.herror as e:
            pass  # No PTR so we skip
        except Exception as e:
            return ACMEProblemResponse(type="serverInternal", title=f"Unknown error occurred while validating domain", detail=str(e))

        subnets = [subnet for subnet in self.cluster if is_valid_subnet(subnet)]
        client_ip_in_subnets = False
        for subnet in subnets:
            if client_ip in subnet:
                client_ip_in_subnets = True
                break

        return set(client_hostnames) & set(self.cluster) or \
            client_ip in self.cluster or \
            client_ip_in_subnets

    def _client_in_dv(self, client_ip: str, domain: DomainValidation) -> bool | ACMEProblemResponse:
        client_hostnames = []
        try:
            host_by_addr = socket.gethostbyaddr(client_ip)
            client_hostnames.append(host_by_addr[0])
            client_hostnames += host_by_addr[1]
        except socket.herror as e:
            pass # No PTR so we skip
        except Exception as e:
            return ACMEProblemResponse(type="serverInternal", title=f"Unknown error occurred while validating domain", detail=str(e))

        subnets = [subnet for subnet in domain.clients if is_valid_subnet(subnet)]
        client_ip_in_subnets = False
        for subnet in subnets:
            if client_ip in subnet:
                client_ip_in_subnets = True
                break

        return set(client_hostnames) & set(domain.clients) or \
            domain.clients == ["*"] or \
            client_ip in domain.clients or \
            client_ip_in_subnets

    def _client_is_allowed(self, client_ip: str, domain: str) -> bool | ACMEProblemResponse:
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
    port: int = 28080
    follow_redirect: bool = True
    timeout_seconds: int = 2
    retries: int = 1
    retry_delay_seconds: int = 0.1

    @field_validator("port")
    @classmethod
    def port_must_be_valid(cls, v):
        if v < 1 or v > 65535:
            raise ValueError("Port must be between 1 and 65535")
        return v

@dataclass
class API:
    host: str = "0.0.0.0"
    port: int = 8080
    
    @field_validator("port")
    @classmethod
    def port_must_be_valid(cls, v):
        if v < 1 or v > 65535:
            raise ValueError("Port must be between 1 and 65535")
        return v
    
    @field_validator("host")
    @classmethod
    def host_must_be_valid(cls, v):
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError("Host must be a valid IP address")

acme_logger = logging.getLogger("vism_acme")

class AcmeConfig(Config):
    log_conf = {
        "log_root": "vism_acme",
        "log_file": "vism_acme.log",
        "error_file": "vism_acme_error.log",
    }
    conf_path = "vism_acme"
    def __init__(self, config_file_path: str):
        super().__init__(config_file_path)

        acme_logger.info("Loading ACME config")

        acme_config = self.raw_config_data.get("vism_acme", {})
        self.database = Database(**acme_config.get("database", {}))
        self.profiles = [Profile(**profile) for profile in acme_config.get("profiles", {})]
        self.default_profile: Optional[Profile] = None
        self.http01 = Http01(**acme_config.get("http01", {}))
        self.api = API(**acme_config.get("api", {}))
        self.nonce_ttl_seconds = str(acme_config.get("nonce_ttl_seconds", 300))
        self.retry_after_seconds = str(acme_config.get("retry_after_seconds", 5))

        self.validate_config()

    def validate_config(self):
        acme_logger.info("Validating ACME config")
        if not self.profiles:
            raise ValueError("No profiles found in config.")

        default_profiles = list(filter(lambda profile: profile.default, self.profiles))
        if len(default_profiles) > 1:
            raise ValueError("Multiple default profiles found.")

        if not default_profiles:
            raise ValueError("No default profile found.")

        self.default_profile = default_profiles[0]

    def get_profile_by_name(self, name: str) -> Optional[Profile]:
        acme_logger.debug(f"Getting profile '{name}'")
        if not name:
            return self.default_profile

        profiles = list(filter(lambda profile: profile.name == name, self.profiles))
        if len(profiles) == 0:
            raise ACMEProblemResponse(type="invalidProfile", title=f"Profile '{name}' not found.")
        if len(profiles) > 1:
            raise ACMEProblemResponse(type="invalidProfile", title=f"Multiple profiles found with the name: '{name}'")

        # juuuuii8u9 | Comment from my cat

        profile = profiles[0]
        if not profile.enabled:
            raise ACMEProblemResponse(type="invalidProfile", title=f"Profile '{name}' is disabled.")

        return profile
