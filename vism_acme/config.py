import socket
import ipaddress
import logging

from pydantic import field_validator
from pydantic.dataclasses import dataclass
from typing import Optional
from vism import Config
from vism.util import is_valid_subnet
from vism_acme.schema.response import ACMEProblemResponse

logger = logging.getLogger(__name__)

@dataclass
class Database:
    host: str = ""
    port: int = 3306
    database: str = ""
    username: str = ""
    password: str = ""

    @field_validator("port")
    @classmethod
    def port_must_be_valid(cls, v):
        if v < 1 or v > 65535:
            raise ValueError("Port must be between 1 and 65535")
        return v


@dataclass
class Logging:
    directory: str = "./logs/"
    level: str = "INFO"
    verbose: bool = False

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

    supported_challenge_types: list[str] = None
    pre_validated: list[DomainValidation] = None
    acl: list[DomainValidation] = None

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
        }

    @field_validator("supported_challenge_types")
    @classmethod
    def challenge_types_must_be_valid(cls, v):
        if v and not isinstance(v, list):
            raise ValueError("Profile challenge types must be a list.")

        if v and "http-01" not in v and "dns-01" not in v:
            raise ValueError("Profile challenge types must contain 'http-01' or 'dns-01'.")

        return v

    def client_is_valid(self, client_ip: str, domain: str) -> bool:
        if not self.pre_validated:
            return False

        for domain_validation in self.pre_validated:
            if domain_validation.domain == domain:
                return self._client_in_dv(client_ip, domain_validation)

        return False

    def _client_in_dv(self, client_ip: str, domain: DomainValidation) -> bool | ACMEProblemResponse:
        client_hostnames = []
        try:
            host_by_addr = socket.gethostbyaddr(client_ip)
            client_hostnames.append(host_by_addr[0])
            client_hostnames += host_by_addr[1]
        except socket.herror as e:
            pass
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

    def client_is_allowed(self, client_ip: str, domain: str) -> bool | ACMEProblemResponse:
        if not self.acl:
            return False

        for domain_validation in self.acl:
            if domain_validation.domain == domain:
                return self._client_in_dv(client_ip, domain_validation)

        return False

    def __post_init__(self):
        if self.supported_challenge_types is None:
            self.supported_challenge_types = ["http-01"]

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


class AcmeConfig(Config):
    def __init__(self, config_file_path: str):
        super().__init__(config_file_path)

        acme_config = self.raw_config_data.get("vism_acme", {})
        self.database = Database(**acme_config.get("database", {}))
        self.logging = Logging(**acme_config.get("logging", {}))
        self.profiles = [Profile(**profile) for profile in acme_config.get("profiles", {})]
        self.default_profile: Optional[Profile] = None
        self.server = API(**acme_config.get("server", {}))
        self.http01 = Http01(**acme_config.get("http01", {}))
        self.nonce_ttl_seconds = str(acme_config.get("nonce_ttl_seconds", 300))
        self.retry_after_seconds = str(acme_config.get("retry_after_seconds", 5))

        self.validate_config()

    def validate_config(self):
        if not self.profiles:
            raise ValueError("No profiles found in config.")

        default_profiles = list(filter(lambda profile: profile.default, self.profiles))
        if len(default_profiles) > 1:
            raise ValueError("Multiple default profiles found.")

        if not default_profiles:
            raise ValueError("No default profile found.")

        self.default_profile = default_profiles[0]

    def get_profile_by_name(self, name: str) -> Optional[Profile]:
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
