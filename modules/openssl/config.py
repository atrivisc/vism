# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""OpenSSL module configuration classes."""
import os
import re
from dataclasses import dataclass, field
from typing import Optional, ClassVar

from modules.openssl.errors import ProfileNotFound, MultipleProfilesFound
from vism_ca import ModuleArgsConfig
from vism_ca import CryptoConfig


@dataclass
class CAProfileAuthorityInfoAccess:
    """Authority Information Access extension configuration."""

    name: str = None
    caIssuersURIs: list[str] = None


@dataclass
class CAProfileCRLDistributionPoints:
    """CRL Distribution Points extension configuration."""

    name: str = None
    URIs: list[str] = None


@dataclass
class CAProfileCertExtension:  # pylint: disable=too-many-instance-attributes
    """Certificate extension configuration."""

    name: str = None
    basicConstraints: str = None
    keyUsage: str = None
    extendedKeyUsage: str = None
    subjectKeyIdentifier: str = None
    authorityKeyIdentifier: str = None
    authorityInfoAccess: str = None
    crlDistributionPoints: str = None


@dataclass
class CAProfileMatchPolicy:
    """Match policy configuration for certificate validation."""

    name: str = None
    countryName: str = "optional"
    stateOrProvinceName: str = "optional"
    localityName: str = "optional"
    organizationName: str = "optional"
    organizationalUnitName: str = "optional"
    commonName: str = "optional"


@dataclass
class CAProfileCRLExtension:
    """CRL extension configuration."""

    name: str = None
    authorityKeyIdentifier: str = None
    authorityInfoAccess: str = None


@dataclass
class CAProfileDefaultCA:  # pylint: disable=too-many-instance-attributes
    """Default CA configuration."""

    default_days: int = None
    policy: str = None
    copy_extensions: str = None
    default_crl_days: int = None
    x509_extensions: str = None
    crl_extensions: str = None
    new_certs_dir: str = None
    certificate: str = None
    private_key: str = None
    serial: str = None
    crlnumber: str = None
    database: str = None
    rand_serial: str = "yes"
    unique_subject: str = "no"
    default_md: str = "sha3-512"
    email_in_dn: str = "no"
    preserve: str = "no"
    name_opt: str = "ca_default"
    cert_opt: str = "ca_default"
    utf8: str = "yes"


@dataclass
class CAProfileDistinguishedNameExtension:
    """Distinguished Name extension configuration."""

    name: str = None
    countryName: str = None
    stateOrProvinceName: str = None
    localityName: str = None
    organizationName: str = None
    organizationalUnitName: str = None
    commonName: str = None


@dataclass
class CAProfileReq:
    """CA profile request configuration."""

    encrypt_key: str = None
    distinguished_name: str = None

    x509_extensions: str = None
    req_extensions: str = None

    default_md: str = "sha3-512"
    utf8: str = "yes"
    prompt: str = "no"


@dataclass
class CAProfile:
    """Complete CA profile configuration."""

    name: str = None
    cert_extensions: list[CAProfileCertExtension] = None
    crl_extensions: list[CAProfileCRLExtension] = None
    crl_distribution_points: list[CAProfileCRLDistributionPoints] = None
    authority_info_access_extensions: list[CAProfileAuthorityInfoAccess] = None
    distinguished_name_extensions: list[CAProfileDistinguishedNameExtension] = None
    match_policies: list[CAProfileMatchPolicy] = None
    default_ca: CAProfileDefaultCA = None
    req: CAProfileReq = None

    defaults: dict = field(default_factory=dict)

    def __post_init__(self):
        self.req = CAProfileReq(**self.req)
        self.default_ca = CAProfileDefaultCA(**self.default_ca)
        self.match_policies = [
            CAProfileMatchPolicy(**data) for data in self.match_policies
        ]
        self.crl_extensions = [
            CAProfileCRLExtension(**data) for data in self.crl_extensions
        ]
        self.cert_extensions = [
            CAProfileCertExtension(**data) for data in self.cert_extensions
        ]
        self.crl_distribution_points = [
            CAProfileCRLDistributionPoints(**data)
            for data in self.crl_distribution_points
        ]
        self.authority_info_access_extensions = [
            CAProfileAuthorityInfoAccess(**data)
            for data in self.authority_info_access_extensions
        ]
        self.distinguished_name_extensions = [
            CAProfileDistinguishedNameExtension(**data)
            for data in self.distinguished_name_extensions
        ]


@dataclass
class OpenSSLConfig(CryptoConfig):
    """OpenSSL module configuration."""

    __path__: ClassVar[str] = "openssl"
    __config_dir__: ClassVar[str] = f"{os.getenv("CONFIG_DIR", os.getcwd()).rstrip("/")}"
    __config_file__: ClassVar[str] = f"{__config_dir__}/openssl.yaml"

    bin: str
    ca_profiles: Optional[list[CAProfile]]
    default_config_template: str = 'openssl.conf.j2'

    def __post_init__(self):
        self.ca_profiles = [
            CAProfile(**profile) for profile in self.ca_profiles
        ]

    def get_profile_by_name(self, name: str) -> CAProfile:
        """Get CA profile by name."""
        profiles = list(
            filter(lambda profile: profile.name == name, self.ca_profiles)
        )
        if len(profiles) == 0:
            raise ProfileNotFound(f"OpenSSL profile '{name}' not found.")

        if len(profiles) > 1:
            raise MultipleProfilesFound(
                f"Multiple profiles found with the name: '{name}'"
            )

        return profiles[0]


@dataclass
class OpenSSLKeyConfig:
    """OpenSSL key generation configuration."""

    password: str
    algorithm: str
    bits: int = 4096


@dataclass
class OpenSSLModuleArgs(ModuleArgsConfig):
    """Module arguments for OpenSSL operations."""

    profile: str = None
    cn: str = None
    extension: str = None
    key: OpenSSLKeyConfig = None
    days: int = None
    config_template: str = 'openssl.conf.j2'

    def __post_init__(self):
        if self.key is not None:
            if isinstance(self.key, dict):
                self.key = OpenSSLKeyConfig(**self.key)


LOGGING_SENSITIVE_PATTERNS = {
    'openssl_pass': {
        'pattern': re.compile(r'(-pass(?:in)?\s(?:pass|env):)\S+'),
        'replace': r'\1[REDACTED]'
    }
}
