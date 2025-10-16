import re
from dataclasses import dataclass, field
from typing import Optional

from modules.openssl.errors import ProfileNotFound, MultipleProfilesFound
from vism_ca.config import ModuleArgsConfig
from vism_ca.ca.crypto import CryptoConfig


@dataclass
class CAProfileAuthorityInfoAccess:
    name: str = None
    caIssuersURIs: list[str] = None

@dataclass
class CAProfileCRLDistributionPoints:
    name: str = None
    URIs: list[str] = None

@dataclass
class CAProfileCertExtension:
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
    name: str = None
    countryName: str = "optional"
    stateOrProvinceName: str = "optional"
    localityName: str = "optional"
    organizationName: str = "optional"
    organizationalUnitName: str = "optional"
    commonName: str = "optional"

@dataclass
class CAProfileCRLExtension:
    name: str = None
    authorityKeyIdentifier: str = None
    authorityInfoAccess: str = None

@dataclass
class CAProfileDefaultCA:
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
    name: str = None
    countryName: str = None
    stateOrProvinceName: str = None
    localityName: str = None
    organizationName: str = None
    organizationalUnitName: str = None
    commonName: str = None

@dataclass
class CAProfileReq:
    encrypt_key: str = None
    distinguished_name: str = None

    x509_extensions: str = None
    req_extensions: str = None

    default_md: str = "sha3-512"
    utf8: str = "yes"
    prompt: str = "no"

@dataclass
class CAProfile:
    name: str = None
    cert_extensions: list[CAProfileCertExtension]  = None
    crl_extensions: list[CAProfileCRLExtension]  = None
    crl_distribution_points: list[CAProfileCRLDistributionPoints]  = None
    authority_info_access_extensions: list[CAProfileAuthorityInfoAccess]  = None
    distinguished_name_extensions: list[CAProfileDistinguishedNameExtension]  = None
    match_policies: list[CAProfileMatchPolicy]  = None
    default_ca: CAProfileDefaultCA  = None
    req: CAProfileReq  = None

    defaults: dict = field(default_factory=dict)

    def __post_init__(self):
        self.req = CAProfileReq(**self.req)
        self.default_ca = CAProfileDefaultCA(**self.default_ca)
        self.match_policies = [CAProfileMatchPolicy(**data) for data in self.match_policies]
        self.crl_extensions = [CAProfileCRLExtension(**data) for data in self.crl_extensions]
        self.cert_extensions = [CAProfileCertExtension(**data) for data in self.cert_extensions]
        self.crl_distribution_points = [CAProfileCRLDistributionPoints(**data) for data in self.crl_distribution_points]
        self.authority_info_access_extensions = [CAProfileAuthorityInfoAccess(**data) for data in self.authority_info_access_extensions]
        self.distinguished_name_extensions = [CAProfileDistinguishedNameExtension(**data) for data in self.distinguished_name_extensions]


@dataclass
class OpenSSLConfig(CryptoConfig):
    uid: int
    gid: int
    bin: str
    ca_profiles: Optional[list[CAProfile]]
    default_config_template: str = 'openssl.conf.j2'

    def __post_init__(self):
        self.ca_profiles = [CAProfile(**profile) for profile in self.ca_profiles]

    def get_profile_by_name(self, name: str) -> CAProfile:
        profiles = list(filter(lambda profile: profile.name == name, self.ca_profiles))
        if len(profiles) == 0:
            raise ProfileNotFound(f"OpenSSL profile '{name}' not found.")

        if len(profiles) > 1:
            raise MultipleProfilesFound(f"Multiple profiles found with the name: '{name}'")

        return profiles[0]

@dataclass
class OpenSSLKeyConfig:
    password: str
    algorithm: str
    bits: int = 4096

@dataclass
class OpenSSLModuleArgs(ModuleArgsConfig):
    profile: str = None
    cn: str = None
    extension: str = None
    key: OpenSSLKeyConfig = None
    days: int = None
    config_template: str = 'openssl.conf.j2'

    def __post_init__(self):
        if self.key is not None:
            self.key = OpenSSLKeyConfig(**self.key)

LOGGING_SENSITIVE_PATTERNS = {
    'openssl_pass': {
        'pattern': re.compile(r'(-pass(?:in)?\s(?:pass|env):)\S+'),
        'replace': r'\1[REDACTED]'
    }
}