from enum import Enum


class IdentifierType(str, Enum):
    DNS = "dns"
    IP = "ip"