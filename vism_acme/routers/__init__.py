# Licensed under the GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
# pylint: disable=missing-module-docstring

from starlette.requests import Request
from starlette.datastructures import State
from vism_acme.db import AccountEntity
from vism_acme.middleware import AcmeJWSEnvelope

from .account import AccountRouter
from .authz import AuthzRouter
from .base import BaseRouter
from .order import OrderRouter

__all__ = [
    "AccountRouter",
    "AuthzRouter",
    "BaseRouter",
    "OrderRouter",
]

class AcmeRequestState(State): # pylint: disable=too-few-public-methods
    """This is purely for type hinting purposes."""
    jws_envelope: AcmeJWSEnvelope
    account: AccountEntity

class AcmeRequest(Request): # pylint: disable=too-few-public-methods
    """This is purely for type hinting purposes."""
    state: AcmeRequestState
