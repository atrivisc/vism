import logging

from datetime import datetime
from typing import Optional, Callable
from jwcrypto.jwk import JWK
from pydantic import field_validator
from pydantic.dataclasses import dataclass as pydantic_dataclass
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response, JSONResponse
from vism.util import is_valid_ip
from vism_acme.schema.response import ACMEProblemResponse
from vism_acme.structs.account import Account
from vism_acme.util.enum import IdentifierType

logger = logging.getLogger(__name__)


class Config:
    arbitrary_types_allowed = True

@pydantic_dataclass(config=Config)
class AcmeProtectedHeader:
    alg: str = None
    nonce: str = None
    url: str = None
    jwk: Optional[dict] = None
    kid: Optional[str] = None

    def __post_init__(self):
        if self.kid and self.kid.startswith("http"):
            self.kid = self.kid.split("/")[-1]

        if self.jwk:
            self.jwk = JWK(**self.jwk)

@pydantic_dataclass
class AcmeIdentifier:
    type: IdentifierType
    value: str

    @field_validator("type")
    @classmethod
    def type_must_be_valid(cls, v):
        if v and v not in [IdentifierType.IP, IdentifierType.DNS]:
            raise ACMEProblemResponse(type="unsupportedIdentifier", title=f"Invalid identifier type value", detail="identifier type must be one of dns, ip")
        return v

    @field_validator("value")
    @classmethod
    def value_must_be_valid(cls, v):
        if v and '*' in v:
            raise ACMEProblemResponse(type="rejectedIdentifier", title=f"Invalid identifier value", detail="identifier values can not be wildcard")
        return v

    def __post_init__(self):
        if self.type == "dns":
            self.value = self.value.lower()
        if self.type == "ip":
            if not is_valid_ip(self.value):
                raise ACMEProblemResponse(type="rejectedIdentifier", title=f"Invalid identifier value", detail="With type ip value must be a valid IP address")

    def to_dict(self):
        return {
            "type": self.type,
            "value": self.value,
        }


@pydantic_dataclass
class AcmeProtectedPayload:
    identifiers: Optional[list[AcmeIdentifier]] = None
    csr: Optional[str] = None
    profile: Optional[str] = None
    onlyReturnExisting: Optional[bool] = None
    contact: Optional[list] = None
    status: Optional[str] = None
    notBefore: Optional[str] = None
    notAfter: Optional[str] = None

    @field_validator("onlyReturnExisting")
    @classmethod
    def onlyReturnExisting_must_be_bool(cls, v):
        if v and not isinstance(v, bool):
            raise ACMEProblemResponse(type="malformed", title=f"Invalid onlyReturnExisting value", detail="onlyReturnExisting must be a boolean")
        return v

    @field_validator("status")
    @classmethod
    def status_must_be_valid(cls, v):
        if v and v not in ["valid", "invalid", "deactivated"]:
            raise ACMEProblemResponse(type="malformed", title=f"Invalid status value", detail="status must be one of valid, invalid, deactivated")
        return v

    @field_validator("notBefore")
    @classmethod
    def notBefore_must_be_valid(cls, v):
        if v:
            try:
                datetime.fromisoformat(v)
            except Exception as e:
                raise ACMEProblemResponse(type="malformed", title=f"Invalid notBefore value", detail="notBefore must be a valid date/time string in ISO 8601 format")
        return v

    @field_validator("notAfter")
    @classmethod
    def notAfter_must_be_valid(cls, v):
        if v:
            try:
                datetime.fromisoformat(v)
                if datetime.fromisoformat(v) < datetime.now():
                    raise ACMEProblemResponse(type="malformed", title=f"Invalid notAfter value", detail="notAfter must be a valid date/time string in ISO 8601 format and in the future")
                return v
            except Exception as e:
                raise ACMEProblemResponse(type="malformed", title=f"Invalid notAfter value", detail="notAfter must be a valid date/time string in ISO 8601 format and in the future")
        return v

    def __bool__(self):
        return bool(self.identifiers) or \
            bool(self.csr) or \
            bool(self.profile) or \
            bool(self.contact) or \
            bool(self.status) or \
            bool(self.onlyReturnExisting) or \
            bool(self.notBefore) or \
            bool(self.notAfter)

class AcmeAccountMiddleware(BaseHTTPMiddleware):
    def __init__(
            self,
            app,
            jwk_paths: Optional[list],
            kid_paths: Optional[list],
            controller=None,
    ):
        super().__init__(app)
        self.jwk_paths = jwk_paths
        self.kid_paths = kid_paths
        self.controller = controller

    async def dispatch(self, request, call_next: Callable) -> Response:
        if not hasattr(request.state, "jws_envelope"):
            return await call_next(request)

        if request.method != "POST":
            return await call_next(request)

        try:
            account = await self._get_account(request)
        except ACMEProblemResponse as exc:
            return JSONResponse(
                status_code=exc.status_code,
                content=exc.error_json,
                headers={
                    "Content-Type": "application/problem+json",
                    "Replay-Nonce": await self.controller.nonce_manager.new_nonce(),
                    "Retry-After": self.controller.config.retry_after_seconds
                }
            )

        nonce_provided = request.state.jws_envelope.headers.nonce
        popped_nonce = await self.controller.nonce_manager.pop_nonce(nonce_provided, account.id if account else None)
        if not nonce_provided or not popped_nonce:
            return JSONResponse(
                status_code=400,
                content={
                    "type": "urn:ietf:params:acme:error:badNonce",
                    "title": "Invalid/missing replay-nonce"
                },
                headers={
                    "Content-Type": "application/problem+json",
                    "Replay-Nonce": await self.controller.nonce_manager.new_nonce(account.id if account else None),
                    "Retry-After": self.controller.config.retry_after_seconds
                }
            )

        request.state.nonce = nonce_provided or popped_nonce
        request.state.account = account

        return await call_next(request)

    async def _get_account(self, request) -> Account:
        jws_envelope = request.state.jws_envelope

        if any(request.url.path.startswith(path) for path in self.jwk_paths) and not jws_envelope.headers.jwk:
            raise ACMEProblemResponse(type="malformed", title=f"{request.url.path} requests must contain a jwk key.")

        if any(request.url.path.startswith(path) for path in self.kid_paths) and not jws_envelope.headers.kid:
            raise ACMEProblemResponse(type="malformed", title=f"{request.url.path} requests must contain a kid.")

        if jws_envelope.headers.kid:
            account = self.controller.database.get_account_by_kid(jws_envelope.headers.kid)
            if not account:
                raise ACMEProblemResponse(type="accountDoesNotExist", title=f"Account {jws_envelope.headers.kid} does not exist.", status_code=403)
        elif jws_envelope.headers.jwk:
            account = self.controller.database.get_account_by_jwk(jws_envelope.headers.jwk)
        else:
            raise ACMEProblemResponse(type="malformed", title=f"Must provide either kid or jwk.")

        if account and account.status != "valid":
            raise ACMEProblemResponse(type="unauthorized", title=f"Account is not valid.", status_code=403)

        return account
