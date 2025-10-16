import json
import logging
from dataclasses import dataclass
from typing import Optional, Dict, Any, Callable
from fastapi import Request, HTTPException
from jwcrypto import jwk, jws as _jws
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response, JSONResponse

from vism.util import b64u_decode
from vism_acme.schema.response import ACMEProblemResponse
from vism_acme.structs.account import Account

logger = logging.getLogger("acme-server")

@dataclass
class AcmeProtectedHeader:
    alg: str
    jwk: Optional[Dict[str, Any]]
    kid: Optional[str]
    nonce: str
    url: str

    def __post_init__(self):
        if self.kid and self.kid.startswith("http"):
            self.kid = self.kid.split("/")[-1]

@dataclass
class AcmeProtectedPayload:
    identifiers: Optional[list]
    csr: Optional[str]
    profile: Optional[str]
    only_return_existing: Optional[bool] = None
    contact: Optional[list] = None
    status: Optional[str] = None

    def __bool__(self):
        return bool(self.identifiers) or \
            bool(self.csr) or \
            bool(self.profile) or \
            bool(self.contact) or \
            bool(self.status) or \
            bool(self.only_return_existing)

@dataclass
class AcmeJWSEnvelope:
    protected: str
    payload: str
    signature: str

    decoded_payload: Optional[AcmeProtectedPayload] = None
    decoded_headers: Optional[AcmeProtectedHeader] = None

    def __post_init__(self):
        decoded_payload = json.loads(b64u_decode(self.payload).decode("utf-8"))
        self.decoded_payload = AcmeProtectedPayload(
            identifiers=decoded_payload.get("identifiers", None),
            profile=decoded_payload.get("profile", None),
            csr=decoded_payload.get("csr", None),
            only_return_existing=decoded_payload.get("onlyReturnExisting", False),
            contact=decoded_payload.get("contact", None),
            status=decoded_payload.get("status", None)
        )

        decoded = json.loads(b64u_decode(self.protected).decode("utf-8"))
        self.decoded_headers = AcmeProtectedHeader(
            alg=decoded.get("alg"),
            jwk=decoded.get("jwk", None),
            kid=decoded.get("kid", None),
            nonce=decoded.get("nonce"),
            url=decoded.get("url"),
        )

    def verify(self, jwk_json: dict):
        compact = ".".join([self.protected, self.payload, self.signature])
        j = _jws.JWS()
        j.deserialize(compact)
        jwk_obj = jwk.JWK(**jwk_json)
        j.verify(jwk_obj)

class JWSMiddleware(BaseHTTPMiddleware):
    def __init__(
            self,
            app,
            jwk_paths: Optional[list],
            kid_paths: Optional[list],
            skip_paths: Optional[list] = None,
            controller = None,
    ):
        super().__init__(app)
        self.skip_paths = skip_paths or []
        self.jwk_paths = jwk_paths
        self.kid_paths = kid_paths
        self.controller = controller

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if any(request.url.path.startswith(path) for path in self.skip_paths):
            return await call_next(request)

        if request.method != "POST":
            return await call_next(request)

        try:
            jws_envelope, account = await self._parse_jws_envelope(request)
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

        nonce_provided = jws_envelope.decoded_headers.nonce
        popped_nonce = await self.controller.nonce_manager.pop_nonce(jws_envelope.decoded_headers.nonce, account.id if account else None)
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

        request.state.jws_envelope = jws_envelope
        request.state.account = account

        return await call_next(request)

    async def _parse_jws_envelope(self, request: Request) -> tuple[AcmeJWSEnvelope, Optional[Account]]:
        raw = await request.body()
        try:
            envelope_json = json.loads(raw)
            jws_envelope = AcmeJWSEnvelope(**envelope_json)
        except Exception as e:
            raise ACMEProblemResponse(type="malformed", title=f"Invalid JSON body", detail=str(e))

        if jws_envelope.decoded_headers.kid and jws_envelope.decoded_headers.jwk:
            raise ACMEProblemResponse(type="malformed", title=f"Client can not provide both kid and jwk.")

        if any(request.url.path.startswith(path) for path in self.jwk_paths) and not jws_envelope.decoded_headers.jwk:
            raise ACMEProblemResponse(type="malformed", title=f"{request.url.path} requests must contain a jwk key.")

        if any(request.url.path.startswith(path) for path in self.kid_paths) and not jws_envelope.decoded_headers.kid:
            raise ACMEProblemResponse(type="malformed", title=f"{request.url.path} requests must contain a kid.")

        if jws_envelope.decoded_headers.kid:
            account = self.controller.database.get_account_by_kid(jws_envelope.decoded_headers.kid)
            if not account:
                raise ACMEProblemResponse(type="accountDoesNotExist", title=f"Account {jws_envelope.decoded_headers.kid} does not exist.")
            jwk_json = account.jwk.to_dict()
        elif jws_envelope.decoded_headers.jwk:
            account = self.controller.database.get_account_by_jwk(jws_envelope.decoded_headers.jwk)
            if not account:
                jwk_json = jws_envelope.decoded_headers.jwk
            else:
                jwk_json = account.jwk.to_dict()
        else:
            raise ACMEProblemResponse(type="malformed", title=f"Must provide either kid or jwk.")

        try:
            jws_envelope.verify(jwk_json)
        except Exception as e:
            raise ACMEProblemResponse(type="badPublicKey", title=f"Invalid JWK.", detail=str(e))

        return jws_envelope, account
