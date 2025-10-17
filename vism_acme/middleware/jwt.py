import json
import logging
from typing import Optional, Callable
from fastapi import Request
from jwcrypto import jws as _jws
from pydantic.dataclasses import dataclass
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response, JSONResponse

from vism.util import b64u_decode
from vism_acme.middleware.acme_request import AcmeProtectedPayload, AcmeProtectedHeader
from vism_acme.schema.response import ACMEProblemResponse

logger = logging.getLogger(__name__)


@dataclass
class AcmeJWSEnvelope:
    encoded_payload: str
    encoded_protected: str
    encoded_signature: str

    payload: Optional[AcmeProtectedPayload] = None
    headers: Optional[AcmeProtectedHeader] = None

    @property
    def is_post_as_get(self):
        return self.encoded_payload == ""

    def __post_init__(self):
        if self.encoded_payload:
            decoded_payload = json.loads(b64u_decode(self.encoded_payload).decode("utf-8"))
            self.payload = AcmeProtectedPayload(**decoded_payload)

        if self.encoded_protected:
            decoded = json.loads(b64u_decode(self.encoded_protected).decode("utf-8"))
            self.headers = AcmeProtectedHeader(**decoded)

        if not self.headers:
            return None

        if self.headers.jwk and self.headers.jwk.get('kty', None) not in ['RSA', 'EC', 'oct']:
            raise ACMEProblemResponse(
                type="badSignatureAlgorithm",
                title=f"Invalid JWK signature algorithm.",
                detail=f"JWK signature algorithm must be one of RSA, EC, oct."
            )

        if self.headers.kid and self.headers.jwk:
            raise ACMEProblemResponse(type="malformed", title=f"Client can not provide both kid and jwk.")

        if not self.headers.jwk:
            return None

        try:
            compact = ".".join([self.encoded_protected, self.encoded_payload, self.encoded_signature])
            j = _jws.JWS()
            j.deserialize(compact)
            j.verify(self.headers.jwk)
        except Exception as e:
            raise ACMEProblemResponse(
                type="badPublicKey",
                title=f"Invalid JWK.",
                detail=str(e)
            )


class JWSMiddleware(BaseHTTPMiddleware):
    def __init__(
            self,
            app,
            skip_paths: Optional[list] = None,
            controller=None,
    ):
        super().__init__(app)
        self.skip_paths = skip_paths or []
        self.controller = controller

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if any(request.url.path.startswith(path) for path in self.skip_paths):
            return await call_next(request)

        if request.method != "POST":
            return await call_next(request)

        try:
            jws_envelope = await self._parse_jws_envelope(request)
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

        request.state.jws_envelope = jws_envelope

        return await call_next(request)

    async def _parse_jws_envelope(self, request: Request) -> AcmeJWSEnvelope:
        raw = await request.body()
        try:
            envelope_json = json.loads(raw)
            jws_envelope = AcmeJWSEnvelope(
                encoded_protected=envelope_json.get("protected", None),
                encoded_payload=envelope_json.get("payload", None),
                encoded_signature=envelope_json.get("signature", None),
            )
        except Exception as e:
            raise ACMEProblemResponse(type="malformed", title=f"Invalid JSON body", detail=str(e))

        return jws_envelope
