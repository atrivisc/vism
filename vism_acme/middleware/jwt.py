# Licensed under the GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""Middleware for JWS (JSON Web Signature) validation."""

import json
import logging
from typing import Optional, Callable
from fastapi import Request
from jwcrypto import jws as _jws
from pydantic.dataclasses import dataclass
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from shared.util import b64u_decode
from vism_acme import ACMEProblemResponse
from vism_acme.middleware import AcmeProtectedPayload, AcmeProtectedHeader

logger = logging.getLogger(__name__)


@dataclass
class AcmeJWSEnvelope:
    """ACME JWS envelope containing protected header, payload, and signature."""

    encoded_payload: str
    encoded_protected: str
    encoded_signature: str

    payload: Optional[AcmeProtectedPayload] = None
    headers: Optional[AcmeProtectedHeader] = None

    @property
    def is_post_as_get(self):
        """Check if this is a POST-as-GET request (empty payload)."""
        return self.encoded_payload == ""

    def __post_init__(self):
        """Decode and validate the JWS envelope."""
        if self.encoded_payload:
            decoded_payload = json.loads(
                b64u_decode(self.encoded_payload).decode("utf-8")
            )
            self.payload = AcmeProtectedPayload(**decoded_payload)

        if self.encoded_protected:
            decoded = json.loads(
                b64u_decode(self.encoded_protected).decode("utf-8")
            )
            self.headers = AcmeProtectedHeader(**decoded)

        if not self.headers:
            return

        if (self.headers.jwk and
                self.headers.jwk.get('kty', None) not in
                ['RSA', 'EC', 'oct']):
            raise ACMEProblemResponse(
                error_type="badSignatureAlgorithm",
                title="Invalid JWK signature algorithm.",
                detail="JWK signature algorithm must be one of RSA, EC, oct."
            )

        if self.headers.kid and self.headers.jwk:
            raise ACMEProblemResponse(
                error_type="malformed",
                title="Client can not provide both kid and jwk."
            )

        if not self.headers.jwk:
            return

        try:
            compact = ".".join([
                self.encoded_protected,
                self.encoded_payload,
                self.encoded_signature
            ])
            j = _jws.JWS()
            j.deserialize(compact)
            j.verify(self.headers.jwk)
        except Exception as exc:
            raise ACMEProblemResponse(
                error_type="badPublicKey",
                title="Invalid JWK.",
                detail=str(exc)
            ) from exc


class JWSMiddleware(BaseHTTPMiddleware): # pylint: disable=too-few-public-methods
    """Middleware for validating JWS envelopes in ACME requests."""

    def __init__(
            self,
            app,
            skip_paths: Optional[list] = None,
            controller=None,
    ):
        super().__init__(app)
        self.skip_paths = skip_paths or []
        self.controller = controller

    async def dispatch(
            self,
            request: Request,
            call_next: Callable
    ) -> Response:
        """Dispatch request with JWS validation."""
        if any(request.url.path.startswith(path)
               for path in self.skip_paths):
            return await call_next(request)

        if request.method != "POST":
            return await call_next(request)

        try:
            jws_envelope = await self._parse_jws_envelope(request)
        except ACMEProblemResponse as exc:
            return await exc.to_json_response(self.controller)

        request.state.jws_envelope = jws_envelope

        return await call_next(request)

    @staticmethod
    async def _parse_jws_envelope(request: Request) -> AcmeJWSEnvelope:
        """Parse JWS envelope from request body."""
        raw = await request.body()
        try:
            envelope_json = json.loads(raw)
            jws_envelope = AcmeJWSEnvelope(
                encoded_protected=envelope_json.get("protected", None),
                encoded_payload=envelope_json.get("payload", None),
                encoded_signature=envelope_json.get("signature", None),
            )
        except Exception as exc:
            raise ACMEProblemResponse(
                error_type="malformed",
                title="Invalid JSON body",
                detail=str(exc)
            ) from exc

        return jws_envelope
