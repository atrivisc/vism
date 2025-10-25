# Licensed under the GPL 3: https://www.gnu.org/licenses/gpl-3.0.html

"""VISM ACME error and exception classes."""

from typing import Any

from pydantic.dataclasses import dataclass
from starlette.responses import JSONResponse

from shared.errors import VismException


@dataclass
class ACMEProblemResponse(Exception):
    """
    ACME Problem Response exception.

    Represents an RFC 8555 compliant ACME problem detail response.
    """

    error_type: str
    title: str
    detail: str = None
    subproblems: list['ACMEProblemResponse'] = None
    status_code: int = 400
    error_json: dict[str, Any] = None

    def post_init(self):
        """Compile error JSON and init exception."""
        self.error_json: dict[str, Any] = {
            "type": f"urn:ietf:params:acme:error:{self.error_type}",
            "title": self.title,
        }
        if self.detail is not None:
            self.error_json["detail"] = self.detail

        if self.subproblems is not None:
            self.error_json['subproblems'] = []
            for problem in self.subproblems:
                self.error_json['subproblems'].append(problem.error_json)

        super().__init__(self.title)

    async def to_json_response(self, controller=None):
        """Convert ACME problem response to JSON response."""
        return JSONResponse(
            status_code=self.status_code,
            content=self.error_json,
            headers={
                "Content-Type": "application/problem+json",
                "Replay-Nonce": (
                    await controller.nonce_manager.new_nonce()
                ),
                "Retry-After": (
                    controller.config.retry_after_seconds
                )
            }
        )

class JWTException(VismException):
    """Exception raised for JWT-related errors."""
