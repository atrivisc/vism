# Licensed under the GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""HTTP-01 challenge validator for ACME."""

import requests
from requests import ReadTimeout
from requests.adapters import HTTPAdapter, Retry
from requests.exceptions import (
    RequestException,
    TooManyRedirects,
    ChunkedEncodingError,
    ContentDecodingError,
    RetryError,
    SSLError,
    ProxyError,
    ConnectTimeout,
    ConnectionError as RequestsConnectionError,
    Timeout
)
from urllib3.exceptions import MaxRetryError, NewConnectionError

from vism_acme import acme_logger
from vism_acme.db import (
    ChallengeEntity,
    ChallengeStatus,
    AuthzStatus,
    OrderStatus,
    ErrorEntity
)


class Http01Validator:  # pylint: disable=too-many-branches,too-many-statements
    """Validator for HTTP-01 ACME challenges."""

    def __init__(self, controller, challenge: ChallengeEntity):
        self.controller = controller
        self.challenge = challenge

    async def get_session(self):
        """Create an HTTP session with retry configuration."""
        acme_logger.debug("Creating new session for HTTP-01 validation.")
        retries_count = self.controller.config.http01.retries
        retry_delay_seconds = (
            self.controller.config.http01.retry_delay_seconds
        )

        session = requests.Session()
        retries = Retry(
            total=retries_count,
            backoff_factor=retry_delay_seconds,
            status_forcelist=[500, 502, 503, 504, 404, 400],
            allowed_methods=["GET"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retries)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    async def validate(self):
        """Validate the HTTP-01 challenge."""
        acme_logger.info(
            "Validating challenge %s with HTTP-01.", self.challenge.id
        )
        token = self.challenge.key_authorization.split(".")[0]
        port = self.controller.config.http01.port
        validation_url = (
            f"http://{self.challenge.authz.identifier_value}:{port}"
            f"/.well-known/acme-challenge/{token}"
        )
        timeout_seconds = self.controller.config.http01.timeout_seconds

        error = None
        error_detail = None
        with await self.get_session() as session:
            self.challenge.status = ChallengeStatus.PROCESSING
            self.challenge: ChallengeEntity = (
                self.controller.database.save_to_db(self.challenge)
            )

            try:
                response = session.get(validation_url, timeout=timeout_seconds)
                if len(response.text.strip()) > 90:
                    error = "incorrectResponse"
                    error_detail = (
                        f"Response from {validation_url} is too long."
                    )
                elif (response.status_code != 200 or
                      response.text.strip() !=
                      self.challenge.key_authorization):
                    error = "incorrectResponse"
                    error_detail = (
                        f"Invalid response from {validation_url}: "
                        f"{response.status_code} {response.text}"
                    )
                elif (response.status_code == 200 and
                      response.text.strip() ==
                      self.challenge.key_authorization):
                    self.challenge.status = ChallengeStatus.VALID
                    self.challenge.authz.status = AuthzStatus.VALID
                    self.challenge = (
                        self.controller.database.save_to_db(self.challenge)
                    )
                    self.challenge.authz = (
                        self.controller.database.save_to_db(
                            self.challenge.authz
                        )
                    )
                else:
                    error = "this should never happen"
                    error_detail = (
                        f"Unknown error when trying to validate challenge: "
                        f"{response.status_code} {response.text}"
                    )
            except ConnectTimeout as exc:
                error = "connection"
                error_detail = (
                    "Timed out waiting for response, this is most likely "
                    "due to a firewall blocking the request."
                )
                acme_logger.exception(exc)
            except TooManyRedirects as exc:
                error = "connection"
                error_detail = (
                    "Too many redirects when trying to validate challenge."
                )
                acme_logger.exception(exc)
            except (ChunkedEncodingError, ContentDecodingError) as exc:
                error = "incorrectResponse"
                # pylint: disable=protected-access
                error_detail = (
                    f"Failed to decode response from {validation_url}: "
                    f"{exc.args[0].reason._message}"
                )
                acme_logger.exception(exc)
            except RetryError as exc:
                error = "connection"
                error_detail = (
                    "Max retries exceeded when trying to validate challenge."
                )
                acme_logger.exception(exc)
            except SSLError as exc:
                error = "connection"
                # pylint: disable=protected-access
                error_detail = (
                    f"SSL error when trying to validate challenge: "
                    f"{exc.args[0].reason._message}"
                )
                acme_logger.exception(exc)
            except ProxyError as exc:
                error = "connection"
                # pylint: disable=protected-access
                error_detail = (
                    f"Proxy error when trying to validate challenge: "
                    f"{exc.args[0].reason._message}"
                )
                acme_logger.exception(exc)
            except MaxRetryError as exc:
                error = "connection"
                error_detail = (
                    "Max retries exceeded when trying to validate challenge."
                )
                acme_logger.exception(exc)
            except (Timeout, ReadTimeout) as exc:
                error = "connection"
                error_detail = (
                    "Timed out waiting for response, this is most likely "
                    "due to a firewall blocking the request."
                )
                acme_logger.exception(exc)
            except (RequestsConnectionError, NewConnectionError) as exc:
                error = "connection"
                # pylint: disable=protected-access
                error_detail = (
                    f"Failed to connect to {validation_url}: "
                    f"{exc.args[0].reason._message}"
                )
                acme_logger.exception(exc)
            except RequestException as exc:
                # pylint: disable=broad-exception-caught
                error = "connection"
                error_detail = (
                    f"Unknown error when trying to validate challenge: "
                    f"{exc.__class__.__name__}: {exc}"
                )
                acme_logger.exception(exc)

        if error:
            self.challenge.status = ChallengeStatus.INVALID
            self.challenge.authz.status = AuthzStatus.INVALID
            self.challenge.authz.order.status = OrderStatus.INVALID

            error_entity = ErrorEntity(
                type=error,
                detail=error_detail,
                title="Failed to validate challenge."
            )
            self.controller.database.save_to_db(error_entity)

            self.challenge = self.controller.database.save_to_db(
                self.challenge
            )
            self.challenge.authz.error = error_entity
            self.challenge.authz = self.controller.database.save_to_db(
                self.challenge.authz
            )
            self.challenge.authz.order = (
                self.controller.database.save_to_db(
                    self.challenge.authz.order
                )
            )
