import time
import logging
import requests
from requests import ReadTimeout
from requests.adapters import HTTPAdapter, Retry
from requests.exceptions import RequestException, TooManyRedirects, ChunkedEncodingError, ContentDecodingError, \
    RetryError, SSLError, ProxyError, ConnectTimeout, ConnectionError, Timeout
from urllib3.exceptions import MaxRetryError, NewConnectionError

from vism_acme import VismACMEController
from vism_acme.db import AuthzEntity, ChallengeEntity
from vism_acme.db.authz import AuthzStatus, ChallengeStatus, ErrorEntity
from vism_acme.db.order import OrderStatus


class Http01Validator:
    def __init__(self, controller: VismACMEController, challenge: ChallengeEntity):
        self.controller = controller
        self.challenge = challenge

    async def get_session(self):
        retries_count = self.controller.config.http01.retries
        retry_delay_seconds = self.controller.config.http01.retry_delay_seconds

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
        token = self.challenge.key_authorization.split(".")[0]
        validation_url = f"http://{self.challenge.authz.identifier_value}:{self.controller.config.http01.port}/.well-known/acme-challenge/{token}"
        timeout_seconds = self.controller.config.http01.timeout_seconds

        error = None
        error_detail = None
        with await self.get_session() as session:
            self.challenge.status = ChallengeStatus.PROCESSING
            self.challenge: ChallengeEntity = self.controller.database.save_to_db(self.challenge)

            try:
                response = session.get(validation_url, timeout=timeout_seconds)
                if response.status_code != 200 or response.text.strip() != self.challenge.key_authorization:
                    error = "incorrectResponse"
                    error_detail = f"Invalid response from {validation_url}: {response.status_code} {response.text}"
                elif response.status_code == 200 and response.text.strip() == self.challenge.key_authorization:
                    self.challenge.status = ChallengeStatus.VALID
                    self.challenge.authz.status = AuthzStatus.VALID
                    self.challenge = self.controller.database.save_to_db(self.challenge)
                    self.challenge.authz = self.controller.database.save_to_db(self.challenge.authz)
                else:
                    error = "this should never happen"
                    error_detail = f"Unknown error when trying to validate challenge: {response.status_code} {response.text}"
            except (ConnectionError, NewConnectionError) as e:
                error = "connection"
                error_detail = f"Failed to connect to {validation_url}: {e.args[0].reason._message}"
            except (Timeout, ConnectTimeout, ReadTimeout) as e:
                error = "connection"
                error_detail = f"Timed out waiting for response, this is most likely due to a firewall blocking the request."
            except TooManyRedirects as e:
                error = "connection"
                error_detail = f"Too many redirects when trying to validate challenge."
            except (ChunkedEncodingError, ContentDecodingError) as e:
                error = "incorrectResponse"
                error_detail = f"Failed to decode response from {validation_url}: {e.args[0].reason._message}"
            except RetryError as e:
                error = "connection"
                error_detail = f"Max retries exceeded when trying to validate challenge."
            except SSLError as e:
                error = "connection"
                error_detail = f"SSL error when trying to validate challenge: {e.args[0].reason._message}"
            except ProxyError as e:
                error = "connection"
                error_detail = f"Proxy error when trying to validate challenge: {e.args[0].reason._message}"
            except MaxRetryError as e:
                error = "connection"
                error_detail = f"Max retries exceeded when trying to validate challenge."
            except (RequestException, Exception) as e:
                error = "connection"
                error_detail = f"Unknown error when trying to validate challenge: {e.__class__.__name__}: {e}"

        if error:
            self.challenge.status = ChallengeStatus.INVALID
            self.challenge.authz.status = AuthzStatus.INVALID
            self.challenge.authz.order.status = OrderStatus.INVALID

            error_entity = ErrorEntity(type=error, detail=error_detail, title="Failed to validate challenge.")
            self.controller.database.save_to_db(error_entity)

            self.challenge = self.controller.database.save_to_db(self.challenge)
            self.challenge.authz.error = error_entity
            self.challenge.authz = self.controller.database.save_to_db(self.challenge.authz)
            self.challenge.authz.order = self.controller.database.save_to_db(self.challenge.authz.order)

