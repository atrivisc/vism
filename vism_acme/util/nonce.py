# Licensed under the GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""Nonce manager for ACME replay protection."""

import secrets
import asyncio
from cachetools import TTLCache
from vism_acme import AcmeConfig, acme_logger


class NonceManager:
    """Manager for ACME nonces with TTL-based expiration."""

    def __init__(self, config: AcmeConfig):
        self.lock = asyncio.Lock()
        self.nonces = TTLCache(
            ttl=int(config.nonce_ttl_seconds),
            maxsize=10000
        )

    async def new_nonce(self, account_id: int = None) -> str:
        """Generate and store a new nonce."""
        nonce = secrets.token_urlsafe(32)
        if account_id is None:
            account_id = -1
        async with self.lock:
            self.nonces[nonce] = account_id

        acme_logger.debug("Created new nonce: %s", nonce)
        return nonce

    async def pop_nonce(self, nonce: str, account_id: int = None) -> bool:
        """Validate and consume a nonce."""
        async with self.lock:
            nonce_account = self.nonces.pop(nonce, None)
            if nonce_account not in (account_id, -1, None):
                acme_logger.debug("Failed to pop nonce: %s", nonce)
                return False

            if nonce_account is None:
                acme_logger.debug("Failed to pop nonce: %s", nonce)
                return False

            acme_logger.debug("Popped nonce: %s", nonce)
            return True
