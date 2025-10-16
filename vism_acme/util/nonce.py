import secrets
import asyncio
from cachetools import TTLCache
from vism_acme.config import AcmeConfig


class NonceManager:

    def __init__(self, config: AcmeConfig):
        self.lock = asyncio.Lock()
        self.nonces = TTLCache(ttl=config.nonce_ttl_seconds, maxsize=10000)

    async def new_nonce(self, account_id: int = None) -> str:
        nonce = secrets.token_urlsafe(32)
        if account_id is None:
            account_id = -1
        async with self.lock:
            self.nonces[nonce] = account_id

        return nonce

    async def pop_nonce(self, nonce: str, account_id: int = None) -> bool:
        async with self.lock:
            nonce_account = self.nonces.get(nonce, None)
            if nonce_account is None or (nonce_account != account_id and nonce_account != -1):
                return False

            return True