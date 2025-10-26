# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""Database interface for VISM ACME operations."""

from typing import Optional
from jwcrypto.jwk import JWK
from shared.db import VismDatabase
from vism_acme.db import (
    OrderEntity,
    AccountEntity,
    AuthzEntity,
    ChallengeEntity,
    JWKEntity
)


class VismAcmeDatabase(VismDatabase):
    """Database interface for VISM ACME operations."""

    def get_orders_by_account_kid(
            self,
            account_kid: str
    ) -> Optional[list[OrderEntity]]:
        """Get all orders for an account by account kid."""
        return self.get(AccountEntity, AccountEntity.kid == account_kid)

    def get_order_by_id(self, order_id: str) -> Optional[OrderEntity]:
        """Get an order by its ID."""
        return self.get(OrderEntity, OrderEntity.id == order_id)

    def get_authz_by_order_id(
            self,
            order_id: str
    ) -> Optional[list[AuthzEntity]]:
        """Get all authorizations for an order."""
        return self.get(
            AuthzEntity,
            AuthzEntity.order_id == order_id,
            multiple=True
        )

    def get_challenges_by_authz_id(
            self,
            authz_id: str
    ) -> Optional[list[ChallengeEntity]]:
        """Get all challenges for an authorization."""
        return self.get(
            ChallengeEntity,
            ChallengeEntity.authz_id == authz_id,
            multiple=True
        )

    def get_authz_by_id(self, authz_id: str) -> Optional[AuthzEntity]:
        """Get an authorization by its ID."""
        return self.get(AuthzEntity, AuthzEntity.id == authz_id)

    def get_challenge_by_id(
            self,
            challenge_id: str
    ) -> Optional[ChallengeEntity]:
        """Get a challenge by its ID."""
        return self.get(ChallengeEntity, ChallengeEntity.id == challenge_id)

    def get_account_by_jwk(
            self,
            jwk_data: JWK
    ) -> Optional[AccountEntity]:
        """Get an account by its JWK."""
        jwk_entity = None

        if jwk_data['kty'] == 'oct':
            jwk_entity = self.get(
                JWKEntity,
                JWKEntity.k == jwk_data['k'],
                JWKEntity.kty == jwk_data['kty']
            )
        elif jwk_data['kty'] == 'EC':
            jwk_entity = self.get(
                JWKEntity,
                JWKEntity.crv == jwk_data['crv'],
                JWKEntity.x == jwk_data['x'],
                JWKEntity.y == jwk_data['y'],
                JWKEntity.kty == jwk_data['kty']
            )
        elif jwk_data['kty'] == 'RSA':
            jwk_entity = self.get(
                JWKEntity,
                JWKEntity.n == jwk_data['n'],
                JWKEntity.e == jwk_data['e'],
                JWKEntity.kty == jwk_data['kty']
            )

        if not jwk_entity:
            return None

        return self.get(
            AccountEntity,
            AccountEntity.jwk_id == jwk_entity.id
        )

    def get_account_by_kid(self, kid: str) -> Optional[AccountEntity]:
        """Get an account by its kid (key ID)."""
        return self.get(AccountEntity, AccountEntity.kid == kid)
