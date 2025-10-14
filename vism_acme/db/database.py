from typing import Optional
from jwcrypto.jwk import JWK
from shared.db import VismDatabase
from vism_acme.db import OrderEntity, AccountEntity, AuthzEntity, ChallengeEntity, JWKEntity


class VismAcmeDatabase(VismDatabase):
    def get_orders_by_account_kid(self, account_kid: str) -> Optional[list[OrderEntity]]:
        return self.get(AccountEntity, AccountEntity.kid == account_kid)

    def get_order_by_id(self, order_id: str) -> Optional[OrderEntity]:
        return self.get(OrderEntity, OrderEntity.id == order_id)

    def get_authz_by_order_id(self, order_id: str) -> Optional[list[AuthzEntity]]:
        return self.get(AuthzEntity, AuthzEntity.order_id == order_id, multiple=True)

    def get_challenges_by_authz_id(self, authz_id: str) -> Optional[list[ChallengeEntity]]:
        return self.get(ChallengeEntity, ChallengeEntity.authz_id == authz_id, multiple=True)

    def get_authz_by_id(self, authz_id: str) -> Optional[AuthzEntity]:
        return self.get(AuthzEntity, AuthzEntity.id == authz_id)

    def get_challenge_by_id(self, challenge_id: str) -> Optional[ChallengeEntity]:
        return self.get(ChallengeEntity, ChallengeEntity.id == challenge_id)

    def get_account_by_jwk(self, jwk_data: JWK) -> Optional[AccountEntity]:
        with self._get_session() as session:
            if jwk_data['kty'] == 'oct':
                jwk_entity = self.get(JWKEntity, JWKEntity.k == jwk_data['k'], JWKEntity.kty == jwk_data['kty'])
            if jwk_data['kty'] == 'EC':
                jwk_entity = self.get(JWKEntity, JWKEntity.crv == jwk_data['crv'], JWKEntity.x == jwk_data['x'], JWKEntity.y == jwk_data['y'], JWKEntity.kty == jwk_data['kty'])
            if jwk_data['kty'] == 'RSA':
                jwk_entity = self.get(JWKEntity, JWKEntity.n == jwk_data['n'], JWKEntity.e == jwk_data['e'], JWKEntity.kty == jwk_data['kty'])

            if not jwk_entity:
                return None

            return self.get(AccountEntity, AccountEntity.jwk_id == jwk_entity.id)

    def get_account_by_kid(self, kid: str) -> Optional[AccountEntity]:
        return self.get(AccountEntity, AccountEntity.kid == kid)
