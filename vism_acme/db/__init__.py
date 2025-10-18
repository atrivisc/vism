from contextlib import contextmanager
from typing import Any, Generator, Optional
from jwcrypto.jwk import JWK
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.engine import URL, create_engine
from vism.util.errors import VismDatabaseException
from vism_acme.config import Database
from vism_acme.db.account import AccountEntity
from vism_acme.db.base import Base
from vism_acme.db.jwk import JWKEntity
from .authz import AuthzEntity, ChallengeEntity
from .order import OrderEntity
from .account import AccountEntity
from .jwk import JWKEntity

class VismDatabase:
    def __init__(self, database_config: Database):
        self.db_url = URL.create(
            drivername="postgresql+psycopg2",
            username=database_config.username,
            password=database_config.password,
            host=database_config.host,
            port=database_config.port,
            database=database_config.database
        )

        self.engine = create_engine(self.db_url, echo=False)
        self.session_maker = sessionmaker(bind=self.engine)
        self._create_tables()

    def get_orders_by_account_kid(self, account_kid: str) -> Optional[list[OrderEntity]]:
        with self._get_session() as session:
            account_entity = session.query(AccountEntity).filter(AccountEntity.kid == account_kid).first()
            if account_entity:
                return session.query(OrderEntity).filter(OrderEntity.account_id == account_entity.id).all()

    def get_order_by_id(self, order_id: str) -> Optional[OrderEntity]:
        with self._get_session() as session:
            return session.query(OrderEntity).filter(OrderEntity.id == order_id).first()

    def get_authz_by_order_id(self, order_id: str) -> Optional[list[AuthzEntity]]:
        with self._get_session() as session:
            return session.query(AuthzEntity).filter(AuthzEntity.order_id == order_id).all()

    def get_challenges_by_authz_id(self, authz_id: str) -> Optional[list[ChallengeEntity]]:
        with self._get_session() as session:
            return session.query(ChallengeEntity).filter(ChallengeEntity.authz_id == authz_id).all()

    def get_authz_by_id(self, authz_id: str) -> Optional[AuthzEntity]:
        with self._get_session() as session:
            return session.query(AuthzEntity).filter(AuthzEntity.id == authz_id).first()

    def get_challenge_by_id(self, challenge_id: str) -> Optional[ChallengeEntity]:
        with self._get_session() as session:
            return session.query(ChallengeEntity).filter(ChallengeEntity.id == challenge_id).first()

    def get_account_by_jwk(self, jwk_data: JWK) -> Optional[AccountEntity]:
        with self._get_session() as session:
            if jwk_data['kty'] == 'oct':
                jwk_entity = session.query(JWKEntity).filter(JWKEntity.k == jwk_data['k'], JWKEntity.kty == jwk_data['kty']).first()
            if jwk_data['kty'] == 'EC':
                jwk_entity = session.query(JWKEntity).filter(JWKEntity.crv == jwk_data['crv'], JWKEntity.x == jwk_data['x'], JWKEntity.y == jwk_data['y'], JWKEntity.kty == jwk_data['kty']).first()
            if jwk_data['kty'] == 'RSA':
                jwk_entity = session.query(JWKEntity).filter(JWKEntity.n == jwk_data['n'], JWKEntity.e == jwk_data['e'], JWKEntity.kty == jwk_data['kty']).first()

            if not jwk_entity:
                return None

            return session.query(AccountEntity).filter(AccountEntity.jwk_id == jwk_entity.id).first()

    def get_account_by_kid(self, kid: str) -> Optional[AccountEntity]:
        with self._get_session() as session:
            return session.query(AccountEntity).filter(AccountEntity.kid == kid).first()

    def save_to_db(self, obj):
        try:
            with self._get_session() as session:
                merged = session.merge(obj)
                session.flush()
                return merged
        except Exception as e:
            raise VismDatabaseException(f"Failed to save to database: {e}")

    def _create_tables(self):
        Base.metadata.create_all(self.engine)

    @contextmanager
    def _get_session(self) -> Generator[Session, Any, None]:
        session = self.session_maker(expire_on_commit=False)
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
