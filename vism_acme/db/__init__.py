from contextlib import contextmanager
from typing import Any, Generator, Optional
from jwcrypto.jwk import JWK
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.engine import URL, create_engine
from vism.util.errors import VismDatabaseException
from vism_acme.config import Database
from vism_acme.db.account import AccountEntry
from vism_acme.db.base import Base
from vism_acme.db.jwk import JWKEntry
from .order import OrderEntry
from .challenge import ChallengeEntry, AuthzEntry
from .account import AccountEntry
from .jwk import JWKEntry

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

    def get_orders_by_account_kid(self, account_kid: str) -> Optional[list[OrderEntry]]:
        with self._get_session() as session:
            account_entry = session.query(AccountEntry).filter(AccountEntry.kid == account_kid).first()
            if account_entry:
                return session.query(OrderEntry).filter(OrderEntry.account_id == account_entry.id).all()

    def get_order_by_id(self, order_id: str) -> Optional[OrderEntry]:
        with self._get_session() as session:
            return session.query(OrderEntry).filter(OrderEntry.id == order_id).first()

    def get_authz_by_order_id(self, order_id: str) -> Optional[list[AuthzEntry]]:
        with self._get_session() as session:
            return session.query(AuthzEntry).filter(AuthzEntry.order_id == order_id).all()

    def get_challenges_by_authz_id(self, authz_id: str) -> Optional[list[ChallengeEntry]]:
        with self._get_session() as session:
            return session.query(ChallengeEntry).filter(ChallengeEntry.authz_id == authz_id).all()

    def get_authz_by_id(self, authz_id: str) -> Optional[AuthzEntry]:
        with self._get_session() as session:
            return session.query(AuthzEntry).filter(AuthzEntry.id == authz_id).first()

    def get_challenge_by_id(self, challenge_id: str) -> Optional[ChallengeEntry]:
        with self._get_session() as session:
            return session.query(ChallengeEntry).filter(ChallengeEntry.id == challenge_id).first()

    def get_account_by_jwk(self, jwk_data: JWK) -> Optional[AccountEntry]:
        with self._get_session() as session:
            if jwk_data['kty'] == 'oct':
                jwk_entry = session.query(JWKEntry).filter(JWKEntry.k == jwk_data['k'], JWKEntry.kty == jwk_data['kty']).first()
            if jwk_data['kty'] == 'EC':
                jwk_entry = session.query(JWKEntry).filter(JWKEntry.crv == jwk_data['crv'], JWKEntry.x == jwk_data['x'], JWKEntry.y == jwk_data['y'], JWKEntry.kty == jwk_data['kty']).first()
            if jwk_data['kty'] == 'RSA':
                jwk_entry = session.query(JWKEntry).filter(JWKEntry.n == jwk_data['n'], JWKEntry.e == jwk_data['e'], JWKEntry.kty == jwk_data['kty']).first()

            if not jwk_entry:
                return None

            return session.query(AccountEntry).filter(AccountEntry.jwk_id == jwk_entry.id).first()

    def get_account_by_kid(self, kid: str) -> Optional[AccountEntry]:
        with self._get_session() as session:
            return session.query(AccountEntry).filter(AccountEntry.kid == kid).first()

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
