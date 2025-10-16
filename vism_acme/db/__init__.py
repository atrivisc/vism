from contextlib import contextmanager
from datetime import datetime
from typing import Any, Generator, Optional
from sqlalchemy import Integer, String, Text, DateTime, func, ForeignKey
from sqlalchemy.orm import sessionmaker, Session, MappedAsDataclass, DeclarativeBase, relationship
from sqlalchemy.engine import URL, create_engine
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from vism.util.errors import VismDatabaseException
from vism_acme.config import Database


class Base(MappedAsDataclass, DeclarativeBase):
    pass

class JWKEntry(Base):
    __tablename__ = 'jwk'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, init=False)
    n: Mapped[str] = mapped_column(Text)
    e: Mapped[str] = mapped_column(String)
    kty: Mapped[str] = mapped_column(String)

    def to_dict(self):
        return {
            "n": self.n,
            "e": self.e,
            "kty": self.kty
        }

class AccountEntry(Base):
    __tablename__ = 'account'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, init=False)
    kid: Mapped[str] = mapped_column(String)
    jwk_id: Mapped[int] = mapped_column(Integer, ForeignKey('jwk.id'))
    status: Mapped[str] = mapped_column(String)
    contact: Mapped[str] = mapped_column(String, nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), init=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now(), init=False)

    jwk: Mapped[JWKEntry] = relationship("JWKEntry", lazy="joined", default=None)

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

    def get_account_by_jwk(self, jwk: dict[str, str]) -> Optional[AccountEntry]:
        with self._get_session() as session:
            jwk_entry = session.query(JWKEntry).filter(JWKEntry.n == jwk['n'], JWKEntry.e == jwk['e'], JWKEntry.kty == jwk['kty']).first()
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
