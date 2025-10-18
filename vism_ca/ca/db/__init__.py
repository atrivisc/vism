from contextlib import contextmanager
from datetime import datetime
from typing import Any, Generator, Optional
from sqlalchemy import Integer, String, Text, Boolean, DateTime, func
from sqlalchemy.orm import sessionmaker, registry, Session, MappedAsDataclass, DeclarativeBase
from sqlalchemy.engine import URL, create_engine
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column

from vism.util.errors import VismDatabaseException
from vism_ca.config import Database

class Base(MappedAsDataclass, DeclarativeBase):
    pass

class ModuleData(Base):
    id: Mapped[int] = mapped_column(Integer, primary_key=True, init=False)

class CertificateEntity(Base):
    __tablename__ = 'certificate'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, init=False)
    name: Mapped[str] = mapped_column(String)
    externally_managed: Mapped[bool] = mapped_column(Boolean)

    crt_pem: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default=None)
    pkey_pem: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default=None)
    pubkey_pem: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default=None)
    csr_pem: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default=None)
    crl_pem: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default=None)
    module: Mapped[Optional[str]] = mapped_column(String, nullable=True, default=None)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), init=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now(), init=False)

    def cert_data(self):
        return {
            "name": self.name,
            "crt_pem": self.crt_pem,
            "crl_pem": self.crl_pem,
        }


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
        self.mapper_registry = registry()

        self.registered_modules = []

        self.create_tables()

    def create_module_tables(self, module_data: type[ModuleData]):
        if module_data.__name__ not in self.registered_modules:
            self.mapper_registry.mapped_as_dataclass(module_data)
            self.mapper_registry.metadata.create_all(self.engine)
            self.registered_modules.append(module_data.__name__)

    def create_tables(self):
        self.mapper_registry.mapped_as_dataclass(CertificateEntity)
        self.mapper_registry.metadata.create_all(self.engine)

    def get_cert_by_name(self, name: str) -> Optional[CertificateEntity]:
        with self.get_session() as session:
            return session.query(CertificateEntity).filter(CertificateEntity.name == name).first()

    def save_to_db(self, obj):
        try:
            with self.get_session() as session:
                merged = session.merge(obj)
                session.flush()
                if merged.id is None:
                    obj.id = merged.id

                return obj
        except Exception as e:
            raise VismDatabaseException(f"Failed to save to database: {e}")


    @contextmanager
    def get_session(self) -> Generator[Session, Any, None]:
        session = self.session_maker(expire_on_commit=False)
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
