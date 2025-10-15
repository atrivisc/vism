from contextlib import contextmanager
from typing import Any, Generator, Optional, ClassVar
from sqlalchemy import Integer, String, Text, Boolean, ForeignKey, Engine
from sqlalchemy.exc import ArgumentError
from sqlalchemy.orm import sessionmaker, registry, Session
from sqlalchemy.engine import URL, create_engine
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column

from vism_ca.config import Database

class ModuleData:
    id: Mapped[int] = mapped_column(Integer, primary_key=True, init=False)

    def save_to_db(self) -> None:
        with VismDatabase.get_session() as session:
            merged = session.merge(self)
            session.flush()
            if merged.id is None:
                self.id = merged.id


class Certificate:
    __tablename__ = 'certificate'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, init=False)
    name: Mapped[str] = mapped_column(String)
    externally_managed: Mapped[bool] = mapped_column(Boolean)

    certificate_pem: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default=None)
    private_key_pem: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default=None)
    public_key_pem: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default=None)
    csr_pem: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default=None)
    crl_pem: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default=None)
    signed_by_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey('certificate.id'), nullable=True,
                                                        default=None)
    module: Mapped[Optional[str]] = mapped_column(String, nullable=True, default=None)

    def save_to_db(self) -> None:
        with VismDatabase.get_session() as session:
            merged = session.merge(self)
            session.flush()
            if merged.id is None:
                self.id = merged.id

    @classmethod
    def get_by_id(cls, cert_id: int) -> Optional['Certificate']:
        with VismDatabase.get_session() as session:
            return session.query(cls).filter(cls.id == cert_id).first()

    @classmethod
    def get_by_name(cls, name: str) -> Optional['Certificate']:
        with VismDatabase.get_session() as session:
            return session.query(cls).filter(cls.name == name).first()


class VismDatabase:
    mapper_registry = registry()
    engine: ClassVar[Optional[Engine]] = None
    session_maker: ClassVar[Optional[sessionmaker]] = None

    def __init__(self, config: Database):
        self.config = config
        if VismDatabase.engine is None:
            db_url = URL.create(
                drivername="postgresql+psycopg2",
                username=config.username,
                password=config.password,
                host=config.host,
                port=config.port,
                database=config.database
            )
            VismDatabase.engine = create_engine(db_url, echo=False)
            VismDatabase.session_maker = sessionmaker(bind=self.engine)

        self.engine = VismDatabase.engine
        self.session = VismDatabase.session_maker

        self.create_tables()

    @classmethod
    def create_module_tables(cls, module: ModuleData):
        try:
            cls.mapper_registry.mapped_as_dataclass(module)
            cls.mapper_registry.metadata.create_all(cls.engine)
        except ArgumentError:
            pass

    @classmethod
    def create_tables(cls):
        cls.mapper_registry.mapped_as_dataclass(Certificate)
        cls.mapper_registry.metadata.create_all(cls.engine)

    @classmethod
    @contextmanager
    def get_session(cls) -> Generator[Session, Any, None]:
        session = cls.session_maker(expire_on_commit=False)
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
