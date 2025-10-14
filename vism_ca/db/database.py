from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Generator, Optional, ClassVar

from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey, Engine
from sqlalchemy.orm import declarative_base, sessionmaker, registry, Session
from sqlalchemy.engine import URL, create_engine

from vism_ca.config import Database

@dataclass
class ModuleData:
    pass

@dataclass
class Certificate:
    __tablename__ = 'certificate'
    __sa_dataclass_metadata_key__ = "sa"

    id: int = field(init=False, metadata={"sa": Column(Integer, primary_key=True)})
    name: str = field(metadata={"sa": Column(String)})

    externally_managed: bool = field(metadata={"sa": Column(Boolean)})

    certificate_pem: str = field(default=None, metadata={"sa": Column(Text, nullable=True)})
    private_key_pem: str = field(default=None, metadata={"sa": Column(Text, nullable=True)})
    public_key_pem: str = field(default=None, metadata={"sa": Column(Text, nullable=True)})
    csr_pem: str = field(default=None, metadata={"sa": Column(Text, nullable=True)})
    signed_by_id: int = field(default=None, metadata={"sa": Column(Integer, ForeignKey('certificate.id'), nullable=True)})
    module: str = field(default=None, metadata={"sa": Column(String, nullable=True)})

    def save_to_db(self) -> None:
        with VismDatabase.get_session() as session:
            session.add(self)
            session.flush()
            session.refresh(self)

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
        VismDatabase.mapper_registry.mapped(module)
        VismDatabase.mapper_registry.metadata.create_all(VismDatabase.engine)

    @classmethod
    def create_tables(cls):
        VismDatabase.mapper_registry.mapped(Certificate)
        VismDatabase.mapper_registry.metadata.create_all(VismDatabase.engine)

    @classmethod
    @contextmanager
    def get_session(cls) -> Generator[Session, Any, None]:
        session = cls.session_maker()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
