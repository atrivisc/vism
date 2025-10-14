import base64
import json
from uuid import UUID, uuid4

from pydantic import field_validator
from pydantic.dataclasses import dataclass
from sqlalchemy import Uuid, String
from sqlalchemy.orm import MappedAsDataclass, DeclarativeBase, Mapped, mapped_column
from contextlib import contextmanager
from typing import Any, Generator, Type
from sqlalchemy import ColumnExpressionArgument
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.engine import URL, create_engine
from shared.errors import VismDatabaseException
from shared import shared_logger
from shared.data.validation import Data

@dataclass
class Database:
    host: str = ""
    port: int = 3306
    database: str = ""
    username: str = ""
    password: str = ""

    @field_validator("port")
    @classmethod
    def port_must_be_valid(cls, v):
        if v < 1 or v > 65535:
            raise ValueError("Port must be between 1 and 65535")
        return v

class Base(MappedAsDataclass, DeclarativeBase):
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4, init=False)
    signature: Mapped[str] = mapped_column(String, nullable=True, default=None, init=False)

    def to_dict(self) -> dict[str, Any]:
        raise NotImplementedError()

    def validate(self, validation_module: Data):
        shared_logger.info(f"Validating {self.__class__.__name__} {self.id}")
        data = self.to_dict()
        data_json = json.dumps(data, sort_keys=True)
        validation_module.verify(data_json.encode("utf-8"), self.signature)

    def sign(self, validation_module: Data):
        shared_logger.info(f"Signing {self.__class__.__name__} {self.id}")
        data = self.to_dict()
        data_json = json.dumps(data, sort_keys=True)
        signature_bytes = validation_module.sign(data_json.encode("utf-8"))
        return base64.urlsafe_b64encode(signature_bytes).decode("utf-8")


class VismDatabase:
    def __init__(self, database_config: Database, validation_module: Data):
        shared_logger.info("Initializing database")
        self.validation_module = validation_module

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

    def get(self, obj_type: Type[Base], *criterion: ColumnExpressionArgument[bool], multiple: bool = False):
        with self._get_session() as session:
            objs: list[Base] = session.query(obj_type).filter(*criterion).all()
            for obj in objs:
                obj.validate(self.validation_module)
            if not multiple:
                if len(objs) == 0:
                    return None
                if len(objs) > 1:
                    raise VismDatabaseException("Multiple objects found.")
                return objs[0]
            return objs

    def save_to_db(self, obj: Base):
        try:
            with self._get_session() as session:
                merged = session.merge(obj)
                session.flush()
                merged.signature = merged.sign(self.validation_module)
                merged = session.merge(merged)
                session.flush()
                shared_logger.info(f"Saved {merged.__class__.__name__} {merged.id} to database")
                return merged
        except Exception as e:
            raise

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
