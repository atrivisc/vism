from datetime import datetime
from typing import Optional
from sqlalchemy import String, Text, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column
from vism_ca.ca.db import ModuleData, VismDatabase


class OpenSSLData(ModuleData):
    __tablename__ = 'openssl_data'

    cert_name: Mapped[str] = mapped_column(String)
    cert_serial: Mapped[Optional[str]] = mapped_column(String, nullable=True, default=None)
    database: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default=None)
    serial: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default=None)
    crlnumber: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default=None)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), init=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now(), init=False)


    @classmethod
    def get_by_cert_serial(cls, db, cert_serial: str) -> Optional['OpenSSLData']:
        with db._get_session() as session:
            return session.query(cls).filter(cls.cert_serial == cert_serial).first()

    @classmethod
    def get_by_cert_name(cls, db, cert_name: str) -> Optional['OpenSSLData']:
        with db._get_session() as session:
            return session.query(cls).filter(cls.cert_name == cert_name).first()