from typing import Optional
from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column
from vism_ca.db import ModuleData, VismDatabase


class OpenSSLData(ModuleData):
    __tablename__ = 'openssl_data'

    cert_name: Mapped[str] = mapped_column(String)
    cert_serial: Mapped[Optional[str]] = mapped_column(String, nullable=True, default=None)
    database: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default=None)
    serial: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default=None)
    crlnumber: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default=None)

    @classmethod
    def get_by_cert_serial(cls, cert_serial: str) -> Optional['OpenSSLData']:
        with VismDatabase.get_session() as session:
            return session.query(cls).filter(cls.cert_serial == cert_serial).first()

    @classmethod
    def get_by_cert_name(cls, cert_name: str) -> Optional['OpenSSLData']:
        with VismDatabase.get_session() as session:
            return session.query(cls).filter(cls.cert_name == cert_name).first()