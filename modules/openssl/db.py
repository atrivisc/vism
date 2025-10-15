from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy import Column, Integer, String, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, registry

from vism_ca.db.database import ModuleData, VismDatabase

class OpenSSLData(ModuleData):
    __tablename__ = 'openssl_data'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, init=False)
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