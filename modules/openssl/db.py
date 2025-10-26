# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""OpenSSL module database models."""

from typing import Optional
from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column
from shared.db import Base
from vism_ca import ModuleData


class OpenSSLData(ModuleData, Base):
    """Database entity for OpenSSL module data."""

    __tablename__ = 'openssl_data'

    cert_name: Mapped[str] = mapped_column(String)
    cert_serial: Mapped[Optional[str]] = mapped_column(
        String, nullable=True, default=None
    )
    database: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, default=None
    )
    serial: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, default=None
    )
    crlnumber: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, default=None
    )

    def to_dict(self):
        """Convert entity to dictionary."""
        return {
            "cert_name": self.cert_name,
            "cert_serial": self.cert_serial,
            "database": self.database,
            "serial": self.serial,
            "crlnumber": self.crlnumber,
        }
