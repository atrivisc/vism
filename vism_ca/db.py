# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html

"""
Database module for Vism CA.

This module provides database models and operations for the Vism CA,
including certificate entities and database management.
"""

from typing import Optional
from sqlalchemy import String, Text, Boolean
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from shared.db import Base, VismDatabase


class ModuleData:
    """Base class for module-specific data storage."""


class CertificateEntity(Base):
    """Database entity representing a certificate."""

    __tablename__ = 'certificate'

    name: Mapped[str] = mapped_column(String)
    externally_managed: Mapped[bool] = mapped_column(Boolean)

    crt_pem: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, default=None
    )
    pkey_pem: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, default=None
    )
    pubkey_pem: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, default=None
    )
    csr_pem: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, default=None
    )
    crl_pem: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, default=None
    )
    module: Mapped[Optional[str]] = mapped_column(
        String, nullable=True, default=None
    )

    def to_dict(self):
        """Convert entity to dictionary representation."""
        return {
            "name": self.name,
            "externally_managed": self.externally_managed,
            "crt_pem": self.crt_pem,
            "pkey_pem": self.pkey_pem,
            "pubkey_pem": self.pubkey_pem,
            "csr_pem": self.csr_pem,
            "crl_pem": self.crl_pem,
            "module": self.module,
        }

    def cert_data(self):
        """Get certificate data for external use."""
        return {
            "name": self.name,
            "crt_pem": self.crt_pem,
            "crl_pem": self.crl_pem,
        }


class VismCADatabase(VismDatabase):
    """Database interface for Vism CA operations."""

    def get_cert_by_name(self, name: str) -> Optional[CertificateEntity]:
        """
        Get a certificate entity by name.

        Args:
            name: Certificate name to search for

        Returns:
            CertificateEntity if found, None otherwise
        """
        with self._get_session() as session:
            obj: CertificateEntity = session.query(
                CertificateEntity
            ).filter(CertificateEntity.name == name).first()
            return obj
