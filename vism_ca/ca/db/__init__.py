from datetime import datetime
from typing import Optional
from sqlalchemy import Integer, String, Text, Boolean, DateTime, func
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from shared.db import Base, VismDatabase

class ModuleData:
    pass

class CertificateEntity(Base):
    __tablename__ = 'certificate'

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

    def to_dict(self):
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
        return {
            "name": self.name,
            "crt_pem": self.crt_pem,
            "crl_pem": self.crl_pem,
        }


class VismCADatabase(VismDatabase):
    def get_cert_by_name(self, name: str) -> Optional[CertificateEntity]:
        return self.get(CertificateEntity, CertificateEntity.name == name)
