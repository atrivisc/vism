from datetime import datetime, timedelta
from enum import Enum
from uuid import UUID

from sqlalchemy import Integer, String, DateTime, func, ForeignKey, Text, Uuid
from sqlalchemy.orm import relationship
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from vism_acme.db import AccountEntity
from vism_acme.db.base import Base

class OrderStatus(Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    READY = "ready"
    VALID = "valid"
    INVALID = "invalid"
    EXPIRED = "expired"

class OrderEntity(Base):
    __tablename__ = 'order'

    profile_name: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, default="pending")

    not_before: Mapped[str] = mapped_column(Integer, default=None, nullable=True)
    not_after: Mapped[str] = mapped_column(Integer, default=None, nullable=True)
    expires: Mapped[str] = mapped_column(String, default=(datetime.now() + timedelta(minutes=30)).isoformat(), init=False)

    csr_pem: Mapped[str] = mapped_column(Text, init=False, default=None, nullable=True)
    crt_pem: Mapped[str] = mapped_column(Text, init=False, default=None, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), init=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now(), init=False)

    account_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey('account.id'), init=False)
    account: Mapped[AccountEntity] = relationship("AccountEntity", lazy="joined", default=None)
