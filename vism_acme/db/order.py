# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""Database models for ACME order entities."""

from datetime import datetime, timedelta
from enum import Enum
from uuid import UUID

from sqlalchemy import Integer, String, ForeignKey, Text, Uuid
from sqlalchemy.orm import relationship
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column

from shared.db import Base
from .account import AccountEntity
from .error import ErrorEntity


class OrderStatus(str, Enum):
    """Enumeration of possible order statuses."""

    PENDING = "pending"
    PROCESSING = "processing"
    READY = "ready"
    VALID = "valid"
    INVALID = "invalid"
    EXPIRED = "expired"

def get_expiry_time():
    return (datetime.now() + timedelta(hours=12)).isoformat()

class OrderEntity(Base):
    """Database entity representing an ACME order."""

    __tablename__ = 'order'

    profile_name: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, default="pending")

    not_before: Mapped[str] = mapped_column(
        Integer, default=None, nullable=True
    )
    not_after: Mapped[str] = mapped_column(
        Integer, default=None, nullable=True
    )
    expires: Mapped[str] = mapped_column(
        String,
        default_factory=get_expiry_time,
        init=False
    )

    csr_pem: Mapped[str] = mapped_column(
        Text, init=False, default=None, nullable=True
    )
    crt_pem: Mapped[str] = mapped_column(
        Text, init=False, default=None, nullable=True
    )

    error_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey('error.id'),
        init=False,
        nullable=True,
        default=None
    )
    error: Mapped[ErrorEntity] = relationship(
        "ErrorEntity", lazy="joined", init=False, default=None
    )

    account_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey('account.id'), init=False
    )
    account: Mapped[AccountEntity] = relationship(
        "AccountEntity", lazy="joined", default=None
    )

    def set_error(self, error: ErrorEntity):
        """Set error for the order and mark it as invalid."""
        self.status = OrderStatus.INVALID
        self.error = error

    def to_dict(self):
        """Convert order entity to dictionary representation."""
        return {
            "profile_name": self.profile_name,
            "status": self.status,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "error_id": str(self.error_id),
            "expires": self.expires,
            "csr_pem": self.csr_pem,
            "crt_pem": self.crt_pem,
            "account_id": str(self.account_id),
        }
