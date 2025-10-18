from datetime import datetime, timedelta
from uuid import UUID
from sqlalchemy import String, DateTime, func, ForeignKey, Uuid, Boolean, Text
from sqlalchemy.orm import relationship
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from vism_acme.db.base import Base
from vism_acme.db.order import OrderEntity
from enum import Enum

from vism_acme.routers import AcmeRequest
from vism_acme.util import absolute_url
from vism_acme.util.enum import IdentifierType


class AuthzStatus(str, Enum):
    PENDING = "pending"
    VALID = "valid"
    INVALID = "invalid"
    DEACTIVATED = "deactivated"
    EXPIRED = "expired"
    REVOKED = "revoked"

class ChallengeStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    VALID = "valid"
    INVALID = "invalid"

class ChallengeType(str, Enum):
    HTTP = "http-01"

class ErrorEntity(Base):
    __tablename__ = 'error'

    type: Mapped[str] = mapped_column(String, nullable=True, default=None)
    title: Mapped[str] = mapped_column(String, nullable=True, default=None)
    detail: Mapped[str] = mapped_column(Text, nullable=True, default=None)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), init=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now(), init=False)


class AuthzEntity(Base):
    __tablename__ = 'authz'

    identifier_type: Mapped[IdentifierType] = mapped_column(String)
    identifier_value: Mapped[str] = mapped_column(String)
    status: Mapped[AuthzStatus] = mapped_column(String)
    wildcard: Mapped[bool] = mapped_column(Boolean)
    expires: Mapped[str] = mapped_column(String, default=(datetime.now() + timedelta(minutes=30)).isoformat(), init=False)

    error_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey('error.id'), init=False, nullable=True, default=None)
    error: Mapped[ErrorEntity] = relationship("ErrorEntity", lazy="joined", init=False, default=None)
    order_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey('order.id'), init=False)
    order: Mapped[OrderEntity] = relationship("OrderEntity", lazy="joined")

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), init=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now(), init=False)

class ChallengeEntity(Base):
    __tablename__ = 'challenge'

    type: Mapped[ChallengeType] = mapped_column(String)
    key_authorization: Mapped[str] = mapped_column(String)
    status: Mapped[ChallengeStatus] = mapped_column(String)

    authz_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey('authz.id'), init=False)
    authz: Mapped[AuthzEntity] = relationship("AuthzEntity", lazy="joined")

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), init=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now(), init=False)

    def to_dict(self, request: AcmeRequest = None):
        data = {
            "type": self.type,
            "token": self.key_authorization.split('.')[0],
            "status": self.status,
        }
        if request:
            data["url"] = absolute_url(request, f"/challenge/{self.id}")
        return data
