# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html

"""Database models for ACME authorization entities."""

from datetime import datetime, timedelta
from enum import Enum
from uuid import UUID

from sqlalchemy import String, ForeignKey, Uuid, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column

from shared.db import Base
from shared.util import absolute_url
from .order import OrderEntity
from .error import ErrorEntity


class IdentifierType(str, Enum):
    """Enumeration of ACME identifier types."""

    DNS = "dns"
    IP = "ip"


class AuthzStatus(str, Enum):
    """Enumeration of ACME authorization statuses."""

    PENDING = "pending"
    VALID = "valid"
    INVALID = "invalid"
    DEACTIVATED = "deactivated"
    EXPIRED = "expired"
    REVOKED = "revoked"


class ChallengeStatus(str, Enum):
    """Enumeration of ACME challenge statuses."""

    PENDING = "pending"
    PROCESSING = "processing"
    VALID = "valid"
    INVALID = "invalid"


class ChallengeType(str, Enum):
    """Enumeration of ACME challenge types."""

    HTTP = "http-01"


class AuthzEntity(Base):
    """Database entity representing an ACME authorization."""

    __tablename__ = 'authz'

    identifier_type: Mapped[IdentifierType] = mapped_column(String)
    identifier_value: Mapped[str] = mapped_column(String)
    status: Mapped[AuthzStatus] = mapped_column(String)
    wildcard: Mapped[bool] = mapped_column(Boolean)
    expires: Mapped[str] = mapped_column(
        String,
        default=(datetime.now() + timedelta(hours=12)).isoformat(),
        init=False
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
    order_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey('order.id'), init=False
    )
    order: Mapped[OrderEntity] = relationship(
        "OrderEntity", lazy="joined"
    )

    def to_dict(self):
        """Convert authorization entity to dictionary representation."""
        return {
            "identifier_type": self.identifier_type,
            "identifier_value": self.identifier_value,
            "status": self.status,
            "wildcard": self.wildcard,
            "expires": self.expires,
            "error_id": str(self.error_id),
            "order_id": str(self.order_id),
        }


class ChallengeEntity(Base):
    """Database entity representing an ACME challenge."""

    __tablename__ = 'challenge'

    type: Mapped[ChallengeType] = mapped_column(String)
    key_authorization: Mapped[str] = mapped_column(String)
    status: Mapped[ChallengeStatus] = mapped_column(String)

    authz_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey('authz.id'), init=False
    )
    authz: Mapped[AuthzEntity] = relationship(
        "AuthzEntity", lazy="joined"
    )

    def to_dict(self):
        """Convert challenge entity to dictionary representation."""
        return {
            "type": self.type,
            "key_authorization": self.key_authorization,
            "status": self.status,
            "authz_id": str(self.authz_id),
        }

    def to_reply_dict(self, request=None):
        """Convert challenge entity to reply in dictionary format."""
        data = {
            "type": self.type,
            "token": self.key_authorization.split('.')[0],
            "status": self.status,
        }
        if request:
            data["url"] = absolute_url(request, f"/challenge/{self.id}")
        return data
