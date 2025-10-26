# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""Database models for ACME account entities."""

from uuid import UUID

from sqlalchemy import String, ForeignKey, Uuid
from sqlalchemy.orm import relationship
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from shared.db import Base
from vism_acme.db.jwk import JWKEntity


class AccountEntity(Base):
    """Database entity representing an ACME account."""

    __tablename__ = 'account'

    kid: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String)
    contact: Mapped[str] = mapped_column(String, nullable=True, default=None)

    jwk_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey('jwk.id'), init=False
    )
    _jwk: Mapped[JWKEntity] = relationship(
        "JWKEntity", lazy="joined", default=None
    )

    @property
    def jwk(self):
        """Get the JWK associated with this account."""
        return self._jwk.to_jwk()

    def to_dict(self):
        """Convert account entity to dictionary representation."""
        return {
            "kid": self.kid,
            "status": self.status,
            "contact": self.contact,
            "jwk_id": str(self.jwk_id),
        }
