from datetime import datetime
from uuid import UUID

from sqlalchemy import String, DateTime, func, ForeignKey, Uuid
from sqlalchemy.orm import relationship
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from vism_acme.db.base import Base
from vism_acme.db.jwk import JWKEntry


class AccountEntry(Base):
    __tablename__ = 'account'

    kid: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String)
    contact: Mapped[str] = mapped_column(String, nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), init=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now(), init=False)

    jwk_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey('jwk.id'), init=False)
    _jwk: Mapped[JWKEntry] = relationship("JWKEntry", lazy="joined", default=None)

    @property
    def jwk(self):
        return self._jwk.to_jwk()