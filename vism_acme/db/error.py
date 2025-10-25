# Licensed under the GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""Database models for ACME error entities."""

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column
from shared.db import Base


class ErrorEntity(Base):
    """Database entity representing an ACME error."""

    __tablename__ = 'error'

    type: Mapped[str] = mapped_column(String, nullable=True, default=None)
    title: Mapped[str] = mapped_column(String, nullable=True, default=None)
    detail: Mapped[str] = mapped_column(Text, nullable=True, default=None)

    def to_dict(self):
        """Convert error entity to dictionary representation."""
        return {
            "type": self.type,
            "title": self.title,
            "detail": self.detail,
        }
