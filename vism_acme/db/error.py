from datetime import datetime
from sqlalchemy import String, Text, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column
from shared.db import Base


class ErrorEntity(Base):
    __tablename__ = 'error'

    type: Mapped[str] = mapped_column(String, nullable=True, default=None)
    title: Mapped[str] = mapped_column(String, nullable=True, default=None)
    detail: Mapped[str] = mapped_column(Text, nullable=True, default=None)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), init=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now(), init=False)

    def to_dict(self):
        return {
            "type": self.type,
            "title": self.title,
            "detail": self.detail,
        }
