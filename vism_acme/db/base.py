from uuid import UUID, uuid4
from sqlalchemy import Uuid
from sqlalchemy.orm import MappedAsDataclass, DeclarativeBase, Mapped, mapped_column


class Base(MappedAsDataclass, DeclarativeBase):
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4, init=False)

