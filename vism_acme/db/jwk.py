# Licensed under the GPL 3: https://www.gnu.org/licenses/gpl-3.0.html

"""Database models for JSON Web Key (JWK) entities."""

from typing import Optional
from jwcrypto.jwk import JWK
from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from shared.db import Base


class JWKEntity(Base):
    """Database entity representing a JSON Web Key (JWK)."""

    __tablename__ = 'jwk'

    kty: Mapped[str] = mapped_column(String)

    ### RSA ###
    n: Mapped[str] = mapped_column(Text, default=None, nullable=True)
    e: Mapped[str] = mapped_column(String, default=None, nullable=True)

    ### EC ###
    crv: Mapped[str] = mapped_column(String, default=None, nullable=True)
    x: Mapped[str] = mapped_column(String, default=None, nullable=True)
    y: Mapped[str] = mapped_column(String, default=None, nullable=True)

    ### OCT ###
    k: Mapped[str] = mapped_column(Text, default=None, nullable=True)

    def to_jwk(self) -> JWK:
        """Convert entity to JWK object."""
        return JWK(**self.to_dict())

    def to_dict(self) -> Optional[dict[str, str]]:
        """Convert JWK entity to dictionary representation."""
        if self.kty == 'oct':
            return {
                "k": self.k,
                "kty": self.kty
            }
        if self.kty == 'EC':
            return {
                "crv": self.crv,
                "x": self.x,
                "y": self.y,
                "kty": self.kty
            }
        if self.kty == 'RSA':
            return {
                "n": self.n,
                "e": self.e,
                "kty": self.kty
            }

        return None
