from typing import Optional
from jwcrypto.jwk import JWK
from sqlalchemy import Integer, String, Text
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from vism_acme.db.base import Base


class JWKEntity(Base):
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
        return JWK(**self.to_dict())

    def to_dict(self) -> Optional[dict[str, str]]:
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