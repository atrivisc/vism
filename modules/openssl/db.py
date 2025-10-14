from dataclasses import dataclass, field

from sqlalchemy import Column, Integer, String, Text, ForeignKey
from vism_ca.db.database import ModuleData


@dataclass
class OpenSSLData(ModuleData):
    __tablename__ = 'openssl_data'
    __sa_dataclass_metadata_key__ = "sa"

    id: int = field(init=False, metadata={"sa": Column(Integer, primary_key=True)})
    cert_name: str = field(metadata={"sa": Column(String)})
    cert_id: int = field(metadata={"sa": Column(Integer, ForeignKey('certificate.id'))})

    database: str = field(default=None, metadata={"sa": Column(Text, nullable=True)})
    serial: str = field(default=None, metadata={"sa": Column(Text, nullable=True)})
    crlnumber: str = field(default=None, metadata={"sa": Column(Text, nullable=True)})
