from sqlalchemy import Boolean, Column, Integer, LargeBinary, String
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


class CARecord(Base):
    __tablename__ = "ca_records"

    id = Column(Integer, primary_key=True)
    private_key_pem = Column(String, nullable=False)
    certificate_pem = Column(String, nullable=False)


class Certificate(Base):
    __tablename__ = "certificates"

    user_id = Column(String, primary_key=True)
    cert_pem = Column(String, nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)


class PublicKeyBundle(Base):
    __tablename__ = "public_keys"

    user_id = Column(String, primary_key=True)
    signing_public_key_pem = Column(String, nullable=False)
    agreement_public_key_pem = Column(String, nullable=False)


class GroupKey(Base):
    __tablename__ = "group_keys"

    id = Column(Integer, primary_key=True)
    group_id = Column(String, nullable=False)
    version = Column(Integer, nullable=False)
    key_bytes = Column(LargeBinary, nullable=False)


class WrappedKey(Base):
    __tablename__ = "wrapped_keys"

    id = Column(Integer, primary_key=True)
    group_id = Column(String, nullable=False)
    version = Column(Integer, nullable=False)
    user_id = Column(String, nullable=False)
    wrapped_key = Column(String, nullable=False)
