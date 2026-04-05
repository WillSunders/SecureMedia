from sqlalchemy import Boolean, Column, ForeignKey, Integer, LargeBinary, String, Text
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    status = Column(String, default="active", nullable=False)

    certificates = relationship("Certificate", back_populates="user")
    memberships = relationship("Membership", back_populates="user")
    posts = relationship("Post", back_populates="author")


class Certificate(Base):
    __tablename__ = "certificates"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    cert_pem = Column(Text, nullable=False)
    issued_at = Column(String, nullable=False)
    expires_at = Column(String, nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)

    user = relationship("User", back_populates="certificates")


class Group(Base):
    __tablename__ = "groups"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    memberships = relationship("Membership", back_populates="group")
    posts = relationship("Post", back_populates="group")
    key_versions = relationship("GroupKeyVersion", back_populates="group")


class Membership(Base):
    __tablename__ = "memberships"

    id = Column(Integer, primary_key=True)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    role = Column(String, default="member", nullable=False)
    active = Column(Boolean, default=True, nullable=False)

    group = relationship("Group", back_populates="memberships")
    user = relationship("User", back_populates="memberships")


class GroupKeyVersion(Base):
    __tablename__ = "group_key_versions"

    id = Column(Integer, primary_key=True)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=False)
    version_number = Column(Integer, nullable=False)

    group = relationship("Group", back_populates="key_versions")
    wrapped_keys = relationship("WrappedKey", back_populates="group_key_version")


class WrappedKey(Base):
    __tablename__ = "wrapped_keys"

    id = Column(Integer, primary_key=True)
    group_key_version_id = Column(Integer, ForeignKey("group_key_versions.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    encrypted_key = Column(Text, nullable=False)

    group_key_version = relationship("GroupKeyVersion", back_populates="wrapped_keys")
    user = relationship("User")


class Post(Base):
    __tablename__ = "posts"

    id = Column(Integer, primary_key=True)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=False)
    author_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    ciphertext = Column(LargeBinary, nullable=False)
    nonce = Column(LargeBinary, nullable=False)
    auth_tag = Column(LargeBinary, nullable=False)
    signature = Column(LargeBinary, nullable=False)
    cert_id = Column(Integer, ForeignKey("certificates.id"), nullable=False)
    key_version = Column(Integer, nullable=False)

    group = relationship("Group", back_populates="posts")
    author = relationship("User", back_populates="posts")
