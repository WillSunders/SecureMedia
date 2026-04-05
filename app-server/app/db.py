import os

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from .models import Base


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg://securemedia:securemedia@localhost:5432/securemedia",
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


def get_session() -> Session:
    return Session(bind=engine)
