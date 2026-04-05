import os
import time

import jwt
from passlib.context import CryptContext


pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

SECRET_KEY = os.getenv("APP_SECRET_KEY", "dev-secret-change-me")
ALGORITHM = "HS256"
TOKEN_TTL_SECONDS = 60 * 60 * 24


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def create_access_token(user_id: int) -> str:
    payload = {
        "sub": str(user_id),
        "iat": int(time.time()),
        "exp": int(time.time()) + TOKEN_TTL_SECONDS,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> int:
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    return int(payload["sub"])
