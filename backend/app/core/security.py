import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from app.core.config import get_settings


password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def create_access_token(user_id: UUID, role: str) -> tuple[str, datetime]:
    settings = get_settings()
    if settings.jwt_secret is None:  # Configuration validation normally makes this unreachable.
        raise RuntimeError("JWT secret is not configured")
    expires = datetime.now(UTC) + timedelta(minutes=settings.jwt_expire_minutes)
    payload = {"sub": str(user_id), "role": role, "exp": expires, "iat": datetime.now(UTC), "type": "admin"}
    return jwt.encode(payload, settings.jwt_secret.get_secret_value(), algorithm=settings.jwt_algorithm), expires


def decode_access_token(token: str) -> dict:
    settings = get_settings()
    if settings.jwt_secret is None:  # Configuration validation normally makes this unreachable.
        raise RuntimeError("JWT secret is not configured")
    return jwt.decode(token, settings.jwt_secret.get_secret_value(), algorithms=[settings.jwt_algorithm])


def generate_api_key() -> tuple[str, str]:
    key = f"sec_{secrets.token_urlsafe(32)}"
    return key, key[:12]


def hash_api_key(key: str) -> str:
    pepper = get_settings().api_key_pepper
    if pepper is None:  # Configuration validation normally makes this unreachable.
        raise RuntimeError("API key pepper is not configured")
    return hmac.new(pepper.get_secret_value().encode(), key.encode(), hashlib.sha256).hexdigest()


def secure_compare(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)
