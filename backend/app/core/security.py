"""
backend/app/core/security.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Cryptographic operations: bcrypt password hashing and PyJWT access token handling.
"""

from datetime import datetime, timedelta, timezone
import logging
import os
from typing import Any

import bcrypt
import jwt

logger = logging.getLogger(__name__)

# Algorithm and Work Factor
ALGORITHM = "HS256"
BCRYPT_ROUNDS = 12
DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES = 60
DEV_FALLBACK_SECRET = "sentinelx-insecure-development-secret-key-32b"


class TokenError(Exception):
    """Base exception for JWT processing errors."""


class TokenExpiredError(TokenError):
    """Token has expired."""


class TokenInvalidError(TokenError):
    """Token signature or claims are invalid."""


def get_jwt_secret_key() -> str:
    """Retrieve JWT secret key from environment or fallback with warning in dev."""
    secret = os.environ.get("JWT_SECRET_KEY")
    if not secret:
        env = os.environ.get("APP_ENV", "development").lower()
        if env == "production":
            raise RuntimeError("JWT_SECRET_KEY environment variable is required in production.")
        logger.warning(
            "JWT_SECRET_KEY not set. Using development fallback secret. Do not use in production!"
        )
        return DEV_FALLBACK_SECRET
    return secret


def get_token_expire_minutes() -> int:
    """Retrieve token lifetime in minutes from environment."""
    try:
        return int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES))
    except ValueError:
        return DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt with work factor 12."""
    if not password:
        raise ValueError("Password cannot be empty.")
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    hashed_bytes = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed_bytes.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a bcrypt hash in constant time."""
    if not plain_password or not hashed_password:
        return False
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except Exception as exc:
        logger.warning("Password verification failed with error: %s", type(exc).__name__)
        return False


def create_access_token(
    user_id: int,
    username: str,
    role: str,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a signed HS256 JWT access token containing standard SOC operator claims."""
    now = datetime.now(timezone.utc)
    if expires_delta is not None:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=get_token_expire_minutes())

    payload: dict[str, Any] = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }

    secret_key = get_jwt_secret_key()
    return jwt.encode(payload, secret_key, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT access token.

    Validates signature, expiration, and presence of required claims ('sub', 'username', 'role').
    Raises TokenExpiredError or TokenInvalidError.
    """
    secret_key = get_jwt_secret_key()
    try:
        payload = jwt.decode(
            token,
            secret_key,
            algorithms=[ALGORITHM],
            options={"require": ["sub", "username", "role", "exp", "iat"]},
        )
    except jwt.ExpiredSignatureError:
        raise TokenExpiredError("Token has expired.") from None
    except jwt.InvalidTokenError as exc:
        raise TokenInvalidError(f"Invalid token: {type(exc).__name__}") from None
    except Exception as exc:
        raise TokenInvalidError("Malformed token.") from None

    if not payload.get("sub"):
        raise TokenInvalidError("Token missing subject claim.")

    return payload
