"""
backend/app/services/auth.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Authentication service: credential verification, token issuance, and user resolution.
"""

import logging
from typing import Any

from sqlalchemy.orm import Session

from app.core.security import create_access_token, decode_access_token, verify_password
from app.models.user import User
from app.repositories.user import get_user_by_email, get_user_by_id, get_user_by_username

logger = logging.getLogger(__name__)

# Pre-computed dummy bcrypt hash (work factor 12) used to equalize response timing
# when an unknown username/email is provided (timing attack mitigation).
DUMMY_BCRYPT_HASH = "$2b$12$4m1sE0Q6k19d2U1i8m8e8eW7pY9tZ0u1i8m8e8m8e8m8e8m8e8m8e"


class AuthError(Exception):
    """Base exception for authentication failures."""


class InvalidCredentialsError(AuthError):
    """Invalid username, email, or password."""


class InactiveUserError(AuthError):
    """User account is disabled."""


def authenticate_user(
    db: Session,
    username_or_email: str,
    password: str,
) -> User:
    """Authenticate an operator by username OR email and password.

    Mitigates timing attacks by executing a dummy bcrypt check when the user
    does not exist. Rejects inactive accounts with InactiveUserError.
    """
    identifier = username_or_email.strip()
    user: User | None = None

    if "@" in identifier:
        user = get_user_by_email(db, identifier)
    else:
        user = get_user_by_username(db, identifier)

    if user is None:
        # Dummy verification to avoid enumeration timing leaks
        verify_password(password, DUMMY_BCRYPT_HASH)
        raise InvalidCredentialsError("Invalid username or password.")

    if not verify_password(password, user.password_hash):
        raise InvalidCredentialsError("Invalid username or password.")

    if not user.is_active:
        raise InactiveUserError("User account is inactive.")

    return user


def issue_token_for_user(user: User) -> tuple[str, int]:
    """Issue a signed JWT access token for the given user.

    Returns (access_token, expires_in_seconds).
    """
    token = create_access_token(
        user_id=user.id,
        username=user.username,
        role=user.role,
    )
    # Default 60 minutes = 3600 seconds
    return token, 3600


def get_user_from_token(db: Session, token: str) -> User:
    """Resolve a User record from a valid JWT access token.

    Validates token signature and expiration, retrieves user from database,
    and asserts account active status.
    """
    payload = decode_access_token(token)
    user_id_str = payload.get("sub")
    if not user_id_str:
        raise InvalidCredentialsError("Token missing subject claim.")

    try:
        user_id = int(user_id_str)
    except ValueError:
        raise InvalidCredentialsError("Invalid user ID in token subject.")

    user = get_user_by_id(db, user_id)
    if user is None:
        raise InvalidCredentialsError("User not found.")

    if not user.is_active:
        raise InactiveUserError("User account is inactive.")

    return user
