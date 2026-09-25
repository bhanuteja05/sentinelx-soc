"""
backend/app/api/deps.py
~~~~~~~~~~~~~~~~~~~~~~~
FastAPI dependencies for JWT authentication and role-based access control.
"""

from collections.abc import Callable
import logging

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.security import TokenError, TokenExpiredError
from app.db import get_db
from app.models.user import User
from app.services.auth import (
    InactiveUserError,
    InvalidCredentialsError,
    get_user_from_token,
)

logger = logging.getLogger(__name__)

# Bearer security scheme with auto_error=False so we can raise standard custom 401s
bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Validate Bearer token and retrieve the corresponding User.

    Raises HTTP 401 if token is missing, expired, malformed, or references an unknown user.
    """
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    try:
        user = get_user_from_token(db, token)
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    except InactiveUserError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    except (TokenError, InvalidCredentialsError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    except Exception as exc:
        logger.error("Unexpected error in auth dependency (%s): %s", type(exc).__name__, exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None

    return user


def get_current_active_user(
    user: User = Depends(get_current_user),
) -> User:
    """Ensure the authenticated user is active."""
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_role(required_role: str) -> Callable:
    """Enforce role requirement. Admins satisfy any required role."""
    def _role_checker(user: User = Depends(get_current_active_user)) -> User:
        if user.role != required_role and user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation requires '{required_role}' role.",
            )
        return user

    return _role_checker
