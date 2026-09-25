"""
backend/app/api/auth.py
~~~~~~~~~~~~~~~~~~~~~~~
Authentication endpoints: login, session profile (me), and stateless logout.
"""

import logging

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user
from app.db import get_db
from app.models.user import User
from app.services.auth import (
    InactiveUserError,
    InvalidCredentialsError,
    authenticate_user,
    issue_token_for_user,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/auth",
    tags=["Authentication"],
)


class LoginRequest(BaseModel):
    """Credentials payload for operator login."""

    username_or_email: str = Field(default="", max_length=255, description="Username or email address")
    password: str = Field(..., min_length=1, max_length=255, description="Operator password")
    username: str | None = Field(default=None, max_length=255)

    @model_validator(mode="before")
    @classmethod
    def resolve_username(cls, values: Any) -> Any:
        if isinstance(values, dict):
            identifier = values.get("username_or_email") or values.get("username")
            if not identifier:
                raise ValueError("username or email is required")
            values["username_or_email"] = identifier
        return values


class UserOut(BaseModel):
    """Public operator profile representation (excludes password hash)."""

    id: int
    username: str
    email: str
    role: str
    is_active: bool

    model_config = {"from_attributes": True}


class LoginResponse(BaseModel):
    """JWT access token response."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserOut


class LogoutResponse(BaseModel):
    """Logout confirmation."""

    message: str


@router.post("/login", response_model=LoginResponse)
def login_endpoint(
    payload: LoginRequest,
    db: Session = Depends(get_db),
) -> LoginResponse:
    """Authenticate with username/email and password to obtain a JWT access token."""
    try:
        user = authenticate_user(
            db=db,
            username_or_email=payload.username_or_email,
            password=payload.password,
        )
    except InactiveUserError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    except InvalidCredentialsError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None

    token, expires_in = issue_token_for_user(user)

    return LoginResponse(
        access_token=token,
        token_type="bearer",
        expires_in=expires_in,
        user=UserOut(
            id=user.id,
            username=user.username,
            email=user.email,
            role=user.role,
            is_active=user.is_active,
        ),
    )


@router.get("/me", response_model=UserOut)
def get_me_endpoint(
    current_user: User = Depends(get_current_active_user),
) -> UserOut:
    """Retrieve identity and permissions for the currently authenticated operator."""
    return UserOut(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        role=current_user.role,
        is_active=current_user.is_active,
    )


@router.post("/logout", response_model=LogoutResponse)
def logout_endpoint() -> LogoutResponse:
    """Stateless logout confirmation endpoint.

    Token invalidation is performed client-side by purging the stored token.
    """
    return LogoutResponse(message="Logged out successfully.")
