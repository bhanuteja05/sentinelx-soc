"""
backend/app/repositories/user.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
CRUD operations for User records in PostgreSQL.
"""

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.user import User


def get_user_by_id(db: Session, user_id: int) -> User | None:
    """Retrieve a User by database primary key."""
    return db.get(User, user_id)


def get_user_by_username(db: Session, username: str) -> User | None:
    """Retrieve a User by exact username (case-sensitive or lowercase trimmed)."""
    if not username:
        return None
    stmt = select(User).where(User.username == username.strip())
    return db.execute(stmt).scalar_one_or_none()


def get_user_by_email(db: Session, email: str) -> User | None:
    """Retrieve a User by exact email."""
    if not email:
        return None
    stmt = select(User).where(User.email == email.strip().lower())
    return db.execute(stmt).scalar_one_or_none()


def create_user(db: Session, user: User | dict[str, Any]) -> User:
    """Persist a new User to the database."""
    if isinstance(user, dict):
        db_user = User(**user)
    else:
        db_user = user
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user
