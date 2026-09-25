"""
backend/scripts/seed_users.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Idempotent development seed script for initial SOC operator accounts.

Reads DEFAULT_ADMIN_PASSWORD and optional DEFAULT_ANALYST_PASSWORD from environment.
Passwords are never hardcoded and are stored strictly as bcrypt hashes.
"""

import os
import sys

# Ensure backend root is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.security import hash_password
from app.db.session import SessionLocal
from app.models.user import User
from app.repositories.user import create_user, get_user_by_email, get_user_by_username


def seed_users() -> int:
    admin_password = os.environ.get("DEFAULT_ADMIN_PASSWORD")
    if not admin_password:
        print("ERROR: DEFAULT_ADMIN_PASSWORD environment variable is not set.", file=sys.stderr)
        return 1

    analyst_password = os.environ.get("DEFAULT_ANALYST_PASSWORD", admin_password)

    db = SessionLocal()
    try:
        # 1. Admin user
        existing_admin = get_user_by_username(db, "admin") or get_user_by_email(db, "admin@sentinelx.local")
        if existing_admin:
            print(f"Admin user '{existing_admin.username}' already exists (ID: {existing_admin.id}). Skipping.")
        else:
            admin_user = User(
                username="admin",
                email="admin@sentinelx.local",
                password_hash=hash_password(admin_password),
                role="admin",
                is_active=True,
            )
            created = create_user(db, admin_user)
            print(f"Created admin user '{created.username}' (ID: {created.id}, role: {created.role}).")

        # 2. Analyst user
        existing_analyst = get_user_by_username(db, "analyst") or get_user_by_email(db, "analyst@sentinelx.local")
        if existing_analyst:
            print(f"Analyst user '{existing_analyst.username}' already exists (ID: {existing_analyst.id}). Skipping.")
        else:
            analyst_user = User(
                username="analyst",
                email="analyst@sentinelx.local",
                password_hash=hash_password(analyst_password),
                role="analyst",
                is_active=True,
            )
            created = create_user(db, analyst_user)
            print(f"Created analyst user '{created.username}' (ID: {created.id}, role: {created.role}).")

        return 0
    except Exception as exc:
        print(f"ERROR: Failed to seed users ({type(exc).__name__}): {exc}", file=sys.stderr)
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(seed_users())
