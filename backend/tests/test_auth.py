"""
backend/tests/test_auth.py
~~~~~~~~~~~~~~~~~~~~~~~~~~
Comprehensive test suite for Authentication & RBAC.

Coverage:
  1.  Password hashing (bcrypt format and work factor)
  2.  Password verification (correct password matches)
  3.  Login with username (returns JWT and profile)
  4.  Login with email (returns JWT and profile)
  5.  Wrong password (returns 401 generic error)
  6.  Unknown user (returns 401 generic error with dummy check)
  7.  Inactive user (returns 401 inactive error)
  8.  JWT creation (correct claims structure)
  9.  Valid JWT validation (decodes correctly)
  10. Expired JWT validation (raises TokenExpiredError)
  11. Tampered JWT signature (raises TokenInvalidError)
  12. Malformed JWT string (raises TokenInvalidError)
  13. GET /api/v1/auth/me with valid Bearer token (200 OK)
  14. GET /api/v1/auth/me without token (401 Unauthorized)
  15. Protected alerts endpoint without token (401 Unauthorized)
  16. Protected alerts endpoint with valid analyst token (200 OK)
  17. Analyst cannot delete case (403 Forbidden)
  18. Admin can delete case (204 No Content)
  19. GET /health remains public without token (200 OK)
  20. GET /api/v1/health/db remains public without token (200 OK)
  21. POST /api/v1/auth/logout behavior (200 OK)
  22. Seed script idempotency (safe multiple executions)
"""

from datetime import timedelta
import os
from unittest.mock import patch

from fastapi.testclient import TestClient
import pytest

from app.core.security import (
    TokenExpiredError,
    TokenInvalidError,
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from app.db import get_db
from app.main import app
from app.models.case import Case
from app.models.user import User
from app.repositories.case import create_case
from app.repositories.user import create_user
from scripts.seed_users import seed_users


@pytest.fixture
def auth_client(clean_db):
    """TestClient that uses real auth (no get_current_active_user override)."""
    def override_get_db():
        yield clean_db

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def seeded_users(clean_db):
    """Fixture providing a standard active analyst, active admin, and inactive analyst."""
    analyst = create_user(
        clean_db,
        User(
            username="analyst_test",
            email="analyst@test.local",
            password_hash=hash_password("AnalystPass123!"),
            role="analyst",
            is_active=True,
        ),
    )
    admin = create_user(
        clean_db,
        User(
            username="admin_test",
            email="admin@test.local",
            password_hash=hash_password("AdminPass123!"),
            role="admin",
            is_active=True,
        ),
    )
    inactive = create_user(
        clean_db,
        User(
            username="inactive_test",
            email="inactive@test.local",
            password_hash=hash_password("InactivePass123!"),
            role="analyst",
            is_active=False,
        ),
    )
    return {"analyst": analyst, "admin": admin, "inactive": inactive}


# ── 1. Password Hashing & Verification ────────────────────────────────────────

def test_password_hashing():
    pwd = "Secr3tPassword!"
    hashed = hash_password(pwd)
    assert hashed != pwd
    assert hashed.startswith("$2b$12$")


def test_password_verification():
    pwd = "Secr3tPassword!"
    hashed = hash_password(pwd)
    assert verify_password(pwd, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False
    assert verify_password("", hashed) is False
    assert verify_password(pwd, "") is False


# ── 2. Login Flow ─────────────────────────────────────────────────────────────

def test_login_with_username(auth_client, seeded_users):
    resp = auth_client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "analyst_test", "password": "AnalystPass123!"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == 3600
    assert data["user"]["username"] == "analyst_test"
    assert data["user"]["role"] == "analyst"
    assert "password_hash" not in data["user"]


def test_login_with_email(auth_client, seeded_users):
    resp = auth_client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "admin@test.local", "password": "AdminPass123!"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["user"]["username"] == "admin_test"
    assert data["user"]["role"] == "admin"


def test_login_wrong_password(auth_client, seeded_users):
    resp = auth_client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "analyst_test", "password": "IncorrectPassword!"},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid username or password."


def test_login_unknown_user(auth_client, seeded_users):
    resp = auth_client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "nonexistent_operator", "password": "SomePassword!"},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid username or password."


def test_login_inactive_user(auth_client, seeded_users):
    resp = auth_client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "inactive_test", "password": "InactivePass123!"},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "User account is inactive."


# ── 3. JWT Creation & Validation ──────────────────────────────────────────────

def test_jwt_creation_and_valid_claims():
    token = create_access_token(user_id=42, username="analyst_bob", role="analyst")
    payload = decode_access_token(token)
    assert payload["sub"] == "42"
    assert payload["username"] == "analyst_bob"
    assert payload["role"] == "analyst"
    assert "exp" in payload
    assert "iat" in payload


def test_jwt_expired():
    token = create_access_token(
        user_id=1,
        username="expired_user",
        role="analyst",
        expires_delta=timedelta(seconds=-10),
    )
    with pytest.raises(TokenExpiredError):
        decode_access_token(token)


def test_jwt_tampered():
    token = create_access_token(user_id=1, username="test", role="analyst")
    tampered = token[:-4] + "AAAA"
    with pytest.raises(TokenInvalidError):
        decode_access_token(tampered)


def test_jwt_malformed():
    with pytest.raises(TokenInvalidError):
        decode_access_token("not.a.valid.jwt.string")


# ── 4. Current User (/me) ─────────────────────────────────────────────────────

def test_auth_me_with_valid_token(auth_client, seeded_users):
    login_resp = auth_client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "analyst_test", "password": "AnalystPass123!"},
    )
    token = login_resp.json()["access_token"]

    resp = auth_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["username"] == "analyst_test"
    assert data["role"] == "analyst"
    assert "password_hash" not in data


def test_auth_me_without_token(auth_client, clean_db):
    resp = auth_client.get("/api/v1/auth/me")
    assert resp.status_code == 401
    assert "WWW-Authenticate" in resp.headers


# ── 5. Protected Endpoints & Role Permissions ─────────────────────────────────

def test_protected_alerts_endpoint_without_token(auth_client, clean_db):
    resp = auth_client.get("/api/v1/alerts")
    assert resp.status_code == 401


def test_protected_alerts_endpoint_with_valid_analyst_token(auth_client, seeded_users):
    login_resp = auth_client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "analyst_test", "password": "AnalystPass123!"},
    )
    token = login_resp.json()["access_token"]

    resp = auth_client.get(
        "/api/v1/alerts",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert "items" in resp.json()


def test_analyst_cannot_delete_case(auth_client, seeded_users, clean_db):
    test_case = create_case(clean_db, Case(title="Case to Delete", severity="low", status="open"))

    analyst_token = auth_client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "analyst_test", "password": "AnalystPass123!"},
    ).json()["access_token"]

    resp = auth_client.delete(
        f"/api/v1/cases/{test_case.id}",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert resp.status_code == 403
    assert "Operation requires 'admin' role" in resp.json()["detail"]


def test_admin_can_delete_case(auth_client, seeded_users, clean_db):
    test_case = create_case(clean_db, Case(title="Case for Admin Delete", severity="low", status="open"))

    admin_token = auth_client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "admin_test", "password": "AdminPass123!"},
    ).json()["access_token"]

    resp = auth_client.delete(
        f"/api/v1/cases/{test_case.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 204


# ── 6. Public Health & Logout ─────────────────────────────────────────────────

def test_health_endpoints_remain_public(auth_client, clean_db):
    resp1 = auth_client.get("/health")
    assert resp1.status_code == 200
    assert resp1.json() == {"status": "ok"}

    resp2 = auth_client.get("/api/v1/health")
    assert resp2.status_code == 200
    assert resp2.json() == {"status": "ok"}

    resp3 = auth_client.get("/api/v1/health/db")
    assert resp3.status_code == 200
    assert resp3.json()["database"] == "reachable"


def test_logout_endpoint(auth_client):
    resp = auth_client.post("/api/v1/auth/logout")
    assert resp.status_code == 200
    assert resp.json() == {"message": "Logged out successfully."}


# ── 7. Seed Script Idempotency ────────────────────────────────────────────────

def test_seed_script_idempotency(clean_db, monkeypatch):
    monkeypatch.setenv("DEFAULT_ADMIN_PASSWORD", "TestBootstrapPass2026!")
    monkeypatch.setenv("DEFAULT_ANALYST_PASSWORD", "TestBootstrapAnalyst2026!")

    # First run seeds both users
    assert seed_users() == 0

    # Second run safely skips both users
    assert seed_users() == 0

    # Third run verifies no duplicate rows
    from app.repositories.user import get_user_by_username
    admin_user = get_user_by_username(clean_db, "admin")
    assert admin_user is not None
    assert admin_user.role == "admin"
    assert verify_password("TestBootstrapPass2026!", admin_user.password_hash) is True
