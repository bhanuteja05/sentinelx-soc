"""
tests/test_case_notes.py
~~~~~~~~~~~~~~~~~~~~~~~~
Comprehensive test suite for Phase 7B: Analyst Case Notes / Investigation Timeline.

Coverage:
  1. Note creation (analyst) -> 201 Created with correct fields and author metadata
  2. Note listing in chronological order (created_at asc)
  3. Validation:
     - Empty content -> 422
     - Whitespace-only content -> 422
     - Content exceeding 10,000 characters -> 422
  4. Nonexistent case handling:
     - Create note on nonexistent case -> 404
     - List notes on nonexistent case -> 404
  5. Note updating (PATCH):
     - Author analyst can update their own note -> 200 OK
     - Non-author analyst cannot update another analyst's note -> 403 Forbidden
     - Update with empty/whitespace content -> 422
     - Update nonexistent note -> 404
  6. Note deletion (DELETE):
     - Author analyst can delete their own note -> 204 No Content
     - Admin can delete another analyst's note -> 204 No Content
     - Non-author analyst cannot delete another analyst's note -> 403 Forbidden
     - Delete nonexistent note -> 404
  7. Unauthenticated access:
     - POST / GET / PATCH / DELETE without token -> 401 Unauthorized
  8. Cascade deletion:
     - Deleting a case deletes all associated notes in database
"""

import time
from fastapi.testclient import TestClient
import pytest

from app.core.security import create_access_token, hash_password
from app.db import get_db
from app.main import app
from app.models.case import Case
from app.models.case_note import CaseNote
from app.models.user import User
from app.repositories.case import create_case, get_case_by_id, get_case_note_by_id
from app.repositories.user import create_user


@pytest.fixture
def auth_client(clean_db):
    """TestClient that uses real auth and clean db session."""
    def override_get_db():
        yield clean_db

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def users(clean_db):
    """Create test users: analyst1, analyst2, admin."""
    analyst1 = create_user(
        clean_db,
        User(
            username="analyst1",
            email="analyst1@sentinelx.local",
            password_hash=hash_password("Pass123!"),
            role="analyst",
            is_active=True,
        ),
    )
    analyst2 = create_user(
        clean_db,
        User(
            username="analyst2",
            email="analyst2@sentinelx.local",
            password_hash=hash_password("Pass123!"),
            role="analyst",
            is_active=True,
        ),
    )
    admin = create_user(
        clean_db,
        User(
            username="admin_user",
            email="admin@sentinelx.local",
            password_hash=hash_password("AdminPass123!"),
            role="admin",
            is_active=True,
        ),
    )
    return {"analyst1": analyst1, "analyst2": analyst2, "admin": admin}


def auth_header(user: User) -> dict[str, str]:
    """Generate bearer auth header for a user."""
    token = create_access_token(user_id=user.id, username=user.username, role=user.role)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def test_case(clean_db):
    """Create an initial test case."""
    return create_case(
        clean_db,
        Case(
            title="Investigate Lateral Movement",
            description="Initial compromise identified on workstation.",
            severity="high",
            status="in_progress",
        ),
    )


# ---------------------------------------------------------------------------
# 1 · Note Creation
# ---------------------------------------------------------------------------


def test_create_case_note_success(auth_client, users, test_case):
    """Analyst can create an investigation note on an existing case."""
    headers = auth_header(users["analyst1"])
    response = auth_client.post(
        f"/api/v1/cases/{test_case.id}/notes",
        headers=headers,
        json={"content": "Analyzed auth logs: observed repeated Kerberos pre-auth failures from 10.0.0.45."},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["case_id"] == test_case.id
    assert data["author_id"] == users["analyst1"].id
    assert data["author_username"] == "analyst1"
    assert data["content"] == "Analyzed auth logs: observed repeated Kerberos pre-auth failures from 10.0.0.45."
    assert "created_at" in data
    assert "updated_at" in data
    assert data["author"]["role"] == "analyst"


def test_create_case_note_validation(auth_client, users, test_case):
    """Note content must not be empty, whitespace-only, or overly long."""
    headers = auth_header(users["analyst1"])

    # Empty string
    res_empty = auth_client.post(
        f"/api/v1/cases/{test_case.id}/notes",
        headers=headers,
        json={"content": ""},
    )
    assert res_empty.status_code == 422

    # Whitespace only
    res_ws = auth_client.post(
        f"/api/v1/cases/{test_case.id}/notes",
        headers=headers,
        json={"content": "   \n\t  "},
    )
    assert res_ws.status_code == 422

    # Exceeding 10,000 characters
    long_content = "A" * 10001
    res_long = auth_client.post(
        f"/api/v1/cases/{test_case.id}/notes",
        headers=headers,
        json={"content": long_content},
    )
    assert res_long.status_code == 422


def test_create_case_note_case_not_found(auth_client, users):
    """Attempting to add note to nonexistent case returns 404."""
    headers = auth_header(users["analyst1"])
    response = auth_client.post(
        "/api/v1/cases/99999/notes",
        headers=headers,
        json={"content": "Valid note on missing case."},
    )
    assert response.status_code == 404
    assert "Case 99999 not found" in response.json()["detail"]


# ---------------------------------------------------------------------------
# 2 · Note Listing (Chronological Timeline)
# ---------------------------------------------------------------------------


def test_list_case_notes_chronological(auth_client, users, test_case):
    """Listing notes returns them ordered chronologically (created_at asc)."""
    headers1 = auth_header(users["analyst1"])
    headers2 = auth_header(users["analyst2"])

    # Create first note
    res1 = auth_client.post(
        f"/api/v1/cases/{test_case.id}/notes",
        headers=headers1,
        json={"content": "Timeline Entry 1: Initial alert triaged."},
    )
    assert res1.status_code == 201

    time.sleep(0.01)

    # Create second note from different analyst
    res2 = auth_client.post(
        f"/api/v1/cases/{test_case.id}/notes",
        headers=headers2,
        json={"content": "Timeline Entry 2: Host isolated from network."},
    )
    assert res2.status_code == 201

    # Fetch notes list
    get_res = auth_client.get(f"/api/v1/cases/{test_case.id}/notes", headers=headers1)
    assert get_res.status_code == 200
    notes = get_res.json()
    assert len(notes) == 2
    assert notes[0]["content"] == "Timeline Entry 1: Initial alert triaged."
    assert notes[0]["author_username"] == "analyst1"
    assert notes[1]["content"] == "Timeline Entry 2: Host isolated from network."
    assert notes[1]["author_username"] == "analyst2"
    assert notes[0]["created_at"] <= notes[1]["created_at"]


def test_list_case_notes_case_not_found(auth_client, users):
    """Listing notes on a nonexistent case returns 404."""
    headers = auth_header(users["analyst1"])
    response = auth_client.get("/api/v1/cases/99999/notes", headers=headers)
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# 3 · Note Updating (PATCH)
# ---------------------------------------------------------------------------


def test_update_case_note_by_author(auth_client, users, test_case):
    """Author analyst can update their own note."""
    headers = auth_header(users["analyst1"])
    create_res = auth_client.post(
        f"/api/v1/cases/{test_case.id}/notes",
        headers=headers,
        json={"content": "Initial note content."},
    )
    note_id = create_res.json()["id"]

    patch_res = auth_client.patch(
        f"/api/v1/cases/{test_case.id}/notes/{note_id}",
        headers=headers,
        json={"content": "Corrected note content with updated IOCs."},
    )
    assert patch_res.status_code == 200
    data = patch_res.json()
    assert data["id"] == note_id
    assert data["content"] == "Corrected note content with updated IOCs."


def test_update_case_note_forbidden_by_other_analyst(auth_client, users, test_case):
    """Analyst cannot update a note authored by another analyst."""
    headers1 = auth_header(users["analyst1"])
    create_res = auth_client.post(
        f"/api/v1/cases/{test_case.id}/notes",
        headers=headers1,
        json={"content": "Note by analyst 1."},
    )
    note_id = create_res.json()["id"]

    # Analyst 2 attempts to edit analyst 1's note
    headers2 = auth_header(users["analyst2"])
    patch_res = auth_client.patch(
        f"/api/v1/cases/{test_case.id}/notes/{note_id}",
        headers=headers2,
        json={"content": "Malicious or accidental edit attempt."},
    )
    assert patch_res.status_code == 403
    assert "Analysts can only edit their own notes" in patch_res.json()["detail"]


def test_update_case_note_validation(auth_client, users, test_case):
    """Updating with blank or whitespace content returns 422."""
    headers = auth_header(users["analyst1"])
    create_res = auth_client.post(
        f"/api/v1/cases/{test_case.id}/notes",
        headers=headers,
        json={"content": "Initial content."},
    )
    note_id = create_res.json()["id"]

    patch_res = auth_client.patch(
        f"/api/v1/cases/{test_case.id}/notes/{note_id}",
        headers=headers,
        json={"content": "   "},
    )
    assert patch_res.status_code == 422


def test_update_case_note_not_found(auth_client, users, test_case):
    """Updating a nonexistent note returns 404."""
    headers = auth_header(users["analyst1"])
    patch_res = auth_client.patch(
        f"/api/v1/cases/{test_case.id}/notes/99999",
        headers=headers,
        json={"content": "Update attempt on missing note."},
    )
    assert patch_res.status_code == 404


# ---------------------------------------------------------------------------
# 4 · Note Deletion (DELETE)
# ---------------------------------------------------------------------------


def test_delete_case_note_by_author(auth_client, users, test_case):
    """Author analyst can delete their own note."""
    headers = auth_header(users["analyst1"])
    create_res = auth_client.post(
        f"/api/v1/cases/{test_case.id}/notes",
        headers=headers,
        json={"content": "Note to be deleted by author."},
    )
    note_id = create_res.json()["id"]

    del_res = auth_client.delete(f"/api/v1/cases/{test_case.id}/notes/{note_id}", headers=headers)
    assert del_res.status_code == 204

    # Verify note is gone
    get_res = auth_client.get(f"/api/v1/cases/{test_case.id}/notes", headers=headers)
    assert not any(n["id"] == note_id for n in get_res.json())


def test_delete_case_note_by_admin(auth_client, users, test_case):
    """Admin can delete a note written by any analyst."""
    headers1 = auth_header(users["analyst1"])
    create_res = auth_client.post(
        f"/api/v1/cases/{test_case.id}/notes",
        headers=headers1,
        json={"content": "Note written by analyst1, will be removed by admin."},
    )
    note_id = create_res.json()["id"]

    # Admin deletes it
    admin_headers = auth_header(users["admin"])
    del_res = auth_client.delete(f"/api/v1/cases/{test_case.id}/notes/{note_id}", headers=admin_headers)
    assert del_res.status_code == 204

    # Verify note is gone
    get_res = auth_client.get(f"/api/v1/cases/{test_case.id}/notes", headers=admin_headers)
    assert not any(n["id"] == note_id for n in get_res.json())


def test_delete_case_note_forbidden_by_other_analyst(auth_client, users, test_case):
    """Analyst cannot delete a note authored by another analyst."""
    headers1 = auth_header(users["analyst1"])
    create_res = auth_client.post(
        f"/api/v1/cases/{test_case.id}/notes",
        headers=headers1,
        json={"content": "Analyst 1 protected note."},
    )
    note_id = create_res.json()["id"]

    headers2 = auth_header(users["analyst2"])
    del_res = auth_client.delete(f"/api/v1/cases/{test_case.id}/notes/{note_id}", headers=headers2)
    assert del_res.status_code == 403
    assert "You do not have permission to delete this note" in del_res.json()["detail"]


def test_delete_case_note_not_found(auth_client, users, test_case):
    """Deleting a nonexistent note returns 404."""
    headers = auth_header(users["analyst1"])
    del_res = auth_client.delete(f"/api/v1/cases/{test_case.id}/notes/99999", headers=headers)
    assert del_res.status_code == 404


# ---------------------------------------------------------------------------
# 5 · Unauthenticated Access
# ---------------------------------------------------------------------------


def test_unauthenticated_requests(auth_client, test_case):
    """Endpoints reject requests without valid Bearer token."""
    res_post = auth_client.post(f"/api/v1/cases/{test_case.id}/notes", json={"content": "test"})
    assert res_post.status_code == 401

    res_get = auth_client.get(f"/api/v1/cases/{test_case.id}/notes")
    assert res_get.status_code == 401

    res_patch = auth_client.patch(f"/api/v1/cases/{test_case.id}/notes/1", json={"content": "test"})
    assert res_patch.status_code == 401

    res_del = auth_client.delete(f"/api/v1/cases/{test_case.id}/notes/1")
    assert res_del.status_code == 401


# ---------------------------------------------------------------------------
# 6 · Cascade Deletion
# ---------------------------------------------------------------------------


def test_case_deletion_cascades_to_notes(auth_client, users, test_case, clean_db):
    """Deleting a case cascades to its notes."""
    headers = auth_header(users["analyst1"])
    create_res = auth_client.post(
        f"/api/v1/cases/{test_case.id}/notes",
        headers=headers,
        json={"content": "Note that should cascade delete."},
    )
    note_id = create_res.json()["id"]

    # Delete case as admin
    admin_headers = auth_header(users["admin"])
    del_res = auth_client.delete(f"/api/v1/cases/{test_case.id}", headers=admin_headers)
    assert del_res.status_code == 204

    # Verify case is gone
    assert get_case_by_id(clean_db, test_case.id) is None
    # Verify note is deleted in database
    assert get_case_note_by_id(clean_db, note_id) is None
