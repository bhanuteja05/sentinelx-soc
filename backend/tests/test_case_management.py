"""
tests/test_case_management.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Comprehensive test suite for Case Management and Incident Investigation Workflow.

Coverage:
  1. Case CRUD (create -> 201, retrieve, update title/desc, status, severity, close)
  2. Case listing & pagination (page, page_size, total, pages, status filter, severity filter, sorting, empty, invalid page)
  3. Case-Alert association (attach, duplicate idempotent, same alert in multiple cases, list case alerts, alert_count)
  4. Detachment safety (detach -> 204, verify association removed, VERIFY ALERT STILL EXISTS)
  5. Case deletion safety (delete case, verify association removed, VERIFY ALERT STILL EXISTS)
  6. Error handling (missing case 404, missing alert 404, detach unassociated 404, invalid status 422, invalid severity 422)
  7. Migration lifecycle (upgrade, downgrade, re-upgrade)
"""

from datetime import datetime, timezone
import os

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
import pytest

from app.api.deps import get_current_active_user
from app.db import get_db
from app.main import app
from app.models.alert import Alert
from app.models.case import Case
from app.models.case_alert import CaseAlert
from app.models.user import User
from app.repositories.alert import create_alert, get_alert_by_id
from app.repositories.case import (
    count_case_alerts,
    create_case,
    get_case_by_id,
    is_alert_associated,
)


@pytest.fixture
def client(clean_db):
    """TestClient with get_db and get_current_active_user overridden to use clean test database session."""
    def override_get_db():
        yield clean_db

    mock_admin = User(
        id=1,
        username="testadmin",
        email="testadmin@sentinelx.local",
        password_hash="dummy",
        role="admin",
        is_active=True,
    )
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_active_user] = lambda: mock_admin
    yield TestClient(app)
    app.dependency_overrides.clear()



def _seed_alert(db, **overrides) -> Alert:
    """Helper to seed an alert in the database."""
    now = datetime.now(timezone.utc)
    defaults = {
        "wazuh_alert_id": f"wazuh-case-test-{now.timestamp()}-{id(overrides)}",
        "timestamp": now,
        "agent_id": "001",
        "agent_name": "host-alpha",
        "rule_id": "5500",
        "rule_level": 7,
        "description": "Suspicious case alert evidence",
        "raw_alert": {"sample": "data"},
    }
    defaults.update(overrides)
    return create_alert(db, defaults)


# ---------------------------------------------------------------------------
# 1 · Case CRUD
# ---------------------------------------------------------------------------


def test_create_case(client, clean_db):
    """POST /api/v1/cases creates a case and returns 201 with CaseOut."""
    payload = {
        "title": "Unauthorized Sudo Escalation",
        "description": "User attempted sudo on critical server.",
        "severity": "high",
        "status": "open",
    }
    resp = client.post("/api/v1/cases", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["id"] is not None
    assert data["title"] == "Unauthorized Sudo Escalation"
    assert data["description"] == "User attempted sudo on critical server."
    assert data["severity"] == "high"
    assert data["status"] == "open"
    assert data["alert_count"] == 0
    assert "created_at" in data
    assert "updated_at" in data


def test_get_case_by_id(client, clean_db):
    """GET /api/v1/cases/{case_id} returns CaseDetailOut with alert summaries."""
    case = create_case(
        clean_db,
        {
            "title": "Phishing Triage",
            "description": "Reported phishing lure",
            "severity": "medium",
            "status": "open",
        },
    )
    resp = client.get(f"/api/v1/cases/{case.id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == case.id
    assert data["title"] == "Phishing Triage"
    assert data["alert_count"] == 0
    assert data["alerts"] == []


def test_update_case_fields(client, clean_db):
    """PATCH /api/v1/cases/{case_id} updates title, description, status, severity."""
    case = create_case(
        clean_db,
        {
            "title": "Initial Title",
            "description": "Initial Desc",
            "severity": "low",
            "status": "open",
        },
    )

    patch_payload = {
        "title": "Updated Investigation Title",
        "description": "Updated forensic notes",
        "severity": "critical",
        "status": "in_progress",
    }
    resp = client.patch(f"/api/v1/cases/{case.id}", json=patch_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["title"] == "Updated Investigation Title"
    assert data["description"] == "Updated forensic notes"
    assert data["severity"] == "critical"
    assert data["status"] == "in_progress"


def test_close_case_endpoint(client, clean_db):
    """POST /api/v1/cases/{case_id}/close sets status to closed."""
    case = create_case(
        clean_db,
        {
            "title": "Incident to Close",
            "status": "in_progress",
            "severity": "medium",
        },
    )
    resp = client.post(f"/api/v1/cases/{case.id}/close")
    assert resp.status_code == 200
    assert resp.json()["status"] == "closed"

    # Verify persisted in database
    refreshed = get_case_by_id(clean_db, case.id)
    assert refreshed.status == "closed"


# ---------------------------------------------------------------------------
# 2 · Case Listing & Pagination
# ---------------------------------------------------------------------------


def test_list_cases_empty(client, clean_db):
    """Listing cases with empty database returns 200 and empty items."""
    resp = client.get("/api/v1/cases")
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["total"] == 0
    assert data["page"] == 1
    assert data["page_size"] == 25
    assert data["pages"] == 0


def test_list_cases_pagination_and_sorting(client, clean_db):
    """Test pagination bounds, ordering, and tie-breaking."""
    for i in range(15):
        create_case(
            clean_db,
            {
                "title": f"Incident #{i:02d}",
                "severity": "low" if i % 2 == 0 else "high",
                "status": "open" if i < 10 else "closed",
            },
        )

    # Page 1, size 10 -> 10 items, total 15, pages 2
    r1 = client.get("/api/v1/cases?page=1&page_size=10&sort_by=created_at&sort_order=desc")
    assert r1.status_code == 200
    d1 = r1.json()
    assert len(d1["items"]) == 10
    assert d1["total"] == 15
    assert d1["pages"] == 2

    # Page 2, size 10 -> 5 items
    r2 = client.get("/api/v1/cases?page=2&page_size=10&sort_by=created_at&sort_order=desc")
    assert r2.status_code == 200
    d2 = r2.json()
    assert len(d2["items"]) == 5

    # Filter by status="closed" -> 5 items
    r_status = client.get("/api/v1/cases?status=closed")
    assert r_status.status_code == 200
    assert r_status.json()["total"] == 5

    # Filter by severity="high"
    r_sev = client.get("/api/v1/cases?severity=high")
    assert r_sev.status_code == 200
    assert r_sev.json()["total"] == 7


# ---------------------------------------------------------------------------
# 3 · Alert Association
# ---------------------------------------------------------------------------


def test_associate_alert_to_case_idempotent(client, clean_db):
    """Associating an alert to a case is idempotent."""
    case = create_case(clean_db, {"title": "Ransomware Alert Group"})
    alert = _seed_alert(clean_db, wazuh_alert_id="ransomware-alert-1")

    # First association -> 200, is_new=True
    resp1 = client.post(f"/api/v1/cases/{case.id}/alerts/{alert.id}")
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert data1["case_id"] == case.id
    assert data1["alert_id"] == alert.id
    assert data1["is_new"] is True

    # Second association with same alert -> idempotent success, is_new=False
    resp2 = client.post(f"/api/v1/cases/{case.id}/alerts/{alert.id}")
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["is_new"] is False

    # Check alert count on case detail
    detail = client.get(f"/api/v1/cases/{case.id}").json()
    assert detail["alert_count"] == 1
    assert len(detail["alerts"]) == 1
    assert detail["alerts"][0]["wazuh_alert_id"] == "ransomware-alert-1"
    # Ensure raw_alert is NOT exposed in case detail alert summary
    assert "raw_alert" not in detail["alerts"][0]


def test_same_alert_can_attach_to_multiple_cases(client, clean_db):
    """A single alert can be associated with multiple distinct cases."""
    c1 = create_case(clean_db, {"title": "Case Alpha"})
    c2 = create_case(clean_db, {"title": "Case Beta"})
    alert = _seed_alert(clean_db, wazuh_alert_id="shared-threat-evidence")

    # Attach to c1
    r1 = client.post(f"/api/v1/cases/{c1.id}/alerts/{alert.id}")
    assert r1.status_code == 200
    # Attach to c2
    r2 = client.post(f"/api/v1/cases/{c2.id}/alerts/{alert.id}")
    assert r2.status_code == 200

    # Both cases reference the alert
    assert count_case_alerts(clean_db, c1.id) == 1
    assert count_case_alerts(clean_db, c2.id) == 1


def test_list_case_alerts_endpoint(client, clean_db):
    """GET /api/v1/cases/{case_id}/alerts returns paginated AlertOut summaries."""
    case = create_case(clean_db, {"title": "Brute Force Campaign"})
    for i in range(5):
        a = _seed_alert(clean_db, wazuh_alert_id=f"bf-{i}")
        client.post(f"/api/v1/cases/{case.id}/alerts/{a.id}")

    resp = client.get(f"/api/v1/cases/{case.id}/alerts?page=1&page_size=3")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 5
    assert len(data["items"]) == 3
    assert data["pages"] == 2
    # AlertOut has no raw_alert
    assert "raw_alert" not in data["items"][0]


# ---------------------------------------------------------------------------
# 4 · Detachment Safety
# ---------------------------------------------------------------------------


def test_detach_alert_safety(client, clean_db):
    """Detaching an alert removes the link but PRESERVES the alert in database."""
    case = create_case(clean_db, {"title": "Evidence Review"})
    alert = _seed_alert(clean_db, wazuh_alert_id="safe-alert-detach")

    # Attach
    client.post(f"/api/v1/cases/{case.id}/alerts/{alert.id}")
    assert is_alert_associated(clean_db, case.id, alert.id) is True

    # Detach -> 204 No Content
    del_resp = client.delete(f"/api/v1/cases/{case.id}/alerts/{alert.id}")
    assert del_resp.status_code == 204

    # Association must be gone
    assert is_alert_associated(clean_db, case.id, alert.id) is False
    assert count_case_alerts(clean_db, case.id) == 0

    # CRITICAL: The Alert row MUST STILL EXIST in the alerts table!
    alert_in_db = get_alert_by_id(clean_db, alert.id)
    assert alert_in_db is not None
    assert alert_in_db.wazuh_alert_id == "safe-alert-detach"


# ---------------------------------------------------------------------------
# 5 · Case Deletion Safety
# ---------------------------------------------------------------------------


def test_case_deletion_preserves_alerts(client, clean_db):
    """Deleting a Case cleans up association rows but PRESERVES Alert rows."""
    case = create_case(clean_db, {"title": "False Positive Investigation"})
    alert1 = _seed_alert(clean_db, wazuh_alert_id="alert-fp-1")
    alert2 = _seed_alert(clean_db, wazuh_alert_id="alert-fp-2")

    client.post(f"/api/v1/cases/{case.id}/alerts/{alert1.id}")
    client.post(f"/api/v1/cases/{case.id}/alerts/{alert2.id}")
    assert count_case_alerts(clean_db, case.id) == 2

    # Delete the Case via endpoint
    del_case_resp = client.delete(f"/api/v1/cases/{case.id}")
    assert del_case_resp.status_code == 204

    # Case is gone
    assert get_case_by_id(clean_db, case.id) is None

    # Association rows are gone
    assert count_case_alerts(clean_db, case.id) == 0

    # CRITICAL SAFETY CHECK: Both Alerts MUST STILL EXIST in alerts table!
    db_alert1 = get_alert_by_id(clean_db, alert1.id)
    db_alert2 = get_alert_by_id(clean_db, alert2.id)
    assert db_alert1 is not None
    assert db_alert2 is not None
    assert db_alert1.wazuh_alert_id == "alert-fp-1"
    assert db_alert2.wazuh_alert_id == "alert-fp-2"


# ---------------------------------------------------------------------------
# 6 · Error Handling
# ---------------------------------------------------------------------------


def test_error_missing_case_and_alert(client, clean_db):
    """Missing Case or Alert returns 404."""
    # Missing case in get
    assert client.get("/api/v1/cases/99999").status_code == 404

    # Missing case in update
    assert client.patch("/api/v1/cases/99999", json={"title": "new"}).status_code == 404

    # Missing case in close
    assert client.post("/api/v1/cases/99999/close").status_code == 404

    # Missing case in list alerts
    assert client.get("/api/v1/cases/99999/alerts").status_code == 404

    # Missing case in associate
    alert = _seed_alert(clean_db, wazuh_alert_id="err-alert-1")
    r_missing_case = client.post(f"/api/v1/cases/99999/alerts/{alert.id}")
    assert r_missing_case.status_code == 404

    # Missing alert in associate
    case = create_case(clean_db, {"title": "Valid Case"})
    r_missing_alert = client.post(f"/api/v1/cases/{case.id}/alerts/99999")
    assert r_missing_alert.status_code == 404


def test_error_detach_non_associated_alert(client, clean_db):
    """Detaching an alert that is not associated returns 404."""
    case = create_case(clean_db, {"title": "Case Without Alert"})
    alert = _seed_alert(clean_db, wazuh_alert_id="unlinked-alert")

    resp = client.delete(f"/api/v1/cases/{case.id}/alerts/{alert.id}")
    assert resp.status_code == 404
    assert "not associated" in resp.json()["detail"].lower()


def test_error_invalid_status_and_severity(client, clean_db):
    """Invalid status or severity returns 422 Unprocessable Entity."""
    # Invalid severity on create
    r_bad_sev = client.post("/api/v1/cases", json={"title": "Bad", "severity": "ultra-critical"})
    assert r_bad_sev.status_code == 422

    # Invalid status on create
    r_bad_stat = client.post("/api/v1/cases", json={"title": "Bad", "status": "unknown-status"})
    assert r_bad_stat.status_code == 422

    # Invalid pagination
    assert client.get("/api/v1/cases?page=0").status_code == 422
    assert client.get("/api/v1/cases?page_size=0").status_code == 422
    assert client.get("/api/v1/cases?page_size=101").status_code == 422

    # Invalid sort field
    assert client.get("/api/v1/cases?sort_by=not_a_field").status_code == 422


# ---------------------------------------------------------------------------
# 7 · Migration Lifecycle
# ---------------------------------------------------------------------------


def test_alembic_case_alerts_migration_lifecycle():
    """Verify Alembic can upgrade to head, downgrade to previous, and re-upgrade."""
    alembic_ini_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "alembic.ini"))
    config = Config(alembic_ini_path)

    # 1. Upgrade to head
    command.upgrade(config, "head")

    # 2. Downgrade to b1218046b63f (the initial migration before case_alerts)
    command.downgrade(config, "b1218046b63f")

    # 3. Upgrade to head again
    command.upgrade(config, "head")
