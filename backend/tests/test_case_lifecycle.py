from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.security import create_access_token, hash_password
from app.main import app
from app.models.alert import Alert
from app.models.case import Case
from app.models.case_evidence import CaseEvidence
from app.models.user import User


@pytest.fixture
def test_client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def auth_users(clean_db: Session) -> dict[str, dict[str, str]]:
    """Seed test users and return auth header dicts."""
    admin = User(
        username="admin_user",
        email="admin@sentinelx.local",
        password_hash=hash_password("adminpass123"),
        role="admin",
        is_active=True,
    )
    analyst1 = User(
        username="analyst_alice",
        email="alice@sentinelx.local",
        password_hash=hash_password("analystpass123"),
        role="analyst",
        is_active=True,
    )
    analyst2 = User(
        username="analyst_bob",
        email="bob@sentinelx.local",
        password_hash=hash_password("analystpass123"),
        role="analyst",
        is_active=True,
    )
    clean_db.add_all([admin, analyst1, analyst2])
    clean_db.commit()
    clean_db.refresh(admin)
    clean_db.refresh(analyst1)
    clean_db.refresh(analyst2)

    return {
        "admin": {
            "user": admin,
            "headers": {"Authorization": f"Bearer {create_access_token(admin.id, admin.username, admin.role)}"},
        },
        "analyst1": {
            "user": analyst1,
            "headers": {"Authorization": f"Bearer {create_access_token(analyst1.id, analyst1.username, analyst1.role)}"},
        },
        "analyst2": {
            "user": analyst2,
            "headers": {"Authorization": f"Bearer {create_access_token(analyst2.id, analyst2.username, analyst2.role)}"},
        },
    }


@pytest.fixture
def sample_case_and_alert(clean_db: Session) -> tuple[Case, Alert]:
    alert = Alert(
        wazuh_alert_id="wazuh-evidence-alert-001",
        timestamp=datetime.now(timezone.utc),
        agent_id="001",
        agent_name="sentinel-victim",
        rule_id="100010",
        rule_level=12,
        description="Cobalt Strike beaconing detected",
        src_ip="198.51.100.42",
        dst_ip="10.0.0.5",
        raw_alert={},
    )
    clean_db.add(alert)
    clean_db.commit()
    clean_db.refresh(alert)

    case = Case(
        title="APT Activity on sentinel-victim",
        description="Initial triage confirmed suspicious beaconing.",
        severity="high",
        status="open",
    )
    clean_db.add(case)
    clean_db.commit()
    clean_db.refresh(case)

    return case, alert


def test_unauthenticated_endpoints_rejected(test_client: TestClient, sample_case_and_alert: tuple[Case, Alert]):
    case, _ = sample_case_and_alert
    assert test_client.post(f"/api/v1/cases/{case.id}/assign").status_code == 401
    assert test_client.get(f"/api/v1/cases/{case.id}/evidence").status_code == 401
    assert test_client.post(f"/api/v1/cases/{case.id}/evidence", json={"evidence_type": "ip", "value": "1.1.1.1"}).status_code == 401
    assert test_client.post(f"/api/v1/cases/{case.id}/resolve", json={"disposition": "true_positive_incident", "root_cause": "malware_execution", "resolution_summary": "Cleaned"}).status_code == 401
    assert test_client.post(f"/api/v1/cases/{case.id}/reopen", json={"reason": "Reopen"}).status_code == 401


def test_assign_claim_and_unassign(
    test_client: TestClient,
    clean_db: Session,
    auth_users: dict,
    sample_case_and_alert: tuple[Case, Alert],
):
    case, _ = sample_case_and_alert
    alice = auth_users["analyst1"]["user"]
    bob = auth_users["analyst2"]["user"]

    # 1. Alice claims incident (no body -> assigns to self)
    res = test_client.post(
        f"/api/v1/cases/{case.id}/assign",
        json={},
        headers=auth_users["analyst1"]["headers"],
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["assignee_id"] == alice.id
    assert data["assignee"]["username"] == "analyst_alice"

    # Verify audit note on timeline
    notes_res = test_client.get(f"/api/v1/cases/{case.id}/notes", headers=auth_users["analyst1"]["headers"])
    assert notes_res.status_code == 200
    notes = notes_res.json()
    assert any("[Case Assignment]" in n["content"] and "analyst_alice" in n["content"] for n in notes)

    # 2. Alice reassigns incident to Bob
    res = test_client.post(
        f"/api/v1/cases/{case.id}/assign",
        json={"assignee_id": bob.id},
        headers=auth_users["analyst1"]["headers"],
    )
    assert res.status_code == 200
    assert res.json()["assignee_id"] == bob.id
    assert res.json()["assignee"]["username"] == "analyst_bob"

    # 3. Unassign case
    res = test_client.post(
        f"/api/v1/cases/{case.id}/assign",
        json={"unassign": True},
        headers=auth_users["analyst2"]["headers"],
    )
    assert res.status_code == 200
    assert res.json()["assignee_id"] is None
    assert res.json()["assignee"] is None

    # 4. Assign to non-existent user -> 404
    res = test_client.post(
        f"/api/v1/cases/{case.id}/assign",
        json={"assignee_id": 99999},
        headers=auth_users["analyst1"]["headers"],
    )
    assert res.status_code == 404


def test_case_queue_filtering(
    test_client: TestClient,
    clean_db: Session,
    auth_users: dict,
):
    alice = auth_users["analyst1"]["user"]
    bob = auth_users["analyst2"]["user"]

    # Create 3 cases: 1 unassigned, 1 Alice, 1 Bob
    c1 = Case(title="Unassigned Case", severity="low", status="open", assignee_id=None)
    c2 = Case(title="Alice Case", severity="medium", status="in_progress", assignee_id=alice.id)
    c3 = Case(title="Bob Case", severity="high", status="open", assignee_id=bob.id)
    clean_db.add_all([c1, c2, c3])
    clean_db.commit()

    # Filter unassigned
    res = test_client.get("/api/v1/cases?unassigned=true", headers=auth_users["analyst1"]["headers"])
    assert res.status_code == 200
    items = res.json()["items"]
    assert any(c["title"] == "Unassigned Case" for c in items)
    assert not any(c["title"] == "Alice Case" for c in items)

    # Filter by Alice
    res = test_client.get(f"/api/v1/cases?assignee_id={alice.id}", headers=auth_users["analyst1"]["headers"])
    assert res.status_code == 200
    items = res.json()["items"]
    assert len(items) == 1
    assert items[0]["title"] == "Alice Case"


def test_evidence_cataloging_and_deduplication(
    test_client: TestClient,
    clean_db: Session,
    auth_users: dict,
    sample_case_and_alert: tuple[Case, Alert],
):
    case, alert = sample_case_and_alert

    # 1. Add IP evidence
    payload = {
        "evidence_type": "ip",
        "value": "198.51.100.42",
        "verdict": "malicious",
        "notes": "C2 server identified in threat intel",
        "alert_id": alert.id,
    }
    res = test_client.post(
        f"/api/v1/cases/{case.id}/evidence",
        json=payload,
        headers=auth_users["analyst1"]["headers"],
    )
    assert res.status_code == 201, res.text
    ev = res.json()
    assert ev["evidence_type"] == "ip"
    assert ev["value"] == "198.51.100.42"
    assert ev["verdict"] == "malicious"
    assert ev["alert_id"] == alert.id
    assert ev["added_by"]["username"] == "analyst_alice"

    # Verify timeline note
    notes_res = test_client.get(f"/api/v1/cases/{case.id}/notes", headers=auth_users["analyst1"]["headers"])
    assert any("[Evidence Cataloged]" in n["content"] and "198.51.100.42" in n["content"] for n in notes_res.json())

    # 2. Deduplication: Adding same evidence again updates it without creating duplicate
    update_payload = {
        "evidence_type": "ip",
        "value": "198.51.100.42",
        "verdict": "suspicious",
        "notes": "Downgraded verdict pending sandbox report",
    }
    res2 = test_client.post(
        f"/api/v1/cases/{case.id}/evidence",
        json=update_payload,
        headers=auth_users["analyst1"]["headers"],
    )
    assert res2.status_code == 201
    ev2 = res2.json()
    assert ev2["id"] == ev["id"]  # Same ID!
    assert ev2["verdict"] == "suspicious"

    # List evidence
    list_res = test_client.get(f"/api/v1/cases/{case.id}/evidence", headers=auth_users["analyst1"]["headers"])
    assert list_res.status_code == 200
    assert len(list_res.json()) == 1


def test_evidence_validation_errors(
    test_client: TestClient,
    sample_case_and_alert: tuple[Case, Alert],
    auth_users: dict,
):
    case, _ = sample_case_and_alert

    # Invalid evidence type
    res = test_client.post(
        f"/api/v1/cases/{case.id}/evidence",
        json={"evidence_type": "invalid_type", "value": "test"},
        headers=auth_users["analyst1"]["headers"],
    )
    assert res.status_code == 422

    # Invalid verdict
    res = test_client.post(
        f"/api/v1/cases/{case.id}/evidence",
        json={"evidence_type": "ip", "value": "10.0.0.1", "verdict": "unknown_verdict"},
        headers=auth_users["analyst1"]["headers"],
    )
    assert res.status_code == 422

    # Empty value
    res = test_client.post(
        f"/api/v1/cases/{case.id}/evidence",
        json={"evidence_type": "ip", "value": "   "},
        headers=auth_users["analyst1"]["headers"],
    )
    assert res.status_code == 422


def test_evidence_update_and_delete_rbac(
    test_client: TestClient,
    clean_db: Session,
    auth_users: dict,
    sample_case_and_alert: tuple[Case, Alert],
):
    case, _ = sample_case_and_alert

    # Alice adds evidence
    res = test_client.post(
        f"/api/v1/cases/{case.id}/evidence",
        json={"evidence_type": "domain", "value": "evil-beacon.com", "verdict": "suspicious"},
        headers=auth_users["analyst1"]["headers"],
    )
    assert res.status_code == 201
    ev_id = res.json()["id"]

    # Bob updates verdict
    patch_res = test_client.patch(
        f"/api/v1/cases/{case.id}/evidence/{ev_id}",
        json={"verdict": "malicious", "notes": "Confirmed malicious by Bob"},
        headers=auth_users["analyst2"]["headers"],
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["verdict"] == "malicious"

    # Bob tries to delete Alice's evidence -> 403 Forbidden
    del_res = test_client.delete(
        f"/api/v1/cases/{case.id}/evidence/{ev_id}",
        headers=auth_users["analyst2"]["headers"],
    )
    assert del_res.status_code == 403

    # Admin deletes Alice's evidence -> 204 No Content
    del_res_admin = test_client.delete(
        f"/api/v1/cases/{case.id}/evidence/{ev_id}",
        headers=auth_users["admin"]["headers"],
    )
    assert del_res_admin.status_code == 204


def test_resolve_incident_success_and_reopen(
    test_client: TestClient,
    clean_db: Session,
    auth_users: dict,
    sample_case_and_alert: tuple[Case, Alert],
):
    case, _ = sample_case_and_alert

    # Resolve case
    resolve_payload = {
        "disposition": "true_positive_incident",
        "root_cause": "credential_compromise",
        "resolution_summary": "Compromised administrator credentials rotated and active session terminated.",
    }
    res = test_client.post(
        f"/api/v1/cases/{case.id}/resolve",
        json=resolve_payload,
        headers=auth_users["analyst1"]["headers"],
    )
    assert res.status_code == 200, res.text
    case_data = res.json()
    assert case_data["status"] == "resolved"
    assert case_data["disposition"] == "true_positive_incident"
    assert case_data["root_cause"] == "credential_compromise"
    assert case_data["resolved_at"] is not None
    assert case_data["resolved_by"]["username"] == "analyst_alice"

    # Verify timeline note
    notes_res = test_client.get(f"/api/v1/cases/{case.id}/notes", headers=auth_users["analyst1"]["headers"])
    assert any("[Incident Resolved]" in n["content"] for n in notes_res.json())

    # Reopen case
    reopen_res = test_client.post(
        f"/api/v1/cases/{case.id}/reopen",
        json={"reason": "Secondary lateral movement detected after credential rotation."},
        headers=auth_users["analyst2"]["headers"],
    )
    assert reopen_res.status_code == 200
    reopened = reopen_res.json()
    assert reopened["status"] == "in_progress"
    assert reopened["resolved_at"] is None

    # Verify reopening note
    notes_res = test_client.get(f"/api/v1/cases/{case.id}/notes", headers=auth_users["analyst1"]["headers"])
    assert any("[Incident Reopened]" in n["content"] and "Secondary lateral movement" in n["content"] for n in notes_res.json())


def test_resolve_incident_validation_errors(
    test_client: TestClient,
    sample_case_and_alert: tuple[Case, Alert],
    auth_users: dict,
):
    case, _ = sample_case_and_alert

    # Invalid disposition
    res = test_client.post(
        f"/api/v1/cases/{case.id}/resolve",
        json={
            "disposition": "not_a_valid_disposition",
            "root_cause": "malware_execution",
            "resolution_summary": "Detailed summary that is long enough.",
        },
        headers=auth_users["analyst1"]["headers"],
    )
    assert res.status_code == 422

    # Invalid root cause
    res = test_client.post(
        f"/api/v1/cases/{case.id}/resolve",
        json={
            "disposition": "true_positive_incident",
            "root_cause": "alien_invasion",
            "resolution_summary": "Detailed summary that is long enough.",
        },
        headers=auth_users["analyst1"]["headers"],
    )
    assert res.status_code == 422

    # Resolution summary too short (< 10 chars)
    res = test_client.post(
        f"/api/v1/cases/{case.id}/resolve",
        json={
            "disposition": "true_positive_incident",
            "root_cause": "malware_execution",
            "resolution_summary": "Short",
        },
        headers=auth_users["analyst1"]["headers"],
    )
    assert res.status_code == 422


def test_case_detail_envelope_includes_evidence_and_assignee(
    test_client: TestClient,
    clean_db: Session,
    auth_users: dict,
    sample_case_and_alert: tuple[Case, Alert],
):
    case, alert = sample_case_and_alert
    alice = auth_users["analyst1"]["user"]

    # Assign case to Alice
    test_client.post(f"/api/v1/cases/{case.id}/assign", json={}, headers=auth_users["analyst1"]["headers"])

    # Add evidence
    test_client.post(
        f"/api/v1/cases/{case.id}/evidence",
        json={"evidence_type": "hash_sha256", "value": "a" * 64, "verdict": "malicious"},
        headers=auth_users["analyst1"]["headers"],
    )

    # Fetch detail
    res = test_client.get(f"/api/v1/cases/{case.id}", headers=auth_users["analyst1"]["headers"])
    assert res.status_code == 200
    detail = res.json()
    assert detail["assignee"]["username"] == alice.username
    assert detail["evidence_count"] == 1
    assert len(detail["evidence"]) == 1
    assert detail["evidence"][0]["value"] == "a" * 64
    assert detail["evidence"][0]["verdict"] == "malicious"
