"""
backend/tests/test_triage.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Comprehensive automated test suite for Phase 7D:
Automated SOC Alert Triage & Incident Escalation Engine.

Coverage:
  1.  Rule matching by severity (min_rule_level)
  2.  Rule matching by Wazuh rule ID
  3.  Rule matching by MITRE technique
  4.  Rule matching by MITRE tactic
  5.  Unmatched alert behavior (no action taken)
  6.  Critical alert auto-case creation
  7.  Correct mapped case severity
  8.  Safe title generation (placeholders, unknown tokens, length limits)
  9.  Existing open-case correlation (same agent/host within 24h)
  10. No duplicate case creation on repeated evaluation
  11. No duplicate alert association
  12. Automated CaseNote creation with detailed telemetry fields
  13. Ingestion resiliency: triage exception does not break alert ingestion
  14. Backlog evaluation endpoint (POST /api/v1/triage/evaluate)
  15. RBAC: Unauthenticated -> 401
  16. RBAC: Analyst mutation attempt -> 403 Forbidden
  17. RBAC: Admin mutation -> 201 Created / 200 OK / 204 No Content
  18. Baseline rules structure and validation
  19. Alembic migration upgrade/downgrade verification
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select

from app.core.security import create_access_token, hash_password
from app.db import get_db
from app.main import app
from app.models.alert import Alert
from app.models.case import Case
from app.models.case_alert import CaseAlert
from app.models.case_note import CaseNote
from app.models.triage_rule import TriageRule
from app.models.user import User
from app.repositories.alert import create_alert
from app.repositories.triage_rule import create_triage_rule, list_triage_rules
from app.repositories.user import create_user
from app.services.triage import (
    evaluate_alert_against_rules,
    evaluate_backlog,
    render_case_title,
    rule_matches_alert,
)
from app.wazuh.service import WazuhService


@pytest.fixture
def auth_client(clean_db):
    """TestClient configured with clean db session."""
    def override_get_db():
        yield clean_db

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def users(clean_db):
    """Create test users: analyst and admin."""
    analyst = create_user(
        clean_db,
        User(
            username="analyst_test",
            email="analyst_test@sentinelx.local",
            password_hash=hash_password("AnalystPassword123!"),
            role="analyst",
            is_active=True,
        ),
    )
    admin = create_user(
        clean_db,
        User(
            username="admin_test",
            email="admin_test@sentinelx.local",
            password_hash=hash_password("AdminPassword123!"),
            role="admin",
            is_active=True,
        ),
    )
    return {"analyst": analyst, "admin": admin}


def auth_header(user: User) -> dict[str, str]:
    token = create_access_token(user_id=user.id, username=user.username, role=user.role)
    return {"Authorization": f"Bearer {token}"}


def make_alert(clean_db, **kwargs) -> Alert:
    """Helper to create a test Alert with realistic defaults."""
    now = datetime.now(timezone.utc)
    defaults = {
        "wazuh_alert_id": f"wazuh-{now.timestamp()}-{kwargs.get('rule_id', '1001')}",
        "timestamp": now,
        "agent_id": "001",
        "agent_name": "ubuntu-srv",
        "rule_id": "1001",
        "rule_level": 3,
        "description": "Default test alert",
        "mitre_tactics": [],
        "mitre_techniques": [],
        "raw_alert": {"sample": "data"},
    }
    defaults.update(kwargs)
    return create_alert(clean_db, defaults)


def seed_baseline_rules(clean_db) -> tuple[TriageRule, TriageRule]:
    """Helper to seed the two approved baseline rules in a clean test DB."""
    r1 = create_triage_rule(
        clean_db,
        TriageRule(
            name="Critical Alert Auto-Escalation",
            description="Auto-escalates critical alerts (level 12+)",
            is_active=True,
            min_rule_level=12,
            rule_ids=[],
            mitre_techniques=[],
            mitre_tactics=[],
            action_type="correlate_or_create",
            case_severity="critical",
            case_title_template="[Auto-Triage] Critical Severity Alert on {agent}",
        ),
    )
    r2 = create_triage_rule(
        clean_db,
        TriageRule(
            name="Credential Access Threat Detection",
            description="Detects MITRE credential access tactics",
            is_active=True,
            min_rule_level=None,
            rule_ids=[],
            mitre_techniques=[],
            mitre_tactics=["credential-access"],
            action_type="correlate_or_create",
            case_severity="high",
            case_title_template="[Auto-Triage] Credential Access Detected on {agent}",
        ),
    )
    return r1, r2


# ── 1-5. Rule Condition Matching Tests ───────────────────────────────────────


def test_rule_matching_by_severity(clean_db):
    rule = TriageRule(name="R1", is_active=True, min_rule_level=12)
    alert_high = Alert(rule_level=12)
    alert_crit = Alert(rule_level=15)
    alert_low = Alert(rule_level=11)
    alert_none = Alert(rule_level=None)

    assert rule_matches_alert(rule, alert_high) is True
    assert rule_matches_alert(rule, alert_crit) is True
    assert rule_matches_alert(rule, alert_low) is False
    assert rule_matches_alert(rule, alert_none) is False


def test_rule_matching_by_wazuh_rule_id(clean_db):
    rule = TriageRule(name="R2", is_active=True, rule_ids=["5710", "5712"])
    alert_match = Alert(rule_id="5710")
    alert_miss = Alert(rule_id="5501")
    alert_none = Alert(rule_id=None)

    assert rule_matches_alert(rule, alert_match) is True
    assert rule_matches_alert(rule, alert_miss) is False
    assert rule_matches_alert(rule, alert_none) is False


def test_rule_matching_by_mitre_technique(clean_db):
    rule = TriageRule(name="R3", is_active=True, mitre_techniques=["T1078", "T1059"])
    alert_match1 = Alert(mitre_techniques=["T1078"])
    alert_match2 = Alert(mitre_techniques=["T1059", "T1003"])
    alert_miss = Alert(mitre_techniques=["T1003"])
    alert_empty = Alert(mitre_techniques=[])

    assert rule_matches_alert(rule, alert_match1) is True
    assert rule_matches_alert(rule, alert_match2) is True
    assert rule_matches_alert(rule, alert_miss) is False
    assert rule_matches_alert(rule, alert_empty) is False


def test_rule_matching_by_mitre_tactic(clean_db):
    rule = TriageRule(name="R4", is_active=True, mitre_tactics=["credential-access"])
    alert_match = Alert(mitre_tactics=["credential-access", "execution"])
    alert_miss = Alert(mitre_tactics=["initial-access"])
    alert_empty = Alert(mitre_tactics=[])

    assert rule_matches_alert(rule, alert_match) is True
    assert rule_matches_alert(rule, alert_miss) is False
    assert rule_matches_alert(rule, alert_empty) is False


def test_unmatched_alert_no_action(clean_db):
    seed_baseline_rules(clean_db)
    alert = make_alert(clean_db, rule_level=5, rule_id="31101", mitre_tactics=["reconnaissance"])

    res = evaluate_alert_against_rules(clean_db, alert)
    assert res is None

    # Verify no cases created and alert remains unassociated
    cases = clean_db.scalars(select(Case)).all()
    assert len(cases) == 0


# ── 6-8. Auto Case Creation & Title Safety Tests ─────────────────────────────


def test_critical_alert_auto_case_creation(clean_db):
    seed_baseline_rules(clean_db)
    alert = make_alert(
        clean_db,
        rule_level=13,
        rule_id="23506",
        agent_name="web-prod-01",
        description="Ransomware file extension detected",
    )

    res = evaluate_alert_against_rules(clean_db, alert)
    assert res is not None
    assert res["action"] == "create"

    # Verify Case exists in DB
    case = clean_db.get(Case, res["case_id"])
    assert case is not None
    assert case.severity == "critical"
    assert case.status == "open"
    assert "Critical Severity Alert on web-prod-01" in case.title

    # Verify alert is associated
    assoc = clean_db.scalars(select(CaseAlert).where(CaseAlert.alert_id == alert.id)).first()
    assert assoc is not None
    assert assoc.case_id == case.id


def test_correct_mapped_case_severity(clean_db):
    seed_baseline_rules(clean_db)
    alert = make_alert(
        clean_db,
        rule_level=7,
        mitre_tactics=["credential-access"],
        description="SSH brute force attempt",
    )

    res = evaluate_alert_against_rules(clean_db, alert)
    assert res is not None
    case = clean_db.get(Case, res["case_id"])
    assert case.severity == "high"


def test_safe_title_generation():
    # 1. Valid placeholders
    t1 = render_case_title(
        "[Auto-Triage] {rule_name} on {agent}: {alert_description}",
        rule_name="Brute Force",
        alert_description="Multiple failures",
        agent="win-dc-01",
    )
    assert t1 == "[Auto-Triage] Brute Force on win-dc-01: Multiple failures"

    # 2. Unknown placeholders stripped safely
    t2 = render_case_title(
        "Incident: {rule_name} {malicious_eval} {__import__}",
        rule_name="Test Rule",
        alert_description="Desc",
        agent="srv",
    )
    assert t2 == "Incident: Test Rule"
    assert "malicious_eval" not in t2
    assert "__import__" not in t2

    # 3. None / Empty inputs fallback safely
    t3 = render_case_title(None, "", None, None)
    assert t3.startswith("[Auto-Triage]")

    # 4. Length capping at 255
    long_desc = "A" * 500
    t4 = render_case_title("[Auto-Triage] {alert_description}", "R", long_desc, "H")
    assert len(t4) <= 255


# ── 9-12. Correlation, Idempotency & Audit Notes Tests ───────────────────────


def test_existing_open_case_correlation(clean_db):
    seed_baseline_rules(clean_db)
    # Alert 1: creates the case
    alert1 = make_alert(
        clean_db,
        rule_level=13,
        agent_name="db-prod-01",
        description="Initial Critical breach indicator",
    )
    res1 = evaluate_alert_against_rules(clean_db, alert1)
    assert res1["action"] == "create"
    case_id = res1["case_id"]

    # Alert 2: occurs on the SAME agent within 24h
    alert2 = make_alert(
        clean_db,
        rule_level=12,
        agent_name="db-prod-01",
        description="Follow-up Critical persistence attempt",
    )
    res2 = evaluate_alert_against_rules(clean_db, alert2)
    assert res2 is not None
    assert res2["action"] == "correlate"
    assert res2["case_id"] == case_id

    # Verify no second case was created
    all_cases = clean_db.scalars(select(Case)).all()
    assert len(all_cases) == 1

    # Verify both alerts are associated with case_id
    assocs = clean_db.scalars(select(CaseAlert).where(CaseAlert.case_id == case_id)).all()
    assert len(assocs) == 2


def test_no_duplicate_case_creation(clean_db):
    seed_baseline_rules(clean_db)
    alert = make_alert(clean_db, rule_level=14, agent_name="srv-01", description="Malware")

    res1 = evaluate_alert_against_rules(clean_db, alert)
    assert res1 is not None
    assert res1["action"] == "create"

    # Second evaluation of the same alert should return None and do nothing
    res2 = evaluate_alert_against_rules(clean_db, alert)
    assert res2 is None

    cases = clean_db.scalars(select(Case)).all()
    assert len(cases) == 1


def test_no_duplicate_alert_association(clean_db):
    seed_baseline_rules(clean_db)
    alert = make_alert(clean_db, rule_level=12, agent_name="srv-02")
    evaluate_alert_against_rules(clean_db, alert)

    # Count associations for alert.id
    count = clean_db.scalar(
        select(CaseAlert).where(CaseAlert.alert_id == alert.id)
    )
    assert count is not None

    # Try evaluating again
    evaluate_alert_against_rules(clean_db, alert)
    assocs = clean_db.scalars(select(CaseAlert).where(CaseAlert.alert_id == alert.id)).all()
    assert len(assocs) == 1


def test_automated_case_note_creation(clean_db):
    seed_baseline_rules(clean_db)
    alert = make_alert(
        clean_db,
        rule_level=13,
        rule_id="23506",
        agent_name="host-win-10",
        mitre_tactics=["defense-evasion"],
        mitre_techniques=["T1070"],
        description="Audit log clearing detected",
    )

    res = evaluate_alert_against_rules(clean_db, alert)
    case_id = res["case_id"]

    notes = clean_db.scalars(select(CaseNote).where(CaseNote.case_id == case_id)).all()
    assert len(notes) == 1
    note = notes[0]

    assert "[Automated Triage]" in note.content
    assert "Rule: Critical Alert Auto-Escalation" in note.content
    assert "Action: CREATE" in note.content
    assert f"Alert ID: {alert.id}" in note.content
    assert "Rule Level: 13 | Rule ID: 23506" in note.content
    assert "Agent: host-win-10" in note.content
    assert "MITRE Tactics: defense-evasion" in note.content
    assert "MITRE Techniques: T1070" in note.content
    assert "Audit log clearing detected" in note.content


# ── 13-14. Ingestion Resiliency & Backlog Endpoint ───────────────────────────


def test_triage_failure_does_not_break_ingestion(clean_db):
    service = WazuhService()
    event_payload = {
        "id": "mock-alert-triage-err-1",
        "timestamp": "2026-09-25T18:00:00.000Z",
        "rule": {"id": "1002", "level": 14, "description": "Critical event"},
        "agent": {"id": "001", "name": "host-agent"},
    }

    # Patch evaluate_alert_against_rules to raise an unexpected runtime error
    with patch(
        "app.services.triage.evaluate_alert_against_rules",
        side_effect=RuntimeError("Database deadlock simulation"),
    ):
        summary = service.ingest_event(clean_db, event_payload)

    # Ingestion must succeed despite triage failure
    assert summary.status == "ok"
    assert summary.received == 1
    assert summary.ingested == 1
    assert summary.errors == 0


def test_backlog_evaluation_endpoint(auth_client, users, clean_db):
    seed_baseline_rules(clean_db)
    # Create 3 unassociated alerts on distinct agents: 1 critical, 1 credential access, 1 normal
    make_alert(clean_db, rule_level=12, agent_id="001", agent_name="srv-a", description="Crit alert")
    make_alert(clean_db, rule_level=4, mitre_tactics=["credential-access"], agent_id="002", agent_name="srv-b")
    make_alert(clean_db, rule_level=3, rule_id="1000", agent_id="003", agent_name="srv-c")

    headers = auth_header(users["analyst"])
    response = auth_client.post("/api/v1/triage/evaluate", headers=headers, json={"limit": 50})
    assert response.status_code == 200
    data = response.json()

    assert data["evaluated_alerts"] == 3
    assert data["matched_alerts"] == 2
    assert data["cases_created"] == 2
    assert data["alerts_correlated"] == 0
    assert data["unmatched_alerts"] == 1
    assert len(data["details"]) == 2


# ── 15-17. RBAC Tests ────────────────────────────────────────────────────────


def test_rbac_unauthenticated_401(auth_client):
    # GET rules
    r1 = auth_client.get("/api/v1/triage/rules")
    assert r1.status_code == 401

    # POST evaluate
    r2 = auth_client.post("/api/v1/triage/evaluate", json={"limit": 10})
    assert r2.status_code == 401

    # POST rule
    r3 = auth_client.post("/api/v1/triage/rules", json={"name": "Test"})
    assert r3.status_code == 401


def test_rbac_analyst_cannot_mutate_rules_403(auth_client, users, clean_db):
    seed_baseline_rules(clean_db)
    headers = auth_header(users["analyst"])

    # 1. Analyst can view rules -> 200 OK
    res_get = auth_client.get("/api/v1/triage/rules", headers=headers)
    assert res_get.status_code == 200
    assert len(res_get.json()) == 2

    # 2. Analyst POST rule -> 403 Forbidden
    res_post = auth_client.post(
        "/api/v1/triage/rules",
        headers=headers,
        json={"name": "Analyst Rule", "min_rule_level": 10},
    )
    assert res_post.status_code == 403

    # 3. Analyst PATCH rule -> 403 Forbidden
    rules = list_triage_rules(clean_db)
    rule_id = rules[0].id
    res_patch = auth_client.patch(
        f"/api/v1/triage/rules/{rule_id}",
        headers=headers,
        json={"is_active": False},
    )
    assert res_patch.status_code == 403

    # 4. Analyst DELETE rule -> 403 Forbidden
    res_del = auth_client.delete(f"/api/v1/triage/rules/{rule_id}", headers=headers)
    assert res_del.status_code == 403


def test_rbac_admin_can_mutate_rules_success(auth_client, users, clean_db):
    headers = auth_header(users["admin"])

    # 1. Admin creates rule
    payload = {
        "name": "Custom Admin Escalation",
        "description": "Admin configured test policy",
        "min_rule_level": 10,
        "rule_ids": ["5710"],
        "mitre_techniques": ["T1078"],
        "action_type": "correlate_or_create",
        "case_severity": "critical",
        "case_title_template": "[Auto-Triage] {rule_name}: {alert_description}",
    }
    res_create = auth_client.post("/api/v1/triage/rules", headers=headers, json=payload)
    assert res_create.status_code == 201
    created_data = res_create.json()
    rule_id = created_data["id"]
    assert created_data["name"] == "Custom Admin Escalation"
    assert created_data["is_active"] is True

    # 2. Admin toggles / updates rule
    res_patch = auth_client.patch(
        f"/api/v1/triage/rules/{rule_id}",
        headers=headers,
        json={"is_active": False, "case_severity": "high"},
    )
    assert res_patch.status_code == 200
    patched_data = res_patch.json()
    assert patched_data["is_active"] is False
    assert patched_data["case_severity"] == "high"

    # 3. Admin deletes rule
    res_del = auth_client.delete(f"/api/v1/triage/rules/{rule_id}", headers=headers)
    assert res_del.status_code == 204

    # Confirm deletion
    res_get = auth_client.get(f"/api/v1/triage/rules", headers=headers)
    assert all(r["id"] != rule_id for r in res_get.json())


# ── 18. Baseline Rules Test ──────────────────────────────────────────────────


def test_baseline_rules_validation(clean_db):
    r1, r2 = seed_baseline_rules(clean_db)
    assert r1.name == "Critical Alert Auto-Escalation"
    assert r1.min_rule_level == 12
    assert r1.case_severity == "critical"
    assert r1.action_type == "correlate_or_create"

    assert r2.name == "Credential Access Threat Detection"
    assert r2.mitre_tactics == ["credential-access"]
    assert r2.case_severity == "high"
    assert r2.action_type == "correlate_or_create"


# ── 19. Migration Lifecycle Test ─────────────────────────────────────────────


def test_alembic_triage_migration_lifecycle():
    import os
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import inspect
    from app.db.session import engine

    ini_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "alembic.ini"))
    alembic_cfg = Config(ini_path)

    # 1. Downgrade by 1 to e1f34341c56e
    command.downgrade(alembic_cfg, "e1f34341c56e")
    inspector = inspect(engine)
    assert "triage_rules" not in inspector.get_table_names()

    # 2. Upgrade back to head
    command.upgrade(alembic_cfg, "head")
    inspector = inspect(engine)
    assert "triage_rules" in inspector.get_table_names()
