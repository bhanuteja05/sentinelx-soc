from datetime import datetime, timezone
import pytest
from sqlalchemy.exc import IntegrityError

from app.models.alert import Alert
from app.models.case import Case


def test_alert_model_instantiation():
    now = datetime.now(timezone.utc)
    alert = Alert(
        wazuh_alert_id="test-alert-001",
        timestamp=now,
        agent_id="001",
        agent_name="agent-ubuntu",
        rule_id="5710",
        rule_level=5,
        description="SSH authentication failure",
        src_ip="192.168.1.100",
        dst_ip="192.168.1.1",
        mitre_tactics=["Initial Access"],
        mitre_techniques=["T1078"],
        raw_alert={"full_log": "Failed password for root"},
    )
    assert alert.wazuh_alert_id == "test-alert-001"
    assert alert.rule_id == "5710"
    assert alert.rule_level == 5
    assert "test-alert-001" in repr(alert)


def test_case_model_instantiation():
    case = Case(
        title="Brute Force Investigation",
        description="Investigating repeated SSH failures",
        severity="high",
        status="in_progress",
    )
    assert case.title == "Brute Force Investigation"
    assert case.severity == "high"
    assert case.status == "in_progress"
    assert "Brute Force Investigation" in repr(case)


def test_alert_insert_and_read(db_session):
    now = datetime.now(timezone.utc)
    alert = Alert(
        wazuh_alert_id="unique-wazuh-id-100",
        timestamp=now,
        agent_id="002",
        agent_name="agent-win",
        rule_id="60100",
        rule_level=7,
        description="Suspicious PowerShell command",
        src_ip="10.0.0.50",
        mitre_tactics=["Execution"],
        mitre_techniques=["T1059.001"],
        raw_alert={"event_id": 4104},
    )
    db_session.add(alert)
    db_session.flush()

    assert alert.id is not None
    assert alert.created_at is not None

    fetched = db_session.get(Alert, alert.id)
    assert fetched is not None
    assert fetched.wazuh_alert_id == "unique-wazuh-id-100"
    assert fetched.rule_id == "60100"
    assert fetched.mitre_tactics == ["Execution"]
    assert fetched.raw_alert == {"event_id": 4104}


def test_case_insert_and_read(db_session):
    case = Case(
        title="Unauthorized Admin Access Attempt",
        description="Multiple failed logons on domain controller",
        severity="critical",
    )
    db_session.add(case)
    db_session.flush()

    assert case.id is not None
    assert case.status == "open"
    assert case.severity == "critical"
    assert case.created_at is not None
    assert case.updated_at is not None

    fetched = db_session.get(Case, case.id)
    assert fetched is not None
    assert fetched.title == "Unauthorized Admin Access Attempt"


def test_alert_unique_constraint(db_session):
    now = datetime.now(timezone.utc)
    alert1 = Alert(
        wazuh_alert_id="dup-alert-id",
        timestamp=now,
        rule_id="100",
    )
    alert2 = Alert(
        wazuh_alert_id="dup-alert-id",
        timestamp=now,
        rule_id="101",
    )
    db_session.add(alert1)
    db_session.flush()

    db_session.add(alert2)
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()
