from datetime import datetime, timezone
import pytest

from app.models.alert import Alert
from app.models.case import Case
from app.repositories.alert import (
    count_alerts,
    create_alert,
    get_alert_by_id,
    get_alert_by_wazuh_id,
    list_alerts,
)
from app.repositories.case import (
    create_case,
    delete_case,
    get_case_by_id,
    list_cases,
    update_case,
)
from app.services.alert import get_recent_alerts, ingest_alert
from app.services.case import close_case, open_case, update_case as service_update_case


def test_alert_repo_crud(clean_db):
    now = datetime.now(timezone.utc)
    alert = create_alert(
        clean_db,
        {
            "wazuh_alert_id": "repo-alert-1",
            "timestamp": now,
            "agent_id": "001",
            "agent_name": "agent-linux",
            "rule_id": "5715",
            "rule_level": 8,
            "description": "SSHD success after failure",
            "src_ip": "10.10.10.5",
        },
    )
    assert alert.id is not None
    assert count_alerts(clean_db) == 1

    by_id = get_alert_by_id(clean_db, alert.id)
    assert by_id is not None
    assert by_id.wazuh_alert_id == "repo-alert-1"

    by_wazuh = get_alert_by_wazuh_id(clean_db, "repo-alert-1")
    assert by_wazuh is not None
    assert by_wazuh.id == alert.id

    filtered = list_alerts(clean_db, rule_id="5715", min_level=5)
    assert len(filtered) == 1

    empty_filter = list_alerts(clean_db, rule_id="9999")
    assert len(empty_filter) == 0


def test_case_repo_crud(clean_db):
    case = create_case(
        clean_db,
        {
            "title": "Malware Outbreak Investigation",
            "description": "Host 002 alerted on ransomware behavior",
            "severity": "high",
            "status": "open",
        },
    )
    assert case.id is not None

    by_id = get_case_by_id(clean_db, case.id)
    assert by_id is not None
    assert by_id.title == "Malware Outbreak Investigation"

    updated = update_case(clean_db, case.id, {"status": "in_progress", "severity": "critical"})
    assert updated is not None
    assert updated.status == "in_progress"
    assert updated.severity == "critical"

    cases = list_cases(clean_db, status="in_progress")
    assert len(cases) == 1

    deleted = delete_case(clean_db, case.id)
    assert deleted is True
    assert get_case_by_id(clean_db, case.id) is None


def test_alert_service_deduplication(clean_db):
    now = datetime.now(timezone.utc)
    payload = {
        "wazuh_alert_id": "dedup-alert-id-123",
        "timestamp": now,
        "rule_id": "5001",
        "description": "Test alert for deduplication",
    }
    alert1, is_new1 = ingest_alert(clean_db, payload)
    assert is_new1 is True
    assert alert1.id is not None

    # Ingest same wazuh_alert_id again -> returns existing alert, is_new=False
    alert2, is_new2 = ingest_alert(clean_db, payload)
    assert is_new2 is False
    assert alert2.id == alert1.id
    assert count_alerts(clean_db) == 1


def test_case_service_lifecycle(clean_db):
    case = open_case(
        clean_db,
        title="Phishing Email Lead",
        description="Employee reported credential harvester link",
        severity="medium",
    )
    assert case.status == "open"
    assert case.severity == "medium"

    updated = service_update_case(clean_db, case.id, status="in_progress", severity="high")
    assert updated is not None
    assert updated.status == "in_progress"
    assert updated.severity == "high"

    closed = close_case(clean_db, case.id)
    assert closed is not None
    assert closed.status == "closed"


def test_case_service_validation_errors(clean_db):
    with pytest.raises(ValueError, match="Invalid case status"):
        open_case(clean_db, title="Test Case", status="invalid_status")

    with pytest.raises(ValueError, match="Invalid case severity"):
        open_case(clean_db, title="Test Case", severity="super_high")
