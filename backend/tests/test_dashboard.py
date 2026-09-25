"""
tests/test_dashboard.py
~~~~~~~~~~~~~~~~~~~~~~~
Comprehensive test suite for Phase 7C: SOC Dashboard and Investigation Analytics.

Coverage:
  1. Summary endpoint authentication (401 without Bearer token)
  2. Empty database / zero-data environment (clean response with zero-filled time series)
  3. Alert counts & time-boundary metrics (total, 24h, 7d)
  4. Alert severity distribution (critical >= 12, high 8-11, medium 5-7, low < 5)
  5. Alert association status (associated vs unassociated alerts)
  6. Case metrics (open cases, status distribution, severity distribution)
  7. Time-series analytics (24 hourly buckets, 7 daily buckets, zero-filling)
  8. MITRE ATT&CK technique and tactic aggregation
  9. IOC extraction and type aggregation from stored alerts
  10. Recent feeds (alerts, cases, case notes investigation activity)
"""

from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
import pytest

from app.core.security import create_access_token, hash_password
from app.db import get_db
from app.main import app
from app.models.alert import Alert
from app.models.case import Case
from app.models.case_alert import CaseAlert
from app.models.case_note import CaseNote
from app.models.user import User
from app.repositories.alert import create_alert
from app.repositories.case import associate_alert_to_case, create_case, create_case_note
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
def analyst_user(clean_db):
    """Create test analyst operator."""
    return create_user(
        clean_db,
        User(
            username="soc_analyst",
            email="analyst@sentinelx.local",
            password_hash=hash_password("Analyst123!"),
            role="analyst",
            is_active=True,
        ),
    )


def auth_header(user: User) -> dict[str, str]:
    """Generate bearer auth header for a user."""
    token = create_access_token(user_id=user.id, username=user.username, role=user.role)
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# 1 · Authentication
# ---------------------------------------------------------------------------


def test_dashboard_summary_unauthenticated(auth_client):
    """Unauthenticated requests are rejected with 401 Unauthorized."""
    response = auth_client.get("/api/v1/dashboard/summary")
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# 2 · Empty Database / Zero Data
# ---------------------------------------------------------------------------


def test_dashboard_summary_empty_database(auth_client, analyst_user):
    """Dashboard handles empty database cleanly without errors."""
    headers = auth_header(analyst_user)
    response = auth_client.get("/api/v1/dashboard/summary", headers=headers)
    assert response.status_code == 200

    data = response.json()
    assert "generated_at" in data

    # Alert metrics
    alerts = data["alerts"]
    assert alerts["total"] == 0
    assert alerts["last_24h"] == 0
    assert alerts["last_7d"] == 0
    assert alerts["by_severity"] == {"critical": 0, "high": 0, "medium": 0, "low": 0}
    assert alerts["by_status"] == {"associated": 0, "unassociated": 0}

    # Case metrics
    cases = data["cases"]
    assert cases["total"] == 0
    assert cases["open"] == 0
    assert cases["by_severity"] == {"critical": 0, "high": 0, "medium": 0, "low": 0}
    assert cases["by_status"] == {
        "open": 0,
        "in_progress": 0,
        "escalated": 0,
        "resolved": 0,
        "closed": 0,
    }

    # Time series (must have 24 zero-filled hours and 7 zero-filled days)
    ts_24h = data["time_series_24h"]
    assert len(ts_24h) == 24
    assert all(b["count"] == 0 for b in ts_24h)

    ts_7d = data["time_series_7d"]
    assert len(ts_7d) == 7
    assert all(b["count"] == 0 for b in ts_7d)

    # MITRE & IOCs
    assert data["mitre"]["top_techniques"] == []
    assert data["mitre"]["top_tactics"] == []
    assert data["iocs"]["total_indicators"] == 0
    assert data["iocs"]["by_type"] == {}

    # Recent lists
    assert data["recent_alerts"] == []
    assert data["recent_cases"] == []
    assert data["recent_activity"] == []


# ---------------------------------------------------------------------------
# 3 · Alert Metrics & Severity Distribution
# ---------------------------------------------------------------------------


def test_dashboard_summary_alert_metrics(auth_client, analyst_user, clean_db):
    """Verify alert aggregation counts across time boundaries and rule levels."""
    now = datetime.now(timezone.utc)

    # 1. Critical alert 2 hours ago (level 13)
    create_alert(
        clean_db,
        {
            "wazuh_alert_id": "test-alert-1",
            "timestamp": now - timedelta(hours=2),
            "rule_id": "1001",
            "rule_level": 13,
            "description": "Root compromise",
            "raw_alert": {},
        },
    )

    # 2. High alert 10 hours ago (level 9)
    create_alert(
        clean_db,
        {
            "wazuh_alert_id": "test-alert-2",
            "timestamp": now - timedelta(hours=10),
            "rule_id": "1002",
            "rule_level": 9,
            "description": "Mimikatz detected",
            "raw_alert": {},
        },
    )

    # 3. Medium alert 3 days ago (level 6) -> within 7d, NOT in 24h
    create_alert(
        clean_db,
        {
            "wazuh_alert_id": "test-alert-3",
            "timestamp": now - timedelta(days=3),
            "rule_id": "1003",
            "rule_level": 6,
            "description": "Failed logon threshold",
            "raw_alert": {},
        },
    )

    # 4. Low alert 10 days ago (level 3) -> outside 7d and 24h
    create_alert(
        clean_db,
        {
            "wazuh_alert_id": "test-alert-4",
            "timestamp": now - timedelta(days=10),
            "rule_id": "1004",
            "rule_level": 3,
            "description": "User login success",
            "raw_alert": {},
        },
    )

    headers = auth_header(analyst_user)
    response = auth_client.get("/api/v1/dashboard/summary", headers=headers)
    assert response.status_code == 200
    data = response.json()

    alerts = data["alerts"]
    assert alerts["total"] == 4
    assert alerts["last_24h"] == 2
    assert alerts["last_7d"] == 3
    assert alerts["by_severity"]["critical"] == 1
    assert alerts["by_severity"]["high"] == 1
    assert alerts["by_severity"]["medium"] == 1
    assert alerts["by_severity"]["low"] == 1


# ---------------------------------------------------------------------------
# 4 · Alert Association Status
# ---------------------------------------------------------------------------


def test_dashboard_summary_alert_status(auth_client, analyst_user, clean_db):
    """Alerts are categorized by association with a case."""
    now = datetime.now(timezone.utc)
    a1 = create_alert(
        clean_db,
        {
            "wazuh_alert_id": "test-alert-assoc-1",
            "timestamp": now,
            "rule_id": "101",
            "rule_level": 5,
            "description": "Associated Alert",
            "raw_alert": {},
        },
    )
    create_alert(
        clean_db,
        {
            "wazuh_alert_id": "test-alert-assoc-2",
            "timestamp": now,
            "rule_id": "102",
            "rule_level": 5,
            "description": "Unassociated Alert",
            "raw_alert": {},
        },
    )

    test_case = create_case(
        clean_db,
        Case(title="Case 1", severity="medium", status="open"),
    )
    associate_alert_to_case(clean_db, test_case.id, a1.id)

    headers = auth_header(analyst_user)
    response = auth_client.get("/api/v1/dashboard/summary", headers=headers)
    assert response.status_code == 200
    data = response.json()

    assert data["alerts"]["by_status"]["associated"] == 1
    assert data["alerts"]["by_status"]["unassociated"] == 1


# ---------------------------------------------------------------------------
# 5 · Case Aggregation Metrics
# ---------------------------------------------------------------------------


def test_dashboard_summary_case_metrics(auth_client, analyst_user, clean_db):
    """Verify case status, severity, and open case totals."""
    create_case(clean_db, Case(title="Open Critical", severity="critical", status="open"))
    create_case(clean_db, Case(title="In Progress High", severity="high", status="in_progress"))
    create_case(clean_db, Case(title="Escalated Medium", severity="medium", status="escalated"))
    create_case(clean_db, Case(title="Resolved Low", severity="low", status="resolved"))
    create_case(clean_db, Case(title="Closed Low", severity="low", status="closed"))

    headers = auth_header(analyst_user)
    response = auth_client.get("/api/v1/dashboard/summary", headers=headers)
    assert response.status_code == 200
    data = response.json()

    cases = data["cases"]
    assert cases["total"] == 5
    assert cases["open"] == 4  # All except closed
    assert cases["by_status"]["open"] == 1
    assert cases["by_status"]["in_progress"] == 1
    assert cases["by_status"]["escalated"] == 1
    assert cases["by_status"]["resolved"] == 1
    assert cases["by_status"]["closed"] == 1
    assert cases["by_severity"]["critical"] == 1
    assert cases["by_severity"]["high"] == 1
    assert cases["by_severity"]["medium"] == 1
    assert cases["by_severity"]["low"] == 2


# ---------------------------------------------------------------------------
# 6 · Time-Series Analytics
# ---------------------------------------------------------------------------


def test_dashboard_summary_time_series(auth_client, analyst_user, clean_db):
    """Hourly and daily time-series return exact counts and correctly zero-fill empty buckets."""
    now = datetime.now(timezone.utc)
    # Seed 3 alerts in the current hour
    current_hour_time = now.replace(minute=10, second=0)
    for i in range(3):
        create_alert(
            clean_db,
            {
                "wazuh_alert_id": f"ts-hour-{i}",
                "timestamp": current_hour_time,
                "rule_id": "200",
                "rule_level": 4,
                "description": "Hourly test alert",
                "raw_alert": {},
            },
        )

    headers = auth_header(analyst_user)
    response = auth_client.get("/api/v1/dashboard/summary", headers=headers)
    assert response.status_code == 200
    data = response.json()

    ts_24h = data["time_series_24h"]
    assert len(ts_24h) == 24
    # The last bucket (current hour) should have count 3
    assert ts_24h[-1]["count"] == 3
    assert sum(b["count"] for b in ts_24h) == 3

    ts_7d = data["time_series_7d"]
    assert len(ts_7d) == 7
    # The last day bucket (today) should have count 3
    assert ts_7d[-1]["count"] == 3
    assert sum(b["count"] for b in ts_7d) == 3


# ---------------------------------------------------------------------------
# 7 · MITRE ATT&CK Analytics
# ---------------------------------------------------------------------------


def test_dashboard_summary_mitre_analytics(auth_client, analyst_user, clean_db):
    """Aggregates techniques and tactics from stored JSONB alert fields."""
    now = datetime.now(timezone.utc)
    create_alert(
        clean_db,
        {
            "wazuh_alert_id": "mitre-1",
            "timestamp": now,
            "rule_id": "301",
            "rule_level": 8,
            "description": "Command execution",
            "mitre_tactics": ["execution"],
            "mitre_techniques": ["T1059", "T1059.001"],
            "raw_alert": {},
        },
    )
    create_alert(
        clean_db,
        {
            "wazuh_alert_id": "mitre-2",
            "timestamp": now,
            "rule_id": "302",
            "rule_level": 7,
            "description": "Script execution",
            "mitre_tactics": ["execution", "defense-evasion"],
            "mitre_techniques": ["T1059"],
            "raw_alert": {},
        },
    )

    headers = auth_header(analyst_user)
    response = auth_client.get("/api/v1/dashboard/summary", headers=headers)
    assert response.status_code == 200
    data = response.json()

    mitre = data["mitre"]
    techniques = {t["technique_id"]: t["count"] for t in mitre["top_techniques"]}
    assert techniques.get("T1059") == 2
    assert techniques.get("T1059.001") == 1

    tactics = {t["tactic"]: t["count"] for t in mitre["top_tactics"]}
    assert tactics.get("execution") == 2
    assert tactics.get("defense-evasion") == 1


# ---------------------------------------------------------------------------
# 8 · IOC Analytics
# ---------------------------------------------------------------------------


def test_dashboard_summary_ioc_analytics(auth_client, analyst_user, clean_db):
    """Extracts and aggregates IOC types from recent stored alerts."""
    now = datetime.now(timezone.utc)
    create_alert(
        clean_db,
        {
            "wazuh_alert_id": "ioc-alert-1",
            "timestamp": now,
            "rule_id": "401",
            "rule_level": 10,
            "description": "Outbound connection to malicious domain evil.example.com and IP 198.51.100.42",
            "raw_alert": {
                "hash": "d41d8cd98f00b204e9800998ecf8427e",
                "target": "https://malicious.net/payload.bin",
            },
        },
    )

    headers = auth_header(analyst_user)
    response = auth_client.get("/api/v1/dashboard/summary", headers=headers)
    assert response.status_code == 200
    data = response.json()

    iocs = data["iocs"]
    assert iocs["source"] == "derived_from_alerts"
    assert iocs["analyzed_alert_count"] == 1
    assert iocs["total_indicators"] > 0
    assert "domain" in iocs["by_type"]
    assert "ipv4" in iocs["by_type"]
    assert "md5" in iocs["by_type"]
    assert "url" in iocs["by_type"]
    assert "evil.example.com" in iocs["samples"]["domain"]


# ---------------------------------------------------------------------------
# 9 · Recent Investigation Activity
# ---------------------------------------------------------------------------


def test_dashboard_summary_recent_activity(auth_client, analyst_user, clean_db):
    """Recent case notes are returned with case title and author username."""
    test_case = create_case(
        clean_db,
        Case(title="Ransomware Outbreak", severity="critical", status="in_progress"),
    )
    create_case_note(
        clean_db,
        case_id=test_case.id,
        author_id=analyst_user.id,
        content="Containment action executed: affected segment quarantined.",
    )

    headers = auth_header(analyst_user)
    response = auth_client.get("/api/v1/dashboard/summary", headers=headers)
    assert response.status_code == 200
    data = response.json()

    activity = data["recent_activity"]
    assert len(activity) == 1
    assert activity[0]["case_id"] == test_case.id
    assert activity[0]["case_title"] == "Ransomware Outbreak"
    assert activity[0]["author_username"] == analyst_user.username
    assert "quarantined" in activity[0]["content"]


# ---------------------------------------------------------------------------
# 10 · Boundary Conditions
# ---------------------------------------------------------------------------


def test_dashboard_summary_boundary_conditions(auth_client, analyst_user, clean_db):
    """Test time boundaries for 24h and 7d metrics."""
    now = datetime.now(timezone.utc)

    # Inside 24h
    create_alert(
        clean_db,
        {
            "wazuh_alert_id": "bound-inside-24h",
            "timestamp": now - timedelta(hours=23, minutes=50),
            "rule_id": "901",
            "rule_level": 7,
            "description": "Inside 24h",
            "raw_alert": {},
        },
    )

    # Outside 24h, inside 7d
    create_alert(
        clean_db,
        {
            "wazuh_alert_id": "bound-outside-24h",
            "timestamp": now - timedelta(hours=24, minutes=10),
            "rule_id": "902",
            "rule_level": 7,
            "description": "Outside 24h, inside 7d",
            "raw_alert": {},
        },
    )

    # Inside 7d
    create_alert(
        clean_db,
        {
            "wazuh_alert_id": "bound-inside-7d",
            "timestamp": now - timedelta(days=6, hours=23),
            "rule_id": "903",
            "rule_level": 7,
            "description": "Inside 7d",
            "raw_alert": {},
        },
    )

    # Outside 7d
    create_alert(
        clean_db,
        {
            "wazuh_alert_id": "bound-outside-7d",
            "timestamp": now - timedelta(days=7, minutes=10),
            "rule_id": "904",
            "rule_level": 7,
            "description": "Outside 7d",
            "raw_alert": {},
        },
    )

    headers = auth_header(analyst_user)
    response = auth_client.get("/api/v1/dashboard/summary", headers=headers)
    assert response.status_code == 200
    data = response.json()

    assert data["alerts"]["total"] == 4
    assert data["alerts"]["last_24h"] == 1
    assert data["alerts"]["last_7d"] == 3
