"""
tests/test_ingestion.py
~~~~~~~~~~~~~~~~~~~~~~~
Tests for the Wazuh → PostgreSQL alert ingestion pipeline.

Coverage:
  1. WazuhAlert → Alert dict mapping (field names, values)
  2. Timestamp conversion: +0000, +00:00, None, garbage
  3. Missing src/dst ip/port → NULL
  4. raw_alert contains normalized WazuhAlert snapshot
  5. Successful ingestion persists a new alert
  6. Duplicate wazuh_alert_id is counted, not double-inserted
  7. One malformed alert (empty id) does not abort the remaining batch
  8. Wazuh client unavailable → 502 from ingest endpoint
  9. Empty Wazuh response → 0 ingested, 0 errors

Wazuh network layer is mocked throughout — no live Wazuh required.
"""

from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.wazuh.ingestion import AlertMappingError, _parse_timestamp, wazuh_alert_to_dict
from app.wazuh.schemas import WazuhAlert, WazuhAlertsResponse


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_wazuh_alert(**overrides) -> WazuhAlert:
    """Factory for WazuhAlert with sensible defaults."""
    defaults = dict(
        id="test-alert-id-001",
        timestamp="2026-09-25T06:30:39.106+0000",
        agent_id="001",
        agent_name="SentinelX-Windows-Host",
        rule_id="60796",
        rule_level=5,
        rule_description="The database engine stopped an instance.",
        rule_groups=["windows", "windows_application"],
        mitre_tactics=["Defense Evasion"],
        mitre_techniques=["Domain Policy Modification"],
        decoder="windows_eventchannel",
        location="EventChannel",
    )
    defaults.update(overrides)
    return WazuhAlert(**defaults)


# ---------------------------------------------------------------------------
# 1 · Field mapping
# ---------------------------------------------------------------------------

def test_mapper_field_names_and_values():
    """All expected keys are present in output dict with correct values."""
    alert = _make_wazuh_alert()
    result = wazuh_alert_to_dict(alert)

    assert result["wazuh_alert_id"] == "test-alert-id-001"
    assert isinstance(result["timestamp"], datetime)
    assert result["timestamp"].tzinfo is not None  # timezone-aware
    assert result["agent_id"] == "001"
    assert result["agent_name"] == "SentinelX-Windows-Host"
    assert result["rule_id"] == "60796"
    assert result["rule_level"] == 5
    assert result["description"] == "The database engine stopped an instance."
    assert result["decoder"] == "windows_eventchannel"
    assert result["location"] == "EventChannel"
    assert result["mitre_tactics"] == ["Defense Evasion"]
    assert result["mitre_techniques"] == ["Domain Policy Modification"]


# ---------------------------------------------------------------------------
# 2 · Timestamp conversion
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ts,expected_utc_hour", [
    ("2026-09-25T06:30:39.106+0000", 6),   # Wazuh native format (no colon)
    ("2026-09-25T06:30:39.106+00:00", 6),  # ISO 8601 with colon
    ("2026-09-25T08:30:39+02:00", 6),      # non-UTC offset → normalizes to UTC 06:30
])
def test_parse_timestamp_formats(ts, expected_utc_hour):
    result = _parse_timestamp(ts)
    assert isinstance(result, datetime)
    assert result.tzinfo is not None
    utc = result.astimezone(timezone.utc)
    assert utc.hour == expected_utc_hour


def test_parse_timestamp_none_returns_fallback():
    result = _parse_timestamp(None)
    assert isinstance(result, datetime)
    assert result.tzinfo is not None


def test_parse_timestamp_garbage_returns_fallback():
    result = _parse_timestamp("not-a-timestamp")
    assert isinstance(result, datetime)
    assert result.tzinfo is not None


# ---------------------------------------------------------------------------
# 3 · src/dst IP/port are NULL
# ---------------------------------------------------------------------------

def test_network_fields_are_null():
    """src_ip, dst_ip, src_port, dst_port are always NULL in this phase."""
    result = wazuh_alert_to_dict(_make_wazuh_alert())
    assert result["src_ip"] is None
    assert result["dst_ip"] is None
    assert result["src_port"] is None
    assert result["dst_port"] is None


# ---------------------------------------------------------------------------
# 4 · raw_alert contains normalized WazuhAlert snapshot
# ---------------------------------------------------------------------------

def test_raw_alert_is_normalized_snapshot():
    alert = _make_wazuh_alert()
    result = wazuh_alert_to_dict(alert)
    raw = result["raw_alert"]

    assert isinstance(raw, dict)
    # raw_alert is alert.model_dump() — must contain the normalized fields
    assert raw["id"] == alert.id
    assert raw["rule_id"] == alert.rule_id
    assert raw["mitre_tactics"] == alert.mitre_tactics
    # Not the raw indexer document — no "_source", "_id" keys expected
    assert "_source" not in raw
    assert "_id" not in raw


# ---------------------------------------------------------------------------
# 5 · Malformed alert raises AlertMappingError
# ---------------------------------------------------------------------------

def test_empty_alert_id_raises():
    alert = _make_wazuh_alert(id="")
    with pytest.raises(AlertMappingError, match="required"):
        wazuh_alert_to_dict(alert)


def test_whitespace_alert_id_raises():
    alert = _make_wazuh_alert(id="   ")
    with pytest.raises(AlertMappingError, match="required"):
        wazuh_alert_to_dict(alert)


# ---------------------------------------------------------------------------
# 6 · rule_id fallback when absent
# ---------------------------------------------------------------------------

def test_rule_id_fallback_when_none():
    alert = _make_wazuh_alert(rule_id=None)
    result = wazuh_alert_to_dict(alert)
    assert result["rule_id"] == "unknown"


# ---------------------------------------------------------------------------
# 7 · Integration: ingest endpoint (TestClient + get_db dependency override)
# ---------------------------------------------------------------------------
# The TestClient uses FastAPI's get_db dependency.  We override it to inject
# the test fixture's session so both the TRUNCATE (clean_db) and the route
# handler share the same connection — avoiding cross-session lock contention.
# ---------------------------------------------------------------------------

_MOCK_ALERT = _make_wazuh_alert(id="integration-test-alert-001")
_MOCK_RESPONSE = WazuhAlertsResponse(
    status="ok",
    source="wazuh-indexer",
    index="wazuh-alerts-4.x-*",
    total=1,
    count=1,
    alerts=[_MOCK_ALERT],
)


@pytest.fixture
def client(clean_db):
    """TestClient with get_db and get_current_active_user overridden to use the clean test session."""
    from app.api.deps import get_current_active_user
    from app.db import get_db
    from app.main import app
    from app.models.user import User

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



@patch("app.api.alerts.wazuh_client")
def test_ingest_new_alert_persists(mock_client, client, clean_db):
    """A new alert is ingested and counted as ingested=1, duplicates=0."""
    mock_client.get_alerts.return_value = _MOCK_RESPONSE

    response = client.post("/api/v1/alerts/ingest?limit=1")
    assert response.status_code == 200
    data = response.json()
    assert data["fetched"] == 1
    assert data["ingested"] == 1
    assert data["duplicates"] == 0
    assert data["errors"] == 0


@patch("app.api.alerts.wazuh_client")
def test_ingest_duplicate_not_double_inserted(mock_client, client, clean_db):
    """Calling ingest twice with the same alert returns ingested=0, duplicates=1."""
    mock_client.get_alerts.return_value = _MOCK_RESPONSE

    # First call — insert
    r1 = client.post("/api/v1/alerts/ingest?limit=1")
    assert r1.json()["ingested"] == 1

    # Second call — same alert id → duplicate
    r2 = client.post("/api/v1/alerts/ingest?limit=1")
    data2 = r2.json()
    assert data2["ingested"] == 0
    assert data2["duplicates"] == 1

    # DB must still have exactly 1 row
    count_resp = client.get("/api/v1/alerts/count")
    assert count_resp.json()["count"] == 1


@patch("app.api.alerts.wazuh_client")
def test_ingest_malformed_alert_does_not_abort_batch(mock_client, client, clean_db):
    """One malformed alert (empty id) does not prevent a valid alert from being ingested."""
    bad_alert = WazuhAlert(
        id="",  # will trigger AlertMappingError
        timestamp="2026-09-25T06:30:39+0000",
        rule_id="999",
    )
    good_alert = _make_wazuh_alert(id="good-alert-batch-001")
    mock_client.get_alerts.return_value = WazuhAlertsResponse(
        total=2, count=2, alerts=[bad_alert, good_alert]
    )

    response = client.post("/api/v1/alerts/ingest?limit=2")
    assert response.status_code == 200
    data = response.json()
    assert data["ingested"] == 1
    assert data["errors"] == 1
    assert data["duplicates"] == 0
    assert len(data["error_details"]) == 1


@patch("app.api.alerts.wazuh_client")
def test_ingest_wazuh_unavailable_returns_502(mock_client, client, clean_db):
    """If the Wazuh client raises, the endpoint returns 502."""
    mock_client.get_alerts.side_effect = ConnectionError("indexer unreachable")

    response = client.post("/api/v1/alerts/ingest?limit=10")
    assert response.status_code == 502
    assert "Wazuh" in response.json()["detail"]


@patch("app.api.alerts.wazuh_client")
def test_ingest_empty_response(mock_client, client, clean_db):
    """An empty Wazuh response returns fetched=0, all counts 0, no errors."""
    mock_client.get_alerts.return_value = WazuhAlertsResponse(
        total=0, count=0, alerts=[]
    )

    response = client.post("/api/v1/alerts/ingest?limit=50")
    assert response.status_code == 200
    data = response.json()
    assert data["fetched"] == 0
    assert data["ingested"] == 0
    assert data["duplicates"] == 0
    assert data["errors"] == 0


# ---------------------------------------------------------------------------
# 8 · GET /api/v1/alerts and /count endpoints
# ---------------------------------------------------------------------------

@patch("app.api.alerts.wazuh_client")
def test_get_alerts_after_ingest(mock_client, client, clean_db):
    """Persisted alerts appear in GET /api/v1/alerts."""
    mock_client.get_alerts.return_value = _MOCK_RESPONSE
    client.post("/api/v1/alerts/ingest?limit=1")

    resp = client.get("/api/v1/alerts")
    assert resp.status_code == 200
    data = resp.json()
    alerts = data["items"]
    assert data["total"] == 1
    assert len(alerts) == 1
    assert alerts[0]["wazuh_alert_id"] == "integration-test-alert-001"
    assert alerts[0]["src_ip"] is None
    assert alerts[0]["dst_ip"] is None


@patch("app.api.alerts.wazuh_client")
def test_count_endpoint_reflects_ingestion(mock_client, client, clean_db):
    """GET /api/v1/alerts/count reflects the ingested alert count."""
    mock_client.get_alerts.return_value = _MOCK_RESPONSE

    assert client.get("/api/v1/alerts/count").json()["count"] == 0
    client.post("/api/v1/alerts/ingest?limit=1")
    assert client.get("/api/v1/alerts/count").json()["count"] == 1


@patch("app.api.alerts.wazuh_client")
def test_get_alert_by_id(mock_client, client, clean_db):
    """GET /api/v1/alerts/{id} returns the correct alert."""
    mock_client.get_alerts.return_value = _MOCK_RESPONSE
    client.post("/api/v1/alerts/ingest?limit=1")

    list_resp = client.get("/api/v1/alerts")
    alert_id = list_resp.json()["items"][0]["id"]

    by_id_resp = client.get(f"/api/v1/alerts/{alert_id}")
    assert by_id_resp.status_code == 200
    assert by_id_resp.json()["wazuh_alert_id"] == "integration-test-alert-001"


def test_get_alert_by_id_not_found(client):
    """GET /api/v1/alerts/99999 returns 404."""
    resp = client.get("/api/v1/alerts/99999")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 9 · Error details do not leak credentials
# ---------------------------------------------------------------------------

@patch("app.api.alerts.wazuh_client")
def test_error_detail_contains_no_secrets(mock_client, client, clean_db):
    """Error details must not contain passwords, tokens, or connection strings."""
    bad_alert = WazuhAlert(id="", rule_id="0")
    mock_client.get_alerts.return_value = WazuhAlertsResponse(
        total=1, count=1, alerts=[bad_alert]
    )

    resp = client.post("/api/v1/alerts/ingest?limit=1")
    body = resp.text
    # None of these patterns should appear in the response
    for forbidden in ("password", "token", "postgresql://", "wazuh-wui", "Bearer"):
        assert forbidden.lower() not in body.lower(), (
            f"Response leaks secret pattern '{forbidden}'"
        )
