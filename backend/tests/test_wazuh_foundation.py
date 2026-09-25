"""
backend/tests/test_wazuh_foundation.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Unit and integration tests for the SentinelX Wazuh Integration Foundation.

Verifies:
  1. Configuration & secret redaction
  2. WazuhClient transport, auth, queries, and exception mapping
  3. WazuhService business logic & push/pull ingestion
  4. Internal event ingestion boundary (POST /api/v1/wazuh/events)
  5. Error isolation (one malformed event doesn't abort batch)
  6. Authentication enforcement on Wazuh routes

All tests use mocks and fixtures — no live Wazuh server required.
"""

from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
import httpx
import pytest

from app.api.deps import get_current_active_user
from app.db import get_db
from app.main import app
from app.models.user import User
from app.wazuh.client import (
    WazuhAuthError,
    WazuhClient,
    WazuhClientError,
    WazuhConnectionError,
    WazuhIndexerError,
)
from app.wazuh.config import WazuhSettings, get_wazuh_settings
from app.wazuh.schemas import WazuhAlert, WazuhAlertsResponse, normalize_alert, normalize_raw_event
from app.wazuh.service import WazuhService


@pytest.fixture
def test_user():
    return User(
        id=1,
        username="analyst_test",
        email="analyst@sentinelx.local",
        password_hash="fakehash",
        role="analyst",
        is_active=True,
    )


@pytest.fixture
def auth_client(test_user, clean_db):
    """TestClient with active operator override."""
    app.dependency_overrides[get_db] = lambda: clean_db
    app.dependency_overrides[get_current_active_user] = lambda: test_user
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def unauth_client(clean_db):
    """TestClient with no user override (requests are unauthenticated)."""
    app.dependency_overrides[get_db] = lambda: clean_db
    yield TestClient(app)
    app.dependency_overrides.clear()


# ── 1. Configuration & Redaction Tests ────────────────────────────────────────

def test_wazuh_settings_defaults(monkeypatch):
    monkeypatch.delenv("WAZUH_API_URL", raising=False)
    monkeypatch.delenv("WAZUH_INDEXER_URL", raising=False)
    monkeypatch.delenv("WAZUH_TIMEOUT", raising=False)
    monkeypatch.delenv("WAZUH_VERIFY_SSL", raising=False)

    settings = get_wazuh_settings()
    assert settings.api_url == "https://host.docker.internal:55000"
    assert settings.indexer_url == "https://wazuh.indexer:9200"
    assert settings.timeout == 10.0
    assert settings.verify_ssl is False


def test_wazuh_settings_env_overrides(monkeypatch):
    monkeypatch.setenv("WAZUH_API_URL", "https://siem.internal:55000/")
    monkeypatch.setenv("WAZUH_API_USER", "custom-user")
    monkeypatch.setenv("WAZUH_API_PASSWORD", "SuperSecretPass123")
    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://indexer.internal:9200/")
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "IndexerSecret456")
    monkeypatch.setenv("WAZUH_TIMEOUT", "25.5")
    monkeypatch.setenv("WAZUH_VERIFY_SSL", "true")

    settings = get_wazuh_settings()
    assert settings.api_url == "https://siem.internal:55000"
    assert settings.api_user == "custom-user"
    assert settings.indexer_url == "https://indexer.internal:9200"
    assert settings.timeout == 25.5
    assert settings.verify_ssl is True

    # Test redaction
    raw_error = "Connection failed for user custom-user with SuperSecretPass123 to IndexerSecret456"
    redacted = settings.redact(raw_error)
    assert "SuperSecretPass123" not in redacted
    assert "IndexerSecret456" not in redacted
    assert "***" in redacted


# ── 2. WazuhClient Transport Tests ───────────────────────────────────────────

def test_client_authenticate_success():
    client = WazuhClient()
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"data": {"token": "test-jwt-token-12345"}}
    mock_resp.raise_for_status = MagicMock()

    with patch("httpx.get", return_value=mock_resp) as mock_get:
        token = client._authenticate()
        assert token == "test-jwt-token-12345"
        mock_get.assert_called_once()


def test_client_authenticate_auth_failure():
    client = WazuhClient()
    mock_resp = MagicMock(status_code=401)
    http_error = httpx.HTTPStatusError("401 Unauthorized", request=MagicMock(), response=mock_resp)

    with patch("httpx.get", side_effect=http_error):
        with pytest.raises(WazuhAuthError):
            client._authenticate()


def test_client_authenticate_connection_failure():
    client = WazuhClient()
    with patch("httpx.get", side_effect=httpx.ConnectError("Connection refused")):
        with pytest.raises(WazuhConnectionError):
            client._authenticate()


def test_client_health():
    client = WazuhClient()
    with patch.object(client, "_authenticate", return_value="token"):
        h = client.health()
        assert h["status"] == "ok"
        assert h["service"] == "wazuh-api"


def test_client_get_agents():
    client = WazuhClient()
    agents_payload = {"data": {"affected_items": [{"id": "001", "name": "win-agent"}]}}
    with patch.object(client, "_request", return_value=agents_payload):
        res = client.get_agents()
        assert res["data"]["affected_items"][0]["name"] == "win-agent"


def test_client_get_alerts_indexer_success():
    client = WazuhClient()
    indexer_json = {
        "hits": {
            "total": {"value": 1},
            "hits": [
                {
                    "_id": "wazuh-hit-001",
                    "_source": {
                        "timestamp": "2026-09-25T12:00:00.000+0000",
                        "rule": {"id": "1001", "level": 7, "description": "Suspicious login"},
                        "agent": {"id": "002", "name": "db-server"},
                        "data": {"srcip": "10.0.0.5", "srcport": "44321"},
                    },
                }
            ],
        }
    }
    mock_resp = MagicMock()
    mock_resp.json.return_value = indexer_json
    mock_resp.raise_for_status = MagicMock()

    with patch("httpx.post", return_value=mock_resp):
        alerts_resp = client.get_alerts(limit=10)
        assert alerts_resp.total == 1
        assert alerts_resp.count == 1
        assert len(alerts_resp.alerts) == 1
        alert = alerts_resp.alerts[0]
        assert alert.id == "wazuh-hit-001"
        assert alert.rule_id == "1001"
        assert alert.rule_level == 7
        assert alert.agent_name == "db-server"
        assert alert.src_ip == "10.0.0.5"
        assert alert.src_port == 44321


def test_client_get_alerts_indexer_failure():
    client = WazuhClient()
    with patch("httpx.post", side_effect=httpx.ConnectError("Indexer down")):
        with pytest.raises(WazuhIndexerError):
            client.get_alerts(limit=5)


# ── 3. Normalization & Schemas Tests ─────────────────────────────────────────

def test_normalize_raw_event_variations():
    # Format 1: Elasticsearch hit
    hit = {
        "_id": "hit-1",
        "_source": {
            "timestamp": "2026-09-25T10:00:00+00:00",
            "rule": {"id": "501", "level": 4, "description": "Test rule"},
            "agent": {"id": "001", "name": "agent1"},
        },
    }
    norm1 = normalize_raw_event(hit)
    assert norm1.id == "hit-1"
    assert norm1.rule_id == "501"

    # Format 2: Wazuh Integrator webhook wrapper
    integrator_event = {
        "alert": {
            "id": "int-1",
            "timestamp": "2026-09-25T10:00:00+00:00",
            "rule": {"id": "502", "level": 6, "description": "Webhook rule"},
            "agent": {"id": "002", "name": "agent2"},
        }
    }
    norm2 = normalize_raw_event(integrator_event)
    assert norm2.id == "int-1"
    assert norm2.rule_id == "502"

    # Format 3: Direct flat dict
    flat = {
        "id": "flat-1",
        "timestamp": "2026-09-25T10:00:00+00:00",
        "rule": {"id": "503", "level": 8, "description": "Flat rule"},
        "agent": {"id": "003", "name": "agent3"},
    }
    norm3 = normalize_raw_event(flat)
    assert norm3.id == "flat-1"
    assert norm3.rule_id == "503"


# ── 4. WazuhService & Ingestion Boundary Tests ────────────────────────────────

def test_service_push_ingest_single_event(clean_db):
    service = WazuhService(client=MagicMock())
    event = {
        "id": "push-event-001",
        "timestamp": "2026-09-25T14:30:00.000+0000",
        "rule": {
            "id": "99001",
            "level": 10,
            "description": "Critical brute-force detection",
            "groups": ["authentication_failed"],
            "mitre": {"tactic": ["Credential Access"], "technique": ["Brute Force"]},
        },
        "agent": {"id": "005", "name": "bastion-host"},
        "data": {"srcip": "198.51.100.25", "srcport": "54321"},
    }

    summary = service.ingest_event(clean_db, event)
    assert summary.status == "ok"
    assert summary.received == 1
    assert summary.ingested == 1
    assert summary.duplicates == 0
    assert summary.errors == 0

    # Idempotent re-ingest: should detect duplicate
    summary_dup = service.ingest_event(clean_db, event)
    assert summary_dup.received == 1
    assert summary_dup.ingested == 0
    assert summary_dup.duplicates == 1


def test_service_push_ingest_batch_with_error_isolation(clean_db):
    service = WazuhService(client=MagicMock())
    batch = [
        # Valid event 1
        {
            "id": "batch-event-001",
            "timestamp": "2026-09-25T14:31:00+00:00",
            "rule": {"id": "99002", "level": 5, "description": "Valid 1"},
        },
        # Invalid event (missing id)
        {
            "id": "",
            "timestamp": "2026-09-25T14:32:00+00:00",
            "rule": {"id": "99003", "level": 5, "description": "Missing ID"},
        },
        # Valid event 2
        {
            "id": "batch-event-002",
            "timestamp": "2026-09-25T14:33:00+00:00",
            "rule": {"id": "99004", "level": 5, "description": "Valid 2"},
        },
    ]

    summary = service.ingest_event(clean_db, batch)
    assert summary.received == 3
    assert summary.ingested == 2
    assert summary.errors == 1
    assert len(summary.error_details) == 1
    assert "Mapping error" in summary.error_details[0].error


# ── 5. API Route Integration Tests ───────────────────────────────────────────

def test_wazuh_routes_unauthenticated_rejected(unauth_client):
    """All /api/v1/wazuh/* routes must reject unauthenticated requests with 401."""
    assert unauth_client.get("/api/v1/wazuh/health").status_code == 401
    assert unauth_client.get("/api/v1/wazuh/agents").status_code == 401
    assert unauth_client.get("/api/v1/wazuh/alerts").status_code == 401
    assert unauth_client.post("/api/v1/wazuh/events", json={"id": "test"}).status_code == 401


def test_wazuh_health_route(auth_client):
    with patch("app.wazuh.routes.wazuh_service.health", return_value={"status": "ok", "service": "wazuh-api"}):
        resp = auth_client.get("/api/v1/wazuh/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    with patch("app.wazuh.routes.wazuh_service.health", side_effect=WazuhConnectionError("Unavailable")):
        resp_err = auth_client.get("/api/v1/wazuh/health")
        assert resp_err.status_code == 503


def test_wazuh_agents_route(auth_client):
    with patch("app.wazuh.routes.wazuh_service.get_agents", return_value={"data": {"total": 5}}):
        resp = auth_client.get("/api/v1/wazuh/agents")
        assert resp.status_code == 200
        assert resp.json()["data"]["total"] == 5

    with patch("app.wazuh.routes.wazuh_service.get_agents", side_effect=WazuhConnectionError("Timeout")):
        resp_err = auth_client.get("/api/v1/wazuh/agents")
        assert resp_err.status_code == 502


def test_wazuh_events_ingest_route(auth_client, clean_db):
    event_payload = {
        "id": "route-event-101",
        "timestamp": "2026-09-25T15:00:00+00:00",
        "rule": {"id": "1002", "level": 8, "description": "Port scan detected"},
        "agent": {"id": "001", "name": "firewall-gw"},
    }

    resp = auth_client.post("/api/v1/wazuh/events", json=event_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["received"] == 1
    assert data["ingested"] == 1
    assert data["duplicates"] == 0
    assert data["errors"] == 0
