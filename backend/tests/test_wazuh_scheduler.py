"""
backend/tests/test_wazuh_scheduler.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Tests for the background Wazuh alert ingestion scheduler.

Verifies:
  1. Configuration parsing and validation
  2. Scheduler start when enabled
  3. Scheduler start skipped when disabled
  4. Correct interval and batch size passed to pull_and_ingest
  5. Concurrency protection (second cycle skipped while first runs)
  6. Wazuh failure isolation (does not crash or stop scheduler)
  7. Unexpected exception isolation (does not crash or stop scheduler)
  8. Clean shutdown and task cancellation
  9. Telemetry & status snapshot updates correctly
  10. Endpoint GET /api/v1/wazuh/ingestion/status auth enforcement and response
"""

import asyncio
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
import pytest

from app.api.deps import get_current_active_user
from app.db import get_db
from app.main import app
from app.models.user import User
from app.wazuh.client import WazuhConnectionError, WazuhIndexerError
from app.wazuh.config import WazuhSettings, get_wazuh_settings
from app.wazuh.scheduler import WazuhIngestionScheduler, wazuh_scheduler
from app.wazuh.schemas import WazuhIngestSummary, WazuhSchedulerStatus


@pytest.fixture
def mock_user():
    return User(
        id=1,
        username="admin",
        email="admin@sentinelx.local",
        password_hash="fakehash",
        role="admin",
        is_active=True,
    )


@pytest.fixture
def custom_settings():
    return WazuhSettings(
        api_url="https://wazuh.manager:55000",
        api_user="wazuh-wui",
        api_password="secretpassword",
        indexer_url="https://wazuh.indexer:9200",
        indexer_username="admin",
        indexer_password="indexersecret",
        timeout=5.0,
        verify_ssl=False,
        ingest_enabled=True,
        ingest_interval_seconds=0.05,
        ingest_batch_size=25,
    )


# ===========================================================================
# 1. Configuration tests
# ===========================================================================


def test_scheduler_config_defaults(monkeypatch):
    monkeypatch.delenv("WAZUH_INGEST_ENABLED", raising=False)
    monkeypatch.delenv("WAZUH_INGEST_INTERVAL_SECONDS", raising=False)
    monkeypatch.delenv("WAZUH_INGEST_BATCH_SIZE", raising=False)

    settings = get_wazuh_settings()
    assert settings.ingest_enabled is True
    assert settings.ingest_interval_seconds == 30.0
    assert settings.ingest_batch_size == 50


def test_scheduler_config_env_overrides(monkeypatch):
    monkeypatch.setenv("WAZUH_INGEST_ENABLED", "false")
    monkeypatch.setenv("WAZUH_INGEST_INTERVAL_SECONDS", "15.5")
    monkeypatch.setenv("WAZUH_INGEST_BATCH_SIZE", "100")

    settings = get_wazuh_settings()
    assert settings.ingest_enabled is False
    assert settings.ingest_interval_seconds == 15.5
    assert settings.ingest_batch_size == 100


def test_scheduler_config_clamps_invalid_values(monkeypatch):
    monkeypatch.setenv("WAZUH_INGEST_INTERVAL_SECONDS", "-10")
    monkeypatch.setenv("WAZUH_INGEST_BATCH_SIZE", "9999")

    settings = get_wazuh_settings()
    # Interval clamped to minimum 1.0s
    assert settings.ingest_interval_seconds == 1.0
    # Batch size clamped to maximum 500
    assert settings.ingest_batch_size == 500


# ===========================================================================
# 2. Scheduler lifecycle tests
# ===========================================================================


@pytest.mark.anyio
async def test_scheduler_starts_when_enabled(custom_settings):
    mock_service = MagicMock()
    mock_session = MagicMock()
    scheduler = WazuhIngestionScheduler(
        service=mock_service,
        settings=custom_settings,
        session_factory=lambda: mock_session,
    )

    await scheduler.start()
    assert scheduler.is_active is True
    assert scheduler._task is not None
    assert not scheduler._task.done()

    await scheduler.stop()
    assert scheduler.is_active is False
    assert scheduler._task is None


@pytest.mark.anyio
async def test_scheduler_does_not_start_when_disabled():
    disabled_settings = WazuhSettings(
        api_url="https://wazuh.manager:55000",
        api_user="wazuh-wui",
        api_password="pwd",
        indexer_url="https://wazuh.indexer:9200",
        indexer_username="admin",
        indexer_password="pwd",
        ingest_enabled=False,
    )
    mock_service = MagicMock()
    scheduler = WazuhIngestionScheduler(
        service=mock_service,
        settings=disabled_settings,
    )

    await scheduler.start()
    assert scheduler.is_active is False
    assert scheduler._task is None


@pytest.mark.anyio
async def test_scheduler_clean_shutdown(custom_settings):
    mock_service = MagicMock()
    mock_service.pull_and_ingest.return_value = WazuhIngestSummary(received=0)
    mock_session = MagicMock()

    scheduler = WazuhIngestionScheduler(
        service=mock_service,
        settings=custom_settings,
        session_factory=lambda: mock_session,
    )

    await scheduler.start()
    # Let it run briefly
    await asyncio.sleep(0.08)
    await scheduler.stop()

    assert scheduler.is_active is False
    assert scheduler._task is None


# ===========================================================================
# 3. Execution & Telemetry tests
# ===========================================================================


def test_scheduler_run_cycle_success(custom_settings):
    mock_service = MagicMock()
    mock_summary = WazuhIngestSummary(
        status="ok",
        received=10,
        ingested=8,
        duplicates=2,
        errors=0,
    )
    mock_service.pull_and_ingest.return_value = mock_summary

    mock_db = MagicMock()
    mock_session_ctx = MagicMock()
    mock_session_ctx.__enter__.return_value = mock_db

    scheduler = WazuhIngestionScheduler(
        service=mock_service,
        settings=custom_settings,
        session_factory=lambda: mock_session_ctx,
    )

    result = scheduler.run_cycle()

    assert result == mock_summary
    mock_service.pull_and_ingest.assert_called_once_with(mock_db, limit=25)

    status = scheduler.get_status()
    assert status.total_cycles == 1
    assert status.successful_cycles == 1
    assert status.failed_cycles == 0
    assert status.skipped_cycles == 0
    assert status.last_run_at is not None
    assert status.last_success_at is not None
    assert status.last_failure_at is None
    assert status.last_error is None
    assert status.last_result is not None
    assert status.last_result.received == 10
    assert status.last_result.ingested == 8
    assert status.last_result.duplicates == 2


def test_scheduler_concurrency_lock_skips_overlapping_cycle(custom_settings):
    mock_service = MagicMock()
    mock_summary = WazuhIngestSummary(received=5, ingested=5)
    mock_service.pull_and_ingest.return_value = mock_summary

    mock_session_ctx = MagicMock()
    scheduler = WazuhIngestionScheduler(
        service=mock_service,
        settings=custom_settings,
        session_factory=lambda: mock_session_ctx,
    )

    # Acquire lock manually to simulate an active cycle
    scheduler._cycle_lock.acquire(blocking=False)
    assert scheduler.is_running is True

    # Attempt to run a cycle while lock is held
    second_result = scheduler.run_cycle()

    assert second_result is None
    assert scheduler.skipped_cycles == 1
    # pull_and_ingest was NOT called for the overlapping attempt
    mock_service.pull_and_ingest.assert_not_called()

    # Release lock
    scheduler._cycle_lock.release()
    assert scheduler.is_running is False


def test_scheduler_wazuh_failure_isolated(custom_settings):
    mock_service = MagicMock()
    mock_service.pull_and_ingest.side_effect = WazuhConnectionError(
        "Failed to connect to indexer with secretpassword"
    )

    mock_session_ctx = MagicMock()
    scheduler = WazuhIngestionScheduler(
        service=mock_service,
        settings=custom_settings,
        session_factory=lambda: mock_session_ctx,
    )

    result = scheduler.run_cycle()

    # Failure returned None, did not raise exception
    assert result is None
    status = scheduler.get_status()
    assert status.total_cycles == 1
    assert status.successful_cycles == 0
    assert status.failed_cycles == 1
    assert status.last_failure_at is not None
    assert "WazuhConnectionError" in status.last_error
    # Secrets must be redacted from error message
    assert "secretpassword" not in status.last_error
    assert "***" in status.last_error


def test_scheduler_unexpected_exception_isolated(custom_settings):
    mock_service = MagicMock()
    mock_service.pull_and_ingest.side_effect = RuntimeError("Database connection pool exhausted")

    mock_session_ctx = MagicMock()
    scheduler = WazuhIngestionScheduler(
        service=mock_service,
        settings=custom_settings,
        session_factory=lambda: mock_session_ctx,
    )

    result = scheduler.run_cycle()

    assert result is None
    status = scheduler.get_status()
    assert status.total_cycles == 1
    assert status.failed_cycles == 1
    assert "RuntimeError" in status.last_error


# ===========================================================================
# 4. API endpoint tests
# ===========================================================================


def test_ingestion_status_unauthenticated(clean_db):
    app.dependency_overrides[get_db] = lambda: clean_db
    client = TestClient(app)
    resp = client.get("/api/v1/wazuh/ingestion/status")
    app.dependency_overrides.clear()

    assert resp.status_code == 401


def test_ingestion_status_authenticated(mock_user, clean_db):
    app.dependency_overrides[get_db] = lambda: clean_db
    app.dependency_overrides[get_current_active_user] = lambda: mock_user

    wazuh_scheduler.reset()

    client = TestClient(app)
    resp = client.get("/api/v1/wazuh/ingestion/status")
    app.dependency_overrides.clear()

    assert resp.status_code == 200
    data = resp.json()
    assert "enabled" in data
    assert "running" in data
    assert "is_active" in data
    assert "interval_seconds" in data
    assert "batch_size" in data
    assert "total_cycles" in data
    assert "successful_cycles" in data
    assert "failed_cycles" in data
    assert "skipped_cycles" in data
