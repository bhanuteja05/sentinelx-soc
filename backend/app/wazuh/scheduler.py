"""
backend/app/wazuh/scheduler.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Background alert ingestion scheduler for periodic Wazuh Indexer polling.

Automates polling and ingestion of security alerts from the Wazuh Indexer
into PostgreSQL without requiring manual operator intervention.
"""

import asyncio
from collections.abc import Callable
from datetime import datetime, timezone
import logging
import os
import threading
import time

from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.wazuh.config import WazuhSettings, get_wazuh_settings
from app.wazuh.schemas import WazuhIngestSummary, WazuhSchedulerResult, WazuhSchedulerStatus
from app.wazuh.service import WazuhService, wazuh_service

logger = logging.getLogger(__name__)


class WazuhIngestionScheduler:
    """Background task orchestrator for periodic Wazuh alert polling and ingestion."""

    def __init__(
        self,
        service: WazuhService | None = None,
        settings: WazuhSettings | None = None,
        session_factory: Callable[[], Session] | None = None,
    ) -> None:
        self.service = service or wazuh_service
        self.settings = settings or get_wazuh_settings()
        self.session_factory = session_factory or SessionLocal

        # Concurrency protection
        self._cycle_lock = threading.Lock()

        # Lifecycle state
        self._task: asyncio.Task[None] | None = None
        self.is_active: bool = False

        # Telemetry & metrics
        self.last_run_at: datetime | None = None
        self.last_success_at: datetime | None = None
        self.last_failure_at: datetime | None = None
        self.last_error: str | None = None
        self.last_result: WazuhSchedulerResult | None = None
        self.total_cycles: int = 0
        self.successful_cycles: int = 0
        self.failed_cycles: int = 0
        self.skipped_cycles: int = 0

    @property
    def enabled(self) -> bool:
        return self.settings.ingest_enabled

    @property
    def interval_seconds(self) -> float:
        return self.settings.ingest_interval_seconds

    @property
    def batch_size(self) -> int:
        return self.settings.ingest_batch_size

    @property
    def is_running(self) -> bool:
        """True if an ingestion cycle is currently executing."""
        return self._cycle_lock.locked()

    def run_cycle(self) -> WazuhIngestSummary | None:
        """Execute a single ingestion cycle with concurrency protection and failure isolation."""
        if getattr(self, "is_default_singleton", False) and os.path.exists("/tmp/.sentinelx_test_running"):
            self.skipped_cycles += 1
            logger.info("Wazuh ingestion cycle skipped: test execution in progress.")
            return None

        acquired = self._cycle_lock.acquire(blocking=False)
        if not acquired:
            self.skipped_cycles += 1
            logger.info("Wazuh ingestion cycle skipped: previous cycle still executing.")
            return None

        start_time = time.monotonic()
        self.last_run_at = datetime.now(timezone.utc)
        self.total_cycles += 1
        logger.info(
            "Wazuh ingestion cycle started: batch_size=%d.",
            self.batch_size,
        )

        try:
            with self.session_factory() as db:
                summary = self.service.pull_and_ingest(db, limit=self.batch_size)

            duration = time.monotonic() - start_time
            self.last_success_at = datetime.now(timezone.utc)
            self.last_error = None
            self.successful_cycles += 1
            self.last_result = WazuhSchedulerResult(
                received=summary.received,
                ingested=summary.ingested,
                duplicates=summary.duplicates,
                errors=summary.errors,
                duration_seconds=round(duration, 3),
            )
            logger.info(
                "Wazuh ingestion cycle completed: batch_size=%d fetched=%d ingested=%d duplicates=%d errors=%d duration=%.3fs.",
                self.batch_size,
                summary.received,
                summary.ingested,
                summary.duplicates,
                summary.errors,
                duration,
            )
            return summary
        except Exception as exc:
            duration = time.monotonic() - start_time
            self.last_failure_at = datetime.now(timezone.utc)
            self.failed_cycles += 1
            err_msg = self.settings.redact(f"{type(exc).__name__}: {exc}")
            self.last_error = err_msg
            logger.error(
                "Wazuh ingestion cycle failed (duration=%.3fs): %s",
                duration,
                err_msg,
            )
            return None
        finally:
            self._cycle_lock.release()

    async def _worker_loop(self) -> None:
        """Continuous background loop running ingestion cycles at the configured interval."""
        logger.info(
            "Wazuh background ingestion worker started (interval=%.1fs, batch_size=%d).",
            self.interval_seconds,
            self.batch_size,
        )
        while self.is_active:
            try:
                await asyncio.to_thread(self.run_cycle)
            except Exception as exc:
                logger.error("Unexpected error in ingestion worker loop (%s): %s", type(exc).__name__, exc)

            try:
                await asyncio.sleep(self.interval_seconds)
            except asyncio.CancelledError:
                logger.info("Wazuh background ingestion worker sleep cancelled.")
                break

        logger.info("Wazuh background ingestion worker stopped.")

    async def start(self) -> None:
        """Start the background worker if enabled and not already running."""
        if not self.enabled:
            logger.info("Wazuh background ingestion is disabled (WAZUH_INGEST_ENABLED=false).")
            return

        if self.is_active:
            logger.warning("Wazuh background ingestion worker is already active.")
            return

        self.is_active = True
        self._task = asyncio.create_task(self._worker_loop())
        logger.info("Wazuh background ingestion worker task created.")

    async def stop(self) -> None:
        """Cleanly cancel and await the background worker task."""
        if not self.is_active and not self._task:
            return

        logger.info("Stopping Wazuh background ingestion worker...")
        self.is_active = False

        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                logger.error("Error while awaiting worker task cancellation (%s): %s", type(exc).__name__, exc)

        self._task = None
        logger.info("Wazuh background ingestion worker shutdown complete.")

    def get_status(self) -> WazuhSchedulerStatus:
        """Return a structured telemetry snapshot of the scheduler."""
        return WazuhSchedulerStatus(
            enabled=self.enabled,
            running=self.is_running,
            is_active=self.is_active,
            interval_seconds=self.interval_seconds,
            batch_size=self.batch_size,
            last_run_at=self.last_run_at,
            last_success_at=self.last_success_at,
            last_failure_at=self.last_failure_at,
            last_error=self.last_error,
            last_result=self.last_result,
            total_cycles=self.total_cycles,
            successful_cycles=self.successful_cycles,
            failed_cycles=self.failed_cycles,
            skipped_cycles=self.skipped_cycles,
        )

    def reset(self) -> None:
        """Reset internal metrics (primarily for test isolation)."""
        self.last_run_at = None
        self.last_success_at = None
        self.last_failure_at = None
        self.last_error = None
        self.last_result = None
        self.total_cycles = 0
        self.successful_cycles = 0
        self.failed_cycles = 0
        self.skipped_cycles = 0


wazuh_scheduler = WazuhIngestionScheduler()
wazuh_scheduler.is_default_singleton = True
