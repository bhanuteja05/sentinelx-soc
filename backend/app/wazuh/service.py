"""
backend/app/wazuh/service.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Wazuh service orchestrating client interactions, normalization, and alert persistence.
Separates SIEM integration business logic from FastAPI presentation routes.
"""

import logging
from typing import Any

from sqlalchemy.orm import Session

from app.services.alert import ingest_alert
from app.wazuh.client import WazuhClient, wazuh_client
from app.wazuh.ingestion import AlertMappingError, wazuh_alert_to_dict
from app.wazuh.schemas import (
    WazuhAlertsResponse,
    WazuhIngestError,
    WazuhIngestSummary,
    normalize_raw_event,
)

logger = logging.getLogger(__name__)


class WazuhService:
    """Service layer coordinating Wazuh SIEM connectivity, querying, and alert ingestion."""

    def __init__(self, client: WazuhClient | None = None) -> None:
        self.client = client or wazuh_client

    def health(self) -> dict[str, str]:
        """Verify Wazuh Manager API health and authentication reachability."""
        return self.client.health()

    def get_agents(self) -> dict[str, Any]:
        """Retrieve Wazuh agents registered on the manager."""
        return self.client.get_agents()

    def get_alerts(self, limit: int = 20) -> WazuhAlertsResponse:
        """Query security alerts directly from Wazuh Indexer."""
        return self.client.get_alerts(limit=limit)

    def ingest_event(
        self,
        db: Session,
        event_payload: dict[str, Any] | list[dict[str, Any]],
    ) -> WazuhIngestSummary:
        """Internal alert ingestion boundary for push events (webhooks, event forwarding).

        Accepts a single raw Wazuh event, an OpenSearch hit, or a batch of events.
        Normalizes and persists each alert independently; one bad event does not abort the batch.
        """
        raw_events: list[dict[str, Any]]
        if isinstance(event_payload, list):
            raw_events = event_payload
        elif isinstance(event_payload, dict):
            # Check if wrapped in a batch container like {"events": [...]}
            if "events" in event_payload and isinstance(event_payload["events"], list):
                raw_events = event_payload["events"]
            else:
                raw_events = [event_payload]
        else:
            return WazuhIngestSummary(
                status="error",
                received=0,
                errors=1,
                error_details=[WazuhIngestError(event_id=None, error="Invalid payload format: must be JSON object or array")],
            )

        received = len(raw_events)
        ingested = 0
        duplicates = 0
        errors = 0
        error_details: list[WazuhIngestError] = []

        for item in raw_events:
            event_id = None
            if isinstance(item, dict):
                event_id = str(item.get("id") or item.get("_id") or "") or None

            try:
                wazuh_alert = normalize_raw_event(item)
                event_id = event_id or wazuh_alert.id
                alert_dict = wazuh_alert_to_dict(wazuh_alert)
                _persisted, is_new = ingest_alert(db, alert_dict)
                if is_new:
                    ingested += 1
                else:
                    duplicates += 1
            except AlertMappingError as exc:
                errors += 1
                error_details.append(WazuhIngestError(event_id=event_id, error=f"Mapping error: {exc}"))
                logger.warning("Event mapping failed for id=%r: %s", event_id, exc)
            except Exception as exc:
                errors += 1
                error_details.append(
                    WazuhIngestError(event_id=event_id, error=f"Ingestion error ({type(exc).__name__}): {exc}")
                )
                logger.error("Event ingestion failed for id=%r: %s", event_id, exc)

        return WazuhIngestSummary(
            status="ok",
            received=received,
            ingested=ingested,
            duplicates=duplicates,
            errors=errors,
            error_details=error_details,
        )

    def pull_and_ingest(self, db: Session, limit: int = 100) -> WazuhIngestSummary:
        """Fetch latest alerts from the Wazuh Indexer and persist new ones into PostgreSQL."""
        response = self.get_alerts(limit=limit)
        wazuh_alerts = response.alerts
        received = len(wazuh_alerts)

        ingested = 0
        duplicates = 0
        errors = 0
        error_details: list[WazuhIngestError] = []

        for wazuh_alert in wazuh_alerts:
            event_id = wazuh_alert.id
            try:
                alert_dict = wazuh_alert_to_dict(wazuh_alert)
                _persisted, is_new = ingest_alert(db, alert_dict)
                if is_new:
                    ingested += 1
                else:
                    duplicates += 1
            except AlertMappingError as exc:
                errors += 1
                error_details.append(WazuhIngestError(event_id=event_id, error=f"Mapping error: {exc}"))
            except Exception as exc:
                errors += 1
                error_details.append(
                    WazuhIngestError(event_id=event_id, error=f"Persistence error ({type(exc).__name__})")
                )

        return WazuhIngestSummary(
            status="ok",
            received=received,
            ingested=ingested,
            duplicates=duplicates,
            errors=errors,
            error_details=error_details,
        )


wazuh_service = WazuhService(client=wazuh_client)
