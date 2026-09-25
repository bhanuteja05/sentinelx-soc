"""
app/api/alerts.py
~~~~~~~~~~~~~~~~~
Persisted alert endpoints.

POST /api/v1/alerts/ingest
    On-demand ingestion: fetch latest N Wazuh alerts, normalize, and
    persist to PostgreSQL via the existing idempotent ingest_alert()
    service.  One malformed or error alert does not abort the batch.

GET  /api/v1/alerts
    Query persisted alerts from PostgreSQL with optional filters.

GET  /api/v1/alerts/count
    Return the total number of persisted alerts.
"""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db import get_db
from app.services.alert import (
    get_alert,
    get_alert_count,
    get_recent_alerts,
    ingest_alert,
)
from app.wazuh.client import wazuh_client
from app.wazuh.ingestion import AlertMappingError, wazuh_alert_to_dict

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/alerts",
    tags=["Alerts"],
)

# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class AlertError(BaseModel):
    """Per-alert error detail returned in the ingest response."""

    wazuh_alert_id: str | None = None
    error: str


class IngestResponse(BaseModel):
    """Summary returned by POST /api/v1/alerts/ingest."""

    requested: int
    fetched: int
    ingested: int
    duplicates: int
    errors: int
    error_details: list[AlertError] = Field(default_factory=list)


class AlertOut(BaseModel):
    """Persisted alert representation returned by GET endpoints."""

    id: int
    wazuh_alert_id: str
    timestamp: str
    agent_id: str | None
    agent_name: str | None
    rule_id: str
    rule_level: int | None
    description: str | None
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    location: str | None
    decoder: str | None
    mitre_tactics: list[str]
    mitre_techniques: list[str]

    model_config = {"from_attributes": True}


class AlertCountResponse(BaseModel):
    count: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MAX_INGEST_LIMIT = 500
_DEFAULT_INGEST_LIMIT = 100


def _safe_alert_id(raw_id: Any) -> str | None:
    """Return a redaction-safe alert id string for error reporting."""
    if raw_id is None:
        return None
    s = str(raw_id).strip()
    return s[:64] if s else None


def _alert_to_out(alert) -> AlertOut:
    """Convert an Alert ORM object to the AlertOut schema."""
    return AlertOut(
        id=alert.id,
        wazuh_alert_id=alert.wazuh_alert_id,
        timestamp=alert.timestamp.isoformat(),
        agent_id=alert.agent_id,
        agent_name=alert.agent_name,
        rule_id=alert.rule_id,
        rule_level=alert.rule_level,
        description=alert.description,
        src_ip=alert.src_ip,
        dst_ip=alert.dst_ip,
        src_port=alert.src_port,
        dst_port=alert.dst_port,
        location=alert.location,
        decoder=alert.decoder,
        mitre_tactics=alert.mitre_tactics or [],
        mitre_techniques=alert.mitre_techniques or [],
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/ingest", response_model=IngestResponse, status_code=200)
def ingest_alerts(
    limit: int = Query(
        default=_DEFAULT_INGEST_LIMIT,
        ge=1,
        le=_MAX_INGEST_LIMIT,
        description="Number of latest Wazuh alerts to fetch and ingest.",
    ),
    db: Session = Depends(get_db),
) -> IngestResponse:
    """Fetch the latest `limit` Wazuh alerts and persist new ones to PostgreSQL.

    Each alert is processed independently — one malformed alert does not
    abort the remaining batch.  Returns a summary of ingested, duplicate,
    and error counts.

    Secrets (Wazuh credentials, DB connection strings) are never included
    in error detail fields.
    """
    # 1. Fetch from Wazuh Indexer
    try:
        response = wazuh_client.get_alerts(limit=limit)
    except Exception as exc:
        logger.error(
            "Wazuh alert fetch failed during ingestion (%s): %s",
            type(exc).__name__,
            str(exc)[:200],
        )
        raise HTTPException(
            status_code=502,
            detail="Failed to fetch alerts from Wazuh. Check Wazuh connectivity.",
        ) from None

    wazuh_alerts = response.alerts
    fetched = len(wazuh_alerts)

    ingested = 0
    duplicates = 0
    errors = 0
    error_details: list[AlertError] = []

    # 2. Normalize and persist each alert individually
    for wazuh_alert in wazuh_alerts:
        raw_id = _safe_alert_id(wazuh_alert.id)
        try:
            alert_dict = wazuh_alert_to_dict(wazuh_alert)
        except AlertMappingError as exc:
            errors += 1
            error_details.append(
                AlertError(
                    wazuh_alert_id=raw_id,
                    error=f"Mapping error: {exc}",
                )
            )
            logger.warning(
                "Alert mapping failed for id=%r: %s", raw_id, exc
            )
            continue

        try:
            _alert, is_new = ingest_alert(db, alert_dict)
            if is_new:
                ingested += 1
            else:
                duplicates += 1
        except Exception as exc:
            errors += 1
            error_details.append(
                AlertError(
                    wazuh_alert_id=raw_id,
                    # Deliberately terse — no DB URL, no credentials
                    error=f"Persistence error: {type(exc).__name__}",
                )
            )
            logger.error(
                "Alert persistence failed for id=%r (%s): %s",
                raw_id,
                type(exc).__name__,
                str(exc)[:300],
            )

    logger.info(
        "Ingest run complete: requested=%d fetched=%d ingested=%d "
        "duplicates=%d errors=%d",
        limit,
        fetched,
        ingested,
        duplicates,
        errors,
    )

    return IngestResponse(
        requested=limit,
        fetched=fetched,
        ingested=ingested,
        duplicates=duplicates,
        errors=errors,
        error_details=error_details,
    )


@router.get("/count", response_model=AlertCountResponse)
def alert_count(db: Session = Depends(get_db)) -> AlertCountResponse:
    """Return the total number of persisted alerts in PostgreSQL."""
    return AlertCountResponse(count=get_alert_count(db))


@router.get("", response_model=list[AlertOut])
def list_alerts(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    rule_id: str | None = Query(default=None),
    min_level: int | None = Query(default=None, ge=0),
    agent_id: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> list[AlertOut]:
    """Return recently persisted alerts from PostgreSQL, ordered by timestamp descending."""
    alerts = get_recent_alerts(
        db=db,
        skip=skip,
        limit=limit,
        rule_id=rule_id,
        min_level=min_level,
        agent_id=agent_id,
    )
    return [_alert_to_out(a) for a in alerts]


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert_by_id(alert_id: int, db: Session = Depends(get_db)) -> AlertOut:
    """Return a single persisted alert by its PostgreSQL primary key."""
    alert = get_alert(db, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")
    return _alert_to_out(alert)
