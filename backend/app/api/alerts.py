"""
app/api/alerts.py
~~~~~~~~~~~~~~~~~
Persisted alert endpoints.

POST /api/v1/alerts/ingest
    On-demand ingestion: fetch latest N Wazuh alerts, normalize, and
    persist to PostgreSQL via the existing idempotent ingest_alert()
    service.  One malformed or error alert does not abort the batch.

GET  /api/v1/alerts
    Query paginated persisted alerts from PostgreSQL with filtering and sorting.

GET  /api/v1/alerts/count
    Return the total number of persisted alerts.

GET  /api/v1/alerts/wazuh/{wazuh_alert_id}
    Retrieve full investigation details of an alert by Wazuh alert ID.

GET  /api/v1/alerts/{alert_id}
    Retrieve full investigation details of an alert by database ID.
"""

from datetime import datetime
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db import get_db
from app.services.alert import (
    get_alert,
    get_alert_by_external_id,
    get_alert_count,
    ingest_alert,
    search_alerts_service,
)
from app.wazuh.client import wazuh_client
from app.wazuh.ingestion import AlertMappingError, wazuh_alert_to_dict

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/alerts",
    tags=["Alerts"],
)

# ---------------------------------------------------------------------------
# Constants & Allowlist
# ---------------------------------------------------------------------------

_MAX_INGEST_LIMIT = 500
_DEFAULT_INGEST_LIMIT = 100
ALLOWED_SORT_FIELDS: set[str] = {"timestamp", "rule_level", "id", "rule_id", "created_at"}

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
    """Persisted alert summary returned by list endpoints (excludes raw_alert)."""

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


class AlertDetailOut(AlertOut):
    """Full forensic alert representation returned by single-alert endpoints."""

    created_at: str
    raw_alert: dict[str, Any]


class PaginatedAlertsResponse(BaseModel):
    """Paginated envelope for alert list queries."""

    items: list[AlertOut]
    total: int
    page: int
    page_size: int
    pages: int


class AlertCountResponse(BaseModel):
    count: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


def _alert_to_detail_out(alert) -> AlertDetailOut:
    """Convert an Alert ORM object to the AlertDetailOut schema with full raw_alert."""
    return AlertDetailOut(
        id=alert.id,
        wazuh_alert_id=alert.wazuh_alert_id,
        timestamp=alert.timestamp.isoformat(),
        created_at=alert.created_at.isoformat(),
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
        raw_alert=alert.raw_alert or {},
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


@router.get("", response_model=PaginatedAlertsResponse)
def list_alerts(
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(default=25, ge=1, le=100, description="Items per page"),
    sort_by: str = Query(default="timestamp", description="Sort field allowlist"),
    sort_order: str = Query(default="desc", pattern="^(?i)(asc|desc)$", description="Sort direction"),
    rule_level: int | None = Query(default=None, ge=0, le=16, description="Exact rule level"),
    min_rule_level: int | None = Query(default=None, ge=0, le=16, description="Minimum rule level"),
    max_rule_level: int | None = Query(default=None, ge=0, le=16, description="Maximum rule level"),
    agent_id: str | None = Query(default=None, max_length=64, description="Agent ID"),
    agent_name: str | None = Query(default=None, max_length=128, description="Agent name"),
    rule_id: str | None = Query(default=None, max_length=64, description="Rule ID"),
    mitre_tactic: str | None = Query(default=None, max_length=128, description="MITRE tactic"),
    mitre_technique: str | None = Query(default=None, max_length=128, description="MITRE technique"),
    start_time: datetime | None = Query(default=None, description="Start timestamp (ISO 8601)"),
    end_time: datetime | None = Query(default=None, description="End timestamp (ISO 8601)"),
    db: Session = Depends(get_db),
) -> PaginatedAlertsResponse:
    """Query paginated persisted alerts with multi-field filtering and sorting."""
    # 1. Sort allowlist validation
    if sort_by.lower() not in ALLOWED_SORT_FIELDS:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid sort_by field '{sort_by}'. Allowed fields: {sorted(ALLOWED_SORT_FIELDS)}",
        )

    # 2. Cross-field validations
    if start_time and end_time and start_time > end_time:
        raise HTTPException(
            status_code=400,
            detail="start_time must be before or equal to end_time",
        )

    if rule_level is not None and (min_rule_level is not None or max_rule_level is not None):
        raise HTTPException(
            status_code=400,
            detail="Cannot combine rule_level with min_rule_level or max_rule_level",
        )

    if min_rule_level is not None and max_rule_level is not None and min_rule_level > max_rule_level:
        raise HTTPException(
            status_code=400,
            detail="min_rule_level cannot be greater than max_rule_level",
        )

    # 3. Service call
    try:
        result = search_alerts_service(
            db=db,
            page=page,
            page_size=page_size,
            sort_by=sort_by.lower(),
            sort_order=sort_order.lower(),
            rule_level=rule_level,
            min_rule_level=min_rule_level,
            max_rule_level=max_rule_level,
            agent_id=agent_id,
            agent_name=agent_name,
            rule_id=rule_id,
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
            start_time=start_time,
            end_time=end_time,
        )
    except Exception as exc:
        logger.error("Alert search query failed (%s): %s", type(exc).__name__, str(exc)[:200])
        raise HTTPException(
            status_code=500,
            detail="Failed to query alerts from database",
        ) from None

    return PaginatedAlertsResponse(
        items=[_alert_to_out(a) for a in result["items"]],
        total=result["total"],
        page=result["page"],
        page_size=result["page_size"],
        pages=result["pages"],
    )


@router.get("/wazuh/{wazuh_alert_id}", response_model=AlertDetailOut)
def get_alert_by_wazuh_id_endpoint(
    wazuh_alert_id: str,
    db: Session = Depends(get_db),
) -> AlertDetailOut:
    """Return a single persisted alert by its external Wazuh alert ID."""
    alert = get_alert_by_external_id(db, wazuh_alert_id)
    if alert is None:
        raise HTTPException(
            status_code=404,
            detail=f"Alert with Wazuh ID '{wazuh_alert_id}' not found.",
        )
    return _alert_to_detail_out(alert)


@router.get("/{alert_id}", response_model=AlertDetailOut)
def get_alert_by_id_endpoint(
    alert_id: int,
    db: Session = Depends(get_db),
) -> AlertDetailOut:
    """Return a single persisted alert by its PostgreSQL primary key."""
    alert = get_alert(db, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")
    return _alert_to_detail_out(alert)
