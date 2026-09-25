"""
backend/app/wazuh/routes.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~
FastAPI routing layer for Wazuh manager proxy and SIEM event ingestion endpoints.
"""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db import get_db
from app.wazuh.client import (
    WazuhAuthError,
    WazuhClientError,
    WazuhConnectionError,
    WazuhIndexerError,
)
from app.wazuh.schemas import WazuhAlertsResponse, WazuhIngestSummary
from app.wazuh.service import wazuh_service

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/wazuh",
    tags=["Wazuh"],
)


@router.get("/health")
def wazuh_health() -> dict[str, str]:
    """Check connectivity and authentication against the Wazuh Manager API."""
    try:
        return wazuh_service.health()
    except (WazuhAuthError, WazuhConnectionError, WazuhClientError) as exc:
        logger.error("Wazuh API health check failed: %s", exc)
        raise HTTPException(
            status_code=503,
            detail="Wazuh API unreachable",
        ) from None
    except Exception as exc:
        logger.error("Unexpected error during Wazuh health check (%s): %s", type(exc).__name__, exc)
        raise HTTPException(
            status_code=503,
            detail="Wazuh API unreachable",
        ) from None


@router.get("/agents")
def wazuh_agents() -> dict[str, Any]:
    """Retrieve registered endpoint agents from the Wazuh Manager."""
    try:
        return wazuh_service.get_agents()
    except (WazuhAuthError, WazuhConnectionError, WazuhClientError) as exc:
        logger.error("Wazuh agents request failed: %s", exc)
        raise HTTPException(
            status_code=502,
            detail="Failed to retrieve Wazuh agents",
        ) from None
    except Exception as exc:
        logger.error("Unexpected error during Wazuh agents query (%s): %s", type(exc).__name__, exc)
        raise HTTPException(
            status_code=502,
            detail="Failed to retrieve Wazuh agents",
        ) from None


@router.get("/alerts", response_model=WazuhAlertsResponse)
def wazuh_alerts(
    limit: int = Query(default=20, ge=1, le=100),
) -> WazuhAlertsResponse:
    """Query live alerts directly from the Wazuh Indexer OpenSearch index."""
    try:
        return wazuh_service.get_alerts(limit=limit)
    except (WazuhIndexerError, WazuhConnectionError, WazuhClientError) as exc:
        logger.error("Wazuh alerts query failed: %s", exc)
        raise HTTPException(
            status_code=502,
            detail="Failed to retrieve Wazuh alerts",
        ) from None
    except Exception as exc:
        logger.error("Unexpected error during Wazuh alerts query (%s): %s", type(exc).__name__, exc)
        raise HTTPException(
            status_code=502,
            detail="Failed to retrieve Wazuh alerts",
        ) from None


@router.post("/events", response_model=WazuhIngestSummary)
def wazuh_ingest_event(
    payload: dict[str, Any] | list[dict[str, Any]],
    db: Session = Depends(get_db),
) -> WazuhIngestSummary:
    """Internal alert ingestion boundary for receiving push events/webhooks from Wazuh.

    Supports single event JSON, Wazuh integrator wrapper ({"alert": {...}}), or batch array.
    Normalizes, validates, and persists events to PostgreSQL with automatic deduplication.
    """
    try:
        return wazuh_service.ingest_event(db, payload)
    except Exception as exc:
        logger.error("Event ingestion boundary failed (%s): %s", type(exc).__name__, exc)
        raise HTTPException(
            status_code=400,
            detail="Failed to process Wazuh event payload",
        ) from None
