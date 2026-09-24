import logging

from fastapi import APIRouter, HTTPException, Query

from app.wazuh.client import wazuh_client
from app.wazuh.schemas import WazuhAlertsResponse

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/wazuh",
    tags=["Wazuh"],
)


@router.get("/health")
def wazuh_health() -> dict:
    try:
        return wazuh_client.health()
    except Exception as exc:
        logger.error("Wazuh API health check failed (%s)", type(exc).__name__)
        raise HTTPException(
            status_code=503,
            detail="Wazuh API unreachable",
        ) from None


@router.get("/agents")
def wazuh_agents() -> dict:
    try:
        return wazuh_client.get_agents()
    except Exception as exc:
        logger.error("Wazuh agents request failed (%s)", type(exc).__name__)
        raise HTTPException(
            status_code=502,
            detail="Failed to retrieve Wazuh agents",
        ) from None


@router.get("/alerts", response_model=WazuhAlertsResponse)
def wazuh_alerts(
    limit: int = Query(default=20, ge=1, le=100),
) -> WazuhAlertsResponse:
    try:
        return wazuh_client.get_alerts(limit=limit)
    except Exception as exc:
        logger.error("Wazuh alerts request failed (%s)", type(exc).__name__)
        raise HTTPException(
            status_code=502,
            detail="Failed to retrieve Wazuh alerts",
        ) from None
