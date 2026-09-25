"""
backend/app/api/dashboard.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SOC Dashboard and Investigation Analytics API.

GET /api/v1/dashboard/summary
    Return comprehensive, live PostgreSQL-backed analytics:
    - Alert metrics (total, 24h, 7d, severity, association status)
    - Case metrics (total, open, severity, status)
    - Time-series analytics (24h hourly and 7d daily buckets, zero-filled)
    - MITRE ATT&CK technique and tactic distributions
    - IOC analytics derived from alert data
    - Recent feeds (alerts, cases, case notes)
"""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db import get_db
from app.services.dashboard import get_dashboard_summary

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/dashboard",
    tags=["Dashboard"],
)

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class TimeSeriesBucket(BaseModel):
    timestamp: str
    label: str
    count: int


class DaySeriesBucket(BaseModel):
    date: str
    label: str
    count: int


class MITRETechniqueSummary(BaseModel):
    technique_id: str
    count: int


class MITRETacticSummary(BaseModel):
    tactic: str
    count: int


class MITREAnalytics(BaseModel):
    top_techniques: list[MITRETechniqueSummary] = Field(default_factory=list)
    top_tactics: list[MITRETacticSummary] = Field(default_factory=list)


class IOCSummary(BaseModel):
    source: str = "derived_from_alerts"
    analyzed_alert_count: int
    total_indicators: int
    by_type: dict[str, int] = Field(default_factory=dict)
    samples: dict[str, list[str]] = Field(default_factory=dict)


class RecentAlertSummary(BaseModel):
    id: int
    wazuh_alert_id: str
    timestamp: str
    agent_id: str | None = None
    agent_name: str | None = None
    rule_id: str
    rule_level: int | None = None
    description: str | None = None
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)


class RecentCaseSummary(BaseModel):
    id: int
    title: str
    status: str
    severity: str
    alert_count: int = 0
    created_at: str


class RecentActivitySummary(BaseModel):
    id: int
    case_id: int
    case_title: str
    author_username: str
    content: str
    created_at: str


class AlertMetrics(BaseModel):
    total: int
    last_24h: int
    last_7d: int
    by_severity: dict[str, int]
    by_status: dict[str, int]


class CaseMetrics(BaseModel):
    total: int
    open: int
    by_severity: dict[str, int]
    by_status: dict[str, int]


class DashboardSummaryOut(BaseModel):
    generated_at: str
    alerts: AlertMetrics
    cases: CaseMetrics
    time_series_24h: list[TimeSeriesBucket]
    time_series_7d: list[DaySeriesBucket]
    mitre: MITREAnalytics
    iocs: IOCSummary
    recent_alerts: list[RecentAlertSummary]
    recent_cases: list[RecentCaseSummary]
    recent_activity: list[RecentActivitySummary]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/summary", response_model=DashboardSummaryOut, status_code=status.HTTP_200_OK)
def get_dashboard_summary_endpoint(
    db: Session = Depends(get_db),
) -> DashboardSummaryOut:
    """Retrieve full SOC dashboard metrics and analytics summary."""
    try:
        data = get_dashboard_summary(db=db)
        return DashboardSummaryOut(**data)
    except Exception as exc:
        logger.error("Failed to generate dashboard summary (%s): %s", type(exc).__name__, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate dashboard summary.",
        ) from None
