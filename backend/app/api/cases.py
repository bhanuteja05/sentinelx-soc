"""
app/api/cases.py
~~~~~~~~~~~~~~~~
Case management and incident investigation endpoints.

POST   /api/v1/cases                           Create a case (201)
GET    /api/v1/cases                           Paginated case listing
GET    /api/v1/cases/{case_id}                 Case investigation detail (includes alert summaries)
PATCH  /api/v1/cases/{case_id}                 Update case metadata, status, or severity
POST   /api/v1/cases/{case_id}/close           Close a case
POST   /api/v1/cases/{case_id}/alerts/{alert_id} Associate alert with case (idempotent)
DELETE /api/v1/cases/{case_id}/alerts/{alert_id} Detach alert from case (204, alert preserved)
GET    /api/v1/cases/{case_id}/alerts          Paginated alerts attached to case
"""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.alerts import AlertOut, PaginatedAlertsResponse, _alert_to_out
from app.api.deps import require_role
from app.db import get_db

from app.repositories.case import SORTABLE_CASE_FIELDS, count_case_alerts
from app.services.case import (
    VALID_SEVERITIES,
    VALID_STATUSES,
    AlertNotFoundError,
    AssociationNotFoundError,
    CaseNotFoundError,
    associate_alert_service,
    close_case as service_close_case,
    delete_case as service_delete_case,
    detach_alert_service,
    get_case_detail_service,
    list_case_alerts_service,
    open_case,
    search_cases_service,
    update_case as service_update_case,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/cases",
    tags=["Cases"],
)

ALLOWED_CASE_SORT_FIELDS: set[str] = set(SORTABLE_CASE_FIELDS.keys())

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CaseCreate(BaseModel):
    """Schema for creating a new Case."""

    title: str = Field(..., min_length=1, max_length=255, description="Case title")
    description: str | None = Field(default=None, description="Detailed case notes/investigation summary")
    severity: str = Field(default="medium", pattern="^(?i)(low|medium|high|critical)$", description="Case severity")
    status: str = Field(default="open", pattern="^(?i)(open|in_progress|escalated|resolved|closed)$", description="Case status")


class CaseUpdate(BaseModel):
    """Schema for partial update of a Case."""

    title: str | None = Field(default=None, min_length=1, max_length=255, description="Updated case title")
    description: str | None = Field(default=None, description="Updated notes")
    severity: str | None = Field(default=None, pattern="^(?i)(low|medium|high|critical)$", description="Updated severity")
    status: str | None = Field(default=None, pattern="^(?i)(open|in_progress|escalated|resolved|closed)$", description="Updated status")


class CaseOut(BaseModel):
    """Standard case representation."""

    id: int
    title: str
    description: str | None
    status: str
    severity: str
    created_at: str
    updated_at: str
    alert_count: int = 0

    model_config = {"from_attributes": True}


class CaseDetailOut(CaseOut):
    """Case investigation representation with associated alert summaries."""

    alerts: list[AlertOut] = Field(default_factory=list)


class PaginatedCasesResponse(BaseModel):
    """Paginated envelope for case listings."""

    items: list[CaseOut]
    total: int
    page: int
    page_size: int
    pages: int


class CaseAlertAssociationOut(BaseModel):
    """Result of an alert-case association."""

    case_id: int
    alert_id: int
    created_at: str
    is_new: bool


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _case_to_out(case, alert_count: int = 0) -> CaseOut:
    return CaseOut(
        id=case.id,
        title=case.title,
        description=case.description,
        status=case.status,
        severity=case.severity,
        created_at=case.created_at.isoformat(),
        updated_at=case.updated_at.isoformat(),
        alert_count=alert_count,
    )


def _case_to_detail_out(case, alert_count: int, alerts) -> CaseDetailOut:
    return CaseDetailOut(
        id=case.id,
        title=case.title,
        description=case.description,
        status=case.status,
        severity=case.severity,
        created_at=case.created_at.isoformat(),
        updated_at=case.updated_at.isoformat(),
        alert_count=alert_count,
        alerts=[_alert_to_out(a) for a in alerts],
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("", response_model=CaseOut, status_code=status.HTTP_201_CREATED)
def create_case_endpoint(
    payload: CaseCreate,
    db: Session = Depends(get_db),
) -> CaseOut:
    """Create a new investigation Case."""
    try:
        case = open_case(
            db=db,
            title=payload.title,
            description=payload.description,
            severity=payload.severity,
            status=payload.status,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        logger.error("Failed to create case (%s): %s", type(exc).__name__, str(exc)[:200])
        raise HTTPException(status_code=500, detail="Database failure creating case.") from None

    return _case_to_out(case, alert_count=0)


@router.get("", response_model=PaginatedCasesResponse)
def list_cases_endpoint(
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(default=25, ge=1, le=100, description="Items per page"),
    status: str | None = Query(default=None, description="Filter by status"),
    severity: str | None = Query(default=None, description="Filter by severity"),
    sort_by: str = Query(default="created_at", description="Field to sort by"),
    sort_order: str = Query(default="desc", pattern="^(?i)(asc|desc)$", description="Sort direction"),
    db: Session = Depends(get_db),
) -> PaginatedCasesResponse:
    """List paginated cases with filtering and sorting."""
    if sort_by.lower() not in ALLOWED_CASE_SORT_FIELDS:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid sort_by field '{sort_by}'. Allowed fields: {sorted(ALLOWED_CASE_SORT_FIELDS)}",
        )

    try:
        result = search_cases_service(
            db=db,
            page=page,
            page_size=page_size,
            status=status,
            severity=severity,
            sort_by=sort_by,
            sort_order=sort_order,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        logger.error("Failed to list cases (%s): %s", type(exc).__name__, str(exc)[:200])
        raise HTTPException(status_code=500, detail="Database failure querying cases.") from None

    items = [_case_to_out(c, alert_count=count_case_alerts(db, c.id)) for c in result["items"]]
    return PaginatedCasesResponse(
        items=items,
        total=result["total"],
        page=result["page"],
        page_size=result["page_size"],
        pages=result["pages"],
    )


@router.post("/{case_id}/close", response_model=CaseOut)
def close_case_endpoint(
    case_id: int,
    db: Session = Depends(get_db),
) -> CaseOut:
    """Close an existing Case."""
    case = service_close_case(db, case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found.")
    alert_count = count_case_alerts(db, case_id)
    return _case_to_out(case, alert_count=alert_count)


@router.post("/{case_id}/alerts/{alert_id}", response_model=CaseAlertAssociationOut)
def associate_alert_endpoint(
    case_id: int,
    alert_id: int,
    db: Session = Depends(get_db),
) -> CaseAlertAssociationOut:
    """Associate an alert with a case (idempotent)."""
    try:
        case_alert, is_new = associate_alert_service(db, case_id, alert_id)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except AlertNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.error("Failed to associate alert %d with case %d (%s): %s", alert_id, case_id, type(exc).__name__, str(exc)[:200])
        raise HTTPException(status_code=500, detail="Database failure associating alert with case.") from None

    return CaseAlertAssociationOut(
        case_id=case_alert.case_id,
        alert_id=case_alert.alert_id,
        created_at=case_alert.created_at.isoformat(),
        is_new=is_new,
    )


@router.delete("/{case_id}/alerts/{alert_id}", status_code=status.HTTP_204_NO_CONTENT)
def detach_alert_endpoint(
    case_id: int,
    alert_id: int,
    db: Session = Depends(get_db),
) -> None:
    """Detach an alert from a case without deleting the alert itself."""
    try:
        detach_alert_service(db, case_id, alert_id)
    except (CaseNotFoundError, AlertNotFoundError, AssociationNotFoundError) as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.error("Failed to detach alert %d from case %d (%s): %s", alert_id, case_id, type(exc).__name__, str(exc)[:200])
        raise HTTPException(status_code=500, detail="Database failure detaching alert from case.") from None


@router.get("/{case_id}/alerts", response_model=PaginatedAlertsResponse)
def list_case_alerts_endpoint(
    case_id: int,
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=25, ge=1, le=100, description="Items per page"),
    db: Session = Depends(get_db),
) -> PaginatedAlertsResponse:
    """Retrieve paginated alerts associated with a specific case."""
    try:
        result = list_case_alerts_service(db, case_id, page=page, page_size=page_size)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.error("Failed to list alerts for case %d (%s): %s", case_id, type(exc).__name__, str(exc)[:200])
        raise HTTPException(status_code=500, detail="Database failure querying case alerts.") from None

    return PaginatedAlertsResponse(
        items=[_alert_to_out(a) for a in result["items"]],
        total=result["total"],
        page=result["page"],
        page_size=result["page_size"],
        pages=result["pages"],
    )


@router.patch("/{case_id}", response_model=CaseOut)
def update_case_endpoint(
    case_id: int,
    payload: CaseUpdate,
    db: Session = Depends(get_db),
) -> CaseOut:
    """Update case title, description, status, or severity."""
    try:
        case = service_update_case(
            db=db,
            case_id=case_id,
            title=payload.title,
            description=payload.description,
            status=payload.status,
            severity=payload.severity,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        logger.error("Failed to update case %d (%s): %s", case_id, type(exc).__name__, str(exc)[:200])
        raise HTTPException(status_code=500, detail="Database failure updating case.") from None

    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found.")

    alert_count = count_case_alerts(db, case_id)
    return _case_to_out(case, alert_count=alert_count)


@router.delete("/{case_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_case_endpoint(
    case_id: int,
    db: Session = Depends(get_db),
    _admin: Any = Depends(require_role("admin")),
) -> None:
    """Delete a Case. Preserves all associated Alert telemetry (admin only)."""
    deleted = service_delete_case(db, case_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found.")



@router.get("/{case_id}", response_model=CaseDetailOut)
def get_case_endpoint(
    case_id: int,
    db: Session = Depends(get_db),
) -> CaseDetailOut:
    """Retrieve full investigation details for a single Case."""
    detail = get_case_detail_service(db, case_id)
    if not detail:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found.")

    case, alert_count, alerts = detail
    return _case_to_detail_out(case, alert_count, alerts)
