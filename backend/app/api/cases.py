"""
app/api/cases.py
~~~~~~~~~~~~~~~~
Case management and incident investigation endpoints.

POST   /api/v1/cases                                  Create a case (201)
GET    /api/v1/cases                                  Paginated case listing (supports assignee_id, unassigned filters)
GET    /api/v1/cases/{case_id}                        Case investigation detail (includes alert summaries and evidence)
PATCH  /api/v1/cases/{case_id}                        Update case metadata, status, or severity
DELETE /api/v1/cases/{case_id}                        Delete a case (admin only)

POST   /api/v1/cases/{case_id}/assign                 Assign or unassign a case (analyst/admin)
POST   /api/v1/cases/{case_id}/resolve                Resolve incident with mandatory disposition and root cause
POST   /api/v1/cases/{case_id}/reopen                 Reopen resolved incident with justification

POST   /api/v1/cases/{case_id}/evidence               Catalog evidence artifact (201)
GET    /api/v1/cases/{case_id}/evidence               List evidence artifacts for case
PATCH  /api/v1/cases/{case_id}/evidence/{evidence_id} Update evidence verdict or notes
DELETE /api/v1/cases/{case_id}/evidence/{evidence_id} Delete evidence artifact (author or admin)

POST   /api/v1/cases/{case_id}/alerts/{alert_id}      Associate alert with case (idempotent)
DELETE /api/v1/cases/{case_id}/alerts/{alert_id}      Detach alert from case (204, alert preserved)
GET    /api/v1/cases/{case_id}/alerts                 Paginated alerts attached to case

POST   /api/v1/cases/{case_id}/notes                  Add investigation note to case (201)
GET    /api/v1/cases/{case_id}/notes                  List investigation notes chronologically
PATCH  /api/v1/cases/{case_id}/notes/{note_id}        Update investigation note (author only)
DELETE /api/v1/cases/{case_id}/notes/{note_id}        Delete investigation note (author or admin)
"""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.alerts import AlertOut, PaginatedAlertsResponse, _alert_to_out
from app.api.deps import get_current_active_user, require_role
from app.db import get_db
from app.models.case import Case, VALID_DISPOSITIONS, VALID_ROOT_CAUSES
from app.models.case_evidence import CaseEvidence, VALID_EVIDENCE_TYPES, VALID_VERDICTS
from app.models.case_note import CaseNote
from app.models.user import User

from app.repositories.case import SORTABLE_CASE_FIELDS, count_case_alerts
from app.services.case import (
    VALID_SEVERITIES,
    VALID_STATUSES,
    AlertNotFoundError,
    AssociationNotFoundError,
    CaseEvidenceNotFoundError,
    CaseEvidencePermissionError,
    CaseNotFoundError,
    CaseNoteNotFoundError,
    CaseNotePermissionError,
    UserNotFoundError,
    add_case_evidence_service,
    add_case_note,
    assign_case_service,
    associate_alert_service,
    close_case as service_close_case,
    delete_case as service_delete_case,
    delete_case_evidence_service,
    delete_case_note_service,
    detach_alert_service,
    get_case_detail_service,
    get_case_evidence_service,
    get_case_notes_service,
    list_case_alerts_service,
    open_case,
    reopen_case_service,
    resolve_case_service,
    search_cases_service,
    update_case as service_update_case,
    update_case_evidence_service,
    update_case_note_service,
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


class UserSummaryOut(BaseModel):
    """Author or assignee summary."""

    id: int
    username: str
    email: str
    role: str

    model_config = {"from_attributes": True}


class CaseCreate(BaseModel):
    """Schema for creating a new Case."""

    title: str = Field(..., min_length=1, max_length=255, description="Case title")
    description: str | None = Field(default=None, description="Detailed case notes/investigation summary")
    severity: str = Field(default="medium", pattern="^(?i)(low|medium|high|critical)$", description="Case severity")
    status: str = Field(default="open", pattern="^(?i)(open|in_progress|escalated|resolved|closed)$", description="Case status")
    assignee_id: int | None = Field(default=None, description="Optional initial assigned analyst ID")


class CaseUpdate(BaseModel):
    """Schema for partial update of a Case."""

    title: str | None = Field(default=None, min_length=1, max_length=255, description="Updated case title")
    description: str | None = Field(default=None, description="Updated notes")
    severity: str | None = Field(default=None, pattern="^(?i)(low|medium|high|critical)$", description="Updated severity")
    status: str | None = Field(default=None, pattern="^(?i)(open|in_progress|escalated|resolved|closed)$", description="Updated status")
    assignee_id: int | None = Field(default=None, description="Updated assignee ID")
    clear_assignee: bool = Field(default=False, description="Set true to unassign case")


class CaseAssignRequest(BaseModel):
    """Schema for assigning or unassigning a case."""

    assignee_id: int | None = Field(
        default=None,
        description="Target user ID to assign. If omitted and unassign is false, claims for current caller.",
    )
    unassign: bool = Field(
        default=False,
        description="Set to true to explicitly unassign the case.",
    )


class CaseResolveRequest(BaseModel):
    """Schema for resolving an incident case with mandatory audit data."""

    disposition: str = Field(
        ...,
        description="Incident disposition: true_positive_incident, false_positive_benign, benign_authorized_activity",
    )
    root_cause: str = Field(
        ...,
        description="Root cause: malware_execution, credential_compromise, privilege_escalation, unauthorized_access, misconfiguration, policy_violation, security_testing",
    )
    resolution_summary: str = Field(
        ...,
        min_length=10,
        max_length=10000,
        description="Detailed resolution explanation (minimum 10 characters)",
    )


class CaseReopenRequest(BaseModel):
    """Schema for reopening an incident case."""

    reason: str = Field(
        ...,
        min_length=1,
        max_length=5000,
        description="Operational justification for reopening the incident",
    )


class CaseEvidenceCreate(BaseModel):
    """Schema for cataloging a new evidence artifact."""

    evidence_type: str = Field(
        ...,
        description="Type: ip, domain, hash_sha256, hash_md5, url, file_path, user_account, host",
    )
    value: str = Field(..., min_length=1, max_length=512, description="Evidence indicator value")
    verdict: str = Field(
        default="suspicious",
        pattern="^(?i)(malicious|suspicious|benign|informational)$",
        description="Analyst verdict",
    )
    notes: str | None = Field(default=None, description="Analyst investigation notes on this evidence")
    alert_id: int | None = Field(default=None, description="Optional associated Alert ID")


class CaseEvidenceUpdate(BaseModel):
    """Schema for updating an evidence verdict or notes."""

    verdict: str | None = Field(
        default=None,
        pattern="^(?i)(malicious|suspicious|benign|informational)$",
        description="Updated analyst verdict",
    )
    notes: str | None = Field(default=None, description="Updated notes")


class CaseEvidenceOut(BaseModel):
    """Representation of an evidence artifact in a case."""

    id: int
    case_id: int
    alert_id: int | None = None
    evidence_type: str
    value: str
    verdict: str
    notes: str | None = None
    added_by_id: int | None = None
    added_by: UserSummaryOut | None = None
    created_at: str
    updated_at: str

    model_config = {"from_attributes": True}


class CaseOut(BaseModel):
    """Standard case representation."""

    id: int
    title: str
    description: str | None
    status: str
    severity: str
    assignee_id: int | None = None
    assignee: UserSummaryOut | None = None
    disposition: str | None = None
    root_cause: str | None = None
    resolution_summary: str | None = None
    resolved_at: str | None = None
    resolved_by_id: int | None = None
    resolved_by: UserSummaryOut | None = None
    created_at: str
    updated_at: str
    alert_count: int = 0
    evidence_count: int = 0

    model_config = {"from_attributes": True}


class CaseDetailOut(CaseOut):
    """Case investigation representation with associated alert summaries and evidence."""

    alerts: list[AlertOut] = Field(default_factory=list)
    evidence: list[CaseEvidenceOut] = Field(default_factory=list)


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


class CaseNoteAuthorOut(BaseModel):
    """Author summary in a case note."""

    id: int
    username: str
    email: str
    role: str

    model_config = {"from_attributes": True}


class CaseNoteCreate(BaseModel):
    """Schema for adding an investigation note."""

    content: str = Field(..., min_length=1, max_length=10000, description="Investigation note content")


class CaseNoteUpdate(BaseModel):
    """Schema for updating an existing investigation note."""

    content: str = Field(..., min_length=1, max_length=10000, description="Updated investigation note content")


class CaseNoteOut(BaseModel):
    """Investigation note representation."""

    id: int
    case_id: int
    author_id: int
    author_username: str
    author: CaseNoteAuthorOut | None = None
    content: str
    created_at: str
    updated_at: str

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _user_to_summary(user: User | None) -> UserSummaryOut | None:
    if not user:
        return None
    return UserSummaryOut(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,
    )


def _evidence_to_out(ev: CaseEvidence) -> CaseEvidenceOut:
    return CaseEvidenceOut(
        id=ev.id,
        case_id=ev.case_id,
        alert_id=ev.alert_id,
        evidence_type=ev.evidence_type,
        value=ev.value,
        verdict=ev.verdict,
        notes=ev.notes,
        added_by_id=ev.added_by_id,
        added_by=_user_to_summary(ev.added_by),
        created_at=ev.created_at.isoformat(),
        updated_at=ev.updated_at.isoformat(),
    )


def _case_to_out(case: Case, alert_count: int = 0, evidence_count: int | None = None) -> CaseOut:
    ev_count = (
        evidence_count
        if evidence_count is not None
        else (len(case.evidence) if hasattr(case, "evidence") and case.evidence is not None else 0)
    )
    return CaseOut(
        id=case.id,
        title=case.title,
        description=case.description,
        status=case.status,
        severity=case.severity,
        assignee_id=case.assignee_id,
        assignee=_user_to_summary(case.assignee),
        disposition=case.disposition,
        root_cause=case.root_cause,
        resolution_summary=case.resolution_summary,
        resolved_at=case.resolved_at.isoformat() if case.resolved_at else None,
        resolved_by_id=case.resolved_by_id,
        resolved_by=_user_to_summary(case.resolved_by),
        created_at=case.created_at.isoformat(),
        updated_at=case.updated_at.isoformat(),
        alert_count=alert_count,
        evidence_count=ev_count,
    )


def _case_to_detail_out(case: Case, alert_count: int, alerts: list[Any]) -> CaseDetailOut:
    evidence_list = [
        _evidence_to_out(e) for e in case.evidence
    ] if hasattr(case, "evidence") and case.evidence is not None else []

    return CaseDetailOut(
        id=case.id,
        title=case.title,
        description=case.description,
        status=case.status,
        severity=case.severity,
        assignee_id=case.assignee_id,
        assignee=_user_to_summary(case.assignee),
        disposition=case.disposition,
        root_cause=case.root_cause,
        resolution_summary=case.resolution_summary,
        resolved_at=case.resolved_at.isoformat() if case.resolved_at else None,
        resolved_by_id=case.resolved_by_id,
        resolved_by=_user_to_summary(case.resolved_by),
        created_at=case.created_at.isoformat(),
        updated_at=case.updated_at.isoformat(),
        alert_count=alert_count,
        evidence_count=len(evidence_list),
        alerts=[_alert_to_out(a) for a in alerts],
        evidence=evidence_list,
    )


def _note_to_out(note: CaseNote) -> CaseNoteOut:
    author_out = None
    author_username = "unknown"
    if note.author:
        author_username = note.author.username
        author_out = CaseNoteAuthorOut(
            id=note.author.id,
            username=note.author.username,
            email=note.author.email,
            role=note.author.role,
        )
    return CaseNoteOut(
        id=note.id,
        case_id=note.case_id,
        author_id=note.author_id,
        author_username=author_username,
        author=author_out,
        content=note.content,
        created_at=note.created_at.isoformat(),
        updated_at=note.updated_at.isoformat(),
    )


# ---------------------------------------------------------------------------
# Core Case Routes
# ---------------------------------------------------------------------------


@router.post("", response_model=CaseOut, status_code=status.HTTP_201_CREATED)
def create_case_endpoint(
    payload: CaseCreate,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_active_user),
) -> CaseOut:
    """Create a new investigation Case."""
    try:
        case = open_case(
            db=db,
            title=payload.title,
            description=payload.description,
            severity=payload.severity,
            status=payload.status,
            assignee_id=payload.assignee_id,
        )
    except UserNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        logger.error("Failed to create case (%s): %s", type(exc).__name__, str(exc)[:200])
        raise HTTPException(status_code=500, detail="Database failure creating case.") from None

    return _case_to_out(case, alert_count=0, evidence_count=0)


@router.get("", response_model=PaginatedCasesResponse)
def list_cases_endpoint(
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(default=25, ge=1, le=100, description="Items per page"),
    status: str | None = Query(default=None, description="Filter by status"),
    severity: str | None = Query(default=None, description="Filter by severity"),
    assignee_id: int | None = Query(default=None, description="Filter by assigned analyst ID"),
    unassigned: bool | None = Query(default=None, description="Filter for unassigned cases"),
    sort_by: str = Query(default="created_at", description="Field to sort by"),
    sort_order: str = Query(default="desc", pattern="^(?i)(asc|desc)$", description="Sort direction"),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_active_user),
) -> PaginatedCasesResponse:
    """List paginated cases with filtering (status, severity, assignee, unassigned) and sorting."""
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
            assignee_id=assignee_id,
            unassigned=unassigned,
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


@router.get("/{case_id}", response_model=CaseDetailOut)
def get_case_endpoint(
    case_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_active_user),
) -> CaseDetailOut:
    """Retrieve full investigation details for a single Case, including alerts and evidence."""
    detail = get_case_detail_service(db, case_id)
    if not detail:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found.")

    case, alert_count, alerts = detail
    return _case_to_detail_out(case, alert_count, alerts)


@router.patch("/{case_id}", response_model=CaseOut)
def update_case_endpoint(
    case_id: int,
    payload: CaseUpdate,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_active_user),
) -> CaseOut:
    """Update case title, description, status, severity, or assignee."""
    try:
        case = service_update_case(
            db=db,
            case_id=case_id,
            title=payload.title,
            description=payload.description,
            status=payload.status,
            severity=payload.severity,
            assignee_id=payload.assignee_id,
            clear_assignee=payload.clear_assignee,
        )
    except UserNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        logger.error("Failed to update case %d (%s): %s", case_id, type(exc).__name__, str(exc)[:200])
        raise HTTPException(status_code=500, detail="Database failure updating case.") from None

    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found.")

    alert_count = count_case_alerts(db, case_id)
    return _case_to_out(case, alert_count=alert_count)


@router.post("/{case_id}/close", response_model=CaseOut)
def close_case_endpoint(
    case_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_active_user),
) -> CaseOut:
    """Close a Case (sets status to 'closed'). Preserved for backward compatibility."""
    case = service_close_case(db, case_id)
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


# ---------------------------------------------------------------------------
# Phase 8: Ownership & Lifecycle Routes
# ---------------------------------------------------------------------------


@router.post("/{case_id}/assign", response_model=CaseOut)
def assign_case_endpoint(
    case_id: int,
    payload: CaseAssignRequest = CaseAssignRequest(),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> CaseOut:
    """Assign case to a user, claim for self, or unassign."""
    if payload.unassign:
        target_id = None
    elif payload.assignee_id is not None:
        target_id = payload.assignee_id
    else:
        target_id = current_user.id
    try:
        case = assign_case_service(
            db=db,
            case_id=case_id,
            assignee_id=target_id,
            actor=current_user,
        )
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except UserNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.error("Failed to assign case %d (%s): %s", case_id, type(exc).__name__, str(exc)[:200])
        raise HTTPException(status_code=500, detail="Database failure assigning case.") from None

    return _case_to_out(case, alert_count=count_case_alerts(db, case_id))


@router.post("/{case_id}/resolve", response_model=CaseOut)
def resolve_case_endpoint(
    case_id: int,
    payload: CaseResolveRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> CaseOut:
    """Resolve an incident case with mandatory disposition, root cause, and summary."""
    try:
        case = resolve_case_service(
            db=db,
            case_id=case_id,
            disposition=payload.disposition,
            root_cause=payload.root_cause,
            resolution_summary=payload.resolution_summary,
            actor=current_user,
        )
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        logger.error("Failed to resolve case %d (%s): %s", case_id, type(exc).__name__, str(exc)[:200])
        raise HTTPException(status_code=500, detail="Database failure resolving case.") from None

    return _case_to_out(case, alert_count=count_case_alerts(db, case_id))


@router.post("/{case_id}/reopen", response_model=CaseOut)
def reopen_case_endpoint(
    case_id: int,
    payload: CaseReopenRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> CaseOut:
    """Reopen a resolved or closed incident case with an auditable reason."""
    try:
        case = reopen_case_service(
            db=db,
            case_id=case_id,
            reason=payload.reason,
            actor=current_user,
        )
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        logger.error("Failed to reopen case %d (%s): %s", case_id, type(exc).__name__, str(exc)[:200])
        raise HTTPException(status_code=500, detail="Database failure reopening case.") from None

    return _case_to_out(case, alert_count=count_case_alerts(db, case_id))


# ---------------------------------------------------------------------------
# Phase 8: Evidence Locker Routes
# ---------------------------------------------------------------------------


@router.post("/{case_id}/evidence", response_model=CaseEvidenceOut, status_code=status.HTTP_201_CREATED)
def add_case_evidence_endpoint(
    case_id: int,
    payload: CaseEvidenceCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> CaseEvidenceOut:
    """Catalog an evidence artifact on a case. Handles deduplication gracefully."""
    try:
        evidence = add_case_evidence_service(
            db=db,
            case_id=case_id,
            evidence_data=payload.model_dump(),
            actor=current_user,
        )
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except AlertNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        logger.error("Failed to add evidence to case %d (%s): %s", case_id, type(exc).__name__, str(exc)[:200])
        raise HTTPException(status_code=500, detail="Database failure cataloging evidence.") from None

    return _evidence_to_out(evidence)


@router.get("/{case_id}/evidence", response_model=list[CaseEvidenceOut])
def list_case_evidence_endpoint(
    case_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_active_user),
) -> list[CaseEvidenceOut]:
    """Retrieve all cataloged evidence artifacts for a case."""
    try:
        evidence_list = get_case_evidence_service(db=db, case_id=case_id)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.error("Failed to list evidence for case %d (%s): %s", case_id, type(exc).__name__, str(exc)[:200])
        raise HTTPException(status_code=500, detail="Database failure listing case evidence.") from None

    return [_evidence_to_out(e) for e in evidence_list]


@router.patch("/{case_id}/evidence/{evidence_id}", response_model=CaseEvidenceOut)
def update_case_evidence_endpoint(
    case_id: int,
    evidence_id: int,
    payload: CaseEvidenceUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> CaseEvidenceOut:
    """Update verdict or notes on an evidence artifact."""
    try:
        evidence = update_case_evidence_service(
            db=db,
            case_id=case_id,
            evidence_id=evidence_id,
            updates=payload.model_dump(exclude_unset=True),
            actor=current_user,
        )
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except CaseEvidenceNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        logger.error("Failed to update evidence %d for case %d (%s): %s", evidence_id, case_id, type(exc).__name__, str(exc)[:200])
        raise HTTPException(status_code=500, detail="Database failure updating evidence.") from None

    return _evidence_to_out(evidence)


@router.delete("/{case_id}/evidence/{evidence_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_case_evidence_endpoint(
    case_id: int,
    evidence_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> None:
    """Delete an evidence artifact. Author or admin only."""
    try:
        delete_case_evidence_service(
            db=db,
            case_id=case_id,
            evidence_id=evidence_id,
            actor=current_user,
        )
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except CaseEvidenceNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except CaseEvidencePermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except Exception as exc:
        logger.error("Failed to delete evidence %d for case %d (%s): %s", evidence_id, case_id, type(exc).__name__, str(exc)[:200])
        raise HTTPException(status_code=500, detail="Database failure deleting evidence.") from None


# ---------------------------------------------------------------------------
# Case Alerts Routes
# ---------------------------------------------------------------------------


@router.post("/{case_id}/alerts/{alert_id}", response_model=CaseAlertAssociationOut, status_code=status.HTTP_200_OK)
def associate_alert_endpoint(
    case_id: int,
    alert_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_active_user),
) -> CaseAlertAssociationOut:
    """Associate an alert to a case. Returns is_new=True if newly associated."""
    try:
        case_alert, is_new = associate_alert_service(db, case_id, alert_id)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except AlertNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.error("Failed to associate alert %d with case %d (%s): %s", alert_id, case_id, type(exc).__name__, str(exc)[:200])
        raise HTTPException(status_code=500, detail="Database failure associating alert with case.") from None

    status_code = status.HTTP_201_CREATED if is_new else status.HTTP_200_OK
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
    _user: User = Depends(get_current_active_user),
) -> None:
    """Detach an alert from a case. Preserves the alert record in the alerts table."""
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
    _user: User = Depends(get_current_active_user),
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


# ---------------------------------------------------------------------------
# Case Notes Routes
# ---------------------------------------------------------------------------


@router.post("/{case_id}/notes", response_model=CaseNoteOut, status_code=status.HTTP_201_CREATED)
def create_case_note_endpoint(
    case_id: int,
    payload: CaseNoteCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> CaseNoteOut:
    """Add an investigation note to a case."""
    try:
        note = add_case_note(
            db=db,
            case_id=case_id,
            author_id=current_user.id,
            content=payload.content,
        )
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        logger.error("Failed to create note for case %d (%s): %s", case_id, type(exc).__name__, str(exc)[:200])
        raise HTTPException(status_code=500, detail="Database failure creating case note.") from None

    return _note_to_out(note)


@router.get("/{case_id}/notes", response_model=list[CaseNoteOut])
def list_case_notes_endpoint(
    case_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_active_user),
) -> list[CaseNoteOut]:
    """Retrieve all investigation notes for a case in chronological order."""
    try:
        notes = get_case_notes_service(db=db, case_id=case_id)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.error("Failed to list notes for case %d (%s): %s", case_id, type(exc).__name__, str(exc)[:200])
        raise HTTPException(status_code=500, detail="Database failure listing case notes.") from None

    return [_note_to_out(n) for n in notes]


@router.patch("/{case_id}/notes/{note_id}", response_model=CaseNoteOut)
def update_case_note_endpoint(
    case_id: int,
    note_id: int,
    payload: CaseNoteUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> CaseNoteOut:
    """Update an investigation note. Only the note's author can edit."""
    try:
        note = update_case_note_service(
            db=db,
            case_id=case_id,
            note_id=note_id,
            content=payload.content,
            user_id=current_user.id,
            user_role=current_user.role,
        )
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except CaseNoteNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except CaseNotePermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        logger.error("Failed to update note %d for case %d (%s): %s", note_id, case_id, type(exc).__name__, str(exc)[:200])
        raise HTTPException(status_code=500, detail="Database failure updating case note.") from None

    return _note_to_out(note)


@router.delete("/{case_id}/notes/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_case_note_endpoint(
    case_id: int,
    note_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> None:
    """Delete an investigation note. The author or an admin can delete."""
    try:
        delete_case_note_service(
            db=db,
            case_id=case_id,
            note_id=note_id,
            user_id=current_user.id,
            user_role=current_user.role,
        )
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except CaseNoteNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except CaseNotePermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except Exception as exc:
        logger.error("Failed to delete note %d for case %d (%s): %s", note_id, case_id, type(exc).__name__, str(exc)[:200])
        raise HTTPException(status_code=500, detail="Database failure deleting case note.") from None
