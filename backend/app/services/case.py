import math
from typing import Any

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.case import Case
from app.models.case_alert import CaseAlert
from app.models.case_note import CaseNote
from app.repositories.alert import get_alert_by_id
from app.repositories.case import (
    associate_alert_to_case,
    count_case_alerts,
    create_case as repo_create_case,
    create_case_note as repo_create_case_note,
    delete_case as repo_delete_case,
    delete_case_note as repo_delete_case_note,
    get_case_by_id,
    get_case_note_by_id as repo_get_case_note,
    is_alert_associated,
    list_case_alerts,
    list_case_notes as repo_list_case_notes,
    list_cases as repo_list_cases,
    remove_alert_from_case,
    search_cases,
    update_case as repo_update_case,
    update_case_note as repo_update_case_note,
)

VALID_STATUSES = {"open", "in_progress", "escalated", "resolved", "closed"}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}


class CaseNotFoundError(Exception):
    """Raised when a referenced Case is not found."""


class AlertNotFoundError(Exception):
    """Raised when a referenced Alert is not found."""


class AssociationNotFoundError(Exception):
    """Raised when an alert-case association is not found upon detachment."""


class CaseNoteNotFoundError(Exception):
    """Raised when a referenced CaseNote is not found."""


class CaseNotePermissionError(Exception):
    """Raised when user does not have permission to modify or delete a note."""


def open_case(
    db: Session,
    title: str,
    description: str | None = None,
    severity: str = "medium",
    status: str = "open",
) -> Case:
    norm_status = status.lower() if status else "open"
    norm_sev = severity.lower() if severity else "medium"

    if norm_status not in VALID_STATUSES:
        raise ValueError(f"Invalid case status: {status}. Must be one of {VALID_STATUSES}")
    if norm_sev not in VALID_SEVERITIES:
        raise ValueError(f"Invalid case severity: {severity}. Must be one of {VALID_SEVERITIES}")

    case = Case(
        title=title.strip(),
        description=description.strip() if description else None,
        severity=norm_sev,
        status=norm_status,
    )
    return repo_create_case(db, case)


def get_case(db: Session, case_id: int) -> Case | None:
    return get_case_by_id(db, case_id)


def update_case(
    db: Session,
    case_id: int,
    title: str | None = None,
    description: str | None = None,
    status: str | None = None,
    severity: str | None = None,
) -> Case | None:
    update_data: dict[str, Any] = {}
    if title is not None:
        update_data["title"] = title.strip()
    if description is not None:
        update_data["description"] = description.strip()
    if status is not None:
        norm_status = status.lower()
        if norm_status not in VALID_STATUSES:
            raise ValueError(f"Invalid case status: {status}")
        update_data["status"] = norm_status
    if severity is not None:
        norm_sev = severity.lower()
        if norm_sev not in VALID_SEVERITIES:
            raise ValueError(f"Invalid case severity: {severity}")
        update_data["severity"] = norm_sev

    if not update_data:
        return get_case_by_id(db, case_id)

    return repo_update_case(db, case_id, update_data)


def close_case(db: Session, case_id: int) -> Case | None:
    return update_case(db, case_id, status="closed")


def delete_case(db: Session, case_id: int) -> bool:
    return repo_delete_case(db, case_id)


def list_cases(
    db: Session,
    skip: int = 0,
    limit: int = 50,
    status: str | None = None,
    severity: str | None = None,
) -> list[Case]:
    return repo_list_cases(db, skip=skip, limit=limit, status=status, severity=severity)


def search_cases_service(
    db: Session,
    page: int = 1,
    page_size: int = 25,
    status: str | None = None,
    severity: str | None = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
) -> dict[str, Any]:
    """Service to search and paginate cases with metadata calculation."""
    if status and status.lower() not in VALID_STATUSES:
        raise ValueError(f"Invalid case status: {status}")
    if severity and severity.lower() not in VALID_SEVERITIES:
        raise ValueError(f"Invalid case severity: {severity}")

    items, total = search_cases(
        db=db,
        page=page,
        page_size=page_size,
        status=status.lower() if status else None,
        severity=severity.lower() if severity else None,
        sort_by=sort_by.lower(),
        sort_order=sort_order.lower(),
    )
    pages = math.ceil(total / page_size) if total > 0 else 0
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
    }


def get_case_detail_service(
    db: Session,
    case_id: int,
    alert_limit: int = 25,
) -> tuple[Case, int, list[Alert]] | None:
    """Retrieve case, total alert count, and associated summary alerts."""
    case = get_case_by_id(db, case_id)
    if not case:
        return None

    total_alerts = count_case_alerts(db, case_id)
    alerts, _ = list_case_alerts(db, case_id, page=1, page_size=alert_limit)
    return case, total_alerts, alerts


def associate_alert_service(
    db: Session,
    case_id: int,
    alert_id: int,
) -> tuple[CaseAlert, bool]:
    """Associate an alert to a case. Validates existence and handles idempotency."""
    case = get_case_by_id(db, case_id)
    if not case:
        raise CaseNotFoundError(f"Case {case_id} not found.")

    alert = get_alert_by_id(db, alert_id)
    if not alert:
        raise AlertNotFoundError(f"Alert {alert_id} not found.")

    return associate_alert_to_case(db, case_id, alert_id)


def detach_alert_service(
    db: Session,
    case_id: int,
    alert_id: int,
) -> bool:
    """Detach an alert from a case. Validates existence and verifies alert remains in DB."""
    case = get_case_by_id(db, case_id)
    if not case:
        raise CaseNotFoundError(f"Case {case_id} not found.")

    alert = get_alert_by_id(db, alert_id)
    if not alert:
        raise AlertNotFoundError(f"Alert {alert_id} not found.")

    if not is_alert_associated(db, case_id, alert_id):
        raise AssociationNotFoundError(f"Alert {alert_id} is not associated with Case {case_id}.")

    return remove_alert_from_case(db, case_id, alert_id)


def list_case_alerts_service(
    db: Session,
    case_id: int,
    page: int = 1,
    page_size: int = 25,
) -> dict[str, Any]:
    """Return paginated Alert records associated with a case."""
    case = get_case_by_id(db, case_id)
    if not case:
        raise CaseNotFoundError(f"Case {case_id} not found.")

    items, total = list_case_alerts(db, case_id, page=page, page_size=page_size)
    pages = math.ceil(total / page_size) if total > 0 else 0
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
    }


def add_case_note(
    db: Session,
    case_id: int,
    author_id: int,
    content: str,
) -> CaseNote:
    """Add an investigation note to a case."""
    case = get_case_by_id(db, case_id)
    if not case:
        raise CaseNotFoundError(f"Case {case_id} not found.")
    clean = content.strip()
    if not clean:
        raise ValueError("Note content cannot be empty.")
    if len(clean) > 10000:
        raise ValueError("Note content exceeds maximum length of 10000 characters.")
    return repo_create_case_note(db, case_id=case_id, author_id=author_id, content=clean)


def get_case_notes_service(
    db: Session,
    case_id: int,
) -> list[CaseNote]:
    """Retrieve all notes for a case chronologically."""
    case = get_case_by_id(db, case_id)
    if not case:
        raise CaseNotFoundError(f"Case {case_id} not found.")
    return repo_list_case_notes(db, case_id=case_id)


def update_case_note_service(
    db: Session,
    case_id: int,
    note_id: int,
    content: str,
    user_id: int,
    user_role: str,
) -> CaseNote:
    """Update a case note with ownership validation."""
    case = get_case_by_id(db, case_id)
    if not case:
        raise CaseNotFoundError(f"Case {case_id} not found.")
    note = repo_get_case_note(db, note_id)
    if not note or note.case_id != case_id:
        raise CaseNoteNotFoundError(f"Note {note_id} not found in case {case_id}.")

    if note.author_id != user_id:
        raise CaseNotePermissionError("Analysts can only edit their own notes.")

    clean = content.strip()
    if not clean:
        raise ValueError("Note content cannot be empty.")
    if len(clean) > 10000:
        raise ValueError("Note content exceeds maximum length of 10000 characters.")

    return repo_update_case_note(db, note, clean)


def delete_case_note_service(
    db: Session,
    case_id: int,
    note_id: int,
    user_id: int,
    user_role: str,
) -> None:
    """Delete a case note with author or admin authorization."""
    case = get_case_by_id(db, case_id)
    if not case:
        raise CaseNotFoundError(f"Case {case_id} not found.")
    note = repo_get_case_note(db, note_id)
    if not note or note.case_id != case_id:
        raise CaseNoteNotFoundError(f"Note {note_id} not found in case {case_id}.")

    if note.author_id != user_id and user_role != "admin":
        raise CaseNotePermissionError("You do not have permission to delete this note.")

    repo_delete_case_note(db, note)
