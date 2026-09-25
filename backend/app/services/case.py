from typing import Any

from sqlalchemy.orm import Session

from app.models.case import Case
from app.repositories.case import (
    create_case as repo_create_case,
    delete_case as repo_delete_case,
    get_case_by_id,
    list_cases as repo_list_cases,
    update_case as repo_update_case,
)

VALID_STATUSES = {"open", "in_progress", "escalated", "resolved", "closed"}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}


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
