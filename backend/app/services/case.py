from datetime import datetime, timezone
import math
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.models.alert import Alert
from app.models.case import (
    VALID_DISPOSITIONS,
    VALID_ROOT_CAUSES,
    Case,
)
from app.models.case_alert import CaseAlert
from app.models.case_evidence import (
    VALID_EVIDENCE_TYPES,
    VALID_VERDICTS,
    CaseEvidence,
)
from app.models.case_note import CaseNote
from app.models.user import User
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
from app.repositories.case_evidence import (
    create_evidence as repo_create_evidence,
    delete_evidence as repo_delete_evidence,
    get_evidence_by_case_type_value as repo_get_evidence_by_case_type_value,
    get_evidence_by_id as repo_get_evidence_by_id,
    list_case_evidence as repo_list_case_evidence,
    update_evidence as repo_update_evidence,
)

VALID_STATUSES = {"open", "in_progress", "escalated", "resolved", "closed"}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}


class CaseNotFoundError(Exception):
    """Raised when a referenced Case is not found."""


class AlertNotFoundError(Exception):
    """Raised when a referenced Alert is not found."""


class UserNotFoundError(Exception):
    """Raised when a referenced User is not found."""


class AssociationNotFoundError(Exception):
    """Raised when an alert-case association is not found upon detachment."""


class CaseNoteNotFoundError(Exception):
    """Raised when a referenced CaseNote is not found."""


class CaseNotePermissionError(Exception):
    """Raised when user does not have permission to modify or delete a note."""


class CaseEvidenceNotFoundError(Exception):
    """Raised when a referenced CaseEvidence item is not found."""


class CaseEvidencePermissionError(Exception):
    """Raised when user does not have permission to delete an evidence item."""


def get_or_create_system_user(db: Session) -> User:
    """Retrieve or create the system bot user for automated audit note attribution."""
    system_user = db.scalars(select(User).where(User.username == "system")).first()
    if system_user:
        return system_user

    admin_user = db.scalars(select(User).where(User.username == "admin")).first()
    if admin_user:
        return admin_user

    system_user = User(
        username="system",
        email="system@sentinelx.local",
        password_hash=hash_password("SystemBotDisabledAuth123!"),
        role="admin",
        is_active=True,
    )
    db.add(system_user)
    db.commit()
    db.refresh(system_user)
    return system_user


def open_case(
    db: Session,
    title: str,
    description: str | None = None,
    severity: str = "medium",
    status: str = "open",
    assignee_id: int | None = None,
) -> Case:
    norm_status = status.lower() if status else "open"
    norm_sev = severity.lower() if severity else "medium"

    if norm_status not in VALID_STATUSES:
        raise ValueError(f"Invalid case status: {status}. Must be one of {VALID_STATUSES}")
    if norm_sev not in VALID_SEVERITIES:
        raise ValueError(f"Invalid case severity: {severity}. Must be one of {VALID_SEVERITIES}")

    if assignee_id is not None:
        user = db.get(User, assignee_id)
        if not user:
            raise UserNotFoundError(f"Assignee user {assignee_id} not found.")

    case = Case(
        title=title.strip(),
        description=description.strip() if description else None,
        severity=norm_sev,
        status=norm_status,
        assignee_id=assignee_id,
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
    assignee_id: int | None = None,
    clear_assignee: bool = False,
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

    if clear_assignee:
        update_data["assignee_id"] = None
    elif assignee_id is not None:
        user = db.get(User, assignee_id)
        if not user:
            raise UserNotFoundError(f"Assignee user {assignee_id} not found.")
        update_data["assignee_id"] = assignee_id

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
    assignee_id: int | None = None,
    unassigned: bool | None = None,
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
        assignee_id=assignee_id,
        unassigned=unassigned,
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


# ---------------------------------------------------------------------------
# Phase 8: Ownership, Evidence, and Resolution Services
# ---------------------------------------------------------------------------


def assign_case_service(
    db: Session,
    case_id: int,
    assignee_id: int | None,
    actor: User,
) -> Case:
    """Assign or unassign a case, logging an auditable system timeline note."""
    case = get_case_by_id(db, case_id)
    if not case:
        raise CaseNotFoundError(f"Case {case_id} not found.")

    if assignee_id is not None:
        target_user = db.get(User, assignee_id)
        if not target_user:
            raise UserNotFoundError(f"Assignee user {assignee_id} not found.")
        case.assignee_id = target_user.id
        audit_content = f"[Case Assignment] Case assigned to '{target_user.username}' by '{actor.username}'."
    else:
        prev_name = case.assignee.username if case.assignee else "Unassigned"
        case.assignee_id = None
        audit_content = f"[Case Assignment] Case unassigned (previously '{prev_name}') by '{actor.username}'."

    db.commit()
    db.refresh(case)

    system_user = get_or_create_system_user(db)
    add_case_note(db, case_id=case_id, author_id=system_user.id, content=audit_content)

    return case


def add_case_evidence_service(
    db: Session,
    case_id: int,
    evidence_data: dict[str, Any],
    actor: User,
) -> CaseEvidence:
    """Catalog or update an evidence artifact on a case, with deduplication and timeline note."""
    case = get_case_by_id(db, case_id)
    if not case:
        raise CaseNotFoundError(f"Case {case_id} not found.")

    evidence_type = (evidence_data.get("evidence_type") or "").strip().lower()
    if evidence_type not in VALID_EVIDENCE_TYPES:
        raise ValueError(
            f"Invalid evidence_type '{evidence_type}'. Must be one of {sorted(VALID_EVIDENCE_TYPES)}"
        )

    verdict = (evidence_data.get("verdict") or "suspicious").strip().lower()
    if verdict not in VALID_VERDICTS:
        raise ValueError(f"Invalid verdict '{verdict}'. Must be one of {sorted(VALID_VERDICTS)}")

    clean_value = (evidence_data.get("value") or "").strip()
    if not clean_value:
        raise ValueError("Evidence value cannot be empty.")
    if len(clean_value) > 512:
        raise ValueError("Evidence value exceeds maximum length of 512 characters.")

    alert_id = evidence_data.get("alert_id")
    if alert_id is not None:
        alert = get_alert_by_id(db, alert_id)
        if not alert:
            raise AlertNotFoundError(f"Alert {alert_id} not found.")

    notes = evidence_data.get("notes")
    clean_notes = notes.strip() if notes else None

    # Deduplication check
    existing = repo_get_evidence_by_case_type_value(db, case_id, evidence_type, clean_value)
    system_user = get_or_create_system_user(db)

    if existing:
        updates: dict[str, Any] = {"verdict": verdict}
        if clean_notes is not None:
            updates["notes"] = clean_notes
        if alert_id is not None and existing.alert_id is None:
            updates["alert_id"] = alert_id
        updated = repo_update_evidence(db, existing, updates)

        add_case_note(
            db,
            case_id=case_id,
            author_id=system_user.id,
            content=(
                f"[Evidence Updated] Updated existing {evidence_type.upper()} '{clean_value}' "
                f"(Verdict: {verdict.upper()}) by '{actor.username}'."
            ),
        )
        return updated

    new_evidence = CaseEvidence(
        case_id=case_id,
        alert_id=alert_id,
        evidence_type=evidence_type,
        value=clean_value,
        verdict=verdict,
        notes=clean_notes,
        added_by_id=actor.id,
    )
    created = repo_create_evidence(db, new_evidence)

    alert_suffix = f" from Alert #{alert_id}" if alert_id else ""
    add_case_note(
        db,
        case_id=case_id,
        author_id=system_user.id,
        content=(
            f"[Evidence Cataloged] Added {evidence_type.upper()} '{clean_value}' "
            f"(Verdict: {verdict.upper()}){alert_suffix} by '{actor.username}'."
        ),
    )
    return created


def get_case_evidence_service(db: Session, case_id: int) -> list[CaseEvidence]:
    """Retrieve all evidence cataloged for a case."""
    case = get_case_by_id(db, case_id)
    if not case:
        raise CaseNotFoundError(f"Case {case_id} not found.")
    return repo_list_case_evidence(db, case_id)


def update_case_evidence_service(
    db: Session,
    case_id: int,
    evidence_id: int,
    updates: dict[str, Any],
    actor: User,
) -> CaseEvidence:
    """Update verdict or notes on an evidence item and log audit note."""
    case = get_case_by_id(db, case_id)
    if not case:
        raise CaseNotFoundError(f"Case {case_id} not found.")

    evidence = repo_get_evidence_by_id(db, evidence_id)
    if not evidence or evidence.case_id != case_id:
        raise CaseEvidenceNotFoundError(f"Evidence #{evidence_id} not found in case #{case_id}.")

    sanitized_updates: dict[str, Any] = {}
    if "verdict" in updates and updates["verdict"] is not None:
        verdict = updates["verdict"].strip().lower()
        if verdict not in VALID_VERDICTS:
            raise ValueError(f"Invalid verdict '{verdict}'. Must be one of {sorted(VALID_VERDICTS)}")
        sanitized_updates["verdict"] = verdict

    if "notes" in updates and updates["notes"] is not None:
        sanitized_updates["notes"] = updates["notes"].strip() or None

    if not sanitized_updates:
        return evidence

    updated = repo_update_evidence(db, evidence, sanitized_updates)

    system_user = get_or_create_system_user(db)
    add_case_note(
        db,
        case_id=case_id,
        author_id=system_user.id,
        content=(
            f"[Evidence Updated] Modified evidence #{evidence.id} "
            f"({evidence.evidence_type.upper()}: '{evidence.value}') by '{actor.username}'. "
            f"Verdict: {evidence.verdict.upper()}."
        ),
    )
    return updated


def delete_case_evidence_service(
    db: Session,
    case_id: int,
    evidence_id: int,
    actor: User,
) -> None:
    """Delete an evidence item with author or admin authorization."""
    case = get_case_by_id(db, case_id)
    if not case:
        raise CaseNotFoundError(f"Case {case_id} not found.")

    evidence = repo_get_evidence_by_id(db, evidence_id)
    if not evidence or evidence.case_id != case_id:
        raise CaseEvidenceNotFoundError(f"Evidence #{evidence_id} not found in case #{case_id}.")

    if evidence.added_by_id != actor.id and actor.role != "admin":
        raise CaseEvidencePermissionError("Analysts can only delete evidence they added.")

    deleted_type = evidence.evidence_type.upper()
    deleted_val = evidence.value
    deleted_verdict = evidence.verdict.upper()

    repo_delete_evidence(db, evidence)

    system_user = get_or_create_system_user(db)
    add_case_note(
        db,
        case_id=case_id,
        author_id=system_user.id,
        content=(
            f"[Evidence Removed] Deleted {deleted_type} '{deleted_val}' "
            f"(Verdict was: {deleted_verdict}) by '{actor.username}'."
        ),
    )


def resolve_case_service(
    db: Session,
    case_id: int,
    disposition: str,
    root_cause: str,
    resolution_summary: str,
    actor: User,
) -> Case:
    """Resolve an incident case with mandatory disposition, root cause, and summary."""
    case = get_case_by_id(db, case_id)
    if not case:
        raise CaseNotFoundError(f"Case {case_id} not found.")

    norm_disp = (disposition or "").strip().lower()
    if norm_disp not in VALID_DISPOSITIONS:
        raise ValueError(
            f"Invalid disposition '{disposition}'. Must be one of {sorted(VALID_DISPOSITIONS)}"
        )

    norm_rc = (root_cause or "").strip().lower()
    if norm_rc not in VALID_ROOT_CAUSES:
        raise ValueError(
            f"Invalid root_cause '{root_cause}'. Must be one of {sorted(VALID_ROOT_CAUSES)}"
        )

    clean_summary = (resolution_summary or "").strip()
    if len(clean_summary) < 10:
        raise ValueError("Resolution summary must be at least 10 characters long.")
    if len(clean_summary) > 10000:
        raise ValueError("Resolution summary exceeds maximum length of 10000 characters.")

    case.status = "resolved"
    case.disposition = norm_disp
    case.root_cause = norm_rc
    case.resolution_summary = clean_summary
    case.resolved_at = datetime.now(timezone.utc)
    case.resolved_by_id = actor.id

    db.commit()
    db.refresh(case)

    disp_title = norm_disp.replace("_", " ").title()
    rc_title = norm_rc.replace("_", " ").title()
    system_user = get_or_create_system_user(db)
    add_case_note(
        db,
        case_id=case_id,
        author_id=system_user.id,
        content=(
            f"[Incident Resolved] Status changed to RESOLVED by '{actor.username}'.\n"
            f"Disposition: {disp_title}\n"
            f"Root Cause: {rc_title}\n"
            f"Summary: {clean_summary}"
        ),
    )

    return case


def reopen_case_service(
    db: Session,
    case_id: int,
    reason: str,
    actor: User,
) -> Case:
    """Reopen a resolved or closed incident case with mandatory justification."""
    case = get_case_by_id(db, case_id)
    if not case:
        raise CaseNotFoundError(f"Case {case_id} not found.")

    clean_reason = (reason or "").strip()
    if not clean_reason:
        raise ValueError("Reopening reason cannot be empty.")
    if len(clean_reason) > 5000:
        raise ValueError("Reopening reason exceeds maximum length of 5000 characters.")

    case.status = "in_progress"
    case.resolved_at = None
    db.commit()
    db.refresh(case)

    system_user = get_or_create_system_user(db)
    add_case_note(
        db,
        case_id=case_id,
        author_id=system_user.id,
        content=(
            f"[Incident Reopened] Incident reopened by '{actor.username}'. Status: IN_PROGRESS.\n"
            f"Reason: {clean_reason}"
        ),
    )

    return case
