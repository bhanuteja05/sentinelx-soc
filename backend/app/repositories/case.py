from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.case import Case
from app.models.case_alert import CaseAlert
from app.models.case_note import CaseNote

SORTABLE_CASE_FIELDS: dict[str, Any] = {
    "created_at": Case.created_at,
    "updated_at": Case.updated_at,
    "severity": Case.severity,
    "status": Case.status,
    "id": Case.id,
    "title": Case.title,
}


def create_case(db: Session, case: Case | dict[str, Any]) -> Case:
    if isinstance(case, dict):
        db_case = Case(**case)
    else:
        db_case = case
    db.add(db_case)
    db.commit()
    db.refresh(db_case)
    return db_case


def get_case_by_id(db: Session, case_id: int) -> Case | None:
    return db.get(Case, case_id)


def search_cases(
    db: Session,
    page: int = 1,
    page_size: int = 25,
    status: str | None = None,
    severity: str | None = None,
    assignee_id: int | None = None,
    unassigned: bool | None = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
) -> tuple[list[Case], int]:
    """Search and paginate cases with filtering and strict sort allowlisting."""
    clauses = []
    if status is not None:
        clauses.append(Case.status == status)
    if severity is not None:
        clauses.append(Case.severity == severity)
    if unassigned is True:
        clauses.append(Case.assignee_id.is_(None))
    elif assignee_id is not None:
        clauses.append(Case.assignee_id == assignee_id)

    # 1. Total filtered count
    count_stmt = select(func.count(Case.id))
    if clauses:
        count_stmt = count_stmt.where(*clauses)
    total = db.scalar(count_stmt) or 0

    # 2. Sorting
    sort_col = SORTABLE_CASE_FIELDS.get(sort_by, Case.created_at)
    primary_order = sort_col.asc() if sort_order.lower() == "asc" else sort_col.desc()
    order_clauses = [primary_order]
    if sort_by != "id":
        order_clauses.append(Case.id.desc())

    # 3. Paginated items
    offset = max(0, (page - 1) * page_size)
    stmt = select(Case)
    if clauses:
        stmt = stmt.where(*clauses)
    stmt = stmt.order_by(*order_clauses).offset(offset).limit(page_size)

    items = list(db.scalars(stmt).all())
    return items, total


def list_cases(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    status: str | None = None,
    severity: str | None = None,
) -> list[Case]:
    stmt = select(Case)
    clauses = []
    if status is not None:
        clauses.append(Case.status == status)
    if severity is not None:
        clauses.append(Case.severity == severity)
    if clauses:
        stmt = stmt.where(*clauses)

    stmt = stmt.order_by(Case.created_at.desc(), Case.id.desc()).offset(skip).limit(limit)
    return list(db.scalars(stmt).all())


def count_cases(
    db: Session,
    status: str | None = None,
    severity: str | None = None,
) -> int:
    stmt = select(func.count(Case.id))
    clauses = []
    if status is not None:
        clauses.append(Case.status == status)
    if severity is not None:
        clauses.append(Case.severity == severity)
    if clauses:
        stmt = stmt.where(*clauses)
    return db.scalar(stmt) or 0


def update_case(db: Session, case_id: int, update_data: dict[str, Any]) -> Case | None:
    case = db.get(Case, case_id)
    if not case:
        return None
    for field, val in update_data.items():
        setattr(case, field, val)
    db.commit()
    db.refresh(case)
    return case


def delete_case(db: Session, case_id: int) -> bool:
    case = db.get(Case, case_id)
    if not case:
        return False
    db.delete(case)
    db.commit()
    return True


def associate_alert_to_case(db: Session, case_id: int, alert_id: int) -> tuple[CaseAlert, bool]:
    """Associate an alert to a case. Returns (case_alert, is_new)."""
    stmt = select(CaseAlert).where(CaseAlert.case_id == case_id, CaseAlert.alert_id == alert_id)
    existing = db.scalars(stmt).first()
    if existing:
        return existing, False

    case_alert = CaseAlert(case_id=case_id, alert_id=alert_id)
    try:
        db.add(case_alert)
        db.commit()
        db.refresh(case_alert)
        return case_alert, True
    except IntegrityError:
        db.rollback()
        existing = db.scalars(stmt).first()
        if existing:
            return existing, False
        raise


def is_alert_associated(db: Session, case_id: int, alert_id: int) -> bool:
    """Return True if an alert is associated with a case."""
    stmt = select(CaseAlert).where(CaseAlert.case_id == case_id, CaseAlert.alert_id == alert_id)
    return db.scalars(stmt).first() is not None


def remove_alert_from_case(db: Session, case_id: int, alert_id: int) -> bool:
    """Remove association between case and alert. Does NOT delete the alert."""
    stmt = select(CaseAlert).where(CaseAlert.case_id == case_id, CaseAlert.alert_id == alert_id)
    case_alert = db.scalars(stmt).first()
    if not case_alert:
        return False

    db.delete(case_alert)
    db.commit()
    return True


def list_case_alerts(
    db: Session,
    case_id: int,
    page: int = 1,
    page_size: int = 25,
) -> tuple[list[Alert], int]:
    """Return paginated Alert records associated with a case and total count."""
    count_stmt = select(func.count(CaseAlert.alert_id)).where(CaseAlert.case_id == case_id)
    total = db.scalar(count_stmt) or 0

    offset = max(0, (page - 1) * page_size)
    stmt = (
        select(Alert)
        .join(CaseAlert, CaseAlert.alert_id == Alert.id)
        .where(CaseAlert.case_id == case_id)
        .order_by(Alert.timestamp.desc(), Alert.id.desc())
        .offset(offset)
        .limit(page_size)
    )
    items = list(db.scalars(stmt).all())
    return items, total


def count_case_alerts(db: Session, case_id: int) -> int:
    """Return total number of alerts associated with a case."""
    stmt = select(func.count(CaseAlert.alert_id)).where(CaseAlert.case_id == case_id)
    return db.scalar(stmt) or 0


def create_case_note(db: Session, case_id: int, author_id: int, content: str) -> CaseNote:
    """Create a new case note."""
    note = CaseNote(case_id=case_id, author_id=author_id, content=content)
    db.add(note)
    db.commit()
    db.refresh(note)
    return note


def get_case_note_by_id(db: Session, note_id: int) -> CaseNote | None:
    """Retrieve a case note by id."""
    return db.get(CaseNote, note_id)


def list_case_notes(db: Session, case_id: int) -> list[CaseNote]:
    """Retrieve all case notes for a case ordered chronologically."""
    stmt = (
        select(CaseNote)
        .where(CaseNote.case_id == case_id)
        .order_by(CaseNote.created_at.asc(), CaseNote.id.asc())
    )
    return list(db.scalars(stmt).all())


def update_case_note(db: Session, note: CaseNote, content: str) -> CaseNote:
    """Update content of an existing case note."""
    note.content = content
    db.commit()
    db.refresh(note)
    return note


def delete_case_note(db: Session, note: CaseNote) -> None:
    """Delete an existing case note."""
    db.delete(note)
    db.commit()
