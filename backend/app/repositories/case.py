from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.case import Case


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


def list_cases(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    status: str | None = None,
    severity: str | None = None,
) -> list[Case]:
    stmt = select(Case)
    if status:
        stmt = stmt.where(Case.status == status)
    if severity:
        stmt = stmt.where(Case.severity == severity)

    stmt = stmt.order_by(Case.created_at.desc()).offset(skip).limit(limit)
    return list(db.scalars(stmt).all())


def update_case(db: Session, case_id: int, update_data: dict[str, Any]) -> Case | None:
    db_case = get_case_by_id(db, case_id)
    if not db_case:
        return None

    for key, value in update_data.items():
        if hasattr(db_case, key) and key != "id":
            setattr(db_case, key, value)

    db.commit()
    db.refresh(db_case)
    return db_case


def delete_case(db: Session, case_id: int) -> bool:
    db_case = get_case_by_id(db, case_id)
    if not db_case:
        return False

    db.delete(db_case)
    db.commit()
    return True
