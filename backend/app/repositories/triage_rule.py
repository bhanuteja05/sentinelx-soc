"""
backend/app/repositories/triage_rule.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Data access repository for automated SOC triage rules.
"""

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.triage_rule import TriageRule


def create_triage_rule(db: Session, rule: TriageRule | dict[str, Any]) -> TriageRule:
    """Persist a new triage rule."""
    if isinstance(rule, dict):
        db_rule = TriageRule(**rule)
    else:
        db_rule = rule
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    return db_rule


def get_triage_rule_by_id(db: Session, rule_id: int) -> TriageRule | None:
    """Retrieve a triage rule by primary key."""
    return db.get(TriageRule, rule_id)


def get_triage_rule_by_name(db: Session, name: str) -> TriageRule | None:
    """Retrieve a triage rule by its unique name."""
    stmt = select(TriageRule).where(TriageRule.name == name)
    return db.scalars(stmt).first()


def list_triage_rules(db: Session, is_active: bool | None = None) -> list[TriageRule]:
    """List all triage rules ordered by id asc, optionally filtered by active status."""
    stmt = select(TriageRule)
    if is_active is not None:
        stmt = stmt.where(TriageRule.is_active == is_active)
    stmt = stmt.order_by(TriageRule.id.asc())
    return list(db.scalars(stmt).all())


def get_active_triage_rules(db: Session) -> list[TriageRule]:
    """Retrieve active triage rules for evaluation."""
    stmt = select(TriageRule).where(TriageRule.is_active.is_(True)).order_by(TriageRule.id.asc())
    return list(db.scalars(stmt).all())


def update_triage_rule(
    db: Session, rule: TriageRule, update_data: dict[str, Any]
) -> TriageRule:
    """Apply updates to an existing triage rule."""
    for key, value in update_data.items():
        if hasattr(rule, key) and value is not None:
            setattr(rule, key, value)
    db.commit()
    db.refresh(rule)
    return rule


def delete_triage_rule(db: Session, rule: TriageRule) -> None:
    """Delete a triage rule."""
    db.delete(rule)
    db.commit()
