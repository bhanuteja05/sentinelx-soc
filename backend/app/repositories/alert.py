from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.alert import Alert


def create_alert(db: Session, alert: Alert | dict[str, Any]) -> Alert:
    if isinstance(alert, dict):
        db_alert = Alert(**alert)
    else:
        db_alert = alert
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    return db_alert


def get_alert_by_id(db: Session, alert_id: int) -> Alert | None:
    return db.get(Alert, alert_id)


def get_alert_by_wazuh_id(db: Session, wazuh_alert_id: str) -> Alert | None:
    stmt = select(Alert).where(Alert.wazuh_alert_id == wazuh_alert_id)
    return db.scalars(stmt).first()


def list_alerts(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    rule_id: str | None = None,
    min_level: int | None = None,
    agent_id: str | None = None,
) -> list[Alert]:
    stmt = select(Alert)
    if rule_id:
        stmt = stmt.where(Alert.rule_id == rule_id)
    if min_level is not None:
        stmt = stmt.where(Alert.rule_level >= min_level)
    if agent_id:
        stmt = stmt.where(Alert.agent_id == agent_id)

    stmt = stmt.order_by(Alert.timestamp.desc()).offset(skip).limit(limit)
    return list(db.scalars(stmt).all())


def count_alerts(db: Session) -> int:
    from sqlalchemy import func
    stmt = select(func.count(Alert.id))
    return db.scalar(stmt) or 0
