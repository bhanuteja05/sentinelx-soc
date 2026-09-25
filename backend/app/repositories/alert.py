from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.alert import Alert

SORTABLE_FIELDS: dict[str, Any] = {
    "timestamp": Alert.timestamp,
    "rule_level": Alert.rule_level,
    "id": Alert.id,
    "rule_id": Alert.rule_id,
    "created_at": Alert.created_at,
}


def _build_alert_filter_clauses(
    rule_level: int | None = None,
    min_rule_level: int | None = None,
    max_rule_level: int | None = None,
    agent_id: str | None = None,
    agent_name: str | None = None,
    rule_id: str | None = None,
    mitre_tactic: str | None = None,
    mitre_technique: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> list[Any]:
    """Build reusable SQLAlchemy filter clauses for alert queries."""
    clauses: list[Any] = []

    if rule_level is not None:
        clauses.append(Alert.rule_level == rule_level)
    else:
        if min_rule_level is not None:
            clauses.append(Alert.rule_level >= min_rule_level)
        if max_rule_level is not None:
            clauses.append(Alert.rule_level <= max_rule_level)

    if agent_id is not None:
        clauses.append(Alert.agent_id == agent_id)
    if agent_name is not None:
        clauses.append(Alert.agent_name == agent_name)
    if rule_id is not None:
        clauses.append(Alert.rule_id == rule_id)
    if mitre_tactic is not None:
        clauses.append(Alert.mitre_tactics.contains([mitre_tactic]))
    if mitre_technique is not None:
        clauses.append(Alert.mitre_techniques.contains([mitre_technique]))
    if start_time is not None:
        clauses.append(Alert.timestamp >= start_time)
    if end_time is not None:
        clauses.append(Alert.timestamp <= end_time)

    return clauses


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


def search_alerts(
    db: Session,
    page: int = 1,
    page_size: int = 25,
    sort_by: str = "timestamp",
    sort_order: str = "desc",
    rule_level: int | None = None,
    min_rule_level: int | None = None,
    max_rule_level: int | None = None,
    agent_id: str | None = None,
    agent_name: str | None = None,
    rule_id: str | None = None,
    mitre_tactic: str | None = None,
    mitre_technique: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> tuple[list[Alert], int]:
    """Search and paginate alerts with dynamic filtering and strict sort allowlisting.

    Returns:
        (items, total_count)
    """
    clauses = _build_alert_filter_clauses(
        rule_level=rule_level,
        min_rule_level=min_rule_level,
        max_rule_level=max_rule_level,
        agent_id=agent_id,
        agent_name=agent_name,
        rule_id=rule_id,
        mitre_tactic=mitre_tactic,
        mitre_technique=mitre_technique,
        start_time=start_time,
        end_time=end_time,
    )

    # 1. Filtered count
    count_stmt = select(func.count(Alert.id))
    if clauses:
        count_stmt = count_stmt.where(*clauses)
    total = db.scalar(count_stmt) or 0

    # 2. Sort ordering with allowlist
    sort_col = SORTABLE_FIELDS.get(sort_by, Alert.timestamp)
    primary_order = sort_col.asc() if sort_order.lower() == "asc" else sort_col.desc()

    order_clauses = [primary_order]
    # Add secondary tie-breaker if primary sort is not id for deterministic pagination
    if sort_by != "id":
        order_clauses.append(Alert.id.desc())

    # 3. Paginated items
    offset = max(0, (page - 1) * page_size)
    stmt = select(Alert)
    if clauses:
        stmt = stmt.where(*clauses)
    stmt = stmt.order_by(*order_clauses).offset(offset).limit(page_size)

    items = list(db.scalars(stmt).all())
    return items, total


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
    stmt = select(func.count(Alert.id))
    return db.scalar(stmt) or 0
