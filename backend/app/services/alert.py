from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.repositories.alert import (
    count_alerts,
    create_alert,
    get_alert_by_id,
    get_alert_by_wazuh_id,
    list_alerts,
)


def ingest_alert(db: Session, alert_dict: dict[str, Any]) -> tuple[Alert, bool]:
    """Ingest an alert, deduplicating by wazuh_alert_id.

    Returns (alert, is_new) where is_new=False means the alert already existed.
    Safe under concurrent ingestion: if two requests race past the pre-check,
    the DB unique constraint fires and the IntegrityError is caught here;
    the session is rolled back and the existing row is returned.
    """
    wazuh_id = alert_dict.get("wazuh_alert_id")
    if wazuh_id:
        existing = get_alert_by_wazuh_id(db, wazuh_id)
        if existing:
            return existing, False

    try:
        new_alert = create_alert(db, alert_dict)
        return new_alert, True
    except IntegrityError:
        db.rollback()
        # Another concurrent request committed the same wazuh_alert_id first.
        if wazuh_id:
            existing = get_alert_by_wazuh_id(db, wazuh_id)
            if existing:
                return existing, False
        raise



def get_alert(db: Session, alert_id: int) -> Alert | None:
    return get_alert_by_id(db, alert_id)


def get_alert_by_external_id(db: Session, wazuh_id: str) -> Alert | None:
    return get_alert_by_wazuh_id(db, wazuh_id)


def get_recent_alerts(
    db: Session,
    skip: int = 0,
    limit: int = 50,
    rule_id: str | None = None,
    min_level: int | None = None,
    agent_id: str | None = None,
) -> list[Alert]:
    return list_alerts(
        db=db,
        skip=skip,
        limit=limit,
        rule_id=rule_id,
        min_level=min_level,
        agent_id=agent_id,
    )


def get_alert_count(db: Session) -> int:
    return count_alerts(db)
