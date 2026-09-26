"""
backend/app/repositories/response_action.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Database persistence layer for active response and defensive containment actions.
"""

from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.models.response_action import ResponseAction


def create_response_action(db: Session, action: ResponseAction) -> ResponseAction:
    """Persist a new ResponseAction record."""
    db.add(action)
    db.commit()
    db.refresh(action)
    return action


def get_response_action_by_id(db: Session, action_id: int) -> ResponseAction | None:
    """Retrieve a response action by its primary key ID."""
    return db.query(ResponseAction).filter(ResponseAction.id == action_id).first()


def update_response_action(
    db: Session, action: ResponseAction, updates: dict[str, Any]
) -> ResponseAction:
    """Update attributes on an existing ResponseAction record."""
    for key, value in updates.items():
        setattr(action, key, value)
    db.commit()
    db.refresh(action)
    return action


def _apply_filters(
    query,
    case_id: int | None = None,
    alert_id: int | None = None,
    agent_id: str | None = None,
    status: str | None = None,
    command: str | None = None,
    target_type: str | None = None,
):
    if case_id is not None:
        query = query.filter(ResponseAction.case_id == case_id)
    if alert_id is not None:
        query = query.filter(ResponseAction.alert_id == alert_id)
    if status is not None:
        query = query.filter(ResponseAction.status == status)
    if command is not None:
        query = query.filter(ResponseAction.command == command)
    if target_type is not None:
        query = query.filter(ResponseAction.target_type == target_type)
    if agent_id is not None:
        # Match if target_type is agent with this ID, or if agent_id is stored in parameters
        query = query.filter(
            (
                (ResponseAction.target_type == "agent")
                & (ResponseAction.target_value == agent_id)
            )
            | (ResponseAction.parameters.contains({"agent_id": agent_id}))
        )
    return query


def list_response_actions(
    db: Session,
    page: int = 1,
    page_size: int = 25,
    case_id: int | None = None,
    alert_id: int | None = None,
    agent_id: str | None = None,
    status: str | None = None,
    command: str | None = None,
    target_type: str | None = None,
) -> list[ResponseAction]:
    """Retrieve paginated response actions ordered by creation time descending."""
    query = db.query(ResponseAction)
    query = _apply_filters(
        query,
        case_id=case_id,
        alert_id=alert_id,
        agent_id=agent_id,
        status=status,
        command=command,
        target_type=target_type,
    )
    offset = (page - 1) * page_size
    return query.order_by(desc(ResponseAction.created_at)).offset(offset).limit(page_size).all()


def count_response_actions(
    db: Session,
    case_id: int | None = None,
    alert_id: int | None = None,
    agent_id: str | None = None,
    status: str | None = None,
    command: str | None = None,
    target_type: str | None = None,
) -> int:
    """Return total count of response actions matching the specified filters."""
    query = db.query(func.count(ResponseAction.id))
    query = _apply_filters(
        query,
        case_id=case_id,
        alert_id=alert_id,
        agent_id=agent_id,
        status=status,
        command=command,
        target_type=target_type,
    )
    return query.scalar() or 0
