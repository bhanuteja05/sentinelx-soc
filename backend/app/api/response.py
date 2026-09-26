"""
backend/app/api/response.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~
FastAPI router for defensive host containment and Wazuh Active Response orchestration.

Endpoints:
  GET  /api/v1/response/commands     - List approved Active Response commands catalog
  POST /api/v1/response/execute      - Execute an approved containment action (Analyst/Admin)
  GET  /api/v1/response/actions      - Query paginated response action history
  GET  /api/v1/response/actions/{id} - Retrieve details for a specific response action
"""

import logging
import math
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user, require_role
from app.db import get_db
from app.models.response_action import ResponseAction
from app.models.user import User
from app.repositories.response_action import (
    count_response_actions,
    get_response_action_by_id,
    list_response_actions,
)
from app.services.response import (
    ResponseCommandInvalidError,
    ResponseDisabledError,
    ResponseSafetyError,
    TargetNotFoundError,
    execute_containment_action,
    get_approved_commands,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/response",
    tags=["Active Response"],
)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ApprovedCommandOut(BaseModel):
    command: str
    name: str
    description: str
    target_type: str
    risk_level: str
    requires_agent_id: bool
    wazuh_command: str
    warning: str


class ExecuteResponseRequest(BaseModel):
    command: str = Field(..., description="Approved active response command identifier")
    target_type: str = Field(..., description="Target type: 'ip' or 'agent'")
    target_value: str = Field(..., description="Target IP address or agent identifier")
    agent_id: str | None = Field(None, description="Target Wazuh agent ID (for IP containment)")
    case_id: int | None = Field(None, description="Optional associated Case ID")
    alert_id: int | None = Field(None, description="Optional associated Alert ID")
    parameters: dict[str, Any] = Field(default_factory=dict, description="Additional command parameters")


class ResponseActionOut(BaseModel):
    id: int
    case_id: int | None = None
    alert_id: int | None = None
    action_type: str
    command: str
    target_type: str
    target_value: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    status: str
    execution_output: dict[str, Any] | None = None
    error_message: str | None = None
    executed_by_id: int | None = None
    created_at: str
    completed_at: str | None = None

    model_config = {"from_attributes": True}


class ResponseActionListResponse(BaseModel):
    items: list[ResponseActionOut]
    total: int
    page: int
    page_size: int
    pages: int


def _action_to_out(action: ResponseAction) -> ResponseActionOut:
    return ResponseActionOut(
        id=action.id,
        case_id=action.case_id,
        alert_id=action.alert_id,
        action_type=action.action_type,
        command=action.command,
        target_type=action.target_type,
        target_value=action.target_value,
        parameters=action.parameters or {},
        status=action.status,
        execution_output=action.execution_output,
        error_message=action.error_message,
        executed_by_id=action.executed_by_id,
        created_at=action.created_at.isoformat() if action.created_at else "",
        completed_at=action.completed_at.isoformat() if action.completed_at else None,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/commands", response_model=list[ApprovedCommandOut], status_code=status.HTTP_200_OK)
def list_commands(
    _user: User = Depends(get_current_active_user),
) -> list[ApprovedCommandOut]:
    """Retrieve catalog of approved Active Response commands and safety constraints."""
    commands = get_approved_commands()
    return [ApprovedCommandOut(**cmd) for cmd in commands]


@router.post("/execute", response_model=ResponseActionOut, status_code=status.HTTP_200_OK)
def execute_response(
    payload: ExecuteResponseRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("analyst")),
) -> ResponseActionOut:
    """Execute a defensive Active Response command against an approved target."""
    try:
        action = execute_containment_action(
            db=db,
            command=payload.command,
            target_type=payload.target_type,
            target_value=payload.target_value,
            agent_id=payload.agent_id,
            case_id=payload.case_id,
            alert_id=payload.alert_id,
            parameters=payload.parameters,
            actor=current_user,
        )
        return _action_to_out(action)
    except ResponseDisabledError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ResponseSafetyError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    except ResponseCommandInvalidError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except TargetNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.get("/actions", response_model=ResponseActionListResponse, status_code=status.HTTP_200_OK)
def get_actions(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(25, ge=1, le=100, description="Items per page"),
    case_id: int | None = Query(None, description="Filter by Case ID"),
    alert_id: int | None = Query(None, description="Filter by Alert ID"),
    agent_id: str | None = Query(None, description="Filter by Agent ID"),
    status_filter: str | None = Query(None, alias="status", description="Filter by action status"),
    command: str | None = Query(None, description="Filter by command"),
    target_type: str | None = Query(None, description="Filter by target type"),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_active_user),
) -> ResponseActionListResponse:
    """Query paginated execution log of active response and containment actions."""
    total = count_response_actions(
        db,
        case_id=case_id,
        alert_id=alert_id,
        agent_id=agent_id,
        status=status_filter,
        command=command,
        target_type=target_type,
    )
    items = list_response_actions(
        db,
        page=page,
        page_size=page_size,
        case_id=case_id,
        alert_id=alert_id,
        agent_id=agent_id,
        status=status_filter,
        command=command,
        target_type=target_type,
    )
    pages = math.ceil(total / page_size) if total > 0 else 1

    return ResponseActionListResponse(
        items=[_action_to_out(item) for item in items],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get("/actions/{action_id}", response_model=ResponseActionOut, status_code=status.HTTP_200_OK)
def get_action_detail(
    action_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_active_user),
) -> ResponseActionOut:
    """Retrieve detailed execution audit record for a single response action."""
    action = get_response_action_by_id(db, action_id)
    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Response action {action_id} not found.",
        )
    return _action_to_out(action)
