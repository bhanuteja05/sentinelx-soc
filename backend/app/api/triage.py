"""
backend/app/api/triage.py
~~~~~~~~~~~~~~~~~~~~~~~~~
FastAPI endpoints for SOC automated alert triage and escalation management.

Endpoints:
  GET    /api/v1/triage/rules         - List all triage rules (Analyst + Admin)
  POST   /api/v1/triage/rules         - Create a triage rule (Admin only)
  PATCH  /api/v1/triage/rules/{id}    - Update / toggle a triage rule (Admin only)
  DELETE /api/v1/triage/rules/{id}    - Delete a triage rule (Admin only)
  POST   /api/v1/triage/evaluate      - Run triage evaluation on backlog (Analyst + Admin)
"""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user, require_role
from app.db import get_db
from app.models.triage_rule import VALID_ACTION_TYPES, VALID_CASE_SEVERITIES, TriageRule
from app.models.user import User
from app.repositories.triage_rule import (
    create_triage_rule as repo_create_triage_rule,
    delete_triage_rule as repo_delete_triage_rule,
    get_triage_rule_by_id,
    get_triage_rule_by_name,
    list_triage_rules,
    update_triage_rule as repo_update_triage_rule,
)
from app.services.triage import evaluate_backlog

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/triage",
    tags=["Triage"],
)

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class TriageRuleOut(BaseModel):
    id: int
    name: str
    description: str | None = None
    is_active: bool
    min_rule_level: int | None = None
    rule_ids: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    action_type: str
    case_severity: str
    case_title_template: str
    created_at: str
    updated_at: str

    model_config = {"from_attributes": True}


class TriageRuleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128, description="Unique triage rule name")
    description: str | None = None
    is_active: bool = True
    min_rule_level: int | None = Field(None, ge=0, le=16, description="Wazuh minimum severity level (0-16)")
    rule_ids: list[str] = Field(default_factory=list, description="Target Wazuh rule IDs")
    mitre_techniques: list[str] = Field(default_factory=list, description="Target MITRE technique IDs")
    mitre_tactics: list[str] = Field(default_factory=list, description="Target MITRE tactic slugs")
    action_type: str = Field("correlate_or_create", description="correlate_or_create | create_case")
    case_severity: str = Field("high", description="critical | high | medium | low")
    case_title_template: str = Field(
        "[Auto-Triage] {rule_name}: {alert_description}",
        max_length=255,
        description="Case title template ({rule_name}, {alert_description}, {agent})",
    )


class TriageRuleUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=128)
    description: str | None = None
    is_active: bool | None = None
    min_rule_level: int | None = Field(None, ge=0, le=16)
    rule_ids: list[str] | None = None
    mitre_techniques: list[str] | None = None
    mitre_tactics: list[str] | None = None
    action_type: str | None = None
    case_severity: str | None = None
    case_title_template: str | None = Field(None, max_length=255)


class TriageActionDetail(BaseModel):
    action: str
    case_id: int
    case_title: str
    rule_id: int
    rule_name: str
    alert_id: int


class TriageEvaluateRequest(BaseModel):
    limit: int = Field(100, ge=1, le=500, description="Max unassociated alerts to evaluate")


class TriageEvaluateResponse(BaseModel):
    evaluated_alerts: int
    matched_alerts: int
    cases_created: int
    alerts_correlated: int
    unmatched_alerts: int
    details: list[TriageActionDetail]


def _rule_to_out(rule: TriageRule) -> TriageRuleOut:
    return TriageRuleOut(
        id=rule.id,
        name=rule.name,
        description=rule.description,
        is_active=rule.is_active,
        min_rule_level=rule.min_rule_level,
        rule_ids=list(rule.rule_ids or []),
        mitre_techniques=list(rule.mitre_techniques or []),
        mitre_tactics=list(rule.mitre_tactics or []),
        action_type=rule.action_type,
        case_severity=rule.case_severity,
        case_title_template=rule.case_title_template,
        created_at=rule.created_at.isoformat(),
        updated_at=rule.updated_at.isoformat(),
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/rules", response_model=list[TriageRuleOut], status_code=status.HTTP_200_OK)
def get_triage_rules_endpoint(
    is_active: bool | None = None,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_active_user),
) -> list[TriageRuleOut]:
    """List all configured triage rules. Accessible to Analysts and Admins."""
    rules = list_triage_rules(db=db, is_active=is_active)
    return [_rule_to_out(r) for r in rules]


@router.post(
    "/rules",
    response_model=TriageRuleOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_role("admin"))],
)
def create_triage_rule_endpoint(
    body: TriageRuleCreate,
    db: Session = Depends(get_db),
) -> TriageRuleOut:
    """Create a new triage rule. Admin-only."""
    clean_name = body.name.strip()
    if not clean_name:
        raise HTTPException(status_code=422, detail="Rule name cannot be empty.")

    existing = get_triage_rule_by_name(db, clean_name)
    if existing:
        raise HTTPException(status_code=409, detail=f"Triage rule with name '{clean_name}' already exists.")

    norm_action = (body.action_type or "correlate_or_create").strip().lower()
    if norm_action not in VALID_ACTION_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid action_type: '{body.action_type}'. Must be one of {sorted(VALID_ACTION_TYPES)}",
        )

    norm_severity = (body.case_severity or "high").strip().lower()
    if norm_severity not in VALID_CASE_SEVERITIES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid case_severity: '{body.case_severity}'. Must be one of {sorted(VALID_CASE_SEVERITIES)}",
        )

    rule = TriageRule(
        name=clean_name,
        description=body.description.strip() if body.description else None,
        is_active=body.is_active,
        min_rule_level=body.min_rule_level,
        rule_ids=body.rule_ids or [],
        mitre_techniques=body.mitre_techniques or [],
        mitre_tactics=body.mitre_tactics or [],
        action_type=norm_action,
        case_severity=norm_severity,
        case_title_template=body.case_title_template.strip() or "[Auto-Triage] {rule_name}: {alert_description}",
    )
    created = repo_create_triage_rule(db, rule)
    return _rule_to_out(created)


@router.patch(
    "/rules/{rule_id}",
    response_model=TriageRuleOut,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_role("admin"))],
)
def update_triage_rule_endpoint(
    rule_id: int,
    body: TriageRuleUpdate,
    db: Session = Depends(get_db),
) -> TriageRuleOut:
    """Update or toggle an existing triage rule. Admin-only."""
    rule = get_triage_rule_by_id(db, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Triage rule {rule_id} not found.")

    update_data: dict[str, Any] = {}
    if body.name is not None:
        clean_name = body.name.strip()
        if not clean_name:
            raise HTTPException(status_code=422, detail="Rule name cannot be empty.")
        existing = get_triage_rule_by_name(db, clean_name)
        if existing and existing.id != rule_id:
            raise HTTPException(status_code=409, detail=f"Rule with name '{clean_name}' already exists.")
        update_data["name"] = clean_name

    if body.description is not None:
        update_data["description"] = body.description.strip() if body.description else None

    if body.is_active is not None:
        update_data["is_active"] = body.is_active

    if body.min_rule_level is not None:
        update_data["min_rule_level"] = body.min_rule_level

    if body.rule_ids is not None:
        update_data["rule_ids"] = body.rule_ids

    if body.mitre_techniques is not None:
        update_data["mitre_techniques"] = body.mitre_techniques

    if body.mitre_tactics is not None:
        update_data["mitre_tactics"] = body.mitre_tactics

    if body.action_type is not None:
        norm_action = body.action_type.strip().lower()
        if norm_action not in VALID_ACTION_TYPES:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid action_type: '{body.action_type}'. Must be one of {sorted(VALID_ACTION_TYPES)}",
            )
        update_data["action_type"] = norm_action

    if body.case_severity is not None:
        norm_severity = body.case_severity.strip().lower()
        if norm_severity not in VALID_CASE_SEVERITIES:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid case_severity: '{body.case_severity}'. Must be one of {sorted(VALID_CASE_SEVERITIES)}",
            )
        update_data["case_severity"] = norm_severity

    if body.case_title_template is not None:
        clean_template = body.case_title_template.strip()
        update_data["case_title_template"] = clean_template or "[Auto-Triage] {rule_name}: {alert_description}"

    updated = repo_update_triage_rule(db, rule, update_data)
    return _rule_to_out(updated)


@router.delete(
    "/rules/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_role("admin"))],
)
def delete_triage_rule_endpoint(
    rule_id: int,
    db: Session = Depends(get_db),
) -> None:
    """Delete a triage rule. Admin-only."""
    rule = get_triage_rule_by_id(db, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Triage rule {rule_id} not found.")
    repo_delete_triage_rule(db, rule)


@router.post(
    "/evaluate",
    response_model=TriageEvaluateResponse,
    status_code=status.HTTP_200_OK,
)
def evaluate_triage_backlog_endpoint(
    body: TriageEvaluateRequest = TriageEvaluateRequest(),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_active_user),
) -> TriageEvaluateResponse:
    """Trigger on-demand automated triage evaluation across unassociated backlog alerts."""
    result = evaluate_backlog(db=db, limit=body.limit)
    return TriageEvaluateResponse(**result)
