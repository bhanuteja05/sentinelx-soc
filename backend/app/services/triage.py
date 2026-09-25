"""
backend/app/services/triage.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Automated SOC alert triage and incident escalation engine.

Evaluates security alerts against configured active triage rules:
  - Severity thresholds (min_rule_level)
  - Wazuh rule IDs
  - MITRE ATT&CK tactics and techniques
Automates Case creation, campaign correlation by host/agent within 24h,
and auditable investigation timeline notes.
"""

from datetime import datetime, timedelta, timezone
import logging
import re
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.models.alert import Alert
from app.models.case import Case
from app.models.case_alert import CaseAlert
from app.models.triage_rule import TriageRule
from app.models.user import User
from app.repositories.triage_rule import (
    create_triage_rule,
    delete_triage_rule,
    get_active_triage_rules,
    get_triage_rule_by_id,
    get_triage_rule_by_name,
    list_triage_rules,
    update_triage_rule,
)
from app.services.case import add_case_note, associate_alert_service, open_case

logger = logging.getLogger(__name__)


def render_case_title(
    template: str | None,
    rule_name: str,
    alert_description: str | None,
    agent: str | None,
) -> str:
    """Safely render a case title template using strict placeholder substitution.

    Supported placeholders:
      - {rule_name}
      - {alert_description}
      - {agent}
    Never uses eval, exec, or arbitrary format execution.
    """
    tmpl = (template or "").strip() or "[Auto-Triage] {rule_name}: {alert_description}"

    replacements = {
        "{rule_name}": rule_name or "Triage Rule",
        "{alert_description}": alert_description or "Security Alert",
        "{agent}": agent or "Unknown Host",
    }

    result = tmpl
    for placeholder, val in replacements.items():
        result = result.replace(placeholder, str(val))

    # Strip any remaining unsupported {placeholder} tokens safely
    result = re.sub(r"\{[a-zA-Z0-9_]+\}", "", result)

    clean_title = " ".join(result.split())[:255].strip()
    return clean_title or "[Auto-Triage] Security Alert"


def get_or_create_system_user(db: Session) -> User:
    """Retrieve or create the system bot user for automated triage attribution."""
    system_user = db.scalars(select(User).where(User.username == "system")).first()
    if system_user:
        return system_user

    # Fallback to existing admin user if present
    admin_user = db.scalars(select(User).where(User.username == "admin")).first()
    if admin_user:
        return admin_user

    # Create dedicated system bot user (role='admin' so it satisfies user constraints)
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


def rule_matches_alert(rule: TriageRule, alert: Alert) -> bool:
    """Evaluate whether an alert satisfies all configured conditions of a triage rule."""
    if not rule.is_active:
        return False

    has_condition = False

    # 1. Minimum Rule Level
    if rule.min_rule_level is not None:
        has_condition = True
        if alert.rule_level is None or alert.rule_level < rule.min_rule_level:
            return False

    # 2. Wazuh Rule IDs
    if rule.rule_ids and len(rule.rule_ids) > 0:
        has_condition = True
        if not alert.rule_id or str(alert.rule_id) not in [str(r) for r in rule.rule_ids]:
            return False

    # 3. MITRE Tactics
    if rule.mitre_tactics and len(rule.mitre_tactics) > 0:
        has_condition = True
        alert_tactics = alert.mitre_tactics or []
        if not any(tac in alert_tactics for tac in rule.mitre_tactics):
            return False

    # 4. MITRE Techniques
    if rule.mitre_techniques and len(rule.mitre_techniques) > 0:
        has_condition = True
        alert_techniques = alert.mitre_techniques or []
        if not any(tech in alert_techniques for tech in rule.mitre_techniques):
            return False

    # Prevent empty rules with no criteria from matching every alert
    return has_condition


def _build_triage_note_content(
    action: str, rule: TriageRule, alert: Alert, now: datetime
) -> str:
    """Format an auditable, structured case note documenting automated triage action."""
    tactics_str = ", ".join(alert.mitre_tactics) if alert.mitre_tactics else "None"
    techniques_str = ", ".join(alert.mitre_techniques) if alert.mitre_techniques else "None"
    agent_str = alert.agent_name or alert.agent_id or "N/A"
    level_str = str(alert.rule_level) if alert.rule_level is not None else "N/A"

    return (
        f"[Automated Triage] Alert Escalation ({action.upper()})\n"
        f"Rule: {rule.name} (ID: {rule.id})\n"
        f"Action: {action.upper()}\n"
        f"Alert ID: {alert.id} (Wazuh ID: {alert.wazuh_alert_id})\n"
        f"Rule Level: {level_str} | Rule ID: {alert.rule_id}\n"
        f"Agent: {agent_str}\n"
        f"MITRE Tactics: {tactics_str}\n"
        f"MITRE Techniques: {techniques_str}\n"
        f"Trigger Description: {alert.description or 'No description'}\n"
        f"Timestamp: {now.isoformat()}"
    )


def evaluate_alert_against_rules(
    db: Session, alert: Alert
) -> dict[str, Any] | None:
    """Evaluate a single alert against active triage rules.

    If an alert matches:
      - correlate_or_create: searches for an open case associated with the same agent/host
        within 24 hours. Attaches if found; creates new case if none exists.
      - create_case: always creates a new case.
    Logs an auditable case note on the case timeline.
    Idempotent: skips evaluation if the alert is already attached to any case.
    """
    # 1. Idempotency: verify alert is not already associated with a case
    existing_assoc = db.scalars(
        select(CaseAlert).where(CaseAlert.alert_id == alert.id)
    ).first()
    if existing_assoc:
        return None

    # 2. Find first active matching rule
    active_rules = get_active_triage_rules(db)
    matched_rule: TriageRule | None = None
    for r in active_rules:
        if rule_matches_alert(r, alert):
            matched_rule = r
            break

    if not matched_rule:
        return None

    now = datetime.now(timezone.utc)
    system_user = get_or_create_system_user(db)
    agent_identifier = alert.agent_name or alert.agent_id

    # 3. Campaign correlation check (if correlate_or_create)
    target_case: Case | None = None
    if matched_rule.action_type == "correlate_or_create" and agent_identifier:
        cutoff_24h = now - timedelta(hours=24)
        case_stmt = (
            select(Case)
            .join(CaseAlert, Case.id == CaseAlert.case_id)
            .join(Alert, Alert.id == CaseAlert.alert_id)
            .where(
                Case.status != "closed",
                Case.created_at >= cutoff_24h,
                or_(
                    Alert.agent_id == alert.agent_id if alert.agent_id else False,
                    Alert.agent_name == alert.agent_name if alert.agent_name else False,
                ),
            )
            .order_by(Case.created_at.desc(), Case.id.desc())
            .limit(1)
        )
        target_case = db.scalars(case_stmt).first()

    # 4. Execute Action
    if target_case:
        # Correlate alert to existing open case
        associate_alert_service(db, target_case.id, alert.id)
        note_content = _build_triage_note_content("CORRELATE", matched_rule, alert, now)
        add_case_note(
            db,
            case_id=target_case.id,
            author_id=system_user.id,
            content=note_content,
        )
        logger.info(
            "Triage: Correlated alert %d into Case #%d via rule '%s'",
            alert.id,
            target_case.id,
            matched_rule.name,
        )
        return {
            "action": "correlate",
            "case_id": target_case.id,
            "case_title": target_case.title,
            "rule_id": matched_rule.id,
            "rule_name": matched_rule.name,
            "alert_id": alert.id,
        }
    else:
        # Create new incident case
        rendered_title = render_case_title(
            matched_rule.case_title_template,
            matched_rule.name,
            alert.description,
            agent_identifier,
        )
        new_case = open_case(
            db=db,
            title=rendered_title,
            description=f"Auto-escalated by Triage Rule: {matched_rule.name} (Rule ID: {matched_rule.id})",
            severity=matched_rule.case_severity,
            status="open",
        )
        associate_alert_service(db, new_case.id, alert.id)
        note_content = _build_triage_note_content("CREATE", matched_rule, alert, now)
        add_case_note(
            db,
            case_id=new_case.id,
            author_id=system_user.id,
            content=note_content,
        )
        logger.info(
            "Triage: Auto-created Case #%d for alert %d via rule '%s'",
            new_case.id,
            alert.id,
            matched_rule.name,
        )
        return {
            "action": "create",
            "case_id": new_case.id,
            "case_title": new_case.title,
            "rule_id": matched_rule.id,
            "rule_name": matched_rule.name,
            "alert_id": alert.id,
        }


def evaluate_backlog(db: Session, limit: int = 100) -> dict[str, Any]:
    """Run triage evaluation across unassociated alerts in the backlog."""
    safe_limit = min(max(1, limit), 500)

    # Find unassociated alerts
    unassociated_stmt = (
        select(Alert)
        .outerjoin(CaseAlert, Alert.id == CaseAlert.alert_id)
        .where(CaseAlert.case_id.is_(None))
        .order_by(Alert.timestamp.desc(), Alert.id.desc())
        .limit(safe_limit)
    )
    unassociated_alerts = list(db.scalars(unassociated_stmt).all())

    cases_created = 0
    alerts_correlated = 0
    matched_count = 0
    details = []

    for alert in unassociated_alerts:
        try:
            res = evaluate_alert_against_rules(db, alert)
            if res:
                matched_count += 1
                if res["action"] == "create":
                    cases_created += 1
                elif res["action"] == "correlate":
                    alerts_correlated += 1
                details.append(res)
        except Exception as exc:
            logger.error("Error evaluating backlog alert %d (%s): %s", alert.id, type(exc).__name__, exc)

    return {
        "evaluated_alerts": len(unassociated_alerts),
        "matched_alerts": matched_count,
        "cases_created": cases_created,
        "alerts_correlated": alerts_correlated,
        "unmatched_alerts": len(unassociated_alerts) - matched_count,
        "details": details,
    }
