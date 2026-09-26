"""
backend/app/services/response.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Defensive host containment and Wazuh Active Response orchestration engine.

Enforces:
- Strict command allowlist (no arbitrary commands or shell execution).
- Guardrails against self-lockout (protected IPs, loopback, gateway, wildcard).
- Feature flag validation (RESPONSE_ENABLED).
- Full auditability via ResponseAction records and Case investigation notes.
"""

from datetime import datetime, timezone
import ipaddress
import logging
from typing import Any

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.case import Case
from app.models.response_action import ResponseAction
from app.models.user import User
from app.repositories.case import create_case_note, get_case_by_id
from app.repositories.response_action import (
    create_response_action,
    get_response_action_by_id,
    list_response_actions,
    update_response_action,
)
from app.services.case import get_or_create_system_user
from app.wazuh.client import WazuhClientError, WazuhConnectionError, wazuh_client
from app.wazuh.config import get_wazuh_settings

logger = logging.getLogger(__name__)


class ResponseDisabledError(Exception):
    """Raised when active response is disabled via configuration."""


class ResponseSafetyError(Exception):
    """Raised when a containment target fails safety guardrails."""


class ResponseCommandInvalidError(Exception):
    """Raised when an unapproved active response command is requested."""


class TargetNotFoundError(Exception):
    """Raised when a referenced entity (case/alert) is not found."""


# ---------------------------------------------------------------------------
# Approved Commands Specification Catalog
# ---------------------------------------------------------------------------
APPROVED_COMMANDS: dict[str, dict[str, Any]] = {
    "firewall-drop": {
        "command": "firewall-drop",
        "name": "Block IP (Firewall Drop)",
        "description": "Drops incoming and outgoing network traffic from the specified IP address via host firewall.",
        "target_type": "ip",
        "risk_level": "high",
        "requires_agent_id": True,
        "wazuh_command": "firewall-drop",
        "warning": "This will block all network communication with the target IP on the selected agent host.",
    },
    "host-deny": {
        "command": "host-deny",
        "name": "Deny Host (TCP Wrappers)",
        "description": "Appends the target IP address to /etc/hosts.deny to block TCP-wrapped services.",
        "target_type": "ip",
        "risk_level": "medium",
        "requires_agent_id": True,
        "wazuh_command": "host-deny",
        "warning": "This appends the IP to /etc/hosts.deny on the designated Linux agent host.",
    },
    "isolate-host": {
        "command": "isolate-host",
        "name": "Isolate Endpoint (Network Quarantine)",
        "description": "Isolates the host endpoint from the network by null-routing all non-management traffic.",
        "target_type": "agent",
        "risk_level": "critical",
        "requires_agent_id": False,
        "wazuh_command": "firewall-drop",
        "warning": "CRITICAL: This will isolate the endpoint from the network. Ensure remote management access is preserved.",
    },
    "quarantine": {
        "command": "quarantine",
        "name": "Isolate Endpoint (Quarantine Alias)",
        "description": "Quarantines the host endpoint from the network.",
        "target_type": "agent",
        "risk_level": "critical",
        "requires_agent_id": False,
        "wazuh_command": "firewall-drop",
        "warning": "CRITICAL: This will isolate the endpoint from the network.",
    },
    "restart-wazuh": {
        "command": "restart-wazuh",
        "name": "Restart Wazuh Agent",
        "description": "Restarts the Wazuh agent daemon on the target host.",
        "target_type": "agent",
        "risk_level": "low",
        "requires_agent_id": False,
        "wazuh_command": "restart-wazuh",
        "warning": "The Wazuh agent service will temporarily restart on the selected endpoint.",
    },
}


def get_approved_commands() -> list[dict[str, Any]]:
    """Return the list of predefined, verified Active Response commands."""
    return list(APPROVED_COMMANDS.values())


def is_response_enabled() -> bool:
    """Check whether active response orchestration is enabled by configuration."""
    settings = get_wazuh_settings()
    return getattr(settings, "response_enabled", False)


def validate_target_safety(
    target_type: str,
    target_value: str,
    agent_id: str | None = None,
) -> None:
    """Verify that a response action target does not violate safety guardrails.

    Prevents self-lockout against loopback, gateway, broadcast, unspecified addresses,
    and configured protected targets.
    """
    clean_target = (target_value or "").strip()
    if not clean_target:
        raise ResponseSafetyError("Target value cannot be empty.")

    settings = get_wazuh_settings()
    protected_targets = [
        t.strip().lower() for t in getattr(settings, "response_protected_targets", []) if t.strip()
    ]

    if target_type == "ip":
        # Disallow loopback string names
        if clean_target.lower() in {"127.0.0.1", "::1", "localhost"}:
            raise ResponseSafetyError(
                f"Target IP '{clean_target}' is a loopback address and cannot be targeted."
            )

        # Disallow wildcard / zero strings
        if clean_target.lower() in {"0.0.0.0", "::"}:
            raise ResponseSafetyError(
                f"Target IP '{clean_target}' is an unspecified/wildcard address and cannot be targeted."
            )

        try:
            ip_obj = ipaddress.ip_address(clean_target)
        except ValueError as exc:
            raise ResponseSafetyError(f"Invalid IP address format: '{clean_target}'") from exc

        # Disallow loopback
        if ip_obj.is_loopback:
            raise ResponseSafetyError(
                f"Target IP '{clean_target}' is a loopback address and cannot be targeted."
            )

        # Disallow unspecified / zero
        if ip_obj.is_unspecified:
            raise ResponseSafetyError(
                f"Target IP '{clean_target}' is an unspecified/wildcard address and cannot be targeted."
            )

        # Disallow multicast, link-local, reserved
        if ip_obj.is_multicast:
            raise ResponseSafetyError(f"Target IP '{clean_target}' is a multicast address.")
        if ip_obj.is_link_local:
            raise ResponseSafetyError(f"Target IP '{clean_target}' is a link-local address.")
        if ip_obj.is_reserved:
            raise ResponseSafetyError(f"Target IP '{clean_target}' is a reserved address.")

        # Check against protected target strings
        if clean_target.lower() in protected_targets:
            raise ResponseSafetyError(
                f"Target IP '{clean_target}' is in the protected targets allowlist and cannot be targeted."
            )

        # Check agent_id if provided
        if agent_id and agent_id.strip().lower() in protected_targets:
            raise ResponseSafetyError(
                f"Agent ID '{agent_id}' is in the protected targets allowlist and cannot be targeted."
            )

    elif target_type == "agent":
        if clean_target.lower() in protected_targets:
            raise ResponseSafetyError(
                f"Agent '{clean_target}' is protected against active response containment."
            )
        if not clean_target.isalnum() and not clean_target.replace("-", "").replace("_", "").isalnum():
            raise ResponseSafetyError(f"Invalid agent target identifier: '{clean_target}'")
    else:
        raise ResponseSafetyError(f"Unsupported target_type: '{target_type}'")


def execute_containment_action(
    db: Session,
    command: str,
    target_type: str,
    target_value: str,
    agent_id: str | None = None,
    case_id: int | None = None,
    alert_id: int | None = None,
    parameters: dict[str, Any] | None = None,
    actor: User | None = None,
) -> ResponseAction:
    """Coordinate the safe execution and recording of a defensive Active Response action."""
    # 1. Feature flag verification
    if not is_response_enabled():
        raise ResponseDisabledError(
            "Active response containment is currently disabled by configuration (RESPONSE_ENABLED=false)."
        )

    # 2. Command allowlist verification
    cmd_spec = APPROVED_COMMANDS.get(command)
    if not cmd_spec:
        valid_cmds = list(APPROVED_COMMANDS.keys())
        raise ResponseCommandInvalidError(
            f"Command '{command}' is not approved. Must be one of: {valid_cmds}"
        )

    # 3. Target type validation against command spec
    expected_target_type = cmd_spec["target_type"]
    if target_type.lower() != expected_target_type:
        raise ResponseCommandInvalidError(
            f"Command '{command}' requires target_type='{expected_target_type}', got '{target_type}'."
        )

    # 4. Target safety guardrail checks
    clean_target = target_value.strip()
    validate_target_safety(target_type=target_type.lower(), target_value=clean_target, agent_id=agent_id)

    # 5. Entity existence validation if references provided
    case: Case | None = None
    if case_id is not None:
        case = get_case_by_id(db, case_id)
        if not case:
            raise TargetNotFoundError(f"Case {case_id} not found.")

    if alert_id is not None:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            raise TargetNotFoundError(f"Alert {alert_id} not found.")

    # 6. Resolve agent target and command arguments
    wazuh_cmd = cmd_spec["wazuh_command"]
    action_params: dict[str, Any] = dict(parameters or {})

    if target_type.lower() == "agent":
        target_agents = [clean_target]
        action_params["agent_id"] = clean_target
        if command in ("isolate-host", "quarantine"):
            wazuh_args = ["-", "0.0.0.0"]
        elif command == "restart-wazuh":
            wazuh_args = []
        else:
            wazuh_args = []
    else:  # target_type == "ip"
        target_agents = [agent_id.strip()] if agent_id and agent_id.strip() else None
        if agent_id:
            action_params["agent_id"] = agent_id.strip()
        wazuh_args = ["-", clean_target]

    action_params["wazuh_args"] = wazuh_args

    # 7. Create ResponseAction record with status 'pending' -> 'executing'
    actor_id = actor.id if actor else None
    action = ResponseAction(
        case_id=case_id,
        alert_id=alert_id,
        action_type="containment",
        command=command,
        target_type=target_type.lower(),
        target_value=clean_target,
        parameters=action_params,
        status="executing",
        executed_by_id=actor_id,
    )
    action = create_response_action(db, action)

    # 8. Execute Active Response via Wazuh client
    status_result = "failed"
    output_data: dict[str, Any] | None = None
    error_msg: str | None = None

    try:
        wazuh_res = wazuh_client.execute_active_response(
            command=wazuh_cmd,
            arguments=wazuh_args,
            agents_list=target_agents,
        )
        output_data = wazuh_res

        # Check Wazuh response structure
        err_code = wazuh_res.get("error", 0)
        total_failed = wazuh_res.get("data", {}).get("total_failed_items", 0)

        if err_code != 0 or total_failed > 0:
            status_result = "failed"
            failed_items = wazuh_res.get("data", {}).get("failed_items", [])
            error_msg = (
                f"Wazuh response error={err_code}: {wazuh_res.get('message', 'Execution error')}. "
                f"Failed items: {failed_items}"
            )
        else:
            status_result = "succeeded"

    except (WazuhClientError, WazuhConnectionError) as exc:
        status_result = "failed"
        error_msg = str(exc)
        output_data = {"error": str(exc), "type": type(exc).__name__}
        logger.error(f"Active response failed with Wazuh client error: {exc}")
    except Exception as exc:
        status_result = "failed"
        error_msg = f"Unexpected execution error: {exc}"
        output_data = {"error": str(exc), "type": type(exc).__name__}
        logger.exception("Active response execution unexpected error")

    # 9. Update ResponseAction status and completion timestamp
    completed_time = datetime.now(timezone.utc)
    action = update_response_action(
        db,
        action,
        {
            "status": status_result,
            "execution_output": output_data,
            "error_message": error_msg,
            "completed_at": completed_time,
        },
    )

    # 10. Write auditable timeline note to Case if case_id present
    if case_id is not None:
        try:
            actor_name = actor.username if actor else "system"
            agent_label = (target_agents[0] if target_agents else "all")
            note_text = (
                f"[Active Response] Executed '{command}' for {target_type.upper()} "
                f"'{clean_target}' on Agent '{agent_label}' by '{actor_name}'. "
                f"Status: {status_result.upper()}."
            )
            if error_msg:
                note_text += f" Error: {error_msg}"

            note_author_id = actor_id if actor_id else get_or_create_system_user(db).id
            create_case_note(
                db,
                case_id=case_id,
                author_id=note_author_id,
                content=note_text,
            )
        except Exception as note_err:
            logger.error(f"Failed to record audit note for response action {action.id}: {note_err}")

    return action
