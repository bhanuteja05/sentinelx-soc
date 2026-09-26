"""
backend/tests/test_containment.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Comprehensive automated test suite for Phase 9:
Active Response & Defensive Host Containment Orchestration.

Coverage:
  1.  Approved commands catalog validation
  2.  Unapproved command rejection
  3.  Target type mismatch rejection
  4.  Safety guardrail: loopback rejection (127.0.0.1, ::1, localhost)
  5.  Safety guardrail: wildcard/unspecified rejection (0.0.0.0, ::)
  6.  Safety guardrail: multicast & invalid IP rejection
  7.  Safety guardrail: empty target rejection
  8.  Safety guardrail: protected targets list rejection
  9.  Safety guardrail: protected agent rejection
  10. Configuration: RESPONSE_ENABLED=false raises ResponseDisabledError (403)
  11. Successful firewall-drop execution & parameter capture
  12. Successful host-deny execution & parameter capture
  13. Successful isolate-host execution
  14. Successful restart-wazuh execution
  15. Automated CaseNote audit timeline note on successful execution
  16. Execution failure: Wazuh response error & audit note
  17. Execution failure: WazuhConnectionError & audit note
  18. Entity reference: Nonexistent case_id raises TargetNotFoundError (404)
  19. Entity reference: Nonexistent alert_id raises TargetNotFoundError (404)
  20. API: GET /api/v1/response/commands (Authenticated 200 / Unauthenticated 401)
  21. API: POST /api/v1/response/execute Analyst permission (200)
  22. API: POST /api/v1/response/execute Admin permission (200)
  23. API: POST /api/v1/response/execute Safety violation (422)
  24. API: POST /api/v1/response/execute Invalid command (400)
  25. API: POST /api/v1/response/execute Nonexistent case (404)
  26. API: GET /api/v1/response/actions pagination & filtering
  27. API: GET /api/v1/response/actions/{id} detail & 404
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select

from app.core.security import create_access_token, hash_password
from app.db import get_db
from app.main import app
from app.models.alert import Alert
from app.models.case import Case
from app.models.case_note import CaseNote
from app.models.response_action import ResponseAction
from app.models.user import User
from app.repositories.alert import create_alert
from app.repositories.case import create_case, list_case_notes
from app.repositories.user import create_user
from app.services.response import (
    APPROVED_COMMANDS,
    ResponseCommandInvalidError,
    ResponseDisabledError,
    ResponseSafetyError,
    TargetNotFoundError,
    execute_containment_action,
    get_approved_commands,
    validate_target_safety,
)
from app.wazuh.client import WazuhConnectionError
from app.wazuh.config import WazuhSettings


@pytest.fixture
def auth_client(clean_db):
    """TestClient configured with clean db session."""
    def override_get_db():
        yield clean_db

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def users(clean_db):
    """Create test users: analyst and admin."""
    analyst = create_user(
        clean_db,
        User(
            username="analyst_containment",
            email="analyst_c@sentinelx.local",
            password_hash=hash_password("AnalystPass123!"),
            role="analyst",
            is_active=True,
        ),
    )
    admin = create_user(
        clean_db,
        User(
            username="admin_containment",
            email="admin_c@sentinelx.local",
            password_hash=hash_password("AdminPass123!"),
            role="admin",
            is_active=True,
        ),
    )
    return {"analyst": analyst, "admin": admin}


def auth_header(user: User) -> dict[str, str]:
    token = create_access_token(user_id=user.id, username=user.username, role=user.role)
    return {"Authorization": f"Bearer {token}"}


def make_alert(clean_db, **kwargs) -> Alert:
    now = datetime.now(timezone.utc)
    defaults = {
        "wazuh_alert_id": f"wazuh-{now.timestamp()}",
        "timestamp": now,
        "agent_id": "001",
        "agent_name": "ubuntu-srv",
        "rule_id": "5710",
        "rule_level": 7,
        "description": "SSHD authentication failure",
        "mitre_tactics": ["initial-access"],
        "mitre_techniques": ["T1110"],
        "raw_alert": {"sample": "data"},
    }
    defaults.update(kwargs)
    return create_alert(clean_db, defaults)


def make_case(clean_db, **kwargs) -> Case:
    defaults = {
        "title": "Incident Investigation",
        "severity": "high",
        "status": "open",
    }
    defaults.update(kwargs)
    case = Case(**defaults)
    return create_case(clean_db, case)


# ---------------------------------------------------------------------------
# 1. Approved Commands Catalog & Validation
# ---------------------------------------------------------------------------


def test_get_approved_commands_catalog():
    cmds = get_approved_commands()
    cmd_names = [c["command"] for c in cmds]
    assert "firewall-drop" in cmd_names
    assert "host-deny" in cmd_names
    assert "isolate-host" in cmd_names
    assert "quarantine" in cmd_names
    assert "restart-wazuh" in cmd_names

    for cmd in cmds:
        assert "name" in cmd
        assert "description" in cmd
        assert "target_type" in cmd
        assert "risk_level" in cmd
        assert "warning" in cmd


def test_unapproved_command_rejected(clean_db):
    with patch("app.services.response.is_response_enabled", return_value=True):
        with pytest.raises(ResponseCommandInvalidError) as exc:
            execute_containment_action(
                clean_db,
                command="rm -rf /",
                target_type="ip",
                target_value="198.51.100.1",
            )
        assert "not approved" in str(exc.value)


def test_target_type_mismatch_rejected(clean_db):
    with patch("app.services.response.is_response_enabled", return_value=True):
        # firewall-drop expects target_type="ip"
        with pytest.raises(ResponseCommandInvalidError) as exc:
            execute_containment_action(
                clean_db,
                command="firewall-drop",
                target_type="agent",
                target_value="001",
            )
        assert "requires target_type='ip'" in str(exc.value)

        # isolate-host expects target_type="agent"
        with pytest.raises(ResponseCommandInvalidError) as exc:
            execute_containment_action(
                clean_db,
                command="isolate-host",
                target_type="ip",
                target_value="198.51.100.1",
            )
        assert "requires target_type='agent'" in str(exc.value)


# ---------------------------------------------------------------------------
# 2. Safety Guardrails & Self-Lockout Prevention
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("loopback_target", ["127.0.0.1", "::1", "localhost"])
def test_safety_guardrail_rejects_loopback(loopback_target):
    with pytest.raises(ResponseSafetyError) as exc:
        validate_target_safety("ip", loopback_target)
    assert "loopback" in str(exc.value).lower() or "protected" in str(exc.value).lower()


@pytest.mark.parametrize("wildcard_target", ["0.0.0.0", "::"])
def test_safety_guardrail_rejects_wildcard(wildcard_target):
    with pytest.raises(ResponseSafetyError) as exc:
        validate_target_safety("ip", wildcard_target)
    assert "unspecified" in str(exc.value).lower() or "wildcard" in str(exc.value).lower()


@pytest.mark.parametrize("invalid_ip", ["999.999.999.999", "not_an_ip", "10.0.0."])
def test_safety_guardrail_rejects_invalid_ip(invalid_ip):
    with pytest.raises(ResponseSafetyError) as exc:
        validate_target_safety("ip", invalid_ip)
    assert "Invalid IP address format" in str(exc.value)


def test_safety_guardrail_rejects_multicast():
    with pytest.raises(ResponseSafetyError) as exc:
        validate_target_safety("ip", "224.0.0.1")
    assert "multicast" in str(exc.value).lower()


def test_safety_guardrail_rejects_empty_target():
    with pytest.raises(ResponseSafetyError) as exc:
        validate_target_safety("ip", "   ")
    assert "cannot be empty" in str(exc.value).lower()


def test_safety_guardrail_rejects_protected_targets():
    mock_settings = MagicMock(spec=WazuhSettings)
    mock_settings.response_protected_targets = ["10.0.0.1", "gateway.local", "000"]

    with patch("app.services.response.get_wazuh_settings", return_value=mock_settings):
        # Target in protected list
        with pytest.raises(ResponseSafetyError) as exc:
            validate_target_safety("ip", "10.0.0.1")
        assert "protected targets allowlist" in str(exc.value)

        # Agent in protected list
        with pytest.raises(ResponseSafetyError) as exc:
            validate_target_safety("agent", "000")
        assert "protected against active response" in str(exc.value)

        # Agent ID parameter in protected list
        with pytest.raises(ResponseSafetyError) as exc:
            validate_target_safety("ip", "198.51.100.5", agent_id="000")
        assert "Agent ID '000' is in the protected targets allowlist" in str(exc.value)


# ---------------------------------------------------------------------------
# 3. Feature Flag
# ---------------------------------------------------------------------------


def test_response_disabled_by_config(clean_db):
    mock_settings = MagicMock(spec=WazuhSettings)
    mock_settings.response_enabled = False

    with patch("app.services.response.get_wazuh_settings", return_value=mock_settings):
        with pytest.raises(ResponseDisabledError) as exc:
            execute_containment_action(
                clean_db,
                command="firewall-drop",
                target_type="ip",
                target_value="198.51.100.10",
            )
        assert "disabled by configuration" in str(exc.value)


# ---------------------------------------------------------------------------
# 4. Execution & Orchestration
# ---------------------------------------------------------------------------


def test_execute_firewall_drop_success(clean_db, users):
    mock_wazuh = MagicMock()
    mock_wazuh.execute_active_response.return_value = {
        "error": 0,
        "message": "Success",
        "data": {
            "affected_items": ["001"],
            "total_affected_items": 1,
            "total_failed_items": 0,
            "failed_items": [],
        },
    }

    with (
        patch("app.services.response.is_response_enabled", return_value=True),
        patch("app.services.response.wazuh_client", mock_wazuh),
    ):
        action = execute_containment_action(
            db=clean_db,
            command="firewall-drop",
            target_type="ip",
            target_value="198.51.100.77",
            agent_id="001",
            actor=users["analyst"],
        )

        assert action.id is not None
        assert action.status == "succeeded"
        assert action.command == "firewall-drop"
        assert action.target_type == "ip"
        assert action.target_value == "198.51.100.77"
        assert action.completed_at is not None
        assert action.error_message is None
        assert action.executed_by_id == users["analyst"].id
        assert action.parameters["agent_id"] == "001"
        assert action.parameters["wazuh_args"] == ["-", "198.51.100.77"]

        mock_wazuh.execute_active_response.assert_called_once_with(
            command="firewall-drop",
            arguments=["-", "198.51.100.77"],
            agents_list=["001"],
        )


def test_execute_host_deny_success(clean_db, users):
    mock_wazuh = MagicMock()
    mock_wazuh.execute_active_response.return_value = {
        "error": 0,
        "message": "Success",
        "data": {"total_affected_items": 1, "total_failed_items": 0},
    }

    with (
        patch("app.services.response.is_response_enabled", return_value=True),
        patch("app.services.response.wazuh_client", mock_wazuh),
    ):
        action = execute_containment_action(
            db=clean_db,
            command="host-deny",
            target_type="ip",
            target_value="198.51.100.80",
            agent_id="001",
            actor=users["analyst"],
        )
        assert action.status == "succeeded"
        assert action.command == "host-deny"
        mock_wazuh.execute_active_response.assert_called_once_with(
            command="host-deny",
            arguments=["-", "198.51.100.80"],
            agents_list=["001"],
        )


def test_execute_isolate_host_success(clean_db, users):
    mock_wazuh = MagicMock()
    mock_wazuh.execute_active_response.return_value = {
        "error": 0,
        "message": "Success",
        "data": {"total_affected_items": 1, "total_failed_items": 0},
    }

    with (
        patch("app.services.response.is_response_enabled", return_value=True),
        patch("app.services.response.wazuh_client", mock_wazuh),
    ):
        action = execute_containment_action(
            db=clean_db,
            command="isolate-host",
            target_type="agent",
            target_value="001",
            actor=users["admin"],
        )
        assert action.status == "succeeded"
        assert action.command == "isolate-host"
        assert action.target_type == "agent"
        assert action.target_value == "001"
        mock_wazuh.execute_active_response.assert_called_once_with(
            command="firewall-drop",
            arguments=["-", "0.0.0.0"],
            agents_list=["001"],
        )


def test_execute_restart_wazuh_success(clean_db, users):
    mock_wazuh = MagicMock()
    mock_wazuh.execute_active_response.return_value = {
        "error": 0,
        "message": "Success",
        "data": {"total_affected_items": 1, "total_failed_items": 0},
    }

    with (
        patch("app.services.response.is_response_enabled", return_value=True),
        patch("app.services.response.wazuh_client", mock_wazuh),
    ):
        action = execute_containment_action(
            db=clean_db,
            command="restart-wazuh",
            target_type="agent",
            target_value="001",
            actor=users["analyst"],
        )
        assert action.status == "succeeded"
        mock_wazuh.execute_active_response.assert_called_once_with(
            command="restart-wazuh",
            arguments=[],
            agents_list=["001"],
        )


def test_execute_containment_creates_audit_case_note(clean_db, users):
    case = make_case(clean_db, title="Active Breach Case")
    mock_wazuh = MagicMock()
    mock_wazuh.execute_active_response.return_value = {
        "error": 0,
        "data": {"total_affected_items": 1, "total_failed_items": 0},
    }

    with (
        patch("app.services.response.is_response_enabled", return_value=True),
        patch("app.services.response.wazuh_client", mock_wazuh),
    ):
        action = execute_containment_action(
            db=clean_db,
            command="firewall-drop",
            target_type="ip",
            target_value="198.51.100.99",
            agent_id="001",
            case_id=case.id,
            actor=users["analyst"],
        )

        assert action.case_id == case.id
        notes = list_case_notes(clean_db, case.id)
        assert len(notes) == 1
        note = notes[0]
        assert "[Active Response]" in note.content
        assert "Executed 'firewall-drop' for IP '198.51.100.99' on Agent '001'" in note.content
        assert "Status: SUCCEEDED" in note.content
        assert note.author_id == users["analyst"].id


def test_execute_containment_failure_wazuh_error(clean_db, users):
    case = make_case(clean_db)
    mock_wazuh = MagicMock()
    mock_wazuh.execute_active_response.return_value = {
        "error": 1750,
        "message": "Command execution failed on agent",
        "data": {
            "total_affected_items": 0,
            "total_failed_items": 1,
            "failed_items": [{"id": ["001"], "error": {"code": 1750}}],
        },
    }

    with (
        patch("app.services.response.is_response_enabled", return_value=True),
        patch("app.services.response.wazuh_client", mock_wazuh),
    ):
        action = execute_containment_action(
            db=clean_db,
            command="firewall-drop",
            target_type="ip",
            target_value="198.51.100.44",
            agent_id="001",
            case_id=case.id,
            actor=users["analyst"],
        )

        assert action.status == "failed"
        assert action.error_message is not None
        assert "Wazuh response error=1750" in action.error_message

        notes = list_case_notes(clean_db, case.id)
        assert len(notes) == 1
        assert "Status: FAILED" in notes[0].content
        assert "Wazuh response error=1750" in notes[0].content


def test_execute_containment_connection_error(clean_db, users):
    mock_wazuh = MagicMock()
    mock_wazuh.execute_active_response.side_effect = WazuhConnectionError("Wazuh API unreachable")

    with (
        patch("app.services.response.is_response_enabled", return_value=True),
        patch("app.services.response.wazuh_client", mock_wazuh),
    ):
        action = execute_containment_action(
            db=clean_db,
            command="isolate-host",
            target_type="agent",
            target_value="001",
            actor=users["analyst"],
        )

        assert action.status == "failed"
        assert "Wazuh API unreachable" in str(action.error_message)


def test_target_not_found_errors(clean_db, users):
    with patch("app.services.response.is_response_enabled", return_value=True):
        with pytest.raises(TargetNotFoundError) as exc:
            execute_containment_action(
                clean_db,
                command="firewall-drop",
                target_type="ip",
                target_value="198.51.100.1",
                case_id=999999,
                actor=users["analyst"],
            )
        assert "Case 999999 not found" in str(exc.value)

        with pytest.raises(TargetNotFoundError) as exc:
            execute_containment_action(
                clean_db,
                command="firewall-drop",
                target_type="ip",
                target_value="198.51.100.1",
                alert_id=999999,
                actor=users["analyst"],
            )
        assert "Alert 999999 not found" in str(exc.value)


# ---------------------------------------------------------------------------
# 5. API Endpoints & RBAC Enforcement
# ---------------------------------------------------------------------------


def test_api_get_commands_endpoint(auth_client, users):
    # Unauthenticated
    res = auth_client.get("/api/v1/response/commands")
    assert res.status_code == 401

    # Authenticated (Analyst)
    res = auth_client.get(
        "/api/v1/response/commands",
        headers=auth_header(users["analyst"]),
    )
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    cmds = [d["command"] for d in data]
    assert "firewall-drop" in cmds
    assert "isolate-host" in cmds


def test_api_execute_endpoint_analyst_permitted(auth_client, users):
    mock_wazuh = MagicMock()
    mock_wazuh.execute_active_response.return_value = {
        "error": 0,
        "message": "Success",
        "data": {"total_affected_items": 1, "total_failed_items": 0},
    }

    payload = {
        "command": "firewall-drop",
        "target_type": "ip",
        "target_value": "198.51.100.55",
        "agent_id": "001",
    }

    with (
        patch("app.services.response.is_response_enabled", return_value=True),
        patch("app.services.response.wazuh_client", mock_wazuh),
    ):
        res = auth_client.post(
            "/api/v1/response/execute",
            json=payload,
            headers=auth_header(users["analyst"]),
        )
        assert res.status_code == 200
        data = res.json()
        assert data["command"] == "firewall-drop"
        assert data["target_value"] == "198.51.100.55"
        assert data["status"] == "succeeded"


def test_api_execute_endpoint_admin_permitted(auth_client, users):
    mock_wazuh = MagicMock()
    mock_wazuh.execute_active_response.return_value = {
        "error": 0,
        "message": "Success",
        "data": {"total_affected_items": 1, "total_failed_items": 0},
    }

    payload = {
        "command": "isolate-host",
        "target_type": "agent",
        "target_value": "001",
    }

    with (
        patch("app.services.response.is_response_enabled", return_value=True),
        patch("app.services.response.wazuh_client", mock_wazuh),
    ):
        res = auth_client.post(
            "/api/v1/response/execute",
            json=payload,
            headers=auth_header(users["admin"]),
        )
        assert res.status_code == 200
        data = res.json()
        assert data["command"] == "isolate-host"
        assert data["target_value"] == "001"
        assert data["status"] == "succeeded"


def test_api_execute_endpoint_unauthenticated_fails(auth_client):
    payload = {
        "command": "firewall-drop",
        "target_type": "ip",
        "target_value": "198.51.100.55",
    }
    res = auth_client.post("/api/v1/response/execute", json=payload)
    assert res.status_code == 401


def test_api_execute_endpoint_safety_violation_returns_422(auth_client, users):
    payload = {
        "command": "firewall-drop",
        "target_type": "ip",
        "target_value": "127.0.0.1",
    }
    with patch("app.services.response.is_response_enabled", return_value=True):
        res = auth_client.post(
            "/api/v1/response/execute",
            json=payload,
            headers=auth_header(users["analyst"]),
        )
        assert res.status_code == 422
        assert "loopback" in res.json()["detail"].lower()


def test_api_execute_endpoint_invalid_command_returns_400(auth_client, users):
    payload = {
        "command": "custom_exploit",
        "target_type": "ip",
        "target_value": "198.51.100.55",
    }
    with patch("app.services.response.is_response_enabled", return_value=True):
        res = auth_client.post(
            "/api/v1/response/execute",
            json=payload,
            headers=auth_header(users["analyst"]),
        )
        assert res.status_code == 400
        assert "not approved" in res.json()["detail"]


def test_api_execute_endpoint_nonexistent_case_returns_404(auth_client, users):
    payload = {
        "command": "firewall-drop",
        "target_type": "ip",
        "target_value": "198.51.100.55",
        "case_id": 999999,
    }
    with patch("app.services.response.is_response_enabled", return_value=True):
        res = auth_client.post(
            "/api/v1/response/execute",
            json=payload,
            headers=auth_header(users["analyst"]),
        )
        assert res.status_code == 404
        assert "Case 999999 not found" in res.json()["detail"]


def test_api_execute_endpoint_disabled_returns_403(auth_client, users):
    payload = {
        "command": "firewall-drop",
        "target_type": "ip",
        "target_value": "198.51.100.55",
    }
    with patch("app.services.response.is_response_enabled", return_value=False):
        res = auth_client.post(
            "/api/v1/response/execute",
            json=payload,
            headers=auth_header(users["analyst"]),
        )
        assert res.status_code == 403
        assert "disabled by configuration" in res.json()["detail"]


def test_api_get_actions_pagination_and_filters(auth_client, clean_db, users):
    case = make_case(clean_db)
    mock_wazuh = MagicMock()
    mock_wazuh.execute_active_response.return_value = {
        "error": 0,
        "message": "Success",
        "data": {"total_affected_items": 1, "total_failed_items": 0},
    }

    with (
        patch("app.services.response.is_response_enabled", return_value=True),
        patch("app.services.response.wazuh_client", mock_wazuh),
    ):
        execute_containment_action(
            clean_db,
            command="firewall-drop",
            target_type="ip",
            target_value="198.51.100.11",
            case_id=case.id,
            actor=users["analyst"],
        )
        execute_containment_action(
            clean_db,
            command="isolate-host",
            target_type="agent",
            target_value="001",
            case_id=case.id,
            actor=users["admin"],
        )

    # Query all
    res = auth_client.get(
        "/api/v1/response/actions",
        headers=auth_header(users["analyst"]),
    )
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 2
    assert len(data["items"]) == 2

    # Filter by command
    res = auth_client.get(
        "/api/v1/response/actions?command=isolate-host",
        headers=auth_header(users["analyst"]),
    )
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 1
    assert data["items"][0]["command"] == "isolate-host"

    # Filter by case_id
    res = auth_client.get(
        f"/api/v1/response/actions?case_id={case.id}",
        headers=auth_header(users["analyst"]),
    )
    assert res.status_code == 200
    assert res.json()["total"] == 2


def test_api_get_action_detail_and_404(auth_client, clean_db, users):
    mock_wazuh = MagicMock()
    mock_wazuh.execute_active_response.return_value = {
        "error": 0,
        "message": "Success",
        "data": {"total_affected_items": 1, "total_failed_items": 0},
    }

    with (
        patch("app.services.response.is_response_enabled", return_value=True),
        patch("app.services.response.wazuh_client", mock_wazuh),
    ):
        action = execute_containment_action(
            clean_db,
            command="firewall-drop",
            target_type="ip",
            target_value="198.51.100.22",
            actor=users["analyst"],
        )

    # Get existing detail
    res = auth_client.get(
        f"/api/v1/response/actions/{action.id}",
        headers=auth_header(users["analyst"]),
    )
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == action.id
    assert data["command"] == "firewall-drop"
    assert data["target_value"] == "198.51.100.22"

    # Get non-existent
    res = auth_client.get(
        "/api/v1/response/actions/999999",
        headers=auth_header(users["analyst"]),
    )
    assert res.status_code == 404
