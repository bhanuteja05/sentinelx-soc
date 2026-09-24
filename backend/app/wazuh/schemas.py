from typing import Any

from pydantic import BaseModel, Field


class WazuhAlert(BaseModel):
    id: str
    timestamp: str | None = None
    agent_id: str | None = None
    agent_name: str | None = None
    rule_id: str | None = None
    rule_level: int | None = None
    rule_description: str | None = None
    rule_groups: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    decoder: str | None = None
    location: str | None = None


class WazuhAlertsResponse(BaseModel):
    status: str = "ok"
    source: str = "wazuh-indexer"
    index: str = "wazuh-alerts-4.x-*"
    total: int = 0
    count: int = 0
    alerts: list[WazuhAlert] = Field(default_factory=list)


def _as_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return None


def _as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        stripped = value.strip()
        return [stripped] if stripped else []
    if isinstance(value, list):
        items: list[str] = []
        for item in value:
            text = _as_str(item)
            if text:
                items.append(text)
        return items
    text = _as_str(value)
    return [text] if text else []


def _as_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


def _nested(source: dict[str, Any], *keys: str) -> Any:
    current: Any = source
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def normalize_alert(hit: dict[str, Any]) -> WazuhAlert:
    source = hit.get("_source")
    if not isinstance(source, dict):
        source = {}

    decoder = source.get("decoder")
    decoder_name = None
    if isinstance(decoder, dict):
        decoder_name = _as_str(decoder.get("name"))
    else:
        decoder_name = _as_str(decoder)

    alert_id = _as_str(hit.get("_id")) or _as_str(source.get("id")) or ""

    return WazuhAlert(
        id=alert_id,
        timestamp=_as_str(source.get("timestamp")),
        agent_id=_as_str(_nested(source, "agent", "id")),
        agent_name=_as_str(_nested(source, "agent", "name")),
        rule_id=_as_str(_nested(source, "rule", "id")),
        rule_level=_as_int(_nested(source, "rule", "level")),
        rule_description=_as_str(_nested(source, "rule", "description")),
        rule_groups=_as_str_list(_nested(source, "rule", "groups")),
        mitre_tactics=_as_str_list(_nested(source, "rule", "mitre", "tactic")),
        mitre_techniques=_as_str_list(_nested(source, "rule", "mitre", "technique")),
        decoder=decoder_name,
        location=_as_str(source.get("location")),
    )


def parse_total(total: Any) -> int:
    if isinstance(total, dict):
        return _as_int(total.get("value")) or 0
    return _as_int(total) or 0
