"""
backend/app/wazuh/schemas.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Pydantic schemas and pure normalization helpers for Wazuh SIEM alerts and events.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class WazuhAlert(BaseModel):
    """Normalized internal representation of a Wazuh security alert."""

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
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None


class WazuhAlertsResponse(BaseModel):
    """Envelope for Wazuh Indexer search query responses."""

    status: str = "ok"
    source: str = "wazuh-indexer"
    index: str = "wazuh-alerts-4.x-*"
    total: int = 0
    count: int = 0
    alerts: list[WazuhAlert] = Field(default_factory=list)


class WazuhIngestError(BaseModel):
    """Per-event error reported when normalizing or persisting an alert."""

    event_id: str | None = None
    error: str


class WazuhIngestSummary(BaseModel):
    """Summary envelope returned by the alert ingestion boundary."""

    status: str = "ok"
    received: int = 0
    ingested: int = 0
    duplicates: int = 0
    errors: int = 0
    error_details: list[WazuhIngestError] = Field(default_factory=list)


class WazuhSchedulerResult(BaseModel):
    """Result summary of a single scheduled ingestion cycle."""

    received: int = 0
    ingested: int = 0
    duplicates: int = 0
    errors: int = 0
    duration_seconds: float = 0.0


class WazuhSchedulerStatus(BaseModel):
    """Telemetry and status representation for the background ingestion scheduler."""

    enabled: bool
    running: bool
    is_active: bool
    interval_seconds: float
    batch_size: int
    last_run_at: datetime | None = None
    last_success_at: datetime | None = None
    last_failure_at: datetime | None = None
    last_error: str | None = None
    last_result: WazuhSchedulerResult | None = None
    total_cycles: int = 0
    successful_cycles: int = 0
    failed_cycles: int = 0
    skipped_cycles: int = 0


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
    """Normalize an OpenSearch/Elasticsearch hit or direct Wazuh source dict into a WazuhAlert."""
    source = hit.get("_source")
    if not isinstance(source, dict):
        source = hit

    decoder = source.get("decoder")
    decoder_name = None
    if isinstance(decoder, dict):
        decoder_name = _as_str(decoder.get("name"))
    else:
        decoder_name = _as_str(decoder)

    alert_id = _as_str(hit.get("_id")) or _as_str(source.get("id")) or ""

    data = source.get("data") if isinstance(source.get("data"), dict) else {}
    src_ip = _as_str(data.get("srcip") or data.get("src_ip") or source.get("srcip") or source.get("src_ip"))
    dst_ip = _as_str(data.get("dstip") or data.get("dst_ip") or source.get("dstip") or source.get("dst_ip"))
    src_port = _as_int(data.get("srcport") or data.get("src_port") or source.get("srcport") or source.get("src_port"))
    dst_port = _as_int(data.get("dstport") or data.get("dst_port") or source.get("dstport") or source.get("dst_port"))

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
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
    )


def normalize_raw_event(event: dict[str, Any]) -> WazuhAlert:
    """Normalize any arbitrary event payload (Elasticsearch hit, webhook wrapper, or flat JSON)."""
    if not isinstance(event, dict):
        raise ValueError("Event must be a JSON object")

    # If wrapped in Wazuh integrator format: {"alert": {...}}
    if "alert" in event and isinstance(event["alert"], dict):
        target = event["alert"]
    elif "_source" in event and isinstance(event["_source"], dict):
        target = event
    else:
        target = event

    return normalize_alert(target)


def parse_total(total: Any) -> int:
    if isinstance(total, dict):
        return _as_int(total.get("value")) or 0
    return _as_int(total) or 0
