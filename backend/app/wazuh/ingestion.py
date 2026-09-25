"""
app/wazuh/ingestion.py
~~~~~~~~~~~~~~~~~~~~~~
Pure normalization layer: WazuhAlert → Alert model dict.

This module has NO database access and NO HTTP access.
It is a deterministic transformation function only.

IMPORTANT — raw_alert scope
----------------------------
In this ingestion phase, `raw_alert` stores the normalized WazuhAlert
snapshot (WazuhAlert.model_dump()), NOT the original untouched Wazuh
Indexer document.

The normalized snapshot is what the existing WazuhClient + normalize_alert()
pipeline produces after projecting `_ALERT_SOURCE_FIELDS` from the indexer
hit. It does not include fields excluded from the projection (e.g. raw event
data, full rule metadata, syscheck details).

When the indexer source projection is widened in a future phase, `raw_alert`
can be updated to store the wider snapshot without a schema change.
"""

from datetime import datetime, timezone
from typing import Any

from app.wazuh.schemas import WazuhAlert


class AlertMappingError(ValueError):
    """Raised when a WazuhAlert cannot be mapped to an Alert dict."""


def wazuh_alert_to_dict(alert: WazuhAlert) -> dict[str, Any]:
    """Map a normalized WazuhAlert to a dict compatible with Alert(**...).

    Field mapping
    -------------
    WazuhAlert.id              → wazuh_alert_id   (rename)
    WazuhAlert.timestamp       → timestamp        (str → timezone-aware datetime)
    WazuhAlert.agent_id        → agent_id
    WazuhAlert.agent_name      → agent_name
    WazuhAlert.rule_id         → rule_id          (fallback "unknown" if absent)
    WazuhAlert.rule_level      → rule_level
    WazuhAlert.rule_description→ description      (rename)
    WazuhAlert.decoder         → decoder
    WazuhAlert.location        → location
    WazuhAlert.mitre_tactics   → mitre_tactics
    WazuhAlert.mitre_techniques→ mitre_techniques
    (absent)                   → src_ip, dst_ip   (NULL — not projected from indexer)
    (absent)                   → src_port,dst_port(NULL — not projected from indexer)
    alert.model_dump()         → raw_alert        (normalized WazuhAlert snapshot)

    Raises
    ------
    AlertMappingError
        If `alert.id` is absent or empty (cannot produce a unique deduplication key).
    """
    if not alert.id or not alert.id.strip():
        raise AlertMappingError(
            "WazuhAlert.id is required for ingestion but was empty or absent."
        )

    return {
        "wazuh_alert_id":   alert.id.strip(),
        "timestamp":        _parse_timestamp(alert.timestamp),
        "agent_id":         alert.agent_id,
        "agent_name":       alert.agent_name,
        "rule_id":          alert.rule_id or "unknown",
        "rule_level":       alert.rule_level,
        "description":      alert.rule_description,
        # Not projected from the Wazuh indexer in the current _ALERT_SOURCE_FIELDS.
        # Stored as NULL. Extend _ALERT_SOURCE_FIELDS + this mapper to populate them.
        "src_ip":           None,
        "dst_ip":           None,
        "src_port":         None,
        "dst_port":         None,
        "location":         alert.location,
        "decoder":          alert.decoder,
        "mitre_tactics":    alert.mitre_tactics,
        "mitre_techniques": alert.mitre_techniques,
        # Normalized WazuhAlert snapshot — see module docstring for scope note.
        "raw_alert":        alert.model_dump(),
    }


def _parse_timestamp(ts: str | None) -> datetime:
    """Parse a Wazuh ISO 8601 timestamp string to a UTC-aware datetime.

    Wazuh Indexer emits timestamps in the form:
        "2026-09-25T06:30:39.106+0000"   ← no colon in UTC offset

    Python's datetime.fromisoformat() requires a colon in the offset
    ("+00:00") on Python < 3.11 and is stricter on all versions with
    the bare "+0000" form.  This function normalizes the offset before
    parsing and falls back to datetime.now(UTC) on any parse failure
    rather than raising, to avoid one bad timestamp aborting an entire
    ingestion batch.

    A fallback timestamp is used (not None) because the Alert model
    requires timestamp NOT NULL.
    """
    if not ts:
        return datetime.now(timezone.utc)

    try:
        normalized = ts.strip()
        # Normalize bare UTC offset "+0000" / "-0000" → "+00:00"
        if len(normalized) > 5 and normalized[-5] in ("+", "-") and ":" not in normalized[-5:]:
            sign = normalized[-5]
            hh = normalized[-4:-2]
            mm = normalized[-2:]
            normalized = normalized[:-5] + f"{sign}{hh}:{mm}"
        return datetime.fromisoformat(normalized)
    except (ValueError, TypeError):
        # Log-worthy but non-fatal: return a safe fallback so the alert
        # can still be persisted with an approximate ingestion time.
        return datetime.now(timezone.utc)
