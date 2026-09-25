"""
backend/app/wazuh/__init__.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SentinelX Wazuh SIEM integration foundation package.
"""

from app.wazuh.client import (
    WazuhAuthError,
    WazuhClient,
    WazuhClientError,
    WazuhConnectionError,
    WazuhIndexerError,
    wazuh_client,
)
from app.wazuh.config import WazuhSettings, get_wazuh_settings
from app.wazuh.schemas import (
    WazuhAlert,
    WazuhAlertsResponse,
    WazuhIngestError,
    WazuhIngestSummary,
    normalize_alert,
    normalize_raw_event,
)
from app.wazuh.service import WazuhService, wazuh_service

__all__ = [
    "WazuhAuthError",
    "WazuhClient",
    "WazuhClientError",
    "WazuhConnectionError",
    "WazuhIndexerError",
    "wazuh_client",
    "WazuhSettings",
    "get_wazuh_settings",
    "WazuhAlert",
    "WazuhAlertsResponse",
    "WazuhIngestError",
    "WazuhIngestSummary",
    "normalize_alert",
    "normalize_raw_event",
    "WazuhService",
    "wazuh_service",
]
