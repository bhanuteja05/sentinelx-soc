"""
backend/app/wazuh/client.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Low-level HTTP transport client for Wazuh Manager API and Wazuh Indexer.
"""

import logging
from typing import Any

import httpx

from app.wazuh.config import WazuhSettings, get_wazuh_settings
from app.wazuh.schemas import WazuhAlertsResponse, normalize_alert, parse_total

logger = logging.getLogger(__name__)

_ALERT_SOURCE_FIELDS = [
    "id",
    "timestamp",
    "agent",
    "rule",
    "decoder",
    "location",
    "data",
]


class WazuhClientError(Exception):
    """Base exception for all Wazuh communication failures."""


class WazuhConnectionError(WazuhClientError):
    """Raised when Wazuh Manager API or Indexer is unreachable or times out."""


class WazuhAuthError(WazuhClientError):
    """Raised when authentication against Wazuh Manager API fails."""


class WazuhIndexerError(WazuhClientError):
    """Raised when querying Wazuh Indexer OpenSearch indices fails."""


class WazuhClient:
    """HTTP client communicating with Wazuh Manager API (port 55000) and Indexer (port 9200)."""

    def __init__(self, settings: WazuhSettings | None = None) -> None:
        self.settings = settings or get_wazuh_settings()

    @property
    def base_url(self) -> str:
        return self.settings.api_url

    @property
    def username(self) -> str:
        return self.settings.api_user

    @property
    def password(self) -> str:
        return self.settings.api_password

    @property
    def indexer_url(self) -> str:
        return self.settings.indexer_url

    @property
    def indexer_username(self) -> str:
        return self.settings.indexer_username

    @property
    def indexer_password(self) -> str:
        return self.settings.indexer_password

    def _redact(self, message: str) -> str:
        return self.settings.redact(message)

    def _authenticate(self) -> str:
        url = f"{self.base_url}/security/user/authenticate"
        try:
            response = httpx.get(
                url,
                auth=(self.username, self.password),
                verify=self.settings.verify_ssl,
                timeout=self.settings.timeout,
            )
            response.raise_for_status()
            data = response.json()
            return data["data"]["token"]
        except httpx.HTTPStatusError as exc:
            msg = self._redact(f"Wazuh auth HTTP error ({exc.response.status_code}): {exc}")
            logger.error(msg)
            raise WazuhAuthError(msg) from exc
        except (httpx.ConnectError, httpx.TimeoutException, httpx.RequestError) as exc:
            msg = self._redact(f"Wazuh auth connection failure ({type(exc).__name__}): {exc}")
            logger.error(msg)
            raise WazuhConnectionError(msg) from exc

    def _request(self, method: str, path: str, **kwargs) -> Any:
        token = self._authenticate()
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {token}"

        url = f"{self.base_url}{path}"
        try:
            response = httpx.request(
                method,
                url,
                headers=headers,
                verify=self.settings.verify_ssl,
                timeout=self.settings.timeout,
                **kwargs,
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as exc:
            msg = self._redact(f"Wazuh API request failed ({exc.response.status_code}): {exc}")
            logger.error(msg)
            raise WazuhClientError(msg) from exc
        except (httpx.ConnectError, httpx.TimeoutException, httpx.RequestError) as exc:
            msg = self._redact(f"Wazuh API connection failure ({type(exc).__name__}): {exc}")
            logger.error(msg)
            raise WazuhConnectionError(msg) from exc

    def health(self) -> dict:
        """Verify API authentication reachability against Wazuh Manager."""
        self._authenticate()
        return {
            "status": "ok",
            "service": "wazuh-api",
            "url": self.base_url,
        }

    def get_agents(self) -> dict:
        """Retrieve registered Wazuh agents list."""
        return self._request("GET", "/agents")

    def get_alerts(self, limit: int = 20) -> WazuhAlertsResponse:
        """Query latest security alerts from Wazuh Indexer via OpenSearch _search."""
        query = {
            "size": limit,
            "_source": _ALERT_SOURCE_FIELDS,
            "sort": [{"timestamp": {"order": "desc"}}],
        }

        url = f"{self.indexer_url}/wazuh-alerts-4.x-*/_search"
        try:
            response = httpx.post(
                url,
                auth=(self.indexer_username, self.indexer_password),
                json=query,
                verify=self.settings.verify_ssl,
                timeout=self.settings.timeout,
            )
            response.raise_for_status()
        except (httpx.ConnectError, httpx.TimeoutException, httpx.RequestError) as exc:
            msg = self._redact(
                f"Wazuh indexer connection failed ({type(exc).__name__}): {exc} url={url}"
            )
            logger.error(msg)
            raise WazuhIndexerError(msg) from exc
        except httpx.HTTPStatusError as exc:
            msg = self._redact(
                f"Wazuh indexer returned HTTP {exc.response.status_code}: url={url}"
            )
            logger.error(msg)
            raise WazuhIndexerError(msg) from exc
        except Exception as exc:
            msg = self._redact(f"Wazuh indexer alert search failed ({type(exc).__name__}): {exc}")
            logger.error(msg)
            raise WazuhIndexerError(msg) from exc

        data = response.json()
        hits = data.get("hits", {}).get("hits", [])
        if not isinstance(hits, list):
            hits = []

        alerts = [normalize_alert(hit) for hit in hits if isinstance(hit, dict)]

        return WazuhAlertsResponse(
            total=parse_total(data.get("hits", {}).get("total")),
            count=len(alerts),
            alerts=alerts,
        )


wazuh_client = WazuhClient()
