import logging
import os

import httpx

from app.wazuh.schemas import WazuhAlertsResponse, normalize_alert, parse_total

logger = logging.getLogger(__name__)

_ALERT_SOURCE_FIELDS = [
    "id",
    "timestamp",
    "agent",
    "rule",
    "decoder",
    "location",
]


class WazuhClient:
    def __init__(self) -> None:
        self.base_url = os.getenv(
            "WAZUH_API_URL",
            "https://host.docker.internal:55000",
        ).rstrip("/")

        self.username = os.getenv("WAZUH_API_USER", "wazuh-wui")
        self.password = os.getenv("WAZUH_API_PASSWORD", "")

        self.indexer_url = os.getenv(
            "WAZUH_INDEXER_URL",
            "https://wazuh.indexer:9200",
        ).rstrip("/")

        self.indexer_username = os.getenv(
            "WAZUH_INDEXER_USERNAME",
            "admin",
        )

        self.indexer_password = os.getenv(
            "WAZUH_INDEXER_PASSWORD",
            "",
        )

    def _redact(self, message: str) -> str:
        redacted = message
        for secret in (self.password, self.indexer_password):
            if secret:
                redacted = redacted.replace(secret, "***")
        return redacted

    def _authenticate(self) -> str:
        response = httpx.get(
            f"{self.base_url}/security/user/authenticate",
            auth=(self.username, self.password),
            verify=False,
            timeout=10.0,
        )

        response.raise_for_status()

        data = response.json()
        return data["data"]["token"]

    def _request(self, method: str, path: str, **kwargs):
        token = self._authenticate()

        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {token}"

        response = httpx.request(
            method,
            f"{self.base_url}{path}",
            headers=headers,
            verify=False,
            timeout=10.0,
            **kwargs,
        )

        response.raise_for_status()

        return response.json()

    def health(self) -> dict:
        self._authenticate()

        return {
            "status": "ok",
            "service": "wazuh-api",
            "url": self.base_url,
        }

    def get_agents(self) -> dict:
        return self._request("GET", "/agents")

    def get_alerts(self, limit: int = 20) -> WazuhAlertsResponse:
        query = {
            "size": limit,
            "_source": _ALERT_SOURCE_FIELDS,
            "sort": [{"timestamp": {"order": "desc"}}],
        }

        try:
            response = httpx.post(
                f"{self.indexer_url}/wazuh-alerts-4.x-*/_search",
                auth=(self.indexer_username, self.indexer_password),
                json=query,
                verify=False,
                timeout=10.0,
            )
            response.raise_for_status()
        except Exception as exc:
            logger.error(
                "Wazuh indexer alert search failed (%s): %s indexer=%s index=wazuh-alerts-4.x-*",
                type(exc).__name__,
                self._redact(str(exc)),
                self.indexer_url,
            )
            raise

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
