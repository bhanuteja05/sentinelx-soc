"""
backend/app/wazuh/config.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Configuration settings for Wazuh SIEM Manager and Indexer connectivity.
"""

from dataclasses import dataclass
import os


@dataclass(frozen=True)
class WazuhSettings:
    """Connection parameters and credentials for Wazuh Manager & Indexer."""

    api_url: str
    api_user: str
    api_password: str
    indexer_url: str
    indexer_username: str
    indexer_password: str
    timeout: float = 10.0
    verify_ssl: bool = False

    def redact(self, text: str) -> str:
        """Redact known credentials from strings before logging or raising."""
        redacted = text
        for secret in (self.api_password, self.indexer_password):
            if secret:
                redacted = redacted.replace(secret, "***")
        return redacted


def get_wazuh_settings() -> WazuhSettings:
    """Construct WazuhSettings from environment variables with sensible lab defaults."""
    api_url = os.getenv("WAZUH_API_URL", "https://host.docker.internal:55000").rstrip("/")
    api_user = os.getenv("WAZUH_API_USER", "wazuh-wui")
    api_password = os.getenv("WAZUH_API_PASSWORD", "")

    indexer_url = os.getenv("WAZUH_INDEXER_URL", "https://wazuh.indexer:9200").rstrip("/")
    indexer_username = os.getenv("WAZUH_INDEXER_USERNAME", "admin")
    indexer_password = os.getenv("WAZUH_INDEXER_PASSWORD", "")

    timeout_raw = os.getenv("WAZUH_TIMEOUT", "10.0")
    try:
        timeout = float(timeout_raw)
    except ValueError:
        timeout = 10.0

    verify_raw = os.getenv("WAZUH_VERIFY_SSL", "false").strip().lower()
    verify_ssl = verify_raw in ("1", "true", "yes")

    return WazuhSettings(
        api_url=api_url,
        api_user=api_user,
        api_password=api_password,
        indexer_url=indexer_url,
        indexer_username=indexer_username,
        indexer_password=indexer_password,
        timeout=timeout,
        verify_ssl=verify_ssl,
    )
