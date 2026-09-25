#!/usr/bin/env python3
"""
SentinelX Custom Wazuh Integration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Production-quality integration script for Wazuh Manager (wazuh-integratord).
Forwards real-time alerts to the SentinelX push ingestion boundary:
POST http://backend:8000/api/v1/wazuh/events

Wazuh invocation arguments:
  sys.argv[1]: path to alert JSON file
  sys.argv[2]: api key / credentials (optional)
  sys.argv[3]: webhook URL (e.g. http://backend:8000/api/v1/wazuh/events)
"""

import json
import logging
import os
import sys
import tempfile
import time

LOG_FILE = "/var/ossec/logs/integrations.log"
TOKEN_CACHE_FILE = "/tmp/sentinelx_token_cache.json"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s sentinelx-integration: %(levelname)s %(message)s",
)
logger = logging.getLogger("sentinelx-integration")

try:
    import requests
except ImportError:
    logger.error("Required 'requests' library not found in Wazuh Python environment.")
    sys.exit(1)


def _save_token_cache(token: str, expires_at: float) -> None:
    """Save token cache atomically with strict 0600 (owner-only) permissions."""
    cache_dir = os.path.dirname(TOKEN_CACHE_FILE) or "/tmp"
    temp_path = None
    try:
        # NamedTemporaryFile creates the file with mode 0600 at creation time on POSIX
        with tempfile.NamedTemporaryFile("w", dir=cache_dir, delete=False, encoding="utf-8") as tf:
            temp_path = tf.name
            try:
                os.chmod(temp_path, 0o600)
            except OSError:
                pass
            json.dump({"token": token, "expires_at": expires_at}, tf)
        os.replace(temp_path, TOKEN_CACHE_FILE)
        try:
            os.chmod(TOKEN_CACHE_FILE, 0o600)
        except OSError:
            pass
    except Exception as exc:
        logger.warning("Failed to write token cache: %s", exc)
        if temp_path and os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass


def get_auth_token(base_url: str, credentials_hint: str) -> str | None:
    """Retrieve a valid JWT token, using cached token if unexpired."""
    now = time.time()
    if os.path.exists(TOKEN_CACHE_FILE):
        try:
            try:
                os.chmod(TOKEN_CACHE_FILE, 0o600)
            except OSError:
                pass
            with open(TOKEN_CACHE_FILE, "r", encoding="utf-8") as f:
                cached = json.load(f)
                if cached.get("expires_at", 0) > now + 60:
                    return cached.get("token")
        except Exception:
            pass

    username = "admin"
    password = ""
    if credentials_hint and ":" in credentials_hint:
        username, password = credentials_hint.split(":", 1)
    else:
        password = (
            os.environ.get("DEFAULT_ADMIN_PASSWORD")
            or os.environ.get("SENTINELX_ADMIN_PASSWORD")
            or credentials_hint
        )

    if not password:
        logger.warning("No password available for SentinelX authentication.")
        return None

    login_url = f"{base_url}/api/v1/auth/login"
    try:
        resp = requests.post(
            login_url,
            json={"username_or_email": username, "password": password},
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json()
            token = data.get("access_token")
            # Cache token for 50 minutes (tokens default to 60m expiry) with strict 0600 mode
            if token:
                _save_token_cache(token, now + 3000)
            return token
        else:
            logger.error("Auth login failed (HTTP %s): %s", resp.status_code, resp.text[:200])
            return None
    except Exception as exc:
        logger.error("Auth login request failed (%s): %s", type(exc).__name__, exc)
        return None


def main():
    if len(sys.argv) < 4:
        logger.error("Insufficient arguments: %s", sys.argv)
        sys.exit(1)

    alert_file = sys.argv[1]
    api_key = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] not in ("", "-") else ""
    hook_url = sys.argv[3] if len(sys.argv) > 3 else "http://backend:8000/api/v1/wazuh/events"

    if not os.path.exists(alert_file):
        logger.error("Alert file does not exist: %s", alert_file)
        sys.exit(1)

    try:
        with open(alert_file, "r", encoding="utf-8") as f:
            alert_json = json.load(f)
    except Exception as exc:
        logger.error("Failed to parse alert JSON (%s): %s", type(exc).__name__, exc)
        sys.exit(1)

    # Wrap in standard Wazuh integrator format: {"alert": {...}}
    payload = {"alert": alert_json}

    headers = {"Content-Type": "application/json"}

    # Handle authentication
    if api_key and not (":" in api_key) and len(api_key) > 50:
        # Direct JWT token passed in api_key
        token = api_key if not api_key.startswith("Bearer ") else api_key.split(" ", 1)[1]
        headers["Authorization"] = f"Bearer {token}"
    else:
        # Use auth login via credentials or env
        base_url = hook_url.split("/api/v1/")[0]
        token = get_auth_token(base_url, api_key)
        if token:
            headers["Authorization"] = f"Bearer {token}"

    try:
        response = requests.post(hook_url, json=payload, headers=headers, timeout=10)
        if response.status_code in (200, 201):
            logger.info("Alert %s forwarded to SentinelX (HTTP %s)", alert_json.get("id"), response.status_code)
            sys.exit(0)
        else:
            logger.error("SentinelX returned HTTP %s for alert %s: %s", response.status_code, alert_json.get("id"), response.text[:200])
            sys.exit(1)
    except Exception as exc:
        logger.error("Failed to forward alert to %s (%s): %s", hook_url, type(exc).__name__, exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
