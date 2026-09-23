# Wazuh lab setup

Wazuh 4.14.8 single-node Docker (indexer, manager, dashboard) is defined in `infrastructure/wazuh/`. It uses network `sentinelx-siem` and does not start with the SentinelX application compose file.

## Host

- Docker Desktop RAM: 12 GB or more when running Wazuh with the app stack
- WSL2: `sysctl -w vm.max_map_count=262144`

## Certificates then staged start

See `infrastructure/wazuh/README.md`.

Dashboard: https://127.0.0.1:8443 (self-signed certificate warning is expected).
Indexer port 9200 is not published to Windows.
