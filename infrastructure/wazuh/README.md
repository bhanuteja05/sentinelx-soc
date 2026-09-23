# Wazuh single-node (Docker)

Official Wazuh **4.14.8** indexer, manager, and dashboard on network `sentinelx-siem`.

This stack is **separate** from PostgreSQL / FastAPI / React. It does not start with `docker compose up` at the repository root.

## Host prerequisites

- Docker Desktop memory at least 8 GB (12 GB+ preferred with the app stack)
- WSL2: `vm.max_map_count=262144`

## Start

From the repository root, with `.env` populated (passwords must match hashes in `config/wazuh_indexer/internal_users.yml`):

```bash
docker compose -f infrastructure/wazuh/docker-compose.yml --env-file .env --profile wazuh config
docker compose -f infrastructure/wazuh/generate-indexer-certs.yml run --rm generator
docker compose -f infrastructure/wazuh/docker-compose.yml --env-file .env --profile wazuh up -d wazuh.indexer
docker compose -f infrastructure/wazuh/docker-compose.yml --env-file .env --profile wazuh up -d wazuh.manager
docker compose -f infrastructure/wazuh/docker-compose.yml --env-file .env --profile wazuh up -d wazuh.dashboard
```

## Local ports

- Dashboard: https://127.0.0.1:8443
- Manager API: https://127.0.0.1:55000
- Agent events / enrollment: 127.0.0.1:1514 / 1515
- Indexer 9200 is **not** published to the host
