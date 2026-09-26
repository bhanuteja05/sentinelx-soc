# SentinelX — Wazuh SIEM Stack Deployment

Wazuh 4.14.8 single-node Docker cluster (Indexer, Manager, Dashboard) is orchestrated under `infrastructure/wazuh/`. It runs on the dedicated Docker network `sentinelx-siem` and is isolated from the main application stack.

---

## Architecture & Ports

| Component | Container Port | Host Port | Network Exposure |
|---|---|---|---|
| **Wazuh Manager** | 1514 (TCP/UDP) | 1514 | Agent enrollment & event collection |
| **Wazuh Manager** | 1515 (TCP) | 1515 | Agent registration (authd) |
| **Wazuh Manager API** | 55000 (HTTPS) | 55000 | SentinelX Backend & Host CLI |
| **Wazuh Indexer** | 9200 (HTTPS) | *None* | Internal `sentinelx-siem` only |
| **Wazuh Dashboard** | 5601 (HTTPS) | 8443 | Web browser (https://127.0.0.1:8443) |

---

## Staged Bootstrapping Procedure

### Step 1: Generate Self-Signed Cluster TLS Certificates

Wazuh components enforce mTLS communication. Generate cluster certificates using the generator container:

```bash
docker compose -f infrastructure/wazuh/generate-indexer-certs.yml --env-file .env run --rm generator
```

This populates `infrastructure/wazuh/config/wazuh_indexer_ssl_certs/` (gitignored).

### Step 2: Start Wazuh Services in Staged Order

```bash
# 1. Start Indexer (OpenSearch database)
docker compose -f infrastructure/wazuh/docker-compose.yml --env-file .env up -d wazuh.indexer

# 2. Wait until healthy (~30-60s), then start Manager
docker compose -f infrastructure/wazuh/docker-compose.yml --env-file .env up -d wazuh.manager

# 3. Start Dashboard
docker compose -f infrastructure/wazuh/docker-compose.yml --env-file .env up -d wazuh.dashboard
```

Verify service status:
```bash
docker compose -f infrastructure/wazuh/docker-compose.yml --env-file .env ps
```

---

## Verifying Wazuh Connectivity from SentinelX

Once healthy, verify backend connectivity:

```bash
# Test Wazuh API health via SentinelX Backend (requires JWT token)
curl -H "Authorization: Bearer <TOKEN>" http://127.0.0.1:8000/api/v1/wazuh/health

# Test Indexer alert query
curl -H "Authorization: Bearer <TOKEN>" http://127.0.0.1:8000/api/v1/wazuh/alerts
```
