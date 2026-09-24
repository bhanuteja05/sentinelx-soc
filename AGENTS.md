# SentinelX

Defensive SOC lab: Wazuh SIEM + FastAPI backend + React/Vite dashboard + PostgreSQL, WSL2/Docker Desktop. Built in incremental milestones; `automation/`, `detections/`, `investigations/`, `scripts/`, `tests/` are still empty scaffolds.

## Two separate Docker stacks

- **App stack** — root `docker-compose.yml` (Postgres 17, FastAPI backend, React frontend). Start with `docker compose up -d --build`.
- **Wazuh stack** — isolated project in `infrastructure/wazuh/`. NOT started by the root command. Requires `--env-file .env` and `--profile wazuh`, and must be booted in staged order (cert generator first):

```bash
docker compose -f infrastructure/wazuh/generate-indexer-certs.yml --env-file .env run --rm generator
docker compose -f infrastructure/wazuh/docker-compose.yml --env-file .env up -d wazuh.indexer
docker compose -f infrastructure/wazuh/docker-compose.yml --env-file .env up -d wazuh.manager
docker compose -f infrastructure/wazuh/docker-compose.yml --env-file .env up -d wazuh.dashboard
```

- App compose declares `sentinelx-siem` as an **external** network, so root `docker compose up` fails with "network not found" until the Wazuh stack has been started once.
- Certs under `infrastructure/wazuh/config/wazuh_indexer_ssl_certs/` are gitignored; regenerate via the `generator` step above.

## Env and Wazuh credentials

- Copy `.env.example` to `.env` (required; `docker compose` interpolates with `${VAR:?}`). Same `.env` is used for both stacks.
- Wazuh credentials in `.env` must **match the committed config files**, not the other way around:
  - `infrastructure/wazuh/config/wazuh_indexer/internal_users.yml` stores **bcrypt hashes** (e.g. `admin`, `kibanaserver`)
  - `infrastructure/wazuh/config/wazuh_dashboard/wazuh.yml` stores the **plaintext** `wazuh-wui` API password
  - Rotating a Wazuh password means editing the compose env vars *and* these files.

## Wazuh ↔ backend wiring

- Backend reaches the Wazuh API at `https://host.docker.internal:55000` (hardcoded in `docker-compose.yml`; manager publishes 55000 to the host).
- Alerts are read from the indexer at `https://wazuh.indexer:9200` — 9200 is **not published** to the host, only reachable inside `sentinelx-siem`.
- Certs are self-signed; every `httpx` call in `backend/app/wazuh/client.py` uses `verify=False`.
- While Wazuh is down, backend `/api/v1/wazuh/*` returns 5xx; the frontend degrades to "Unavailable" instead of crashing.

## Ports (host)

| Service | Endpoint |
|---|---|
| Frontend | http://127.0.0.1:5173 |
| Backend | http://127.0.0.1:8000 — `/health`, `/api/v1/health`, `/api/v1/health/db`, `/docs` |
| PostgreSQL | 127.0.0.1:5433 (container 5432) |
| Wazuh dashboard | https://127.0.0.1:8443 |
| Wazuh manager API | https://127.0.0.1:55000 |
| Agent enrollment | 1514 / 1515 |

## Frontend (`frontend/`)

- Scripts: `npm run dev`, `npm run build` (= `tsc -b && vite build`), `npm run lint` (= `eslint .`). No test script.
- Vite proxies `/api` → backend via `BACKEND_PROXY_TARGET` (default `http://backend:8000`); the app calls relative `/api/v1/*`, no CORS involved.
- In compose, `./frontend` is bind-mounted with a named `frontend_node_modules` volume — the container uses that volume, not a host `node_modules`.

## Backend (`backend/`)

- FastAPI app rooted in `app/main.py`; Wazuh client in `app/wazuh/` (API auth via `/security/user/authenticate`, alerts via indexer `_search`, normalized in `schemas.py`).
- No tests, linter, or typecheck tooling configured; `tests/` is empty. Docker compose is the primary run path. `requirements.txt` is pinned.

## Git and docs

- Work on `feat/*` branches merged into `main` (currently on `feat/wazuh-integration`); commits use conventional style (`feat:`, `chore:`).
- Never commit real secrets: `.env` and `*.pem`/`*.key`/`*.csr` are gitignored.
- Canonical setup notes: `docs/setup/development-environment.md`, `docs/setup/wazuh.md`, `infrastructure/wazuh/README.md`. `wazuh-openapi.json` at root is a Wazuh API reference used to build the client.