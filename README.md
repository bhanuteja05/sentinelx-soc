# SentinelX SOC Lab — v1.0

> **Enterprise-grade SOC Detection & Incident Response Lab**

> Wazuh SIEM · FastAPI · PostgreSQL · React/TypeScript · Docker · Active Response

SentinelX is a fully-functional, end-to-end Security Operations Center (SOC) platform built for **defensive security learning, detection engineering practice, and portfolio demonstration**.
It ingests real Wazuh SIEM alerts, enriches them with MITRE ATT&CK and IOC data, enables structured case management, and provides human-in-the-loop active response containment — all in a single composable Docker environment.

---

## Table of Contents

1. [Problem Statement](#problem-statement)
2. [Key Capabilities](#key-capabilities)
3. [Architecture](#architecture)
4. [Technology Stack](#technology-stack)
5. [Component Breakdown](#component-breakdown)
6. [Prerequisites](#prerequisites)
7. [Environment Configuration](#environment-configuration)
8. [Docker Startup — App Stack](#docker-startup--app-stack)
9. [Database Migration](#database-migration)
10. [User Seed](#user-seed)
11. [Wazuh Stack Setup](#wazuh-stack-setup)
12. [Authentication & RBAC](#authentication--rbac)
13. [Alert Investigation](#alert-investigation)
14. [Case Management](#case-management)
15. [Active Response Safety Model](#active-response-safety-model)
16. [Testing](#testing)
17. [API Overview](#api-overview)
18. [Demo Workflow](#demo-workflow)
19. [Security Considerations](#security-considerations)
20. [Known Limitations](#known-limitations)
21. [Future Improvements](#future-improvements)

---

## Problem Statement

Most SOC training environments are either too simplistic (premade labs with click-through exercises) or too complex to set up (enterprise SIEM deployments requiring dedicated hardware). SentinelX bridges this gap by providing:

- A **real SIEM integration** (Wazuh) with live alert ingestion
- A **structured investigation workflow** matching professional SOC practices
- **Automated triage**, **case management**, and **evidence locker** capabilities
- **Controlled active response** execution with layered safety guardrails
- A **full API + React dashboard** enabling end-to-end SOC workflow simulation

---

## Key Capabilities

| Capability | Status |
|---|---|
| Wazuh SIEM integration (Manager API + Indexer) | ✅ Implemented |
| Background alert ingestion & deduplication | ✅ Implemented |
| MITRE ATT&CK enrichment | ✅ Implemented |
| IOC extraction (IP, domain, hash, URL) | ✅ Implemented |
| Alert query & investigation layer | ✅ Implemented |
| Case management (create, assign, update) | ✅ Implemented |
| Analyst ownership & work queues | ✅ Implemented |
| Case evidence locker (IOC → Evidence promotion) | ✅ Implemented |
| Investigation notes & audit timeline | ✅ Implemented |
| Automated triage rules & alert correlation | ✅ Implemented |
| Incident escalation (24-hour correlation) | ✅ Implemented |
| Structured incident resolution (disposition, root cause) | ✅ Implemented |
| SOC dashboard & analytics | ✅ Implemented |
| Authentication / RBAC (JWT, bcrypt, role enforcement) | ✅ Implemented |
| Active response containment (human-in-the-loop) | ✅ Implemented |
| Active response audit trail | ✅ Implemented |

---

## Architecture

```
╔══════════════════════════════════════════════════════════════════╗
║                         WAZUH STACK                             ║
║   Wazuh Manager (agents, rules)                                 ║
║         ↓ alerts stored in                                      ║
║   Wazuh Indexer (OpenSearch) ←→ Wazuh Dashboard (https:8443)   ║
╚══════════════════════════════════════════════════════════════════╝
           ↓ /active-response API (port 55000)
           ↓ Indexer search (port 9200, internal network only)
╔══════════════════════════════════════════════════════════════════╗
║                         APP STACK                               ║
║   FastAPI Backend (port 8000)                                   ║
║     ├── Background scheduler: poll Wazuh Indexer every 30s      ║
║     │     └── Deduplicate → Enrich (MITRE + IOC) → Store       ║
║     ├── Alert Query Layer (filter, paginate, enrich)            ║
║     ├── Case Management (create, assign, evidence, resolve)     ║
║     ├── Automated Triage (rule eval, case creation)             ║
║     ├── SOC Dashboard (metrics, time series, MITRE analytics)   ║
║     ├── Active Response (allowlist, safety guardrails, audit)   ║
║     └── Auth / RBAC (JWT HS256, bcrypt, role enforcement)       ║
║           ↓ SQLAlchemy ORM                                      ║
║   PostgreSQL 17 (port 5433 → container 5432)                   ║
╚══════════════════════════════════════════════════════════════════╝
           ↓ Vite proxy /api → backend
╔══════════════════════════════════════════════════════════════════╗
║   React + TypeScript Frontend (port 5173)                       ║
║     ├── Dashboard · Alerts · Cases · Triage                     ║
║     └── Active Response panel (CaseDetail / AlertDetail)        ║
╚══════════════════════════════════════════════════════════════════╝

ANALYST FLOW:
  Browser → Login (JWT) → Dashboard → Alerts → Case → Contain
                                ↓ require_role("analyst"|"admin")
                         Server-side role check
                                ↓ RESPONSE_ENABLED=true
                         Feature flag check (fail-closed)
                                ↓ command allowlist
                         5 approved commands only
                                ↓ target validation
                         IP safety (loopback/multicast blocked)
                                ↓ human confirmation checkbox
                         Explicit analyst confirmation
                                ↓
                         Wazuh Active Response API
                                ↓
                         ResponseAction audit record + Case note
```

---

## Technology Stack

| Layer | Technology |
|---|---|
| SIEM | Wazuh 4.x (Manager, Indexer/OpenSearch, Dashboard) |
| Backend | Python 3.13, FastAPI 0.118, SQLAlchemy 2.0, Alembic, Uvicorn |
| Auth | PyJWT (HS256), bcrypt (rounds=12) |
| Database | PostgreSQL 17, psycopg3 |
| HTTP client | httpx |
| Frontend | React 18, TypeScript, Vite 8 |
| Containerization | Docker Compose (two isolated stacks) |
| Testing | pytest 9, FastAPI TestClient |

---

## Component Breakdown

### Backend (`backend/`)

```
app/
├── api/           # FastAPI routers (auth, alerts, cases, dashboard, triage, response, wazuh)
├── core/          # JWT + bcrypt security primitives
├── db/            # SQLAlchemy session, Base, connection check
├── models/        # ORM models: Alert, Case, CaseNote, CaseEvidence,
│                  #             TriageRule, ResponseAction, User
├── repositories/  # DB access layer (no business logic)
├── services/      # Business logic: auth, case, triage, response, dashboard
├── analysis/      # IOC extraction, MITRE ATT&CK enrichment
└── wazuh/         # Wazuh client, config, ingestion scheduler, schemas
alembic/versions/  # 7 reversible migrations (full upgrade/downgrade lifecycle)
scripts/           # seed_users.py (idempotent, reads from env)
tests/             # 272 tests across 14 test modules
```

### Frontend (`frontend/src/`)

```
pages/        # Dashboard, Alerts, AlertDetail, Cases, CaseDetail,
              # CreateCase, Triage, Login
components/   # Nav, Pagination, SeverityBadge, ProtectedRoute, ErrorBanner
context/      # AuthContext (JWT storage, role-aware routing)
api/          # client.ts — typed fetch wrappers for all backend endpoints
```

### Infrastructure

```
docker-compose.yml                     # App stack (db, backend, frontend)
infrastructure/wazuh/docker-compose.yml # Wazuh stack (indexer, manager, dashboard)
infrastructure/wazuh/config/           # Wazuh indexer, dashboard, cluster configs
automation/playbooks/                  # SOC response playbooks (host containment, IP blocking, ransomware)
```

---

## Prerequisites

- **Docker Desktop** (WSL2 backend recommended on Windows) with Compose v2
- Git
- A terminal (PowerShell, bash, or zsh)
- Minimum: 8 GB RAM available to Docker (Wazuh indexer alone requires ~4 GB)

---

## Environment Configuration

```bash
# 1. Copy the example env file
cp .env.example .env

# 2. Fill in required values in .env:
```

| Variable | Required | Description |
|---|---|---|
| `JWT_SECRET_KEY` | ✅ | Random 32+ byte hex string. Generate: `python -c "import secrets; print(secrets.token_hex(32))"` |
| `DEFAULT_ADMIN_PASSWORD` | ✅ | Initial admin password (min 8 chars) |
| `POSTGRES_PASSWORD` | ✅ | PostgreSQL password |
| `WAZUH_API_PASSWORD` | ✅ (Wazuh) | Must match `wazuh-wui` hash in `internal_users.yml` |
| `WAZUH_INDEXER_PASSWORD` | ✅ (Wazuh) | Must match `admin` bcrypt hash in `internal_users.yml` |
| `WAZUH_DASHBOARD_PASSWORD` | ✅ (Wazuh) | Must match `kibanaserver` bcrypt hash |
| `RESPONSE_ENABLED` | Optional | `true` to enable active response. **Defaults to `false` (fail-closed).** |
| `RESPONSE_PROTECTED_TARGETS` | Optional | Comma-separated IP list to protect in addition to built-in loopback/unspecified/multicast/link-local/reserved blocks |

> **Security note:** `.env` is gitignored. Never commit it. The `JWT_SECRET_KEY` **must** be set to a unique random value — the application logs a warning and uses an insecure fallback if unset in non-production environments.

---

## Docker Startup — App Stack

The app stack (PostgreSQL, FastAPI backend, React frontend) runs independently of Wazuh and boots first:

```bash
# Start app stack (always safe to run first)
docker compose up -d --build

# Verify services
docker compose ps
```

Service endpoints once healthy:

| Service | URL |
|---|---|
| Frontend | http://127.0.0.1:5173 |
| Backend API | http://127.0.0.1:8000 |
| Backend health | http://127.0.0.1:8000/health |
| API health | http://127.0.0.1:8000/api/v1/health |
| DB health | http://127.0.0.1:8000/api/v1/health/db |
| OpenAPI docs | http://127.0.0.1:8000/docs |
| PostgreSQL | 127.0.0.1:5433 |

---

## Database Migration

Alembic manages 7 incremental migrations. Run after the app stack is healthy:

```bash
# Apply all migrations
docker compose exec backend alembic upgrade head

# Verify current revision
docker compose exec backend alembic current

# (Optional) Roll back one step
docker compose exec backend alembic downgrade -1
```

Migration chain:

```
b1218046b63f  initial alert and case models
c7e2d94a1b05  add case_alerts table
d8f3a1e5b204  add users table
e1f34341c56e  add case notes table
f3b5c719e204  create triage rules table
a8c9d1e2f304  add case evidence and lifecycle fields
b9d1e2f3a405  create response_actions table   ← HEAD
```

---

## User Seed

After migration, seed the initial analyst accounts:

```bash
docker compose exec \
  -e DEFAULT_ADMIN_PASSWORD=YourAdminPassword \
  -e DEFAULT_ANALYST_PASSWORD=YourAnalystPassword \
  backend python scripts/seed_users.py
```

This creates two accounts idempotently (skips if they already exist):

| Username | Role | Email |
|---|---|---|
| `admin` | admin | admin@sentinelx.local |
| `analyst` | analyst | analyst@sentinelx.local |

---

## Wazuh Stack Setup

Wazuh runs in a **separate isolated Compose project**. Boot order matters:

```bash
# Step 1: Generate TLS certificates (one-time, or after cert reset)
docker compose \
  -f infrastructure/wazuh/generate-indexer-certs.yml \
  --env-file .env \
  run --rm generator

# Step 2: Start Wazuh Indexer (OpenSearch)
docker compose \
  -f infrastructure/wazuh/docker-compose.yml \
  --env-file .env \
  up -d wazuh.indexer

# Step 3: Start Wazuh Manager (rules + active response)
docker compose \
  -f infrastructure/wazuh/docker-compose.yml \
  --env-file .env \
  up -d wazuh.manager

# Step 4: Start Wazuh Dashboard
docker compose \
  -f infrastructure/wazuh/docker-compose.yml \
  --env-file .env \
  up -d wazuh.dashboard
```

| Service | URL |
|---|---|
| Wazuh Dashboard | https://127.0.0.1:8443 (self-signed cert — accept in browser) |
| Wazuh Manager API | https://127.0.0.1:55000 |
| Agent enrollment | 127.0.0.1:1514 / 1515 |

> The backend reaches the Wazuh Manager at `https://host.docker.internal:55000` and the Indexer at `https://wazuh.indexer:9200` (internal `sentinelx-siem` network only). When Wazuh is down, all `/api/v1/wazuh/*` endpoints return 5xx and the frontend degrades gracefully to "Unavailable."

See [`infrastructure/wazuh/README.md`](infrastructure/wazuh/README.md) and [`docs/setup/wazuh.md`](docs/setup/wazuh.md) for detailed Wazuh configuration.

---

## Authentication & RBAC

All API endpoints (except `/health`, `/api/v1/health`, `/api/v1/health/db`, and `/api/v1/auth/login`) require a valid JWT Bearer token.

```bash
# Login
curl -s -X POST http://127.0.0.1:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "YourAdminPassword"}' | python -m json.tool

# Use the returned access_token for subsequent calls
TOKEN="<access_token>"
curl -s http://127.0.0.1:8000/api/v1/alerts \
  -H "Authorization: Bearer $TOKEN" | python -m json.tool
```

**Role model:**

| Role | Capabilities |
|---|---|
| `analyst` | All read + write operations on alerts, cases, notes, evidence, triage, active response execution |
| `admin` | All analyst permissions + user management |

Tokens are HS256 JWTs signed with `JWT_SECRET_KEY`, bcrypt-verified passwords (rounds=12), 60-minute default expiry.

---

## Alert Investigation

The background scheduler polls the Wazuh Indexer every 30 seconds (configurable via `WAZUH_INGEST_INTERVAL_SECONDS`). Alerts are:

1. **Deduplicated** by `wazuh_alert_id` — no duplicates stored
2. **Enriched inline** with MITRE ATT&CK tactics/techniques and IOC extraction
3. **Stored** in PostgreSQL for structured querying

Query parameters for `GET /api/v1/alerts`:

```
page, page_size, sort_by, sort_order
rule_level (exact), min_rule_level, max_rule_level
agent_id, agent_name, rule_id
mitre_tactic, mitre_technique
start_time, end_time (ISO 8601)
```

Enrichment: `GET /api/v1/alerts/{id}/enrich`
Returns: IOC indicators (IP, domain, hash, URL), MITRE techniques, MITRE tactics

---

## Case Management

Cases are the central unit of investigation. Each case tracks:

- **Title, description, severity** (critical / high / medium / low / info)
- **Status** (open → investigating → resolved / closed)
- **Assignee** (analyst ownership + work queue filters)
- **Linked alerts** (many-to-many)
- **Evidence locker** (deduplicated by type + value; verdicts: malicious / suspicious / benign / informational)
- **Investigation notes** (timestamped audit timeline)
- **Resolution** (disposition, root_cause, resolution_summary, resolved_at, resolved_by)

Key endpoints:

```
POST   /api/v1/cases                      Create case
GET    /api/v1/cases                      List (filter: status, severity, assignee_id, unassigned)
GET    /api/v1/cases/{id}                 Case detail (alerts + evidence included)
PATCH  /api/v1/cases/{id}                 Update
POST   /api/v1/cases/{id}/assign          Assign to analyst / claim / unassign
POST   /api/v1/cases/{id}/alerts/{aid}    Attach alert
POST   /api/v1/cases/{id}/notes           Add investigation note
POST   /api/v1/cases/{id}/evidence        Add evidence artifact
POST   /api/v1/cases/{id}/resolve         Structured resolution with disposition
POST   /api/v1/cases/{id}/reopen          Reopen with reason
```

**Automated triage** (`/api/v1/triage/rules`) evaluates unprocessed alerts against configurable rules (min rule level, MITRE techniques/tactics, specific rule IDs) and auto-creates or correlates cases. Run `POST /api/v1/triage/evaluate` to trigger manually.

---

## Active Response Safety Model

> ⚠️ **Active response execution is disabled by default.** Set `RESPONSE_ENABLED=true` in `.env` to enable. The system is fail-closed — if the variable is missing or any value other than `true`/`1`/`yes`, execution is blocked.

SentinelX implements a **layered safety model** for defensive host containment:

### Approved Commands (5 total — no others accepted)

| Command | Target | Risk | Wazuh Action |
|---|---|---|---|
| `firewall-drop` | IP address | High | Block IP via host firewall |
| `host-deny` | IP address | Medium | Append to `/etc/hosts.deny` |
| `isolate-host` | Agent ID | Critical | Full network isolation via null-routing |
| `quarantine` | Agent ID | Critical | Network quarantine (alias for isolate-host) |
| `restart-wazuh` | Agent ID | Low | Restart Wazuh agent daemon |

### Target Validation Guardrails

All of the following are **unconditionally rejected** regardless of configuration:

- `127.0.0.1`, `::1`, `localhost` (loopback)
- `0.0.0.0`, `::` (unspecified/wildcard)
- Multicast ranges (`224.0.0.0/4`, `ff00::/8`)
- Link-local addresses (`169.254.0.0/16`, `fe80::/10`)
- Reserved ranges (per Python `ipaddress` library)
- Any IP in `RESPONSE_PROTECTED_TARGETS` (configurable)
- Malformed IP addresses (rejected before parsing)
- Invalid agent identifiers (non-alphanumeric characters)

### Human-in-the-Loop

The frontend **requires explicit confirmation** before executing any containment action. The analyst must:

1. Select a command from the backend-approved catalog (no frontend hardcoding)
2. Enter the target value
3. Check an explicit confirmation checkbox displaying the target, command, and risk level
4. Click the execute button (disabled until confirmed)

The confirmation modal prevents accidental execution and double-submit.

### Audit Trail

Every execution — whether succeeded or failed — records a `ResponseAction` with:
- `command`, `target_type`, `target_value`, `agent_id`
- `status` (executing → succeeded/failed)
- `execution_output` (full Wazuh response JSON)
- `error_message` (failure reason if applicable)
- `executed_by_id`, `created_at`, `completed_at`

A case timeline note is also created automatically when a `case_id` is provided.

See [`automation/playbooks/`](automation/playbooks/) for operational SOPs.

---

## Testing

```bash
# Full backend test suite (272 tests)
docker compose exec backend pytest -q --tb=short

# Frontend lint (eslint)
docker compose exec frontend npm run lint

# Frontend build (tsc + vite)
docker compose exec frontend npm run build

# Validate app compose configuration
docker compose config --quiet

# Validate Wazuh compose configuration
docker compose -f infrastructure/wazuh/docker-compose.yml --env-file .env config --quiet

# Check for trailing whitespace
git diff --check
```

**Test coverage by module:**

| Module | Tests |
|---|---|
| `test_auth.py` | JWT, login, token expiry, inactive user |
| `test_alert_queries.py` | Alert filtering, pagination, sort |
| `test_analysis.py` | IOC extraction, MITRE enrichment |
| `test_case_management.py` | Case CRUD, assignment, association |
| `test_case_lifecycle.py` | Resolution, reopen, disposition |
| `test_case_notes.py` | Notes create/update/delete, audit trail |
| `test_containment.py` | Active response safety (33 tests), allowlist, target validation |
| `test_dashboard.py` | Metrics, time-series, MITRE analytics |
| `test_ingestion.py` | Wazuh alert deduplication, normalization |
| `test_migrations.py` | Alembic upgrade/downgrade/re-upgrade lifecycle |
| `test_models.py` | SQLAlchemy ORM column integrity |
| `test_repositories.py` | DB access layer |
| `test_triage.py` | Triage rule evaluation, escalation |
| `test_wazuh_*.py` | Wazuh client, scheduler, foundation |

---

## API Overview

Full interactive documentation: **http://127.0.0.1:8000/docs** (FastAPI OpenAPI UI)

### Auth — `/api/v1/auth`

| Method | Path | Description |
|---|---|---|
| POST | `/login` | Login with username/password → JWT token |
| GET | `/me` | Current user profile |
| POST | `/logout` | Invalidate session |

### Alerts — `/api/v1/alerts`

| Method | Path | Description |
|---|---|---|
| GET | `/` | List alerts (rich filter, pagination, sort) |
| GET | `/{id}` | Alert detail with raw Wazuh data |
| GET | `/{id}/enrich` | MITRE ATT&CK + IOC enrichment |
| GET | `/count` | Total alert count |

### Cases — `/api/v1/cases`

| Method | Path | Description |
|---|---|---|
| POST | `/` | Create case |
| GET | `/` | List cases (status, severity, assignee, unassigned) |
| GET | `/{id}` | Case detail (alerts + evidence) |
| PATCH | `/{id}` | Update case |
| DELETE | `/{id}` | Delete case |
| POST | `/{id}/assign` | Assign / claim / unassign |
| POST | `/{id}/close` | Close case |
| POST | `/{id}/resolve` | Structured resolution |
| POST | `/{id}/reopen` | Reopen with reason |
| POST/DELETE | `/{id}/alerts/{aid}` | Attach / detach alert |
| GET/POST | `/{id}/notes` | Investigation notes |
| PATCH/DELETE | `/{id}/notes/{nid}` | Edit / delete note |
| GET/POST | `/{id}/evidence` | Evidence locker |
| PATCH/DELETE | `/{id}/evidence/{eid}` | Update / delete evidence |

### Triage — `/api/v1/triage`

| Method | Path | Description |
|---|---|---|
| GET/POST | `/rules` | Manage triage rules |
| PATCH/DELETE | `/rules/{id}` | Update / delete rule |
| POST | `/evaluate` | Run triage against alert backlog |

### Active Response — `/api/v1/response`

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/commands` | Any authenticated user | Approved command catalog |
| POST | `/execute` | analyst / admin | Execute containment action |
| GET | `/actions` | Any authenticated user | Paginated action history |
| GET | `/actions/{id}` | Any authenticated user | Single action detail |

### Wazuh — `/api/v1/wazuh`

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Wazuh Manager API reachability |
| GET | `/alerts` | Live alerts from Wazuh Indexer |
| GET | `/agents` | Registered Wazuh agents |

### Dashboard — `/api/v1/dashboard`

| Method | Path | Description |
|---|---|---|
| GET | `/summary` | Metrics, time-series, MITRE analytics, recent activity |

---

## Demo Workflow

This workflow demonstrates the complete SOC alert-to-containment lifecycle. Assumes the app stack is running, migrations applied, and users seeded.

### 1. Login

Navigate to **http://127.0.0.1:5173** and log in as `admin` or `analyst`.

### 2. Dashboard

The dashboard shows:
- Total alerts (last 24h / 7d), open cases, severity distribution
- Alert time-series chart
- Top MITRE ATT&CK techniques and tactics
- Recent alerts and case activity

### 3. Investigate an Alert

Go to **Alerts** → click an alert to open its detail view.

Observe:
- Rule ID, level, agent name, timestamp, MITRE tactics/techniques
- Source/destination IPs, decoder, location
- Raw Wazuh alert JSON

Click **Enrich** to view extracted IOC indicators and full MITRE mapping.

### 4. Create a Case

From the alert detail:
- Click **Create Case** (pre-fills the alert title)
- Set severity to `high` or `critical`
- Submit

The alert is automatically linked to the new case.

### 5. Investigate in Case Detail

Open the case and observe:
- Linked alerts
- Investigation timeline (empty initially)
- Evidence locker (empty initially)

Add a note: *"Suspicious outbound connection from endpoint. Reviewing firewall logs."*

Promote an IOC to evidence: click **Promote to Evidence** on an alert enrichment indicator, set verdict to `suspicious`.

### 6. Update & Assign

- Assign the case to yourself using **Claim → Assign to Me**
- Change status to `investigating`
- Change severity to `critical` if warranted

### 7. Execute Active Response (TEST-NET only)

> ⚠️ **Requires `RESPONSE_ENABLED=true` in `.env` and backend restart, and a running Wazuh Manager.**

In the case detail, open the **🛡️ Active Response** panel:

1. Select command: `firewall-drop`
2. Target type: `IP`
3. Target value: `198.51.100.77` (TEST-NET-2, RFC 5737 — safe, non-routable)
4. Agent ID: your test agent ID
5. Check the confirmation checkbox: *"I confirm this action..."*
6. Click **Execute**

The response panel shows the execution status. Navigate to the **Timeline** tab to see the auto-generated audit note:

```
[Active Response] Executed 'firewall-drop' for IP '198.51.100.77' on Agent '001' by 'admin'. Status: SUCCEEDED.
```

### 8. View Response Audit Record

`GET /api/v1/response/actions` lists all executed containment actions with timestamps, status, and full Wazuh output.

### 9. Resolve the Case

Click **Resolve Case**:
- Disposition: `true positive`
- Root cause: `Compromised endpoint with C2 callback`
- Resolution summary: `IP blocked via firewall-drop on affected agent. Host quarantined pending reimaging.`

### 10. Evidence & History

Review the final case state:
- Timeline: notes + active response audit entries
- Evidence locker: promoted IOC with verdict
- Resolution details with timestamp and resolver

---

## Security Considerations

### What is secured

- **All API endpoints** require JWT authentication (except health checks and login)
- **Role enforcement** is server-side — the frontend cannot grant elevated access
- **Passwords** are bcrypt-hashed (rounds=12) and never stored in plaintext
- **JWT** uses HS256 with a configurable secret; requires `JWT_SECRET_KEY` in production
- **Active response** is fail-closed (`RESPONSE_ENABLED=false` by default)
- **Command allowlist** is server-side; the frontend fetches allowed commands from `/api/v1/response/commands` and cannot introduce arbitrary commands
- **Target validation** blocks loopback, unspecified, multicast, link-local, and reserved IPs regardless of configuration
- **Wazuh credentials** are redacted before logging via `WazuhSettings.redact()`
- **PostgreSQL** is bound to `127.0.0.1:5433` only (not exposed to the network)
- **Wazuh Indexer** (port 9200) is not published to the host — accessible only inside the `sentinelx-siem` Docker network

### What is NOT production-ready

- `verify_ssl=False` on Wazuh API/Indexer calls (self-signed certs in lab)
- No rate limiting on login or API endpoints
- No token revocation / refresh token mechanism
- No audit log for user management operations
- No network-level mTLS between backend and Wazuh
- The dev fallback JWT secret (`sentinelx-insecure-development-secret-key-32b`) must **never** be used in production — set `JWT_SECRET_KEY` explicitly

---

## Known Limitations

1. **Single-node Wazuh** — Docker single-node deployment; not suitable for high-availability or production-scale agent deployments
2. **No real-time push** — The frontend polls or navigates to refresh; no WebSocket/SSE real-time updates
3. **No token refresh** — JWT tokens expire after 60 minutes; users must re-login
4. **No file evidence upload** — Evidence locker stores structured key-value artifacts, not binary files (PCAP, memory dumps, logs)
5. **Active response requires Wazuh** — Containment execution fails gracefully when Wazuh is down; it does not queue for retry
6. **Wazuh 4.x only** — Client and schema normalized for Wazuh 4.x OpenSearch index format; Wazuh 5.x may require schema updates
7. **No multi-tenancy** — All analysts share the same namespace; no per-team data isolation
8. **No email/Slack notifications** — Triage automation and escalation are in-platform only

---

## Future Improvements

- [ ] WebSocket real-time alert feed
- [ ] Sigma rule management and evaluation pipeline
- [ ] YARA scan integration
- [ ] Zeek/Suricata network telemetry ingestion
- [ ] Case export (PDF/STIX)
- [ ] Binary evidence file storage (S3/MinIO)
- [ ] JWT refresh tokens and session management
- [ ] Rate limiting (login endpoint, execute endpoint)
- [ ] mTLS for backend ↔ Wazuh communication
- [ ] Multi-tenancy / team isolation
- [ ] Notification integrations (Slack, email, PagerDuty)
- [ ] Threat intelligence enrichment (VirusTotal, AbuseIPDB, Shodan)
- [ ] Custom detection rules (Sigma → Wazuh rule compilation)
- [ ] Playbook automation engine

---

## Project History

| Commit | Phase | Capability |
|---|---|---|
| Initial | Foundation | Repository structure, Docker, PostgreSQL |
| `feat: add SOC analyst dashboard` | Dashboard foundation | React frontend, auth stub |
| `feat: add authentication and RBAC` | Auth | JWT, bcrypt, role enforcement |
| `feat: add Wazuh integration foundation` | Wazuh | Manager API client, agent listing |
| `feat: add IOC and MITRE alert enrichment` | Enrichment | IOC extraction, MITRE ATT&CK mapping |
| `feat: add background Wazuh ingestion scheduler` | Phase 7A | Background ingestion, deduplication |
| `feat: add analyst case investigation notes` | Phase 7B | Case notes, audit timeline |
| `feat: add SOC dashboard and investigation analytics` | Phase 7C | Metrics, time-series, MITRE analytics |
| `feat: add automated SOC alert triage and escalation` | Phase 7D | Triage rules, incident correlation |
| `feat: add incident lifecycle and evidence locker` | Phase 8 | Evidence locker, resolution, analyst ownership |
| `feat: add active response containment orchestration` | Phase 9 | Human-in-the-loop containment, audit trail |

---

*Built for defensive security learning. Do not use against systems you do not own or have explicit permission to test.*
