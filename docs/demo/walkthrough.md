# SentinelX SOC Lab — Demonstration Walkthrough

This document guides SOC analysts, hiring managers, and interviewers through an end-to-end incident investigation workflow in SentinelX.

---

## Prerequisites

1. Ensure the SentinelX app stack and Wazuh stack are running:
   ```bash
   docker compose ps
   ```
2. Verify all 6 containers are healthy:
   - `sentinelx-soc-backend-1`
   - `sentinelx-soc-db-1`
   - `sentinelx-soc-frontend-1`
   - `sentinelx-wazuh-wazuh.manager-1`
   - `sentinelx-wazuh-wazuh.indexer-1`
   - `sentinelx-wazuh-wazuh.dashboard-1`

---

## Step 1: Authentication & RBAC

1. Open your browser to `http://127.0.0.1:5173/login`.
2. Log in with analyst credentials:
   - **Username:** `analyst` (or `admin`)
   - **Password:** configured in your `.env` (seeded via `scripts/seed_users.py`)
3. The platform validates your credentials via bcrypt, issues a signed JWT HS256 access token, and loads the SOC Console.

---

## Step 2: SOC Analytics Dashboard

1. Upon login, navigate to `/` (Dashboard).
2. Review real-time operational metrics:
   - **Total Ingested Alerts:** All-time volume processed from Wazuh Indexer.
   - **Active Endpoints:** Count of online Wazuh agents (e.g. `SentinelX-Windows-Host`).
   - **Severity Distribution:** Breakdown across Critical (12+), High (8-11), Medium (4-7), and Low (0-3).
   - **Time-Series Ingestion:** Hourly alert volume over the past 24 hours.
   - **MITRE ATT&CK Analytics:** Top observed tactics and techniques.
   - **Extracted IOC Telemetry:** Extracted public IPs, domains, and hashes.

---

## Step 3: Alert Ingestion & Threat Investigation

1. Click on **Alerts** in the navigation bar (`/alerts`).
2. Filter alerts by:
   - **Severity / Rule Level:** e.g., Level `7` or `8`.
   - **Agent Host:** e.g., `SentinelX-Windows-Host`.
   - **MITRE Tactic:** e.g., `Defense Evasion` or `Persistence`.
3. Click **Investigate** on an alert to view its detailed breakdown (`/alerts/{id}`):
   - **Agent Metadata:** ID, hostname, decoder, event location.
   - **MITRE ATT&CK Mapping:** Tactic badges, normalized technique IDs.
   - **Extracted IOCs:** Public IPs, URLs, domain names, hashes.
   - **Raw SIEM Event:** Formatted JSON payload from Wazuh.

---

## Step 4: Automated Triage & Correlation

1. Navigate to **Triage** (`/triage`).
2. Review active escalation policies:
   - *Critical Alert Auto-Escalation* (Rule level ≥ 12)
   - *Credential Access Threat Detection* (Tactic: `credential-access`)
   - *High Severity Security Warning* (Rule level ≥ 7)
3. Click **Run Triage Evaluation** to scan unprocessed alerts:
   - Matching alerts are evaluated in chronological order.
   - If an existing open case exists for that host within 24 hours, the alert is automatically correlated into the case.
   - Otherwise, a new investigation case is opened, and audit notes are logged.

---

## Step 5: Incident Lifecycle & Evidence Locker

1. Navigate to **Cases** (`/cases`).
2. Select an active incident (e.g., `Case #1`).
3. **Claim Case:** Click *Claim* to assign the investigation to yourself.
4. **Attach Evidence:**
   - Scroll to the **Evidence Locker** section.
   - Promote extracted IOCs or manually catalog artifacts (e.g. IP `198.51.100.25`, verdict `Suspicious`).
   - The platform catalogs the artifact and writes an immutable audit note.
5. **Add Investigation Notes:**
   - Document findings, host analysis, and timeline observations.

---

## Step 6: Defensive Active Response Containment

1. In the Case detail view, click **+ Execute Response** (or click *Contain Agent* from an alert).
2. The **Execute Defensive Active Response** modal appears:
   - **Command:** Select an allowlisted command (e.g. `Block IP (Firewall Drop)` or `Isolate Endpoint`).
   - **Target:** Enter the target IP address or host agent ID.
   - Review the risk warning banner.
   - Select the mandatory confirmation checkbox: *"I confirm execution of defensive command..."*.
3. Click **Execute Containment**.
4. The backend evaluates safety guardrails (loopback rejection, RFC safety, allowlist).
5. The command is dispatched to Wazuh Active Response, and an auditable `ResponseAction` record and case note are created.

---

## Step 7: Incident Resolution & Audit Trail

1. When containment and investigation are complete, click **Resolve Incident**.
2. Fill out mandatory SOC resolution criteria:
   - **Disposition:** e.g. `True Positive — Incident Confirmed`
   - **Root Cause:** e.g. `Misconfiguration` or `Malware Execution`
   - **Resolution Summary:** Minimum 10 characters detailing remediation and lessons learned.
3. Submit resolution:
   - Status updates to `Resolved`.
   - Resolution metadata and timestamp are sealed.
   - Should further threat telemetry arrive, the incident can be reopened with mandatory operational justification.
