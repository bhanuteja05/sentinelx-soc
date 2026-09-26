# Host Containment Standard Operating Procedure (SOP)

## 1. Overview & Objective
This playbook defines the standardized operational procedure for isolating a compromised endpoint from the network using the SentinelX Active Response orchestration engine and Wazuh SIEM. Host containment prevents adversary lateral movement, data exfiltration, and malware propagation while preserving telemetry back to the SOC management infrastructure.

---

## 2. Trigger Criteria & Authority
Host containment is a **high-impact defensive action** and is authorized when:
- Active Command & Control (C2) beaconing is identified on an endpoint.
- Unauthorized administrative credential access or lateral movement (e.g., PsExec, WMI, WinRM) originates from the host.
- Ransomware staging or precursor activity (e.g., volume shadow copy deletion, mass file modifications) is detected.
- An open SOC Case has escalated to **High** or **Critical** severity with confirmed endpoint compromise.

> [!WARNING]
> **Safety Notice:** Never contain the Wazuh Manager (Agent `000`) or primary domain controllers without explicit SOC Manager and IT Infrastructure authorization.

---

## 3. Human-in-the-Loop Execution Workflow

### Step 1: Endpoint Identification & Verification
1. Navigate to the affected incident in SentinelX: `/cases/:id` or alert in `/alerts/:id`.
2. Identify the target Wazuh Agent ID (e.g., `001`, `002`) and hostname from the alert metadata.
3. Verify that the agent is currently connected and reporting telemetry via the Wazuh dashboard or agents API.

### Step 2: Safety Guardrail Validation
SentinelX automatically enforces server-side safety checks:
- Verifies that `RESPONSE_ENABLED=true`.
- Confirms the target is not in `RESPONSE_PROTECTED_TARGETS`.
- Ensures the agent identifier is valid and active.

### Step 3: Trigger Containment
1. In the SentinelX Case Detail page, locate the **Defensive Containment & Active Response** panel.
2. Click **+ Execute Response** (or click **🔒 Isolate Host** on a host artifact in the Evidence Locker).
3. In the Containment modal:
   - Select Command: `isolate-host` (or `quarantine`).
   - Target Type: `agent`.
   - Target Value: `<Target Agent ID>`.
4. Carefully read the defensive risk warning.
5. Check the confirmation box: *"I confirm execution of defensive command..."*.
6. Click **Execute Containment**.

### Step 4: Verification & Audit Logging
1. SentinelX submits the active response request to the Wazuh Manager API (`PUT /active-response`).
2. Review the execution outcome in the Defensive Containment table:
   - Status must transition to **SUCCEEDED**.
   - If **FAILED**, review the `error_message` and raw execution output.
3. Verify that SentinelX automatically records an auditable timeline note in the Case:
   ```
   [Active Response] Executed 'isolate-host' for AGENT '001' on Agent '001' by 'analyst1'. Status: SUCCEEDED.
   ```
4. Confirm network isolation:
   - Target host can no longer communicate with internal subnets or the Internet.
   - Endpoint continues reporting telemetry to the Wazuh Manager over port 1514/1515.

---

## 4. Post-Containment Investigation
1. Acquire forensic artifacts (volatile memory dump, event logs, prefetch files).
2. Record all discovered malicious indicators (hashes, C2 IPs, persistence keys) in the **Case Evidence Locker**.
3. Identify initial access vector and root cause.

---

## 5. Remediation & Release from Quarantine
1. Eradicate malware and remove persistence mechanisms.
2. Verify host integrity through fresh Wazuh syscheck/rootcheck scans.
3. Restart the Wazuh agent using `restart-wazuh` or restore host firewall rules.
4. Resolve the case using the SentinelX **Resolve Incident** modal with root cause and remediation summary.
