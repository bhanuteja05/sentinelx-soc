# Ransomware Incident Response Playbook

## 1. Executive Summary & Objective
This playbook provides rapid-response procedures for detecting, containing, investigating, and eradicating ransomware activity within the SentinelX SOC lab environment. Speed of containment is critical to prevent lateral movement, active data exfiltration, and volume shadow copy destruction across Windows and Linux endpoints.

---

## 2. Detection Indicators & Immediate Escalation
Escalate to **P1 / Critical** immediately upon detecting:
- Execution of `vssadmin.exe delete shadows /all /quiet`, `wmic shadowcopy delete`, or `wbadmin delete catalog`.
- Rapid file renaming or entropy changes detected by Wazuh syscheck/FIM or Sysmon Event ID 11.
- Mass process termination of database, backup, or security services (e.g., `net stop`, `taskkill`).
- Unrecognized ransomware notes (`.txt`, `.hta`, `.html`) appearing in user directories or network shares.
- Sudden spikes in outbound network SMB/RPC connections or anomalous PsExec execution.

---

## 3. High-Velocity Incident Response Phases

### Phase 1: Immediate Defensive Containment (Triage + T+5 Minutes)
1. **Identify the Patient Zero Endpoint:**
   - Locate the initial alert in SentinelX (`/alerts/:id`).
   - Extract the affected Wazuh `agent_id` and hostname.
2. **Execute Host Isolation:**
   - On the Alert Detail page or open Case, click **🔒 Contain Agent**.
   - Select command `isolate-host` (or `quarantine`).
   - Confirm the Human-in-the-Loop authorization modal.
   - SentinelX dispatches the active response command to the Wazuh Manager to isolate the host from all non-management traffic.
3. **Block Adversary Infrastructure:**
   - If C2 domains or external IP addresses are identified in the alert IOCs:
   - Navigate to the **Evidence Locker** in the Case or Alert Detail page.
   - Click **🛡️ Block IP** to execute `firewall-drop` across other endpoints to sever external control channels.

### Phase 2: Containment Verification
1. Confirm the `ResponseAction` status in the SentinelX Case Detail page shows **SUCCEEDED**.
2. Verify the automated audit entry in the Case investigation timeline:
   ```
   [Active Response] Executed 'isolate-host' for AGENT '001' on Agent '001' by 'analyst1'. Status: SUCCEEDED.
   ```
3. Verify that the infected endpoint can no longer reach domain controllers, file servers, or peer endpoints.

### Phase 3: Forensic Artifact Preservation
Before powering down or wiping the contained endpoint:
1. Capture volatile memory (RAM) if feasible for key extraction and process memory analysis.
2. Collect Wazuh alerts and local Windows Security / Sysmon event logs.
3. Identify ransomware binary samples and compute cryptographic hashes (SHA-256).
4. Catalog all hashes, drop paths, and C2 endpoints into the **Case Evidence Locker** with verdict `malicious`.

### Phase 4: Eradication & Recovery
1. Identify and close the initial entry vector (e.g., phishing attachment, exposed RDP, vulnerable web service).
2. Scan and verify backup repositories for ransomware compromise or shadow deletion attempts.
3. Re-image or restore the affected endpoint from clean, verified offline backups.
4. Update Wazuh detection rules to alert on the newly discovered indicators.

### Phase 5: Structured Incident Resolution & Post-Mortem
1. In the SentinelX Case Detail page, click **✓ Resolve Incident**.
2. Select:
   - Disposition: `True Positive — Incident Confirmed`
   - Root Cause: `Malware Execution` (or appropriate root cause)
   - Resolution Summary: Detail patient zero identification, containment actions taken (`isolate-host`, `firewall-drop`), forensic hashes cataloged, and backup restoration verification.
3. Document lessons learned and update detection engineering rules.
