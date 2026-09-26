# Malicious IP Blocking Standard Operating Procedure (SOP)

## 1. Overview & Objective
This playbook defines the standardized operational procedure for blocking malicious incoming or outgoing network communications from known hostile IP addresses using SentinelX Active Response and Wazuh `firewall-drop` / `host-deny` capabilities.

---

## 2. Trigger Criteria
IP blocking is executed when an analyst detects:
- Brute-force authentication attacks against SSH, RDP, or web services.
- Confirmed Command & Control (C2) callback beacons or external data exfiltration endpoints.
- Port scanning or vulnerability exploit attempts originating from a malicious public IP.
- Newly enriched Threat Intelligence IOC matching high-confidence malicious infrastructure.

---

## 3. Pre-Execution Safety Checks
Before executing a block action, the analyst must verify:
- **IP Target Verification:** Confirm the IP address does not belong to essential infrastructure (DNS, NTP, internal gateways, corporate proxy, Wazuh indexer/manager).
- **Automated Guardrail Enforcement:** SentinelX server-side validation will automatically reject:
  - Loopback addresses (`127.0.0.1`, `::1`, `localhost`)
  - Wildcard / unspecified addresses (`0.0.0.0`, `::`)
  - Multicast / link-local / reserved ranges
  - Protected targets specified in `RESPONSE_PROTECTED_TARGETS`

---

## 4. Execution Workflow

### Method A: From the Case Evidence Locker
1. In the open Case, navigate to the **Evidence Locker** section.
2. Locate the IP address artifact with verdict `malicious` or `suspicious`.
3. Click the **🛡️ Block IP** button in the Actions column.
4. The Active Response modal opens pre-populated with:
   - Command: `firewall-drop`
   - Target Type: `ip`
   - Target Value: `<Target IP>`
5. Enter the target Wazuh **Agent ID** (or leave empty to target all reporting agents).
6. Check the confirmation checkbox and click **Execute Containment**.

### Method B: From the Alert Detail Page
1. On the alert detail page (`/alerts/:id`), locate the network metadata.
2. Click **🛡️ Block Source IP (<IP>)** in the header actions.
3. Review the confirmation dialog and confirm execution.

### Method C: Manual Response Dispatch
1. Open the Case Detail page and locate **Defensive Containment & Active Response**.
2. Click **+ Execute Response**.
3. Select `firewall-drop` (for host firewall packet drop) or `host-deny` (for `/etc/hosts.deny` TCP wrapper blocking).
4. Enter target IP and Agent ID.
5. Confirm and execute.

---

## 5. Verification & Case Documentation
1. Confirm the ResponseAction transitions to status **SUCCEEDED**.
2. Verify the automated audit note generated in the Case timeline:
   ```
   [Active Response] Executed 'firewall-drop' for IP '203.0.113.50' on Agent '001' by 'analyst1'. Status: SUCCEEDED.
   ```
3. Catalog the IP in the Case Evidence Locker:
   - Type: `IP Address`
   - Value: `203.0.113.50`
   - Verdict: `malicious`
   - Notes: `Blocked via active response firewall-drop.`
