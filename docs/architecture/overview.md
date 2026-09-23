# SentinelX architecture overview

High-level data flow for the planned SOC lab. Nothing in this diagram is implemented in the current milestone.

```
Windows / Sysmon  ──┐
                    ├──► Wazuh ──► alerts
Linux / Auditd    ──┘

Zeek + Suricata ──► network telemetry

Wazuh alerts ──► SentinelX backend ──► investigation / application data ──► PostgreSQL

React dashboard ──► analyst interface (reads/writes via the backend)
```

## Telemetry sources

- **Windows / Sysmon → Wazuh:** endpoint process, network, and file activity from Windows hosts.
- **Linux / Auditd → Wazuh:** Linux audit events collected into the same SIEM path.
- **Zeek + Suricata → network telemetry:** protocol metadata (Zeek) and IDS alerts / packet-oriented detections (Suricata).

## Detection and alerting

- **Wazuh → alerts:** correlation and alerting on ingested endpoint (and, later, related) telemetry.

## Application layer

- **SentinelX backend → investigation / application data:** case handling, investigation notes, and application APIs (planned).
- **PostgreSQL → application data:** durable storage for SentinelX application records, not SIEM indices.
- **React dashboard → analyst interface:** the SOC analyst view for alerts, investigations, and lab workflows.

This layout will be refined as components are added in later milestones.
