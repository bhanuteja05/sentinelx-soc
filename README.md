# SentinelX

SentinelX is an **Enterprise SOC Detection & Incident Response Lab** for legitimate defensive security learning and portfolio demonstration.

It is a controlled environment for practicing how a security operations center (SOC) collects telemetry, detects suspicious activity, investigates alerts, and documents incident response. The project is **defensive only**: it is intended to learn detection engineering, log analysis, and investigation workflow—not offensive tooling or unauthorized access.

## Planned components

The following components are planned and will be added in later milestones:

- **Endpoint telemetry:** Windows/Sysmon and Linux/Auditd ingested by Wazuh
- **Network telemetry:** Zeek and Suricata
- **Detection content:** Sigma rules, YARA, and MITRE ATT&CK mapping
- **SIEM / alerting:** Wazuh
- **Application layer:** SentinelX backend, PostgreSQL, and a React analyst dashboard
- **Automation and investigations:** playbooks, case notes, and supporting scripts

## Development approach

This repository is built **incrementally**. The current milestone is repository foundation only (layout, ignore rules, environment variable names, and high-level documentation). Detection pipelines, SOC stack configuration, and application functionality are not implemented yet.

See:

- [Architecture overview](docs/architecture/overview.md)
- [Development environment](docs/setup/development-environment.md)
