# SentinelX — Development Environment Setup

This document details prerequisites and environment configuration required to run SentinelX SOC Lab.

---

## 1. System Requirements

| Resource | Minimum | Recommended |
|---|---|---|
| OS | Windows 10/11 (with WSL2), Ubuntu 22.04+, or macOS | Windows 11 with WSL2 Ubuntu |
| RAM | 8 GB (App stack only) | 16 GB (App stack + Wazuh SIEM stack) |
| CPU | 4 cores | 8 cores |
| Disk | 20 GB free space | 40 GB SSD free space |

---

## 2. Toolchain Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| **Docker Desktop** | 24+ (Compose v2) | Container runtime and orchestration for isolated stacks |
| **WSL2** | Kernel 5.15+ | Linux kernel subsystem for Docker Desktop backend |
| **Python** | 3.13+ | Backend runtime, Alembic migrations, and seeding scripts |
| **Node.js** | 20+ | Frontend development and static build compilation |
| **Git** | 2.40+ | Version control |

---

## 3. Host System Configuration (WSL2 / Linux)

Wazuh Indexer requires adequate virtual memory allocation for OpenSearch mmap operations:

```bash
# In WSL2 or Linux host terminal
sudo sysctl -w vm.max_map_count=262144

# To persist across reboots, add to /etc/sysctl.conf:
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

In Docker Desktop Settings:
- **Resources → Advanced:** Allocate at least 12 GB RAM and 4 CPUs when running both App and Wazuh stacks concurrently.
- **Resources → WSL Integration:** Ensure Ubuntu distribution integration is enabled.

---

## 4. Repository Setup

```bash
git clone https://github.com/bhanuteja05/sentinelx-soc.git
cd sentinelx-soc

# Copy environment configuration
cp .env.example .env

# Configure passwords and secure JWT secret in .env
```
