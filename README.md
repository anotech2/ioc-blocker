# IOC Blocker for Palo Alto NGFW

Automates the ingestion of **malicious IP indicators** from multiple OSINT sources, optionally **enriches** with VirusTotal, and **enforces blocks** on a Palo Alto Networks firewall using a **Dynamic Address Group (DAG)** and a deny policy. Designed for SOC/Blue-Team workflows in both **lab** and **production**.

---

## Features

- **OSINT feeds** out of the box: Spamhaus DROP/eDROP, Emerging Threats compromised, DShield Top.
- **Optional sources**: AbuseIPDB, AlienVault OTX, local Excel list.
- **VirusTotal enrichment** (configurable thresholds): keep only high-confidence bad IPs.
- **Two modes**:
  - **objects** – creates Address Objects tagged `malicious` (supports CIDRs; requires commit).
  - **user-id** – registers IP→tag via User-ID (no commit; IPs only; fast churn).
- **Idempotent**: ensures tag/DAG/policy exist and only applies deltas.
- **Verification**: checks candidate & running config; can query DAG members.
- **24/7**: simple loop runner (`service.py`), cron, or systemd.

---

## Architecture (high level)

flowchart LR
    A[Feeds] --> B[Collector & Dedupe]
    B --> C[Optional VT Enrichment]
    C --> D[Final IOC Set]
    D -->|mode=objects| E[Address Objects + tag=malicious] --> F[DAG(filter='malicious')] --> G[Deny Rule]
    D -->|mode=user-id| H[User-ID Register IP→tag] --> F
