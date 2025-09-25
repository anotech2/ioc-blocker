# Build an Automated IOC Blocker for Palo Alto NGFW — End‑to‑End Guide (Step‑by‑Step)

## README for GitHub Repository


## **IOC Blocker for Palo Alto NGFW**

Automates the ingestion of **malicious IP indicators** from multiple OSINT sources, optionally enriches with VirusTotal, and enforces blocks on a Palo Alto Networks firewall using a **Dynamic Address Group (DAG)** and a deny policy.

## Features
- **OSINT feeds**: Spamhaus DROP/eDROP, Emerging Threats, DShield Top, optional AbuseIPDB & AlienVault OTX
- **VirusTotal enrichment** (configurable thresholds)
- **Two modes**:
  - **objects**: creates Address Objects (supports CIDRs; requires commit)
  - **user-id**: registers IP→tag (no commit; IPs only; fast churn)
- **Idempotent**: ensures tag/DAG/rule exist, applies only deltas
- **Verification**: checks candidate & running config; query DAG members
- **Scheduler**: run once or continuously (`service.py`, cron, or systemd)

## Quick Start

### Clone and setup
```bash
git clone https://github.com/anotech2/ioc-blocker.git
cd ioc-blocker
python -m venv .venv
# On Windows
.venv\Scripts\activate
# On macOS/Linux
source .venv/bin/activate
pip install -r requirements.txt
````

### Configure

Copy `.env.example` to `.env` and fill in with firewall details and API keys:

```bash
cp .env.example .env
```

### Run once

```bash
python run_once.py
```

### Run continuously

```bash
python service.py
```

## Folder Layout

```
ioc-blocker/
├─ panos_api.py       # PAN-OS XML API helper
├─ run_once.py        # Pipeline: feeds → enrich → update firewall
├─ service.py         # Loop scheduler
├─ vt_enrich.py       # VirusTotal helpers
├─ ioc_sources/       # Feed collectors
├─ feeds.yaml         # Feed toggles + thresholds
├─ requirements.txt   # Dependencies
├─ .env.example       # Safe config template
└─ .gitignore         # Ensures .env is ignored
```

## Security Notes

* **Never commit `.env`** (secrets)
* Use least-privilege firewall credentials
* Enable TLS verification in production (`PAN_VERIFY=true`)

**Check the below link for step by step guidance.**

https://medium.com/@ano.tech2/automated-ioc-blocker-for-palo-alto-ngfw-f55728743295

