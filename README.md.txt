@'
# IOC Blocker for Palo Alto NGFW

Automates ingesting OSINT IPs, optional VirusTotal enrichment, and DAG-based blocking on PAN-OS.

## Quick start
```bash
git clone <your-repo-url> ioc-blocker
cd ioc-blocker
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env   # fill with your values
python .\run_once.py
