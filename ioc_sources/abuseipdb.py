import requests
from .base import collect_unique

def fetch_abuseipdb(api_key: str, confidence_min: int = 75, days: int = 7, limit: int = 500) -> set[str]:
    url = f"https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum={confidence_min}&limit={limit}"
    headers = {"Key": api_key, "Accept": "application/json"}
    r = requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()
    data = r.json().get("data", [])
    ips = [row["ipAddress"] for row in data]
    return collect_unique(ips)
