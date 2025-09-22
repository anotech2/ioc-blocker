import requests
import time
from typing import Optional

def vt_score_ip(ip: str, api_key: str) -> Optional[dict]:
    """Return VirusTotal last_analysis_stats for an IP, with basic backoff."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    backoff = 6
    for _ in range(7):
        r = requests.get(url, headers=headers, timeout=20)
        if r.status_code == 200:
            data = r.json()
            return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        if r.status_code in (429, 503):
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)
            continue
        # treat others as no data
        return None
    return None

def is_malicious_by_threshold(stats: dict | None, vt_malicious_min: int, vt_suspicious_min: int) -> bool:
    if not stats:
        return False
    mal = int(stats.get("malicious", 0))
    sus = int(stats.get("suspicious", 0))
    return (mal >= vt_malicious_min) or (sus >= vt_suspicious_min)
