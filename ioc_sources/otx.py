import requests
from .base import collect_unique
from typing import List, Optional

def fetch_otx_ipv4(api_key: str, pulse_ids: Optional[List[str]] = None) -> set[str]:
    headers = {"X-OTX-API-KEY": api_key}
    ips = set()
    if pulse_ids:
        for pid in pulse_ids:
            url = f"https://otx.alienvault.com/api/v1/pulses/{pid}"
            r = requests.get(url, headers=headers, timeout=30)
            r.raise_for_status()
            indicators = r.json().get("indicators", [])
            for ind in indicators:
                if ind.get("type") == "IPv4":
                    ips.add(ind.get("indicator", "").strip())
    else:
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
        r = requests.get(url, headers=headers, timeout=30)
        r.raise_for_status()
        for result in r.json().get("results", []):
            for ind in result.get("indicators", []):
                if ind.get("type") == "IPv4":
                    ips.add(ind.get("indicator", "").strip())
    return collect_unique(ips)
