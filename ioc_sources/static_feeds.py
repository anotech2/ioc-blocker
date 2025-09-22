import requests
from .base import collect_unique

def fetch_spamhaus_drop() -> set[str]:
    url = "https://www.spamhaus.org/drop/drop.txt"
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    ips = []
    for line in r.text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        ips.append(line.split(";")[0].strip())
    return collect_unique(ips)

def fetch_spamhaus_edrop() -> set[str]:
    url = "https://www.spamhaus.org/drop/edrop.txt"
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    ips = []
    for line in r.text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        ips.append(line.split(";")[0].strip())
    return collect_unique(ips)

def fetch_emerging_threats_compromised() -> set[str]:
    url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    ips = [ln.strip() for ln in r.text.splitlines() if ln and not ln.startswith("#")]
    return collect_unique(ips)

def fetch_dshield_top() -> set[str]:
    url = "https://www.dshield.org/ipsascii.html?limit=10000"
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    ips = []
    for line in r.text.splitlines():
        line=line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if parts:
            ips.append(parts[0])
    return collect_unique(ips)
