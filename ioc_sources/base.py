from typing import Iterable, Set

def normalize_ip(ip: str) -> str:
    return ip.strip()

def collect_unique(ips: Iterable[str]) -> Set[str]:
    out: Set[str] = set()
    for ip in ips:
        ip = normalize_ip(ip)
        if ip:
            out.add(ip)
    return out
