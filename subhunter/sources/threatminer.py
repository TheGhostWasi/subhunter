"""ThreatMiner passive DNS"""
from .base import safe_get_json

NAME = "threatminer"
REQUIRES_API_KEY = False


async def fetch(session, domain):
    subs = set()
    url = f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5"
    data = await safe_get_json(session, url)
    if not data:
        return subs
    for host in data.get("results", []):
        host = host.strip()
        if host:
            subs.add(host)
    return subs
