"""AlienVault OTX passive DNS"""
from .base import safe_get_json

NAME = "alienvault_otx"
REQUIRES_API_KEY = False


async def fetch(session, domain):
    subs = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    data = await safe_get_json(session, url)
    if not data:
        return subs
    for entry in data.get("passive_dns", []):
        hostname = entry.get("hostname", "").strip()
        if hostname:
            subs.add(hostname)
    return subs
