"""CertSpotter certificate transparency API (free tier, no key required)"""
from .base import safe_get_json

NAME = "certspotter"
REQUIRES_API_KEY = False


async def fetch(session, domain):
    subs = set()
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    data = await safe_get_json(session, url)
    if not data:
        return subs
    for entry in data:
        for name in entry.get("dns_names", []):
            name = name.strip()
            if name:
                subs.add(name)
    return subs
