"""
SecurityTrails passive DNS — OPTIONAL, requires a free/paid API key.
Set the SUBHUNTER_SECURITYTRAILS_API_KEY environment variable to enable.
Silently skipped (reported as "unavailable") if the key isn't set.
"""
import os
from .base import safe_get_json

NAME = "securitytrails"
REQUIRES_API_KEY = True
API_KEY_ENV = "SUBHUNTER_SECURITYTRAILS_API_KEY"


async def fetch(session, domain):
    subs = set()
    api_key = os.environ.get(API_KEY_ENV)
    if not api_key:
        return subs  # optional source, silently skipped when no key configured
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    data = await safe_get_json(session, url, headers={"APIKEY": api_key})
    if not data:
        return subs
    for sub in data.get("subdomains", []):
        sub = str(sub).strip()
        if sub:
            subs.add(f"{sub}.{domain}")
    return subs
