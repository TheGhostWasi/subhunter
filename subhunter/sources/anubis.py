"""Anubis-DB (jonlu.ca) subdomain archive"""
from .base import safe_get_json

NAME = "anubis"
REQUIRES_API_KEY = False


async def fetch(session, domain):
    subs = set()
    url = f"https://jonlu.ca/anubis/subdomains/{domain}"
    data = await safe_get_json(session, url)
    if not data:
        return subs
    for host in data:
        host = str(host).strip()
        if host:
            subs.add(host)
    return subs
