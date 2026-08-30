"""urlscan.io search API (no key required for public search)"""
from .base import safe_get_json

NAME = "urlscan"
REQUIRES_API_KEY = False


async def fetch(session, domain):
    subs = set()
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000"
    data = await safe_get_json(session, url)
    if not data:
        return subs
    for result in data.get("results", []):
        page = result.get("page", {})
        host = (page.get("domain") or "").strip()
        if host:
            subs.add(host)
    return subs
