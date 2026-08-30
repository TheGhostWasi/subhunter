"""HackerTarget hostsearch API"""
from .base import safe_get

NAME = "hackertarget"
REQUIRES_API_KEY = False


async def fetch(session, domain):
    subs = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    text = await safe_get(session, url)
    if not text or "error" in text.lower() or "api count exceeded" in text.lower():
        return subs
    for line in text.splitlines():
        host = line.split(",")[0].strip()
        if host:
            subs.add(host)
    return subs
