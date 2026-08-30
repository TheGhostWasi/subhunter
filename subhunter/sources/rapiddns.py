"""RapidDNS.io HTML scrape (subdomain listing, no key required)"""
import re
from .base import safe_get

NAME = "rapiddns"
REQUIRES_API_KEY = False
_ROW_RE = re.compile(r"<td>([a-zA-Z0-9_.-]+\.[a-zA-Z]{2,})</td>")


async def fetch(session, domain):
    subs = set()
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    text = await safe_get(session, url, timeout=20)
    if not text:
        return subs
    for m in _ROW_RE.finditer(text):
        host = m.group(1).strip()
        if host.endswith(domain):
            subs.add(host)
    return subs
