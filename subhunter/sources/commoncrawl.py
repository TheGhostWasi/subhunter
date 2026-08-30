"""Common Crawl index — hostnames from archived URLs (uses latest index)"""
import re
from .base import safe_get, safe_get_json

NAME = "commoncrawl"
REQUIRES_API_KEY = False
_PATTERN = re.compile(r"https?://([a-zA-Z0-9_.-]+)")


async def _latest_index(session):
    data = await safe_get_json(session, "https://index.commoncrawl.org/collinfo.json", timeout=15)
    if not data:
        return None
    return data[0].get("cdx-api") if data else None


async def fetch(session, domain):
    subs = set()
    cdx_api = await _latest_index(session)
    if not cdx_api:
        return subs
    url = f"{cdx_api}?url=*.{domain}/*&output=json&fl=url&limit=2000"
    text = await safe_get(session, url, timeout=25)
    if not text:
        return subs
    for line in text.splitlines():
        m = _PATTERN.search(line)
        if m:
            subs.add(m.group(1))
    return subs
