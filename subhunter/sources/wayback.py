"""Wayback Machine CDX API — hostnames from archived URLs"""
import re
from .base import safe_get

NAME = "wayback"
REQUIRES_API_KEY = False
_PATTERN = re.compile(r"https?://([a-zA-Z0-9_.-]+)")


async def fetch(session, domain):
    subs = set()
    url = (
        f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
        "&output=text&fl=original&collapse=urlkey&limit=100000"
    )
    text = await safe_get(session, url, timeout=30)
    if not text:
        return subs
    for line in text.splitlines():
        m = _PATTERN.match(line.strip())
        if m:
            subs.add(m.group(1))
    return subs
