"""Certificate Transparency logs via crt.sh"""
from .base import safe_get
import json

NAME = "crt.sh"
REQUIRES_API_KEY = False


async def fetch(session, domain):
    subs = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    text = await safe_get(session, url, timeout=25)
    if not text:
        return subs
    try:
        data = json.loads(text)
        for entry in data:
            name_value = entry.get("name_value", "")
            for line in name_value.split("\n"):
                subs.add(line.strip())
    except Exception:
        pass
    return subs
