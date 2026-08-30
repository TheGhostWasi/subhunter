"""Shared helpers for passive source plugins."""

HEADERS = {"User-Agent": "SubHunter/2.0 (+security-research)"}


async def safe_get(session, url, timeout=15, headers=None):
    """GET a URL, return text or None on any failure. Never raises."""
    try:
        async with session.get(url, headers=headers or HEADERS, timeout=timeout, ssl=False) as resp:
            if resp.status == 200:
                return await resp.text()
            return None
    except Exception:
        return None


async def safe_get_json(session, url, timeout=15, headers=None):
    """GET a URL, return parsed JSON or None on any failure."""
    import json
    text = await safe_get(session, url, timeout=timeout, headers=headers)
    if text is None:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None
