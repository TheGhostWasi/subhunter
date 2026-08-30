"""
Optional IP/ASN/organization/country lookup.
Uses ip-api.com's free batch endpoint (no API key required for reasonable
volumes). Best-effort only — failures never break the scan.
"""

import asyncio
import json

from .models import IPInfo

BATCH_URL = "http://ip-api.com/batch?fields=status,query,as,org,country,isp"
BATCH_SIZE = 100  # ip-api.com batch limit


async def lookup_ips(session, ips, timeout_s=10):
    """
    ips: iterable of unique IP strings.
    Returns {ip: IPInfo}. Silently skips IPs that fail lookup.
    """
    ips = list(dict.fromkeys(ips))  # dedupe, preserve order
    results = {}

    for i in range(0, len(ips), BATCH_SIZE):
        chunk = ips[i:i + BATCH_SIZE]
        try:
            async with session.post(
                BATCH_URL,
                data=json.dumps(chunk),
                headers={"Content-Type": "application/json"},
                timeout=timeout_s,
            ) as resp:
                if resp.status != 200:
                    continue
                data = await resp.json(content_type=None)
                for entry in data:
                    if entry.get("status") != "success":
                        continue
                    ip = entry.get("query")
                    if not ip:
                        continue
                    results[ip] = IPInfo(
                        ip=ip,
                        asn=entry.get("as"),
                        org=entry.get("org") or entry.get("isp"),
                        country=entry.get("country"),
                    )
        except Exception:
            continue  # best-effort — never fail the scan over this
        # Be polite to the free tier
        if i + BATCH_SIZE < len(ips):
            await asyncio.sleep(1.2)

    return results
