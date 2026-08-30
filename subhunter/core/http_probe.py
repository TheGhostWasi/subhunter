"""
HTTP/HTTPS probing for resolved hosts, with lightweight best-effort
technology and CDN/WAF fingerprinting from passive evidence
(headers, cookies, HTML markers). No exploitation, no auth bypass.
"""

import re
import time
import asyncio

import aiohttp

HEADERS = {"User-Agent": "SubHunter/2.0 (+security-research)"}
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# (technology, matcher-fn(headers, body)) — best-effort, not exhaustive
_TECH_SIGNATURES = [
    ("WordPress", lambda h, b: "wp-content" in b or "wp-includes" in b),
    ("Next.js", lambda h, b: "__next" in b or h.get("x-powered-by", "").lower() == "next.js"),
    ("React", lambda h, b: "data-reactroot" in b or "react" in b[:2000].lower()),
    ("Laravel", lambda h, b: "laravel_session" in str(h.get("set-cookie", ""))),
    ("Django", lambda h, b: "csrftoken" in str(h.get("set-cookie", ""))),
    ("Express", lambda h, b: h.get("x-powered-by", "").lower() == "express"),
    ("PHP", lambda h, b: "php" in h.get("x-powered-by", "").lower() or "phpsessid" in str(h.get("set-cookie", "")).lower()),
    ("nginx", lambda h, b: "nginx" in h.get("server", "").lower()),
    ("Apache", lambda h, b: "apache" in h.get("server", "").lower()),
]

# (label, matcher-fn(headers)) — labeled "Likely X" since evidence is passive/indirect
_CDN_WAF_SIGNATURES = [
    ("Likely CDN: Cloudflare", lambda h: "cloudflare" in h.get("server", "").lower() or "cf-ray" in h),
    ("Likely CDN: Fastly", lambda h: "fastly" in h.get("server", "").lower() or "x-served-by" in h and "fastly" in h.get("x-served-by", "").lower()),
    ("Likely CDN: Akamai", lambda h: "akamai" in h.get("server", "").lower() or "x-akamai" in "".join(h.keys()).lower()),
    ("Likely CDN: Amazon CloudFront", lambda h: "cloudfront" in h.get("via", "").lower() or "x-amz-cf-id" in h),
    ("Likely WAF: Cloudflare", lambda h: "cf-chl" in "".join(h.keys()).lower()),
]


def _extract_title(body: str):
    if not body:
        return None
    m = _TITLE_RE.search(body)
    if m:
        return re.sub(r"\s+", " ", m.group(1)).strip()[:200]
    return None


def _detect_tech(headers: dict, body: str):
    headers_lower = {k.lower(): v for k, v in headers.items()}
    body_snippet = (body or "")[:20000]
    found = []
    for name, matcher in _TECH_SIGNATURES:
        try:
            if matcher(headers_lower, body_snippet):
                found.append(name)
        except Exception:
            continue
    return found


def _detect_cdn_waf(headers: dict):
    headers_lower = {k.lower(): v for k, v in headers.items()}
    found = []
    for label, matcher in _CDN_WAF_SIGNATURES:
        try:
            if matcher(headers_lower):
                found.append(label)
        except Exception:
            continue
    return found


async def probe_host(session, host, timeout_s=5, max_body_bytes=200_000):
    """
    Try HTTPS then HTTP. Returns an HTTPInfo-shaped dict, or None if both fail.
    Never raises — connection errors just mean "not HTTP reachable".
    """
    from .models import HTTPInfo

    timeout = aiohttp.ClientTimeout(total=timeout_s)

    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        start = time.monotonic()
        try:
            async with session.get(
                url, headers=HEADERS, timeout=timeout, ssl=False, allow_redirects=True, max_redirects=5
            ) as resp:
                elapsed_ms = (time.monotonic() - start) * 1000
                raw = await resp.content.read(max_body_bytes)
                body = raw.decode(errors="ignore")
                headers = dict(resp.headers)

                info = HTTPInfo(
                    scheme=scheme,
                    status=resp.status,
                    final_url=str(resp.url),
                    redirect_location=str(resp.history[-1].headers.get("Location")) if resp.history else None,
                    title=_extract_title(body),
                    server=headers.get("Server"),
                    content_type=headers.get("Content-Type"),
                    content_length=len(raw),
                    response_time_ms=round(elapsed_ms, 1),
                    technologies=_detect_tech(headers, body),
                    cdn_waf=_detect_cdn_waf(headers),
                )
                return info
        except Exception as e:
            if scheme == "http":
                return HTTPInfo(error=str(e)[:200])
            continue  # HTTPS failed, try HTTP

    return None


async def probe_batch(hosts, concurrency=50, timeout_s=5, progress_cb=None):
    """
    Probe many hosts concurrently (bounded, separate from DNS concurrency).
    `hosts` is an iterable of hostnames. Returns {host: HTTPInfo}.
    """
    sem = asyncio.Semaphore(concurrency)
    results = {}
    done = 0
    total = len(hosts) if hasattr(hosts, "__len__") else None

    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:

        async def _one(h):
            async with sem:
                return h, await probe_host(session, h, timeout_s=timeout_s)

        tasks = [asyncio.create_task(_one(h)) for h in hosts]
        for coro in asyncio.as_completed(tasks):
            host, info = await coro
            done += 1
            if info is not None:
                results[host] = info
            if progress_cb and total and (done % 10 == 0 or done == total):
                progress_cb(done, total)

    return results
