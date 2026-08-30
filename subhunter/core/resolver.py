"""
DNS resolution engine.

Responsibilities:
  - Resolve hostnames to A/AAAA/CNAME (+ optionally MX/NS/TXT) records.
  - Detect wildcard DNS on the target domain before brute-forcing, so
    brute-force results aren't polluted by "everything resolves" domains.
  - Retry/timeout/resolver-rotation for reliability against flaky resolvers.
"""

import asyncio
import random
import string

import dns.asyncresolver
import dns.resolver
import dns.exception

DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


def build_resolver(nameservers=None, timeout=3.0):
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = nameservers or DEFAULT_RESOLVERS
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def _classify_exception(exc) -> str:
    if isinstance(exc, dns.resolver.NXDOMAIN):
        return "NXDOMAIN"
    if isinstance(exc, dns.resolver.NoAnswer):
        return "NoAnswer"
    if isinstance(exc, dns.resolver.NoNameservers):
        return "SERVFAIL"
    if isinstance(exc, dns.exception.Timeout):
        return "TIMEOUT"
    return "ERROR"


async def _query(resolver, hostname, rtype, retries=1):
    last_error = None
    for attempt in range(retries + 1):
        try:
            answers = await resolver.resolve(hostname, rtype)
            return [str(r).rstrip(".") for r in answers], None
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            last_error = _classify_exception(e)
            if last_error == "NXDOMAIN":
                break  # no point retrying a definitive NXDOMAIN
            continue
        except Exception as e:
            last_error = str(e)
            continue
    return [], last_error


async def resolve_full(resolver, hostname, sem, retries=1, extra_records=False):
    """
    Resolve one hostname across record types.
    Returns a dict: {a, aaaa, cname, ns, mx, txt, error}
    `error` is only set when NOTHING resolved.
    """
    async with sem:
        result = {"a": [], "aaaa": [], "cname": None, "ns": [], "mx": [], "txt": [], "error": None}

        a_records, a_err = await _query(resolver, hostname, "A", retries)
        result["a"] = a_records

        cname_records, _ = await _query(resolver, hostname, "CNAME", retries)
        if cname_records:
            result["cname"] = cname_records[0]

        aaaa_records, _ = await _query(resolver, hostname, "AAAA", retries)
        result["aaaa"] = aaaa_records

        if not result["a"] and not result["aaaa"] and not result["cname"]:
            result["error"] = a_err or "NXDOMAIN"
            return hostname, result

        if extra_records:
            ns_records, _ = await _query(resolver, hostname, "NS", retries)
            mx_records, _ = await _query(resolver, hostname, "MX", retries)
            txt_records, _ = await _query(resolver, hostname, "TXT", retries)
            result["ns"] = ns_records
            result["mx"] = mx_records
            result["txt"] = txt_records

        return hostname, result


async def resolve_batch(hostnames, concurrency=300, nameservers=None, timeout=3.0, retries=1,
                         extra_records=False, progress_cb=None):
    """
    Resolve many hostnames concurrently.
    Returns dict {hostname: result_dict} — only for hostnames that resolved
    to at least one record (accuracy filter: dead hosts are dropped).
    """
    resolver = build_resolver(nameservers, timeout)
    sem = asyncio.Semaphore(concurrency)
    hostnames = list(hostnames)
    total = len(hostnames)
    results = {}
    done = 0

    tasks = [
        asyncio.create_task(resolve_full(resolver, h, sem, retries=retries, extra_records=extra_records))
        for h in hostnames
    ]
    for coro in asyncio.as_completed(tasks):
        host, result = await coro
        done += 1
        if not result.get("error"):
            results[host] = result
        if progress_cb and (done % 25 == 0 or done == total):
            progress_cb(done, total)

    return results


async def detect_wildcard(domain, nameservers=None, timeout=3.0, samples=3):
    """
    Detect wildcard DNS by resolving several random, almost-certainly-unused
    subdomains. If they all resolve to the same IP set, that's the wildcard.

    Returns (is_wildcard: bool, wildcard_ips: set[str])
    """
    resolver = build_resolver(nameservers, timeout)
    ip_sets = []

    for _ in range(samples):
        rand_label = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
        candidate = f"{rand_label}.{domain}"
        a_records, _ = await _query(resolver, candidate, "A", retries=1)
        aaaa_records, _ = await _query(resolver, candidate, "AAAA", retries=1)
        ip_sets.append(frozenset(a_records + aaaa_records))

    non_empty = [s for s in ip_sets if s]
    if len(non_empty) >= 2 and len(set(non_empty)) == 1:
        return True, set(non_empty[0])
    if len(non_empty) >= 1 and len(non_empty) == samples:
        # All samples resolved (even if IPs differ slightly, e.g. round-robin) -> treat as wildcard
        union_ips = set()
        for s in non_empty:
            union_ips |= s
        return True, union_ips

    return False, set()


def filter_wildcard_false_positives(results: dict, wildcard_ips: set) -> tuple:
    """
    Remove entries whose A/AAAA records are a subset of the known wildcard IPs
    AND that have no distinguishing CNAME. Returns (filtered_results, removed_count).
    """
    if not wildcard_ips:
        return results, 0

    filtered = {}
    removed = 0
    for host, data in results.items():
        host_ips = set(data.get("a", []) + data.get("aaaa", []))
        looks_like_wildcard = bool(host_ips) and host_ips.issubset(wildcard_ips) and not data.get("cname")
        if looks_like_wildcard:
            removed += 1
            continue
        filtered[host] = data
    return filtered, removed


async def bruteforce_candidates(domain, wordlist, concurrency=300, nameservers=None,
                                 timeout=3.0, retries=1, progress_cb=None):
    """Generate hostname candidates from a wordlist and resolve them."""
    candidates = (
        f"{word.strip()}.{domain}"
        for word in wordlist
        if word.strip() and not word.startswith("#")
    )
    return await resolve_batch(
        candidates, concurrency=concurrency, nameservers=nameservers,
        timeout=timeout, retries=retries, progress_cb=progress_cb,
    )
