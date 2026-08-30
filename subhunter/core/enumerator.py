"""
Full enumeration pipeline:

  1. Passive sources (concurrent, per-source failure isolation)
  2. Hostname normalization + validation + dedup + source-tracking merge
  3. Optional permutation generation (bounded)
  4. Optional active DNS bruteforce
  5. Wildcard DNS detection (before trusting brute-force/permutation results)
  6. DNS resolution/verification (A/AAAA/CNAME [+NS/MX/TXT])
  7. Wildcard false-positive filtering
  8. Scope/exclusion evaluation
  9. Optional HTTP/HTTPS probing
  10. Optional IP/ASN enrichment
"""

import asyncio
import time

import aiohttp

from .. import sources as source_pkg
from . import resolver as dns_resolver
from . import http_probe
from . import ip_info as ip_info_mod
from .normalize import normalize_hostname, is_subdomain_of
from .permutations import generate_permutations
from .scope import Scope
from .models import Host, DNSInfo, IPInfo


class ScanResult:
    def __init__(self):
        self.target = None
        self.hosts = {}  # host -> Host
        self.source_counts = {}  # source_name -> int | None (None = unavailable)
        self.candidates_total = 0
        self.wildcard_detected = False
        self.wildcard_ips = set()
        self.wildcard_removed = 0
        self.duration_seconds = 0.0

    def summary(self):
        live = [h for h in self.hosts.values() if h.dns and h.dns.resolved]
        http_live = [h for h in live if h.http and h.http.status is not None]
        https_live = [h for h in http_live if h.http.scheme == "https"]
        return {
            "candidates": self.candidates_total,
            "dns_resolved": len(live),
            "http_live": len(http_live),
            "https_live": len(https_live),
        }


async def run_scan(
    domain,
    active=False,
    wordlist_path=None,
    concurrency=300,
    nameservers=None,
    dns_timeout=3.0,
    dns_retries=1,
    extra_dns_records=False,
    do_permutations=False,
    do_http=False,
    do_ip_info=False,
    scope_file=None,
    exclude_file=None,
    selected_sources=None,
    skip_resolve=False,
    log=print,
):
    start = time.monotonic()
    result = ScanResult()
    result.target = domain
    scope = Scope(scope_file, exclude_file)

    connector = aiohttp.TCPConnector(limit=50, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        log(f"[*] Collecting passive subdomains for: {domain}")

        def _src_progress(name, count):
            result.source_counts[name] = count
            if count is None:
                log(f"    [!] {name:<15} unavailable (no API key configured)")
            else:
                log(f"    [+] {name:<15} {count}")

        raw_host_sources = await source_pkg.run_all_sources(
            session, domain, selected=selected_sources, progress_cb=_src_progress
        )

    # --- Normalize + validate + merge sources ---
    for raw_host, src_names in raw_host_sources.items():
        clean = normalize_hostname(raw_host)
        if not clean or not is_subdomain_of(clean, domain):
            continue
        h = result.hosts.setdefault(clean, Host(host=clean))
        h.sources |= src_names

    # Always include the root domain itself as a candidate
    root_host = result.hosts.setdefault(domain, Host(host=domain))
    root_host.sources.add("root")

    log(f"[*] Unique candidates after normalization: {len(result.hosts)}")

    # --- Optional permutations (seeded from what passive already found) ---
    if do_permutations:
        perm_candidates = generate_permutations(result.hosts.keys(), domain)
        log(f"[*] Generated {len(perm_candidates)} permutation candidates")
        for cand in perm_candidates:
            clean = normalize_hostname(cand)
            if clean and clean not in result.hosts:
                result.hosts[clean] = Host(host=clean, sources={"permutation"})

    # --- Optional active bruteforce ---
    if active:
        if not wordlist_path:
            raise ValueError("Active mode requires a wordlist path (-w)")
        with open(wordlist_path, "r", errors="ignore") as f:
            wordlist = f.readlines()
        log(f"[*] Active bruteforce starting ({len(wordlist)} words)...")
        for word in wordlist:
            word = word.strip()
            if not word or word.startswith("#"):
                continue
            candidate = normalize_hostname(f"{word}.{domain}")
            if candidate and candidate not in result.hosts:
                result.hosts[candidate] = Host(host=candidate, sources={"bruteforce"})

    result.candidates_total = len(result.hosts)

    if skip_resolve:
        result.duration_seconds = time.monotonic() - start
        return result

    # --- Wildcard DNS detection (only meaningful if we're doing active work) ---
    if active or do_permutations:
        log("[*] Checking wildcard DNS...")
        is_wc, wc_ips = await dns_resolver.detect_wildcard(domain, nameservers, dns_timeout)
        result.wildcard_detected = is_wc
        result.wildcard_ips = wc_ips
        if is_wc:
            log(f"    [+] Wildcard detected -> {', '.join(sorted(wc_ips)) or '(no IPs captured)'}")
        else:
            log("    [-] No wildcard DNS detected")

    # --- DNS resolution/verification ---
    log(f"[*] Resolving {len(result.hosts)} candidates via DNS...")

    def _resolve_progress(done, total):
        log(f"    [~] Resolved: {done}/{total}")

    resolved = await dns_resolver.resolve_batch(
        result.hosts.keys(),
        concurrency=concurrency,
        nameservers=nameservers,
        timeout=dns_timeout,
        retries=dns_retries,
        extra_records=extra_dns_records,
        progress_cb=_resolve_progress,
    )

    # --- Wildcard false-positive filtering ---
    if result.wildcard_detected:
        before = len(resolved)
        resolved, removed = dns_resolver.filter_wildcard_false_positives(resolved, result.wildcard_ips)
        result.wildcard_removed = removed
        if removed:
            log(f"[*] Applying wildcard filtering... removed {removed} false positives")

    # Attach DNS info; drop hosts that never resolved
    live_hosts = {}
    for host, data in resolved.items():
        h = result.hosts.get(host, Host(host=host, sources={"bruteforce"}))
        h.dns = DNSInfo(a=data["a"], aaaa=data["aaaa"], cname=data["cname"],
                         ns=data.get("ns", []), mx=data.get("mx", []), txt=data.get("txt", []))
        in_scope, excluded = scope.evaluate(host)
        h.in_scope = in_scope
        h.excluded = excluded
        live_hosts[host] = h

    result.hosts = live_hosts
    log(f"[+] Live/valid subdomains: {len(result.hosts)}")

    # --- Optional HTTP/HTTPS probing (only for in-scope, non-excluded hosts) ---
    if do_http:
        probe_targets = [h for h, host_obj in result.hosts.items() if host_obj.in_scope and not host_obj.excluded]
        log(f"[*] Probing HTTP/HTTPS on {len(probe_targets)} in-scope hosts...")

        def _http_progress(done, total):
            log(f"    [~] Probed: {done}/{total}")

        http_results = await http_probe.probe_batch(probe_targets, progress_cb=_http_progress)
        for host, info in http_results.items():
            result.hosts[host].http = info
        http_live = sum(1 for i in http_results.values() if i.status is not None)
        log(f"[+] HTTP(S) reachable: {http_live}")

    # --- Optional IP/ASN enrichment ---
    if do_ip_info:
        all_ips = set()
        for h in result.hosts.values():
            if h.dns:
                all_ips |= set(h.dns.a) | set(h.dns.aaaa)
        log(f"[*] Looking up ASN/organization info for {len(all_ips)} unique IPs...")
        connector = aiohttp.TCPConnector(limit=10, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            ip_map = await ip_info_mod.lookup_ips(session, all_ips)
        for h in result.hosts.values():
            if not h.dns:
                continue
            for ip in h.dns.a + h.dns.aaaa:
                if ip in ip_map:
                    h.ip_info.append(ip_map[ip])

    result.duration_seconds = time.monotonic() - start
    return result


def run_scan_sync(*args, **kwargs):
    return asyncio.run(run_scan(*args, **kwargs))
