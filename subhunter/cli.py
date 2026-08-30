#!/usr/bin/env python3
"""
SubHunter CLI v2.0 — Fast & Accurate Subdomain Enumeration Tool
For authorized security testing, bug bounty programs, and security research only.
"""

import argparse
import asyncio
import os
import sys
import time

from . import __version__
from .config import load_config
from .core.enumerator import run_scan
from .output import text, json_out, csv_out, html_out

BANNER = rf"""
   _____       __    __  __            __
  / ___/__  __/ /_  / / / /_  ______  / /____  _____
  \__ \/ / / / __ \/ /_/ / / / / __ \/ __/ _ \/ ___/
 ___/ / /_/ / /_/ / __  / /_/ / / / / /_/  __/ /
/____/\__,_/_.___/_/ /_/\__,_/_/ /_/\__/\___/_/   v{__version__}

  Fast & Accurate Subdomain Enumeration for Authorized Security Testing
"""


def build_parser():
    parser = argparse.ArgumentParser(
        prog="subhunter",
        description="Fast & accurate subdomain enumeration tool (passive + active). "
                     "For authorized security testing and bug bounty use only.",
    )
    # --- v1 flags (preserved, unchanged behavior) ---
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--json", action="store_true", help="Save/print output as JSON")
    parser.add_argument("-a", "--active", action="store_true", help="Enable active DNS bruteforce")
    parser.add_argument("-w", "--wordlist", help="Wordlist path for active bruteforce")
    parser.add_argument("-c", "--concurrency", type=int, default=None, help="Concurrent DNS resolutions (default: 300)")
    parser.add_argument("-r", "--resolvers", help="Comma-separated custom DNS resolvers (default: 1.1.1.1,8.8.8.8,9.9.9.9)")
    parser.add_argument("--no-resolve", action="store_true", help="Skip DNS verification step (faster, less accurate)")
    parser.add_argument("-s", "--silent", action="store_true", help="Only print final results, no progress logs")
    parser.add_argument("-v", "--version", action="version", version=f"SubHunter {__version__}")

    # --- v2 new flags ---
    parser.add_argument("--http", action="store_true", help="Probe HTTP/HTTPS on resolved hosts")
    parser.add_argument("--ip-info", action="store_true", help="Look up ASN/organization/country for resolved IPs")
    parser.add_argument("--permutations", action="store_true", help="Generate & verify bounded subdomain permutations")
    parser.add_argument("--scope", help="Scope file (patterns like *.example.com) — only these are actively probed")
    parser.add_argument("--exclude", help="Exclusion file — these are never actively probed even if in scope")
    parser.add_argument("--csv", action="store_true", help="Save output as CSV (use with -o)")
    parser.add_argument("--html", help="Write an HTML report to this path")
    parser.add_argument("--dns-timeout", type=float, default=None, help="Per-query DNS timeout in seconds (default: 3)")
    parser.add_argument("--dns-retries", type=int, default=None, help="DNS query retries (default: 1)")
    parser.add_argument("--extra-dns", action="store_true", help="Also collect NS/MX/TXT records (slower)")
    parser.add_argument("--sources", help="Comma-separated list of passive sources to use (default: all available)")
    parser.add_argument("--show-sources", action="store_true", help="Show which source(s) discovered each host")
    parser.add_argument("--config", help=f"Path to config file (default: {os.path.expanduser('~/.config/subhunter/config.yaml')})")
    parser.add_argument("--debug", action="store_true", help="Verbose debug output")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.silent:
        print(text.cyan(BANNER))

    if args.active and not args.wordlist:
        print(text.red("[!] --active requires --wordlist (-w)."))
        sys.exit(1)

    if args.wordlist and not os.path.isfile(args.wordlist):
        print(text.red(f"[!] Wordlist file not found: {args.wordlist}"))
        sys.exit(1)

    if args.scope and not os.path.isfile(args.scope):
        print(text.red(f"[!] Scope file not found: {args.scope}"))
        sys.exit(1)

    if args.exclude and not os.path.isfile(args.exclude):
        print(text.red(f"[!] Exclude file not found: {args.exclude}"))
        sys.exit(1)

    # Load config file, then let explicit CLI args override it
    config = load_config(args.config)
    concurrency = args.concurrency if args.concurrency is not None else config["concurrency"]
    dns_timeout = args.dns_timeout if args.dns_timeout is not None else config["dns_timeout"]
    dns_retries = args.dns_retries if args.dns_retries is not None else config["dns_retries"]
    nameservers = args.resolvers.split(",") if args.resolvers else config["resolvers"]
    selected_sources = [s.strip() for s in args.sources.split(",")] if args.sources else None

    def log(msg):
        if not args.silent:
            print(msg)

    start = time.time()
    try:
        result = asyncio.run(
            run_scan(
                domain=args.domain,
                active=args.active,
                wordlist_path=args.wordlist,
                concurrency=concurrency,
                nameservers=nameservers,
                dns_timeout=dns_timeout,
                dns_retries=dns_retries,
                extra_dns_records=args.extra_dns,
                do_permutations=args.permutations,
                do_http=args.http,
                do_ip_info=args.ip_info,
                scope_file=args.scope,
                exclude_file=args.exclude,
                selected_sources=selected_sources,
                skip_resolve=args.no_resolve,
                log=log,
            )
        )
    except KeyboardInterrupt:
        print(text.red("\n[!] Interrupted by user."))
        sys.exit(130)
    except Exception as e:
        print(text.red(f"[!] Error: {e}"))
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    elapsed = time.time() - start

    if not args.silent:
        print()
        print(text.render_summary_box(result))
        print()

    for host_obj in sorted(result.hosts.values(), key=lambda h: h.host):
        print(text.render_host_line(
            host_obj, show_sources=args.show_sources, show_dns=True, show_http=args.http
        ))

    print(text.bold(f"\n[+] {len(result.hosts)} subdomains found in {elapsed:.1f}s"))

    # --- Output files ---
    if args.output:
        if args.csv:
            csv_out.write_csv(result, args.output)
        elif args.json:
            json_out.write_json(result, args.output)
        else:
            with open(args.output, "w") as f:
                f.write("\n".join(sorted(result.hosts.keys())) + "\n")
        print(text.bold(f"[+] Results saved to: {args.output}"))
    elif args.json:
        import json as _json
        print(_json.dumps(json_out.build_json(result), indent=2, default=str))

    if args.html:
        html_out.write_html(result, args.html)
        print(text.bold(f"[+] HTML report saved to: {args.html}"))


if __name__ == "__main__":
    main()
