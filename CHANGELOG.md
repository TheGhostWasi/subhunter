# Changelog

## v2.0.0

### Added
- **5 new passive sources**: CertSpotter, urlscan.io, RapidDNS, Common Crawl, and optional SecurityTrails (requires `SUBHUNTER_SECURITYTRAILS_API_KEY`)
- **Source tracking** — every hostname now records which source(s) discovered it (`--show-sources`)
- **Wildcard DNS detection** — probes random subdomains before trusting brute-force/permutation results, then filters out wildcard false positives
- **Extended DNS records** — optional NS/MX/TXT collection via `--extra-dns`
- **HTTP/HTTPS probing** (`--http`) — status code, redirect chain, title, `Server` header, content type/length, response time
- **Lightweight technology fingerprinting** — best-effort detection of nginx, Apache, WordPress, Next.js, React, Laravel, Django, Express, PHP from passive HTTP evidence
- **CDN/WAF awareness** — labeled "Likely CDN: X" / "Likely WAF: X", never asserted as certain
- **Optional IP/ASN/org/country enrichment** (`--ip-info`) via ip-api.com
- **Bounded subdomain permutation generation** (`--permutations`) — seeded from discovered hosts, capped at 2,000 candidates
- **Scope control** (`--scope`, `--exclude`) — glob-pattern scope/exclusion files; out-of-scope or excluded hosts are reported but never actively probed
- **New output formats**: `--csv` and `--html report.html` (self-contained report, no external dependencies)
- **Configuration file support** — optional `~/.config/subhunter/config.yaml` (`--config` to override path); CLI flags always take precedence
- **Robust hostname normalization** — strips protocols, paths, ports, userinfo, trailing dots, wildcards; validates against RFC-1035-style label rules; rejects malformed entries
- **Resolver improvements** — configurable `--dns-timeout` / `--dns-retries`, graceful per-query failure classification (NXDOMAIN/SERVFAIL/TIMEOUT/NoAnswer)
- **33 automated tests** covering normalization, scope matching, wildcard filtering, permutation bounds, JSON/CSV output, CLI argument parsing, and source registry behavior — all mocked, no live network dependency
- Redesigned modular architecture: `core/` (models, resolver, http_probe, scope, permutations, enumerator), `sources/` (one plugin module per source), `output/` (text, json, csv, html)

### Fixed
- Removed all accidental Bengali/mixed-language text from CLI output — all terminal messages are now professional English
- DNS resolution no longer conflates "HTTP unreachable" with "DNS dead" — the two are tracked and reported separately
- Each passive source now has an explicit per-source timeout and independent exception handling; one source failing/timing out no longer affects any other source

### Changed
- Internal package restructured from a flat `subhunter/*.py` layout into `core/`, `sources/`, `output/` submodules (no user-facing impact — the `subhunter` CLI command and all v1 flags are unchanged)
- JSON output structure is richer (includes `sources`, `dns`, `http`, `scope` per host) — see README for the full schema

### Backward compatibility
All v1.0.0 commands continue to work unchanged:
```bash
subhunter -d example.com
subhunter -d example.com -a -w wordlist.txt
subhunter -d example.com -o result.txt
subhunter -d example.com --json -o result.json
subhunter -d example.com -r 1.1.1.1,8.8.8.8 -c 500
subhunter -d example.com -s
```

## v1.0.0
Initial release — passive enumeration (6 sources), active DNS bruteforce, DNS verification, TXT/JSON export, custom resolvers, configurable concurrency, silent mode.
