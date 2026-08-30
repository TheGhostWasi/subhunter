# 🔍 SubHunter v2.0

**Fast & accurate subdomain enumeration and reconnaissance tool for Kali Linux, bug bounty programs, and authorized security research.**

SubHunter collects subdomains from 10+ passive sources, optionally brute-forces with a wordlist, verifies everything through DNS, filters out wildcard-DNS false positives, and can optionally probe HTTP/HTTPS, fingerprint technologies, and enrich results with IP/ASN data — all while respecting scope files so you never accidentally test something you're not authorized to.

> ⚠️ **For authorized use only.** See [Responsible Use](#️-responsible-use) below.

---

## ✨ Features

- ⚡ **Fast** — all network I/O is `asyncio`-based and runs concurrently, with independently bounded concurrency for DNS vs HTTP work
- 🎯 **Accurate** — every candidate is DNS-verified; wildcard DNS is detected and filtered automatically so brute-force/permutation results aren't polluted with false positives
- 🔓 **10+ passive sources** — crt.sh, HackerTarget, AlienVault OTX, ThreatMiner, Wayback Machine, Anubis-DB, CertSpotter, urlscan.io, RapidDNS, Common Crawl, and optional SecurityTrails (API key)
- 🧩 **Source tracking** — see exactly which source(s) discovered each host (`--show-sources`)
- 🌐 **HTTP/HTTPS probing** (`--http`) — status codes, redirects, page titles, headers, response time
- 🧠 **Best-effort tech & CDN/WAF fingerprinting** — passive evidence only, always labeled "likely," never asserted as certain
- 🧬 **Bounded subdomain permutations** (`--permutations`) — generates and DNS-verifies plausible variants like `dev-api.example.com`
- 🛡️ **Scope control** (`--scope` / `--exclude`) — out-of-scope or excluded hosts are reported as discovered but never actively probed
- 🌍 **Optional IP/ASN/org/country enrichment** (`--ip-info`)
- 📦 **Easy install** — one command via pip or GitHub, works globally after install
- 🎨 **Clean, professional CLI output** — colored, readable, exports to TXT/JSON/CSV/HTML
- 🧪 **33 automated tests**, all mocked — no live network dependency for CI

---

## 📥 Installation

### Option 1 — pip, directly from GitHub (simplest)

```bash
pip install --break-system-packages git+https://github.com/TheGhostWasi/subhunter.git
```

### Option 2 — clone and run the install script

```bash
git clone https://github.com/TheGhostWasi/subhunter.git
cd subhunter
bash install.sh
```

### Option 3 — one-line curl install (once the repo is public)

```bash
curl -sSL https://raw.githubusercontent.com/TheGhostWasi/subhunter/main/install.sh | bash
```

After installation, `subhunter` is available globally from any terminal.

**Requirements:** Python 3.8+. Core dependencies (`aiohttp`, `dnspython`) install automatically. `PyYAML` is optional — only needed for `~/.config/subhunter/config.yaml` support (see [Configuration](#️-configuration)).

---

## 🚀 Basic Usage

```bash
# Passive enumeration only (fastest)
subhunter -d example.com

# Active bruteforce with the bundled wordlist
subhunter -d example.com -a -w subhunter/wordlists/common-subdomains.txt

# Bigger wordlist (SecLists recommended for real engagements)
subhunter -d example.com -a -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Save results
subhunter -d example.com -o result.txt
subhunter -d example.com --json -o result.json
subhunter -d example.com --csv -o result.csv
subhunter -d example.com --html report.html

# Silent mode (only final results, no progress logs)
subhunter -d example.com -s
```

---

## 🔬 Advanced Usage

```bash
# HTTP/HTTPS probing — status, title, server, tech fingerprinting
subhunter -d example.com --http

# HTTP probing + IP/ASN/org enrichment
subhunter -d example.com --http --ip-info

# Bounded subdomain permutations (dev-api.example.com, api-staging.example.com, ...)
subhunter -d example.com --permutations

# Scope control — only actively probe what's authorized
subhunter -d example.com --scope scope.txt --exclude exclude.txt

# Show which source discovered each host
subhunter -d example.com --show-sources

# Also collect NS/MX/TXT records (slower)
subhunter -d example.com --extra-dns

# Custom DNS resolvers, timeout, retries, concurrency
subhunter -d example.com -r 1.1.1.1,8.8.8.8 --dns-timeout 5 --dns-retries 2 -c 500

# Restrict to specific passive sources
subhunter -d example.com --sources crt.sh,hackertarget,urlscan

# Debug mode (full tracebacks on error)
subhunter -d example.com --debug
```

### Scope and exclude file format

```text
# scope.txt — patterns of what's authorized
example.com
*.example.com
api.example.net

# exclude.txt — never actively probed even if in scope
*.internal.example.com
```

---

## 🗒️ All CLI Options

| Flag | Description |
|---|---|
| `-d, --domain` | Target domain (required) |
| `-o, --output` | Output file path |
| `--json` | Output as JSON |
| `--csv` | Output as CSV (use with `-o`) |
| `--html PATH` | Write a self-contained HTML report |
| `-a, --active` | Enable active DNS bruteforce |
| `-w, --wordlist` | Wordlist path for bruteforce |
| `--permutations` | Generate & verify bounded subdomain permutations |
| `--http` | Probe HTTP/HTTPS on resolved hosts |
| `--ip-info` | Look up ASN/organization/country for resolved IPs |
| `--scope FILE` | Scope file — only these hosts are actively probed |
| `--exclude FILE` | Exclusion file — never actively probed even if in scope |
| `--sources LIST` | Comma-separated list of passive sources to use |
| `--show-sources` | Show which source(s) discovered each host |
| `--extra-dns` | Also collect NS/MX/TXT records |
| `-c, --concurrency` | Concurrent DNS resolutions (default: 300) |
| `-r, --resolvers` | Comma-separated custom DNS resolvers |
| `--dns-timeout` | Per-query DNS timeout in seconds (default: 3) |
| `--dns-retries` | DNS query retries (default: 1) |
| `--no-resolve` | Skip DNS verification (faster, less accurate) |
| `--config PATH` | Path to config file |
| `-s, --silent` | Only print final results |
| `--debug` | Verbose debug output with tracebacks |
| `-v, --version` | Show version |

---

## 🧩 How It Works

1. **Passive collection** — 10+ sources queried concurrently; each has its own timeout and failure isolation, so one dead source never blocks the rest
2. **Normalization** — every raw hostname is cleaned (lowercase, strips protocols/paths/ports/trailing dots) and validated; malformed entries are dropped
3. **Permutations (optional)** — bounded, DNS-verified variants generated from what's already been found
4. **Active bruteforce (optional)** — wordlist-driven candidate generation
5. **Wildcard DNS detection** — before trusting brute-force/permutation results, SubHunter probes random subdomains to detect wildcard DNS and identify the wildcard IP(s)
6. **DNS verification** — every candidate is resolved (A/AAAA/CNAME, optionally NS/MX/TXT); wildcard false positives are filtered out
7. **Scope evaluation** — each host is marked in-scope / out-of-scope / excluded
8. **HTTP probing (optional)** — only in-scope, non-excluded hosts are actively probed
9. **IP/ASN enrichment (optional)** — resolved IPs are looked up for organization/ASN/country

---

## 📄 Output Formats

### JSON structure

```json
{
  "target": "example.com",
  "scan_time": "2026-08-29T22:00:00+00:00",
  "duration_seconds": 18.4,
  "summary": {
    "candidates": 1284,
    "dns_resolved": 347,
    "http_live": 291,
    "https_live": 276
  },
  "wildcard": {
    "detected": false,
    "ips": [],
    "false_positives_removed": 0
  },
  "sources": { "crt.sh": 120, "hackertarget": 74, "securitytrails": null },
  "hosts": [
    {
      "host": "api.example.com",
      "sources": ["crt.sh", "wayback"],
      "dns": { "a": ["203.0.113.10"], "aaaa": [], "cname": null },
      "http": { "status": 200, "title": "API", "server": "nginx", "technologies": ["nginx"] },
      "in_scope": true,
      "excluded": false
    }
  ]
}
```

`sources` values of `null` mean that source was unavailable (typically because an optional API key wasn't configured — see below).

### CSV and HTML
`--csv` produces a flat, spreadsheet-friendly file (host, sources, DNS records, HTTP status/title/server, tech, scope). `--html` produces a single self-contained report file with a summary panel and sortable-by-eye host table — no external frontend framework or CDN required.

---

## ⚙️ Configuration

Optional config file at `~/.config/subhunter/config.yaml` (or pass `--config /path/to/file.yaml`). Requires `pip install PyYAML` — if it's not installed, or the file doesn't exist, SubHunter just uses its built-in defaults silently.

```yaml
concurrency: 300
dns_timeout: 3
dns_retries: 2
resolvers:
  - 1.1.1.1
  - 8.8.8.8
```

**CLI flags always override the config file.**

---

## 🔑 Optional API Keys

Only one source currently requires a key, and it's entirely optional — SubHunter works fully without it:

```bash
export SUBHUNTER_SECURITYTRAILS_API_KEY="your-key-here"
```

If unset, `securitytrails` is silently skipped and reported as unavailable in the source log — the scan is unaffected.

---

## 🛡️ Wildcard DNS

Some domains resolve *any* subdomain (via a wildcard `*` DNS record), which would otherwise make brute-force/permutation results meaningless — every guess would "succeed." SubHunter detects this automatically before active enumeration:

```text
[*] Checking wildcard DNS...
    [+] Wildcard detected -> 203.0.113.10

[*] Applying wildcard filtering... removed 182 false positives
```

Active enumeration is **not disabled** when wildcard DNS is found — results are simply filtered against the known wildcard response.

---

## 🧪 Testing

```bash
pip install --break-system-packages pytest
pytest tests/ -v
```

33 tests cover hostname normalization, scope/exclude matching, wildcard false-positive filtering, permutation bounds, JSON/CSV output structure, CLI argument parsing, and the source plugin registry. All are mocked — no live network access is needed to run the suite.

---

## 🩺 Troubleshooting

| Problem | Fix |
|---|---|
| `subhunter: command not found` | Add `export PATH="$HOME/.local/bin:$PATH"` to `~/.bashrc`, then `source ~/.bashrc` |
| A source repeatedly shows `0` results | The source's API may have changed its response format — open an issue with the domain you tested |
| Many DNS timeouts | Lower `-c/--concurrency` or increase `--dns-timeout` |
| `--active` requires a wordlist | Pass `-w path/to/wordlist.txt`, e.g. the bundled `subhunter/wordlists/common-subdomains.txt` |
| Config file not loading | Confirm `PyYAML` is installed (`pip install PyYAML`) and the path is correct |

---

## ⚠️ Responsible Use

This tool is built for **authorized security testing, bug bounty programs, security research, and infrastructure you own or have explicit written permission to test.** Active enumeration, HTTP probing, and permutation generation all send real traffic to real hosts.

Use `--scope` and `--exclude` to keep active probing strictly within your authorized boundaries. Running this tool against domains you don't have permission to test may be illegal in your jurisdiction. You are responsible for how you use it.

---

## 🤝 Contributing

Pull requests and issues are welcome. To add a new passive source, drop a new module in `subhunter/sources/` following the existing plugin interface (`NAME`, `REQUIRES_API_KEY`, `async def fetch(session, domain)`) and register it in `subhunter/sources/__init__.py`.

## 📄 License

MIT License — see [LICENSE](LICENSE)
