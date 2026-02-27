# 🌐 Subdomain Crawler

Multi-source subdomain enumeration module used by all bug bounty tools in this suite.

## Features

- **DNS Brute-Force** — 150+ common prefixes (250+ in `--deep` mode), multi-threaded
- **crt.sh** — Certificate Transparency log search
- **DNS Zone Transfer** — AXFR attempt on all nameservers
- **SPF/TXT Extraction** — Finds subdomains referenced in SPF records
- **HTTP Alive Check** — Verifies which subdomains respond
- **Login Detection** — Scans for password forms and common login paths
- **HTML + JSON Reports**

## Usage

### Standalone
```bash
# Basic scan
python subdomain_crawler.py -d target.com

# Deep scan with login detection
python subdomain_crawler.py -d target.com --deep --find-logins --threads 30

# Verbose with custom output
python subdomain_crawler.py -d target.com -v -o results/
```

### As a Library (used by other tools)
```python
from subdomain_crawler import SubdomainCrawler

crawler = SubdomainCrawler("target.com", threads=20, deep=True, find_logins=True)
results = crawler.run()

# Get just alive subdomains
alive = crawler.get_alive_subdomains()

# Get login endpoints
logins = crawler.get_login_endpoints()
```

### Integrated with Other Tools
```bash
# SPF Checker: scan subdomains for email misconfig
python spf_checker.py -d target.com --crawl-subs

# Long Password DoS: auto-find login endpoints
python long_password_dos.py -d target.com

# Session Tester: discover login pages
python session_logout_tester.py -d target.com

# Origin IP Finder: automatically uses crt.sh via this module
python origin_ip_finder.py -d target.com
```

## Options

| Flag | Description |
|------|-------------|
| `-d` | Target domain |
| `--threads` | Thread count (default: 20) |
| `--timeout` | Timeout per request (default: 5s) |
| `--deep` | Extended wordlist (250+ prefixes) |
| `--find-logins` | Detect login forms on subdomains |
| `--no-alive` | Skip HTTP alive checking |
| `-v` | Verbose output |
| `-o` | Output directory |

## Bug Bounty Value

- Discover forgotten staging/dev subdomains with weak security
- Find login endpoints on subdomains for session/DoS testing
- Identify subdomains with different SPF/DMARC policies
- Locate origin IPs via subdomain DNS records

## Requirements

```
requests
dnspython
colorama
```
