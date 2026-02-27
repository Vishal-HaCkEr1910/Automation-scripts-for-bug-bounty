# 📧 SPF / DMARC / DKIM Checker v2.0.0

Industry-standard email security misconfiguration scanner for bug bounty hunters.

## Features

- **SPF Analysis** — Recursive include resolution (RFC 7208), 10-lookup counting, void lookup tracking
- **DMARC Parsing** — Full tag parsing (p, sp, pct, rua, ruf, adkim, aspf, fo, ri)
- **DKIM Discovery** — 58 common selectors, key algorithm & bit-length analysis
- **BIMI Check** — Brand Indicators for Message Identification
- **MX & NS Records** — Full mail infrastructure mapping
- **Risk Scoring** — 0-100 numeric score with spoofability verdict
- **Subdomain Crawling** — `--crawl-subs` discovers subdomains and checks SPF on all of them
- **Spoof PoC** — Optional test email to prove spoofability
- **HTML + JSON Reports**

## Usage

```bash
# Single domain
python spf_checker.py -d target.com

# Multiple domains with verbose
python spf_checker.py -d target.com example.com --verbose

# With subdomain crawling
python spf_checker.py -d target.com --crawl-subs --deep-subs

# From file
python spf_checker.py -f domains.txt --quick-dkim

# Send spoof test
python spf_checker.py -d target.com --spoof-test --from ceo@target.com --to you@gmail.com
```

## Options

| Flag | Description |
|------|-------------|
| `-d` | One or more domains |
| `-f` | File with domains |
| `--crawl-subs` | Auto-discover subdomains and check SPF on each |
| `--deep-subs` | Extended subdomain wordlist |
| `--quick-dkim` | Check only 15 selectors (faster) |
| `--verbose` | Show include resolution details |
| `--spoof-test` | Send proof-of-concept email |
| `--timeout` | DNS timeout (default: 5s) |

## Bug Bounty Tips

- SPF `~all` + DMARC `p=none` → **Spoofable** → report as "Email Spoofing"
- No SPF + No DMARC → **Critical** → "Missing Email Authentication"
- SPF >10 lookups → **permerror** → "SPF Misconfiguration (RFC 7208)"
- Subdomain with different SPF → "Subdomain Email Spoofing"

## Requirements

```
dnspython
colorama
requests  # for subdomain crawling
```
