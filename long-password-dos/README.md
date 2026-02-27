# 💣 Long Password DoS Tester v2.0.0

Detect denial-of-service vulnerabilities caused by processing extremely long passwords (bcrypt/scrypt abuse).

## Features

- **Escalating Size Test** — 10 → 1M character passwords with timing analysis
- **Multi-Run Averaging** — Configurable runs per size for accurate measurements
- **Baseline Comparison** — Calculates slowdown factor vs normal request
- **Request Body Tracking** — Shows payload size in KB
- **Concurrency Stress Test** — ThreadPoolExecutor simultaneous requests
- **Subdomain Crawling** — `-d domain` auto-discovers login endpoints
- **Custom Headers & Proxy** — Burp Suite integration
- **Severity Assessment** — Auto-classifies vulnerability level
- **HTML + JSON Reports**

## Usage

```bash
# Direct URL
python long_password_dos.py -u https://target.com/login

# JSON API endpoint
python long_password_dos.py -u https://target.com/api/login --json \
    --username test@test.com --username-field email

# Auto-discover login endpoints via subdomain crawling
python long_password_dos.py -d target.com

# With concurrency test
python long_password_dos.py -u https://target.com/login --concurrent 10

# Custom sizes + proxy
python long_password_dos.py -u https://target.com/login \
    --sizes 100 1000 10000 100000 \
    --proxy http://127.0.0.1:8080
```

## Options

| Flag | Description |
|------|-------------|
| `-u` | Login/register endpoint URL |
| `-d` | Domain to crawl for login endpoints |
| `--username` | Username to send |
| `--username-field` | Form field name for username |
| `--password-field` | Form field name for password |
| `--json` | Send as JSON body |
| `--sizes` | Custom password sizes |
| `--concurrent` | Concurrency test threads |
| `--runs` | Runs per size for averaging |
| `--delay` | Delay between requests |
| `--proxy` | HTTP proxy |
| `--header` | Custom headers |
| `--sub-threads` | Subdomain crawler threads |
| `--deep-subs` | Extended subdomain wordlist |

## Bug Bounty Tips

- **>10x slowdown** = Reportable DoS via long password **(CWE-400)**
- **Timeout** = Critical — server hashing unbounded input
- **Server rejects at 72 chars?** That's bcrypt's built-in limit = SAFE
- **HTTP 413** = Server enforces body size limit = SAFE

## Requirements

```
requests
colorama
```
