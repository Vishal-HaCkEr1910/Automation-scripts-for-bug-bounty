# 🔐 Session Logout Tester v2.0.0

Verify that session tokens are properly invalidated after logout — a common bug bounty finding.

## Features

- **Session Replay Attack** — Tests if old cookies/tokens still work after logout
- **Cookie Flag Audit** — HttpOnly, Secure, SameSite analysis
- **Cache-Control Check** — Ensures authenticated pages aren't cached
- **Security Header Audit** — X-Frame-Options, HSTS, X-Content-Type-Options
- **CSRF Token Auto-Extraction** — Handles 5 common CSRF field patterns
- **Subdomain Crawling** — `-d domain` discovers login endpoints across subdomains
- **Multiple Auth Methods** — Cookie, JWT/Bearer, custom headers
- **Proxy Support** — Route through Burp Suite
- **HTML + JSON Reports**

## Usage

```bash
# With pre-captured cookie
python session_logout_tester.py -u https://target.com/dashboard \
    --logout-url /logout --cookie "session=abc123"

# With login credentials
python session_logout_tester.py -u https://target.com/dashboard \
    --login-url /login --logout-url /logout \
    --username admin --password pass

# With JWT token
python session_logout_tester.py -u https://target.com/api/me \
    --logout-url /api/logout --token "eyJhbGci..."

# Discover login endpoints via subdomain crawling
python session_logout_tester.py -d target.com

# Through Burp proxy
python session_logout_tester.py -u https://target.com/dashboard \
    --logout-url /logout --cookie "session=abc" \
    --proxy http://127.0.0.1:8080
```

## Options

| Flag | Description |
|------|-------------|
| `-u` | Authenticated page URL |
| `-d` | Domain to crawl for login endpoints |
| `--login-url` | Login endpoint |
| `--logout-url` | Logout endpoint |
| `--cookie` | Pre-captured session cookie |
| `--token` | JWT/Bearer token |
| `--header` | Custom auth header |
| `--proxy` | HTTP proxy |
| `--logout-method` | auto/GET/POST |
| `--sub-threads` | Subdomain crawler threads |
| `--deep-subs` | Extended subdomain wordlist |

## Bug Bounty Tips

- Session valid after logout = **"Insufficient Session Expiration" (CWE-613)**
- Missing HttpOnly on session cookie = **"Missing Cookie Flag" (P4)**
- Missing Secure flag = **cookie sent over HTTP (P4)**
- SameSite=None = **CSRF risk**

## Requirements

```
requests
colorama
```
