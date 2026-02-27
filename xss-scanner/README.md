# 🎯 XSS Hunter Pro v3.0

> **Advanced Cross-Site Scripting Vulnerability Scanner**  
> Reflected · Stored · Blind · Header · DOM XSS Detection  
> 810+ Payloads | CSP Analysis | WAF Fingerprinting | BFS Crawler  
> Author: **Vishal Rao** ([@Vishal-HaCkEr1910](https://github.com/Vishal-HaCkEr1910))

---

## ⚠️ Legal Disclaimer

> This tool is for **authorized penetration testing only**. Unauthorized use is illegal and may result in criminal prosecution. The author accepts no liability for misuse.

---

## 🚀 What It Does

Automated XSS vulnerability scanner that crawls target websites, discovers injection points (URL parameters, form fields, HTTP headers), and tests 810+ context-aware payloads with encoding bypass, WAF evasion, and CSP analysis. Supports reflected, stored, blind, and header-based XSS detection.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **BFS Crawler** | Auto-discovers pages, forms, and URL parameters across the target |
| **810+ Payloads** | Built-in payload database with context-aware selection |
| **5 XSS Types** | Reflected, Stored, Blind, Header Injection, DOM-based |
| **Context Detection** | Identifies HTML, attribute, JavaScript, and URL injection contexts |
| **WAF Fingerprinting** | Detects Cloudflare, Akamai, ModSecurity, Sucuri, etc. and adapts payloads |
| **CSP Analysis** | Evaluates Content Security Policy headers for weaknesses |
| **Encoding Engine** | URL, HTML entity, Unicode, double-encoding, and mixed bypass |
| **Parameter Discovery** | Auto-discovers hidden parameters on pages |
| **Header Scanning** | Tests XSS in HTTP request headers (User-Agent, Referer, etc.) |
| **Blind XSS** | Callback server for out-of-band blind XSS detection |
| **Email Alerts** | SMTP email notifications when blind XSS fires |
| **Auth Support** | Cookies, custom headers, Basic auth, Bearer tokens |
| **Proxy Support** | Route through Burp Suite or any HTTP proxy |
| **Reports** | JSON, CSV, and HTML export formats |
| **Rate Limiting** | Adaptive request delay to avoid bans |

---

## 📦 Installation

```bash
cd xss-scanner
pip3 install -r requirements.txt
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `requests` | HTTP requests with session management |
| `beautifulsoup4` | HTML parsing for form/link discovery |
| `lxml` | Fast HTML parser backend |
| `colorama` | Colored terminal output |

---

## ⚡ Usage

### Basic Commands

```bash
# Scan a single URL for XSS
python3 xss_scanner.py -u http://testphp.vulnweb.com/

# Crawl entire site and scan all pages
python3 xss_scanner.py -u http://testphp.vulnweb.com/ --crawl

# Crawl with custom depth and page limit
python3 xss_scanner.py -u http://target.com/ --crawl --depth 3 --max-pages 500

# Add delay between requests (avoid rate limiting)
python3 xss_scanner.py -u http://target.com/ --crawl --delay 1.0

# Increase timeout for slow servers
python3 xss_scanner.py -u http://target.com/ --timeout 20
```

### Scan Type Selection

```bash
# Only scan for reflected XSS
python3 xss_scanner.py -u http://target.com/ --crawl --reflected-only

# Only scan for stored XSS
python3 xss_scanner.py -u http://target.com/ --crawl --stored-only

# Only scan for blind XSS (requires callback URL)
python3 xss_scanner.py -u http://target.com/ --blind-only --callback-url https://your-server.com/callback

# Scan HTTP headers for XSS (User-Agent, Referer, etc.)
python3 xss_scanner.py -u http://target.com/ --crawl --scan-headers

# Auto-discover hidden parameters
python3 xss_scanner.py -u http://target.com/ --crawl --discover-params
```

### Blind XSS with Callback

```bash
# Enable blind XSS with callback URL
python3 xss_scanner.py -u http://target.com/ --crawl --blind --callback-url https://your-xsshunter.com/

# Blind XSS + inject into headers
python3 xss_scanner.py -u http://target.com/ --crawl --blind --callback-url https://your-server.com/ --inject-headers

# Blind XSS + email alerts
python3 xss_scanner.py -u http://target.com/ --crawl --blind \
  --callback-url https://your-server.com/ \
  --email you@gmail.com \
  --smtp-host smtp.gmail.com --smtp-port 587 \
  --smtp-user you@gmail.com --smtp-pass "app_password"
```

### Authentication

```bash
# With cookies (authenticated scanning)
python3 xss_scanner.py -u http://target.com/ --crawl --cookies "session=abc123; csrf=xyz789"

# With custom headers (JSON format)
python3 xss_scanner.py -u http://target.com/ --crawl --headers '{"X-Custom": "value"}'

# Basic authentication
python3 xss_scanner.py -u http://target.com/ --crawl --auth-type basic --auth-cred "admin:password123"

# Bearer token
python3 xss_scanner.py -u http://target.com/ --crawl --auth-type bearer --auth-cred "eyJhbGciOi..."
```

### Proxy & Browser Impersonation

```bash
# Route through Burp Suite
python3 xss_scanner.py -u http://target.com/ --crawl --proxy http://127.0.0.1:8080

# Custom User-Agent
python3 xss_scanner.py -u http://target.com/ --crawl --user-agent "Googlebot/2.1"

# Rotate User-Agent on every request
python3 xss_scanner.py -u http://target.com/ --crawl --rotate-ua
```

### Custom Payloads

```bash
# Use your own payload file (one payload per line)
python3 xss_scanner.py -u http://target.com/ --crawl --payload-file /path/to/payloads.txt
```

### CLI Reference

| Group | Flag | Type | Default | Description |
|-------|------|------|---------|-------------|
| **Target** | `-u, --url` | string | **required** | Target URL or domain |
| **Crawling** | `--crawl` | flag | off | Enable site-wide crawling |
| | `--depth` | int | `3` | Crawl depth |
| | `--max-pages` | int | `500` | Maximum pages to crawl |
| **Performance** | `--delay` | float | `0` | Delay between requests (seconds) |
| | `--timeout` | int | `10` | Request timeout (seconds) |
| **Payloads** | `--payload-file` | path | built-in | Custom payload file |
| **Scan Types** | `--reflected-only` | flag | | Only reflected XSS |
| | `--stored-only` | flag | | Only stored XSS |
| | `--blind-only` | flag | | Only blind XSS |
| | `--blind` | flag | | Enable blind XSS detection |
| **Advanced** | `--scan-headers` | flag | | Scan HTTP headers for XSS |
| | `--discover-params` | flag | | Auto-discover hidden parameters |
| **Blind XSS** | `--callback-url` | URL | | Callback URL for blind XSS |
| | `--inject-headers` | flag | | Inject blind payloads into headers |
| **Email** | `--email` | string | | Alert email for blind XSS |
| | `--smtp-host` | string | | SMTP server hostname |
| | `--smtp-port` | int | `587` | SMTP port |
| | `--smtp-user` | string | | SMTP username |
| | `--smtp-pass` | string | | SMTP password |
| **Auth** | `--cookies` | string | | Cookies: `"session=abc; tok=xyz"` |
| | `--headers` | JSON | | Custom headers as JSON string |
| | `--auth-type` | choice | | `basic` or `bearer` |
| | `--auth-cred` | string | | `user:pass` or token |
| **Browser** | `--user-agent` | string | auto | Custom User-Agent |
| | `--rotate-ua` | flag | | Rotate UA on every request |
| **Proxy** | `--proxy` | URL | | Proxy URL (e.g., `http://127.0.0.1:8080`) |

---

## 📊 Output

- **Terminal** — Real-time findings with color-coded severity
- **JSON** — Machine-readable results for CI/CD pipelines
- **CSV** — Spreadsheet-compatible export
- **HTML** — Visual report with tables and details

For the full detailed usage guide with output examples, report writing templates, and verification steps, see **[README_xss.md](README_xss.md)**.

---

## 📄 License

MIT — For authorized penetration testing only.
