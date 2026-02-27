<p align="center">
  <h1 align="center">🛡️ Automation Scripts for Bug Bounty</h1>
  <p align="center">
    <strong>A curated arsenal of Python-based security automation tools and bug bounty playbooks</strong>
  </p>
  <p align="center">
    <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"></a>
    <a href="#"><img src="https://img.shields.io/badge/Tools-14-blue?style=for-the-badge" alt="Tools"></a>
    <a href="#-bug-bounty-notes"><img src="https://img.shields.io/badge/Guides-8-orange?style=for-the-badge" alt="Guides"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"></a>
  </p>
</p>

---

## ⚠️ Legal Disclaimer

> **All tools and guides in this repository are intended exclusively for authorized security professionals, penetration testers, and bug bounty hunters.**  
> Using these tools against systems you do not own or have explicit written permission to test is **illegal** and may result in criminal prosecution under the CFAA (US), IT Act (India), Computer Misuse Act (UK), and similar laws worldwide.  
> The author accepts **no liability** for misuse.

---

## 📂 Repository Structure

```
Automation-scripts-for-bug-bounty/
│
├── subdomain-crawler/          # Shared Subdomain Enumeration Engine ← NEW
│   ├── subdomain_crawler.py
│   └── README.md
│
├── spf-checker/                # Email Security & SPF/DMARC Analyzer ← NEW
│   ├── spf_checker.py
│   └── README.md
│
├── origin-ip-finder/           # CDN/WAF Origin IP Discovery ← NEW
│   ├── origin_ip_finder.py
│   └── README.md
│
├── session-tester/             # Session Invalidation Tester ← NEW
│   ├── session_logout_tester.py
│   └── README.md
│
├── long-password-dos/          # Long Password DoS Tester ← NEW
│   ├── long_password_dos.py
│   └── README.md
│
├── broken-link-hijacker/       # Broken Link Takeover Scanner
│   ├── blh.py
│   ├── requirements.txt
│   └── README.md
│
├── xss-scanner/                # XSS Vulnerability Scanner
│   ├── xss_scanner.py
│   ├── requirements.txt
│   ├── README.md
│   └── README_xss.md
│
├── phone-tracker/              # Phone Number Intelligence System
│   ├── phone_tracker.py
│   ├── requirements.txt
│   └── README.md
│
├── js-secrets-scanner/         # JavaScript Recon & Secret Extraction
│   ├── js_secrets_scanner.py
│   ├── setup.sh
│   └── README.md
│
├── github-recon-tool/          # GitHub Reconnaissance Scanner
│   ├── github_secrets_finding.py
│   ├── github_recon_readme.md
│   ├── requirements.txt
│   └── README.md
│
├── port-scanner/               # TCP Port Scanner with Banner Grabbing
│   ├── portscanner.py
│   ├── requirements.txt
│   └── README.md
│
├── ssh-bruteforcer/            # SSH Dictionary Attack Tool
│   ├── ssh_Bruteforcer.py
│   ├── requirements.txt
│   └── README.md
│
├── keylogger/                  # Keyboard Input Monitor
│   ├── keylogger.py
│   ├── requirements.txt
│   └── README.md
│
├── pdf-password-protector/     # PDF Encryption Tool
│   ├── pdf_pass.py
│   ├── requirements.txt
│   └── README.md
│
├── notes/                      # Bug Bounty Playbooks & Guides
│   ├── csrf.md
│   ├── idor.md
│   ├── xss_injection.md
│   ├── web_vulns_advanced.md
│   ├── subdomain_takeover.md
│   ├── js_recon.md
│   ├── price_manipulation_guide.md
│   ├── Low_Hanging_Fruits.md   ← NEW
│   └── README.md
│
├── requirements.txt
├── .gitignore
└── README.md                   # ← You are here
```

---

## 🆕 New Tools — Subdomain-Integrated Security Suite

Five new industry-standard tools with a **shared subdomain enumeration engine** that expands attack surface automatically. Every tool can discover subdomains to find more targets.

### 🌐 Subdomain Integration Map

| Tool | Flag | What Subdomain Crawling Adds |
|------|------|------------------------------|
| **SPF Checker** | `--crawl-subs` | Discovers subdomains → scans each for SPF/DMARC/DKIM |
| **Origin IP Finder** | Built-in | Uses crt.sh + DNS brute-force for wider IP coverage |
| **Session Tester** | `-d domain` | Crawls subdomains → finds login endpoints → suggests tests |
| **Long Password DoS** | `-d domain` | Crawls subdomains → finds login forms → tests each |
| **Subdomain Crawler** | Standalone | Used by all tools above, also works as CLI tool |

---

## 🔧 Tools

### 🌐 [Subdomain Crawler](subdomain-crawler/) — `subdomain_crawler.py` `NEW`
> Shared subdomain enumeration engine — DNS brute-force (250+ prefixes), crt.sh certificate transparency, AXFR zone transfers, SPF/TXT extraction, HTTP alive checking, and login form detection. Works standalone or as a library imported by other tools.

```bash
python3 subdomain_crawler.py -d example.com --deep --find-logins
```

| Highlights | |
|---|---|
| 4 discovery methods | DNS brute-force, crt.sh, AXFR, SPF/TXT |
| 250+ prefixes | Deep mode with extended wordlist |
| Login detection | Finds password forms and common login paths |
| Dual mode | Standalone CLI + importable library |

---

### ✉️ [SPF Checker](spf-checker/) — `spf_checker.py` `NEW`
> Email security analyzer — SPF record parsing with 15+ mechanism types, DMARC policy analysis, DKIM selector brute-force (120+ selectors), BIMI record detection, email spoofability scoring, and subdomain crawling integration.

```bash
python3 spf_checker.py -d example.com --crawl-subs --dkim-deep
```

| Highlights | |
|---|---|
| 890+ lines | SPF, DMARC, DKIM, BIMI analysis |
| 120+ selectors | DKIM brute-force discovery |
| Spoofability score | 0-100 risk rating per domain |
| Subdomain mode | `--crawl-subs` scans all discovered subdomains |

---

### 🔎 [Origin IP Finder](origin-ip-finder/) — `origin_ip_finder.py` `NEW`
> CDN/WAF bypass tool — discovers real origin server IPs behind Cloudflare, Akamai, AWS CloudFront, and 15+ CDN providers. Uses DNS history, subdomain enumeration (crt.sh + brute-force), mail server analysis, and multiple verification methods.

```bash
python3 origin_ip_finder.py -d example.com --deep --verify
```

| Highlights | |
|---|---|
| 685+ lines | 15+ CDN/WAF fingerprints |
| Multi-method | DNS history, subdomains, MX records, certificate matching |
| crt.sh integration | Via shared subdomain crawler |
| Confidence scoring | Low/Medium/High per candidate IP |

---

### 🔐 [Session Tester](session-tester/) — `session_logout_tester.py` `NEW`
> Session invalidation tester — verifies whether session tokens/cookies remain valid after logout. Tests cookie security flags (Secure, HttpOnly, SameSite), cache-control headers, session timeout behavior, and OWASP compliance.

```bash
# Single URL mode
python3 session_logout_tester.py -u https://example.com/dashboard --cookie "session=abc123" --logout-url https://example.com/logout

# Domain discovery mode
python3 session_logout_tester.py -d example.com
```

| Highlights | |
|---|---|
| 780+ lines | Session replay, cookie flags, timeout testing |
| OWASP scoring | Compliance rating per endpoint |
| Domain mode | `-d` discovers subdomains → finds login pages |
| Cache analysis | Cache-Control, Pragma, ETag headers |

---

### 💥 [Long Password DoS](long-password-dos/) — `long_password_dos.py` `NEW`
> Tests login endpoints for denial-of-service via extremely long passwords (up to 1MB). Measures response time degradation, detects hashing bottlenecks, and scores vulnerability severity.

```bash
# Single URL mode
python3 long_password_dos.py -u https://example.com/login --runs 5

# Domain discovery mode
python3 long_password_dos.py -d example.com
```

| Highlights | |
|---|---|
| 660+ lines | Incremental password lengths (1KB → 1MB) |
| Smart detection | Baseline comparison, response time analysis |
| Domain mode | `-d` crawls subdomains for login forms |
| Reports | JSON + HTML with timing charts |

---

### 🔗 [Broken Link Hijacker](broken-link-hijacker/) — `blh.py`
> Async crawler that finds dead external links and detects **claimable resources** — expired domains, deleted GitHub repos, unclaimed S3 buckets, dangling CNAMEs, and 35+ service fingerprints. Rich live dashboard, JSON + HTML reports.

```bash
python3 blh.py -u https://example.com --depth 3 --threads 40 --max-pages 500
```

| Highlights | |
|---|---|
| 1,860+ lines | Async aiohttp + BFS crawler |
| 35 fingerprints | GitHub Pages, S3, Azure, Heroku, Netlify, Shopify, expired domains... |
| Cloudflare-safe | Proper SSL context with certifi |
| Source tracking | Shows which page each dead link was found on |

---

### 🎯 [XSS Scanner](xss-scanner/) — `xss_scanner.py`
> Advanced XSS vulnerability scanner with 810+ payloads, context-aware injection, BFS crawler, WAF fingerprinting, CSP analysis, blind XSS callbacks, and multi-format reporting.

```bash
python3 xss_scanner.py -u http://testphp.vulnweb.com/ --crawl --depth 3
```

| Highlights | |
|---|---|
| 3,480+ lines | Reflected, Stored, Blind, Header, DOM XSS |
| 810+ payloads | Context-aware with encoding bypass |
| WAF detection | Cloudflare, Akamai, ModSecurity fingerprinting |
| Reports | JSON, CSV, HTML export |

---

### 📱 [Phone Tracker](phone-tracker/) — `phone_tracker.py`
> Law enforcement grade phone intelligence system with multi-API geolocation, 700+ India telecom prefix database, OSINT platform probing, interactive maps, and forensic evidence reports with SHA-256 integrity hashing.

```bash
python3 phone_tracker.py +919876543210
```

| Highlights | |
|---|---|
| 2,650+ lines | Multi-API location triangulation |
| 700+ prefixes | India telecom circle database |
| OSINT probes | Cross-platform social media checks |
| Evidence grade | SHA-256 hashing, audit trails, case management |

---

### 🔍 [JS Secrets Scanner](js-secrets-scanner/) — `js_secrets_scanner.py`
> Multi-phase JavaScript reconnaissance pipeline using 7 discovery tools (Katana, GAU, Waybackurls, etc.), AST analysis with jsluice, source map recovery, and Nuclei-verified secret detection.

```bash
python3 js_secrets_scanner.py -i subdomains.txt -t 50
```

| Highlights | |
|---|---|
| Auto-setup | `setup.sh` installs all dependencies |
| 7 recon tools | Katana, GAU, Waybackurls, Hakrawler, Subjs, Gospider, getJS |
| Deep analysis | AST parsing, source map reconstruction |
| Verification | Nuclei integration for finding validation |

---

### 🔍 [GitHub Recon Tool](github-recon-tool/) — `github_secrets_finding.py`
> Passive GitHub reconnaissance with 60+ secret pattern signatures, org-wide scanning, sensitive file discovery, Gitleaks/TruffleHog integration, and interactive false-positive filtering.

```bash
python3 github_secrets_finding.py
```

| Highlights | |
|---|---|
| 60+ patterns | AWS keys, JWTs, private keys, DB credentials |
| Org scanning | Enumerate all repos in an organization |
| Validation | Human-in-the-loop false positive filtering |
| Reports | JSON + HTML dashboards |

---

### 🔌 [Port Scanner](port-scanner/) — `portscanner.py`
> Multi-target TCP port scanner with banner grabbing and domain-to-IP resolution.

```bash
python3 portscanner.py
```

---

### 🔐 [SSH Bruteforcer](ssh-bruteforcer/) — `ssh_Bruteforcer.py`
> Dictionary-based SSH password cracker using Paramiko.

```bash
python3 ssh_Bruteforcer.py
```

---

### ⌨️ [Keylogger](keylogger/) — `keylogger.py`
> Lightweight keyboard input monitor with human-readable log formatting.

```bash
python3 keylogger.py
```

---

### 🔒 [PDF Password Protector](pdf-password-protector/) — `pdf_pass.py`
> Encrypt any PDF file with AES password protection.

```bash
python3 pdf_pass.py input.pdf output.pdf MyPassword
```

---

## 📚 Bug Bounty Notes

In-depth playbooks and methodology guides for bug bounty hunters:

| Guide | Description |
|-------|-------------|
| [**CSRF Playbook**](notes/csrf.md) | Cross-Site Request Forgery — from basics to P1 bounties (3,950+ lines) |
| [**IDOR Playbook**](notes/idor.md) | Insecure Direct Object Reference — methodology, escalation, reporting (3,200+ lines) |
| [**XSS Injection**](notes/xss_injection.md) | All 7 XSS types, payloads, WAF evasion, CSP bypass |
| [**Advanced Web Vulns**](notes/web_vulns_advanced.md) | HTTP headers, price manipulation, host header injection, HTML injection (4,300+ lines) |
| [**Subdomain Takeover**](notes/subdomain_takeover.md) | DNS mechanics, CNAME takeovers, service fingerprints |
| [**JS Recon**](notes/js_recon.md) | JavaScript file mining, source maps, secret extraction |
| [**Price Manipulation**](notes/price_manipulation_guide.md) | Mobile app price tampering, Burp Suite, SSL pinning bypass, Frida |
| [**Low Hanging Fruits**](notes/Low_Hanging_Fruits.md) | Quick wins for bug bounty — easy vulns to check first |

---

## 🚀 Quick Start

### Install Everything

```bash
git clone https://github.com/Vishal-HaCkEr1910/Automation-scripts-for-bug-bounty.git
cd Automation-scripts-for-bug-bounty
pip3 install -r requirements.txt
```

### Install Per Tool

```bash
cd broken-link-hijacker  # or any tool folder
pip3 install -r requirements.txt
python3 blh.py -u https://example.com
```

### Subdomain-Integrated Workflow

```bash
# 1. Discover subdomains first
python3 subdomain-crawler/subdomain_crawler.py -d target.com --deep --find-logins

# 2. Check email security across all subdomains
python3 spf-checker/spf_checker.py -d target.com --crawl-subs

# 3. Find origin IPs behind CDN
python3 origin-ip-finder/origin_ip_finder.py -d target.com --deep

# 4. Discover login endpoints and test session security
python3 session-tester/session_logout_tester.py -d target.com

# 5. Test login forms for long password DoS
python3 long-password-dos/long_password_dos.py -d target.com
```

---

## 🐍 Python Compatibility

| Python Version | Status |
|----------------|--------|
| 3.8+ | ✅ Supported |
| 3.10+ | ✅ Recommended |
| 3.13+ | ✅ Tested |

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-tool`)
3. Commit your changes (`git commit -m 'Add new tool'`)
4. Push to the branch (`git push origin feature/new-tool`)
5. Open a Pull Request

---

## 👤 Author

**Vishal Rao** — Security Researcher & Bug Bounty Hunter

- GitHub: [@Vishal-HaCkEr1910](https://github.com/Vishal-HaCkEr1910)

---

## ⭐ Support

If these tools help you in your bug bounty journey:
- ⭐ **Star** this repo
- 🍴 **Fork** it
- 📢 **Share** with fellow hunters
- 🐛 **Report issues** or suggest features

---

## 📄 License

This project is licensed under the MIT License — see individual tool READMEs for specific terms.

**For authorized security testing and educational purposes only.**
