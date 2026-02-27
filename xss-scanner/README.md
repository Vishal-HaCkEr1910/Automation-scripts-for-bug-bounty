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

Automated XSS vulnerability scanner that crawls target websites, discovers injection points, and tests 810+ context-aware payloads with encoding bypass, WAF evasion, and CSP analysis.

---

## ✨ Features

- 🕷️ **BFS Crawler** — Auto-discovers pages, forms, and parameters
- 🧬 **Context-Aware Payloads** — HTML, attribute, JS, URL context detection
- 🛡️ **WAF Fingerprinting** — Detects and adapts to WAFs (Cloudflare, Akamai, etc.)
- 🔐 **CSP Analysis** — Evaluates Content Security Policy weaknesses
- 📧 **Blind XSS** — Callback server for blind XSS detection
- 🔄 **Encoding Retry** — URL, HTML, Unicode, double-encoding bypass
- 📊 **Reports** — JSON, CSV, and HTML export
- ⚡ **Adaptive Rate Limiting** — Respects target rate limits

---

## 📦 Installation

```bash
cd xss-scanner
pip3 install -r requirements.txt
```

---

## ⚡ Usage

```bash
# Single URL scan
python3 xss_scanner.py -u http://testphp.vulnweb.com/

# Crawl and scan entire site
python3 xss_scanner.py -u http://testphp.vulnweb.com/ --crawl --depth 3

# With custom headers
python3 xss_scanner.py -u http://target.com/ --crawl --headers "Cookie: session=abc123"
```

For detailed usage, see [README_xss.md](README_xss.md).

---

## 📄 License

MIT — For authorized penetration testing only.
