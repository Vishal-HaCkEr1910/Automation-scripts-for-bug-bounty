# 🔗 Broken Link Hijacker (BLH) v1.0

> **Automated Broken Link Takeover Scanner for Bug Bounty Hunters**  
> Crawl → Find Dead Links → Detect Claimable Resources → Generate Reports  
> Author: **Vishal Rao** ([@Vishal-HaCkEr1910](https://github.com/Vishal-HaCkEr1910))

---

## ⚠️ Legal Disclaimer

> This tool is for **authorized security testing only**. Only scan websites you own or have explicit written permission to test. The author accepts no liability for misuse.

---

## 🚀 What It Does

BLH crawls a target website, discovers all external links, checks if they're dead, and determines if the dead resources are **claimable** — expired domains, deleted GitHub repos/pages, unclaimed S3 buckets, dangling CNAMEs, dead social profiles, and more.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Async Crawler** | BFS-based async crawler with configurable depth and concurrency |
| **Smart SSL Handling** | Proper SSL → ssl=False → HTTP fallback chain (works on Cloudflare sites) |
| **35 Fingerprints** | Detects claimable services: GitHub Pages, S3, Azure, GCP, Heroku, Netlify, Shopify, NPM, social media, expired domains, etc. |
| **False Positive Filtering** | Filters infrastructure domains (analytics, trackers) without hiding real targets |
| **Source Page Tracking** | Shows which page each dead link was found on |
| **Rich Live Dashboard** | Real-time progress with Rich terminal UI |
| **Dual Reports** | JSON + HTML report generation with full details |
| **Robots.txt Compliant** | Respects robots.txt disallow rules |
| **User-Agent Rotation** | Realistic browser fingerprints via fake-useragent |

---

## 📦 Installation

```bash
cd broken-link-hijacker
pip3 install -r requirements.txt
```

---

## ⚡ Usage

```bash
# Basic scan
python3 blh.py -u https://example.com

# Deep scan with more pages
python3 blh.py -u https://example.com --depth 3 --threads 40 --max-pages 500

# Full scan with custom timeout
python3 blh.py -u https://example.com --full --timeout 15

# Custom output filename
python3 blh.py -u https://example.com --output my_report
```

### CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u, --url` | Target URL (required) | — |
| `--depth` | Crawl depth | `3` |
| `--threads` | Concurrent requests | `40` |
| `--max-pages` | Maximum pages to crawl | `5000` |
| `--timeout` | Request timeout (seconds) | `10` |
| `--output` | Output filename prefix | auto-generated |
| `--full` | Enable comprehensive scan mode | `False` |

---

## 📊 Sample Output

```
╭─── Dead Links Found: 51 ──────────────────────────────────────────╮
│ #  │ Dead URL                              │ Status │ Found On    │
│ 1  │ secondary.biharboardonline.com/...    │ DEAD   │ /iit-jee   │
│ 2  │ facebook.com/physicswallah            │ 400    │ /products   │
│ 3  │ twitter.com/physicswallah             │ 400    │ /notes      │
╰────────────────────────────────────────────────────────────────────╯
```

Reports saved to `output/` as JSON + HTML.

---

## 🎯 What Makes a Link "Hijackable"?

| Service | How BLH Detects It |
|---------|-------------------|
| **GitHub Pages** | "There isn't a GitHub Pages site here" |
| **AWS S3** | "NoSuchBucket" response |
| **Heroku** | "No such app" error page |
| **Expired Domains** | NXDOMAIN DNS resolution |
| **Shopify** | "Sorry, this shop is currently unavailable" |
| **Netlify** | "Not Found - Request ID" |
| 30+ more services... | See fingerprints in source code |

---

## 📄 License

MIT — For authorized security testing only.
