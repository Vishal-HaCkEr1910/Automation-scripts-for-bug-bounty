# �� Broken Link Hijacker (BLH) v1.0

> **Automated Broken Link Takeover Scanner for Bug Bounty Hunters**  
> Crawl → Find Dead Links → Detect Claimable Resources → Generate Reports  
> Author: **Vishal Rao** ([@Vishal-HaCkEr1910](https://github.com/Vishal-HaCkEr1910))

---

## ⚠️ Legal Disclaimer

> This tool is for **authorized security testing only**. Only scan websites you own or have explicit written permission to test. The author accepts no liability for misuse.

---

## 🚀 What It Does

BLH crawls a target website using an async BFS crawler, discovers all external links, checks if they're dead (404, 410, timeout, DNS failure), and then analyzes whether the dead resources are **claimable** — meaning an attacker could register/claim them and serve malicious content under the target's domain trust.

### How It Works — 4 Phases

```
Phase 1: CRAWL         → Async BFS spider discovers all pages on target
Phase 2: EXTRACT       → Finds every external link (<a>, <script>, <img>, <iframe>, CSS)
Phase 3: CHECK         → Concurrent HTTP checks on all external links (dead/alive)
Phase 4: ANALYZE       → Matches dead links against 33 claimable service fingerprints
```

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Async BFS Crawler** | aiohttp-based crawler with configurable depth, concurrency, and max pages |
| **Smart SSL Handling** | Tries proper SSL (certifi) → falls back to ssl=False → falls back to HTTP. Works on Cloudflare-protected sites |
| **33 Service Fingerprints** | Detects claimable services (see full list below) |
| **False Positive Filtering** | Filters infrastructure/analytics domains (Google Tag Manager, Sentry, etc.) without hiding real takeover targets |
| **Source Page Tracking** | Shows exactly which page each dead link was found on |
| **Rich Live Dashboard** | Real-time progress display with Rich library |
| **Robots.txt Compliant** | Respects `robots.txt` disallow rules (override with `--ignore-robots`) |
| **User-Agent Rotation** | Realistic browser fingerprints via `fake-useragent` |
| **Dual Report Output** | JSON (machine-readable) + HTML (visual) reports |
| **Link Extraction** | Extracts from `<a>`, `<script src>`, `<img src>`, `<iframe>`, `<link>`, inline CSS `url()`, `srcset` |

### 🎯 33 Claimable Service Fingerprints

| Category | Services Detected |
|----------|------------------|
| **Code Hosting** | GitHub Pages, GitHub Repos, GitHub Raw, Bitbucket |
| **Cloud Hosting** | Heroku, Netlify, Vercel, Render, Surge, Fly.io |
| **Cloud Storage** | AWS S3 (implied), Azure Blob, Azure CloudApp, Azure Websites, Azure Traffic Manager, GCP Storage, GCP AppSpot |
| **CMS / SaaS** | Shopify, WordPress, Freshdesk, Zendesk |
| **CDN** | jsDelivr, unpkg |
| **Social Media** | Facebook Pages, Twitter/X Profiles, Instagram, LinkedIn Companies, TikTok, YouTube Channels |
| **Package Registries** | NPM packages, PyPI packages |
| **Domain Parking** | Sedo Parking, Expired Domains (DNS NXDOMAIN) |

---

## �� Installation

```bash
cd broken-link-hijacker
pip3 install -r requirements.txt
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `aiohttp` | Async HTTP client for crawling & link checking |
| `beautifulsoup4` | HTML parsing and link extraction |
| `lxml` | Fast HTML parser backend |
| `tldextract` | Domain comparison (internal vs external links) |
| `certifi` | Mozilla CA certificate bundle (Cloudflare SSL) |
| `rich` | Live terminal dashboard & tables |
| `colorama` | Colored terminal output |
| `fake-useragent` | Realistic User-Agent string rotation |

---

## ⚡ Usage

### Basic Commands

```bash
# Simple scan (default: depth 3, 40 threads, 5000 max pages)
python3 blh.py -u https://example.com

# Deep scan with more coverage
python3 blh.py -u https://example.com --depth 4 --threads 50 --max-pages 10000

# Quick scan with higher timeout (for slow sites)
python3 blh.py -u https://example.com --depth 2 --timeout 20

# Custom output filename
python3 blh.py -u https://example.com -o flipkart_scan

# Custom output directory
python3 blh.py -u https://example.com --output-dir /path/to/results

# Ignore robots.txt
python3 blh.py -u https://example.com --ignore-robots

# Check version
python3 blh.py --version
```

### Real-World Examples

```bash
# Scan PhysicsWallah (Cloudflare-protected)
python3 blh.py -u https://www.pw.live --depth 3 --threads 40 --max-pages 500 --timeout 15

# Scan a bug bounty target
python3 blh.py -u https://www.target.com --depth 3 --threads 50 --max-pages 5000

# Scan vulnerable test site
python3 blh.py -u http://testphp.vulnweb.com --depth 2
```

### CLI Reference

| Flag | Long Form | Type | Default | Description |
|------|-----------|------|---------|-------------|
| `-u` | `--url` | string | **required** | Target URL to scan |
| `-d` | `--depth` | int | `3` | Crawl depth (how many links deep to follow) |
| `-t` | `--threads` | int | `40` | Concurrent connections for crawling & checking |
| `-o` | `--output` | string | auto | Output filename prefix (without extension) |
| | `--output-dir` | string | `output/` | Directory for output files |
| | `--timeout` | int | `10` | HTTP request timeout in seconds |
| | `--max-pages` | int | `5000` | Maximum pages to crawl |
| | `--ignore-robots` | flag | `false` | Ignore robots.txt restrictions |
| `-v` | `--version` | flag | | Show version and exit |

### Tuning Guide

| Site Type | Recommended Settings |
|-----------|---------------------|
| **Small site** (<100 pages) | `--depth 2 --threads 20` |
| **Medium site** (100-1000 pages) | `--depth 3 --threads 40` |
| **Large site** (1000+ pages) | `--depth 3 --threads 50 --max-pages 10000` |
| **Cloudflare/WAF protected** | `--timeout 15 --threads 30` |
| **Slow server** | `--timeout 20 --threads 10` |

---

## 📊 Output

### Terminal Output

```
╭─── Dead Links Found: 51 ──────────────────────────────────────────────╮
│ #  │ Dead URL                              │ Status │ Found On        │
│ 1  │ secondary.biharboardonline.com/...    │ DEAD   │ /iit-jee        │
│ 2  │ facebook.com/physicswallah            │ 400    │ /products/...   │
│ 3  │ twitter.com/physicswallah             │ 400    │ /notes          │
╰────────────────────────────────────────────────────────────────────────╯
```

### Output Files

| File | Format | Content |
|------|--------|---------|
| `output/blh_<domain>_<timestamp>.json` | JSON | Full scan data — all dead links, hijackable links, source pages, metadata |
| `output/blh_<domain>_<timestamp>.html` | HTML | Visual report with tables, color-coded severity, clickable links |

---

## �� License

MIT — For authorized security testing only.
