# 📱 Phone Tracker Pro v5.0

> **Law Enforcement Grade Phone Intelligence System**  
> Multi-API Location · HLR/VLR Simulation · OSINT Probes · Evidence Reports  
> 700+ India Telecom Prefixes | SHA-256 Integrity | Chain-of-Custody Logging  
> Author: **Vishal Rao** ([@Vishal-HaCkEr1910](https://github.com/Vishal-HaCkEr1910))

---

## ⚠️ Legal Disclaimer

> This tool is for **authorized law enforcement and security research use only**. Tracking individuals without consent or legal authority is illegal. Handle all data per applicable data protection laws (IT Act 2000, GDPR, etc.).

---

## 🚀 What It Does

Comprehensive phone number intelligence system that performs carrier lookup, geolocation, telecom circle identification, OSINT platform probing, and generates forensic-grade evidence reports with SHA-256 integrity hashing and audit trails.

### Scan Phases

```
Phase 1: VALIDATION    → Parse number, identify country, carrier, line type
Phase 2: TELECOM DB    → Match against 700+ India prefix database (operator, circle, region)
Phase 3: LIVE LOCATION → Multi-API geolocation (OpenCage, NumVerify, AbstractAPI)
Phase 3B: IP GRABBER   → Optional: Generate tracking link to capture target's IP/GPS
Phase 4: GEOLOCATION   → Advanced location triangulation with confidence scoring
Phase 5: OSINT         → WhatsApp, Telegram, Truecaller platform intelligence
Phase 6: DEEP OSINT    → Spam databases, breach indicators, web mention scraping
Phase 7: REPORT        → JSON + HTML + Interactive Map + Evidence packaging
```

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Phone Validation** | International format parsing (works with +91, 0, or raw 10-digit input) |
| **700+ Prefix DB** | India telecom circle database — identifies operator and region from first 4 digits |
| **Multi-API Location** | Triangulates location using OpenCage, NumVerify, and AbstractAPI simultaneously |
| **IP Grabber** | Generates a tracking link (local HTTP server) that captures visitor's IP + GPS coordinates |
| **WhatsApp Detection** | Checks if number is registered on WhatsApp |
| **Telegram Lookup** | Detects Telegram profile existence |
| **Truecaller Lookup** | Multi-method Truecaller search (API + web scraping) for name and email |
| **Spam Check** | Queries SpamCalls.net and other databases for spam/scam reports |
| **Breach Detection** | Checks for exposure in known data breaches |
| **Interactive Maps** | Folium-based HTML maps with markers and heatmaps |
| **Evidence Reports** | SHA-256 hashed JSON + HTML reports for legal proceedings |
| **Audit Trail** | Tamper-evident logging for chain-of-custody compliance |
| **Case Management** | Case ID, officer name, department, classification level metadata |

---

## 📦 Installation

```bash
cd phone-tracker
pip3 install -r requirements.txt
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `phonenumbers` | Phone number parsing, validation, carrier detection |
| `opencage` | OpenCage geocoding API client |
| `folium` | Interactive HTML map generation |
| `requests` | HTTP requests for API calls and OSINT probes |
| `beautifulsoup4` | HTML parsing for web scraping |
| `rich` | Rich terminal UI — tables, panels, progress bars |
| `colorama` | Colored terminal output |
| `python-dotenv` | Load API keys from `.env` file |

---

## 🔑 API Keys Setup

The tool works with **zero API keys** (basic mode), but adding keys unlocks additional features:

### Method 1: `.env` File (Recommended)

Create a `.env` file in the same directory:

```env
# Required for geolocation (free: 2,500 requests/day)
OPENCAGE_API_KEY=your_opencage_key_here

# Optional: Additional phone validation APIs
NUMVERIFY_API_KEY=your_numverify_key_here
ABSTRACT_API_KEY=your_abstract_key_here

# Optional: IP geolocation for IP Grabber mode
IPINFO_TOKEN=your_ipinfo_token_here
```

### Method 2: Environment Variables

```bash
export OPENCAGE_API_KEY="your_key_here"
export NUMVERIFY_API_KEY="your_key_here"
export ABSTRACT_API_KEY="your_key_here"
export IPINFO_TOKEN="your_key_here"
```

### Where to Get API Keys

| API | Free Tier | Sign Up |
|-----|-----------|---------|
| **OpenCage** | 2,500 req/day | [opencagedata.com](https://opencagedata.com/) |
| **NumVerify** | 100 req/month | [numverify.com](https://numverify.com/) |
| **AbstractAPI** | 100 req/month | [abstractapi.com](https://www.abstractapi.com/) |
| **IPinfo** | 50,000 req/month | [ipinfo.io](https://ipinfo.io/) |

### What Works Without API Keys

| Feature | Needs API Key? |
|---------|---------------|
| Phone validation, carrier, line type | ❌ No |
| India telecom circle identification | ❌ No |
| WhatsApp / Telegram detection | ❌ No |
| Truecaller lookup | ❌ No |
| Spam database check | ❌ No |
| Breach indicator check | ❌ No |
| OpenCage geolocation | ✅ Yes (`OPENCAGE_API_KEY`) |
| NumVerify validation | ✅ Yes (`NUMVERIFY_API_KEY`) |
| AbstractAPI validation | ✅ Yes (`ABSTRACT_API_KEY`) |
| IP Grabber IP geolocation | ✅ Yes (`IPINFO_TOKEN`) |

---

## ⚡ Usage

### Basic Commands

```bash
# Full scan (all phases)
python3 phone_tracker.py +919876543210

# Works with these input formats too:
python3 phone_tracker.py 9876543210       # Raw 10-digit (assumes India +91)
python3 phone_tracker.py 09876543210      # With leading 0
python3 phone_tracker.py +1-202-555-0100  # International format

# Quick scan (basic info + telecom circle only, fastest)
python3 phone_tracker.py +919876543210 --quick
```

### Skip Phases (Faster Scans)

```bash
# Skip live location API calls
python3 phone_tracker.py +919876543210 --skip-live

# Skip OSINT probes (WhatsApp, Telegram, Truecaller)
python3 phone_tracker.py +919876543210 --skip-osint

# Skip deep OSINT (spam, breach, web mentions)
python3 phone_tracker.py +919876543210 --skip-deep

# Skip both OSINT phases (fastest full scan)
python3 phone_tracker.py +919876543210 --skip-osint --skip-deep
```

### IP Grabber Mode

```bash
# Launch IP Grabber link server (default port 8888)
python3 phone_tracker.py +919876543210 --grab

# Custom port
python3 phone_tracker.py +919876543210 --grab --grab-port 9999
```

When activated, the tool starts a local HTTP server and generates a tracking URL. When the target visits the link, their IP address and GPS coordinates (if browser permits) are captured.

### Law Enforcement Mode

```bash
# With case metadata for evidence packaging
python3 phone_tracker.py +919876543210 \
  --case-id "FIR-2026-0042" \
  --officer "SI Sharma" \
  --unit "Cyber Cell Delhi" \
  --classification CONFIDENTIAL
```

Classification levels: `UNCLASSIFIED`, `RESTRICTED` (default), `CONFIDENTIAL`, `SECRET`

### Report Options

```bash
# JSON report only (no HTML or map)
python3 phone_tracker.py +919876543210 --json-only

# Skip map generation
python3 phone_tracker.py +919876543210 --no-map

# Skip HTML report (JSON only)
python3 phone_tracker.py +919876543210 --no-report

# Custom output directory
python3 phone_tracker.py +919876543210 --output-dir /path/to/results/
```

### CLI Reference

| Group | Flag | Type | Default | Description |
|-------|------|------|---------|-------------|
| **Target** | `phone` | positional | **required** | Phone number (any format) |
| **Scan** | `--quick` | flag | | Quick mode: basic info + telecom only |
| | `--skip-live` | flag | | Skip multi-API live location |
| | `--skip-osint` | flag | | Skip WhatsApp/Telegram/Truecaller |
| | `--skip-deep` | flag | | Skip spam/breach/web mentions |
| **Case** | `--case-id` | string | auto UUID | Case/FIR number |
| | `--officer` | string | | Investigating officer name |
| | `--unit` | string | | Department / Unit |
| | `--classification` | choice | `RESTRICTED` | `UNCLASSIFIED` / `RESTRICTED` / `CONFIDENTIAL` / `SECRET` |
| **IP Grab** | `--grab` | flag | | Launch IP Grabber link server |
| | `--grab-port` | int | `8888` | Port for IP Grabber server |
| **Report** | `--no-map` | flag | | Skip Folium map generation |
| | `--no-report` | flag | | Skip HTML report generation |
| | `--json-only` | flag | | Only generate JSON report |
| | `--output-dir` | path | `output/` | Output directory for reports |
| **Info** | `--version` | flag | | Show version and exit |

---

## 📊 Output Files

| File | Format | Content |
|------|--------|---------|
| `output/phone_intel_<number>_<timestamp>.json` | JSON | Full intelligence data with SHA-256 hash |
| `output/phone_report_<number>_<timestamp>.html` | HTML | Visual intelligence report |
| `output/phone_map_<number>_<timestamp>.html` | HTML | Interactive Folium map with markers |
| `output/audit_logs/audit_<date>.log` | Log | Tamper-evident audit trail |

---

## 📄 License

MIT — For authorized law enforcement and security research use only.
