# 🔍 JS Secrets Scanner v2.0

> **Multi-Phase JavaScript Reconnaissance & Secret Extraction Framework**  
> 7 Discovery Tools · AST Analysis · Source Map Recovery · Nuclei Verification  
> Author: **Vishal Rao** ([@Vishal-HaCkEr1910](https://github.com/Vishal-HaCkEr1910))

---

## ⚠️ Legal Disclaimer

> This tool is for **authorized security research only**. Analyzing JavaScript files from applications you do not have permission to test is illegal. The author accepts no liability for misuse.

---

## 🚀 What It Does

Multi-phase JavaScript reconnaissance pipeline that discovers JavaScript files across subdomains, downloads and beautifies them, recovers source maps, performs AST analysis for hidden endpoints and secrets, and verifies findings with Nuclei templates.

### Pipeline Phases

```
Phase 1: DISCOVERY     → Find JS URLs using 7 recon tools (Katana, GAU, Waybackurls, etc.)
Phase 2: FILTER        → Remove vendor/framework noise (jQuery, React bundles, analytics)
Phase 3: DOWNLOAD      → Parallel download + beautification of JS files
Phase 4: SOURCE MAPS   → Detect .js.map files + reconstruct original source code
Phase 5: ANALYSIS      → AST parsing with jsluice — extract endpoints, secrets, auth logic
Phase 6: VERIFICATION  → Nuclei template scanning for confirmed vulnerabilities
Phase 7: REPORTING     → Severity-categorized findings in TXT + JSON format
```

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **7 Discovery Tools** | Katana, GAU, Waybackurls, Hakrawler, Subjs, Gospider, getJS |
| **Noise Filtering** | Auto-skips jQuery, Bootstrap, React bundles, analytics scripts |
| **Source Map Recovery** | Finds `.js.map` files and reconstructs original source code |
| **AST Analysis** | jsluice-based AST parsing for endpoints, secrets, and auth logic |
| **Secret Detection** | API keys, tokens, hardcoded credentials, internal URLs |
| **Nuclei Integration** | Automated verification of exposed secrets with Nuclei templates |
| **Multi-threaded** | Parallel downloading with configurable thread count |
| **Structured Reports** | Findings categorized by severity (High, Medium, Informational) |

---

## 📦 Installation

### Auto-Install (Recommended — Linux/Kali/Ubuntu)

```bash
cd js-secrets-scanner
chmod +x setup.sh
./setup.sh
source ~/.bashrc
```

The setup script automatically installs:
- Go, Python 3, Node.js + NPM
- All 7 discovery tools (Katana, GAU, Waybackurls, Hakrawler, Subjs, Gospider, getJS)
- Analysis tools (Nuclei, jsluice, TruffleHog, Retire.js, LinkFinder, SecretFinder)
- Updates Nuclei templates

### Manual Install (External Tools Required in $PATH)

| Category | Tools Required |
|----------|---------------|
| **Discovery** | `katana`, `gau`, `waybackurls`, `hakrawler`, `subjs`, `gospider`, `getjs` |
| **Analysis** | `nuclei`, `jsluice`, `trufflehog`, `retire` |
| **Optional** | LinkFinder (`/opt/LinkFinder/linkfinder.py`), SecretFinder (`/opt/SecretFinder/SecretFinder.py`) |
| **Runtime** | Go, Python 3, Node.js + NPM, curl |

No Python pip dependencies required — the script uses only standard library + subprocess calls to external tools.

---

## ⚡ Usage

### Basic Commands

```bash
# Basic scan with subdomain list
python3 js_secrets_scanner.py -i subdomains.txt

# Increase download threads (default: CPU cores)
python3 js_secrets_scanner.py -i subdomains.txt -t 50

# Analyze existing JS files only (skip discovery + download)
python3 js_secrets_scanner.py -i subdomains.txt --skip-discovery --skip-download

# Use custom Nuclei templates
python3 js_secrets_scanner.py -i subdomains.txt --templates /path/to/custom-templates/
```

### Input File Format

Create a text file with one subdomain per line:

```
# subdomains.txt
app.target.com
api.target.com
cdn.target.com
admin.target.com
```

### CLI Reference

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-i, --input` | path | **required** | Input file with domains/subdomains (one per line) |
| `-t, --threads` | int | CPU cores | Number of parallel download threads |
| `--templates` | path | default Nuclei | Path to custom Nuclei templates |
| `--skip-discovery` | flag | | Skip JS URL discovery phase |
| `--skip-download` | flag | | Skip JS file download phase |

---

## 📊 Output Structure

```
recon_output/          → Discovery results (katana.txt, gau.txt, wayback.txt)
js_storage/            → Downloaded + beautified JS files (hashed filenames)
js_maps/               → Discovered .js.map source map files
source_code/           → Reconstructed original source from maps
final_results/
  ├── endpoints.txt    → Discovered API endpoints
  ├── secrets.json     → Extracted secrets and tokens
  └── nuclei_findings.txt → Nuclei-verified vulnerabilities
metadata/              → Hash → original URL mappings
```

---

## 📄 License

MIT — For authorized security research only.
