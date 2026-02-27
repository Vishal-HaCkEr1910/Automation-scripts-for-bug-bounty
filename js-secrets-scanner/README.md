# 🔍 JS Secrets Scanner v2.0

> **JavaScript Reconnaissance & Secrets Discovery Framework**  
> Multi-Source JS Discovery · AST Analysis · Secret Detection · Source Map Recovery  
> Author: **Vishal Rao** ([@Vishal-HaCkEr1910](https://github.com/Vishal-HaCkEr1910))

---

## ⚠️ Legal Disclaimer

> This tool is for **authorized security testing only**. Scanning JavaScript files from applications without permission is illegal. The author accepts no liability for misuse.

---

## 🚀 What It Does

Multi-phase JavaScript reconnaissance pipeline that discovers JS files across subdomains using 7 recon tools, performs deep static analysis, recovers source maps, extracts secrets, and verifies findings with Nuclei.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **7 Discovery Tools** | Katana, GAU, Waybackurls, Hakrawler, Subjs, Gospider, getJS |
| **Noise Filtering** | Skips vendor/framework JS (jQuery, React bundles, analytics) |
| **Source Map Recovery** | Detects `.js.map` files, reconstructs original source |
| **AST Analysis** | Parses JS AST with jsluice for deep analysis |
| **Secret Extraction** | API keys, tokens, credentials, hidden endpoints |
| **Nuclei Verification** | Automated vulnerability verification |
| **Structured Reports** | TXT + JSON output categorized by severity |

---

## 📦 Installation

### Auto Install (Recommended for Linux/Kali/Ubuntu)

```bash
cd js-secrets-scanner
chmod +x setup.sh
./setup.sh
source ~/.bashrc
```

This installs Go, Node, Python, and all required recon & analysis tools.

### Required External Tools

- **Discovery:** Katana, GAU, Waybackurls, Hakrawler, Subjs, Gospider, getJS
- **Analysis:** Nuclei, jsluice, TruffleHog, Retire.js, LinkFinder, SecretFinder
- **Runtime:** Go, Python 3, Node.js

---

## ⚡ Usage

```bash
# Basic scan with subdomain list
python3 js_secrets_scanner.py -i subdomains.txt

# With custom threads
python3 js_secrets_scanner.py -i subdomains.txt -t 50

# Skip discovery, analyze existing files only
python3 js_secrets_scanner.py -i subdomains.txt --skip-discovery --skip-download

# Custom Nuclei templates
python3 js_secrets_scanner.py -i subdomains.txt --templates /path/to/templates/
```

---

## 📂 Output Structure

```
recon_output/       → Raw discovery results
js_storage/         → Beautified JS files
js_maps/            → Discovered .js.map files
source_code/        → Reconstructed source from maps
final_results/      → Endpoints, secrets, nuclei findings
metadata/           → Hash → URL mappings
```

---

## 📄 License

MIT — For authorized security testing only.
