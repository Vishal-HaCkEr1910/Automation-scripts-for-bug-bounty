# 📱 Phone Tracker Pro v5.0

> **Law Enforcement Grade Phone Intelligence System**  
> Multi-API Location · HLR/VLR Simulation · OSINT Probes · Evidence Reports  
> 700+ India Telecom Prefixes | SHA-256 Integrity | Chain-of-Custody Logging  
> Author: **Vishal Rao** ([@Vishal-HaCkEr1910](https://github.com/Vishal-HaCkEr1910))

---

## ⚠️ Legal Disclaimer

> This tool is for **authorized law enforcement and security research use only**. Tracking individuals without consent or legal authority is illegal. Handle data per applicable data protection laws.

---

## 🚀 What It Does

Comprehensive phone number intelligence system that performs carrier lookup, geolocation, telecom circle identification, OSINT platform probing, and generates forensic-grade evidence reports with SHA-256 integrity hashing and audit trails.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Phone Validation** | International format parsing with 700+ India prefix DB |
| **Carrier Lookup** | Operator and telecom circle identification |
| **Geolocation** | Multi-API location triangulation with confidence scoring |
| **OSINT Probes** | Cross-platform social media and service checks |
| **Interactive Maps** | Folium-based HTML maps with heatmaps |
| **Evidence Reports** | JSON + HTML reports with SHA-256 integrity hashing |
| **Audit Trail** | Tamper-evident logging for chain-of-custody |
| **Case Management** | Evidence packaging for legal proceedings |

---

## 📦 Installation

```bash
cd phone-tracker
pip3 install -r requirements.txt
```

### API Keys (Optional)

Create a `.env` file:
```env
OPENCAGE_API_KEY=your_key_here
```

---

## ⚡ Usage

```bash
# Basic lookup
python3 phone_tracker.py +919876543210

# Skip OSINT probes
python3 phone_tracker.py +919876543210 --skip-osint

# Quick mode
python3 phone_tracker.py +919876543210 --skip-osint --skip-deep
```

---

## 📊 Output

Reports are saved to `output/`:
- `phone_intel_<number>_<timestamp>.json` — Full intelligence data
- `phone_report_<number>_<timestamp>.html` — Visual HTML report
- `phone_map_<number>_<timestamp>.html` — Interactive map

---

## 📄 License

MIT — For authorized use only.
