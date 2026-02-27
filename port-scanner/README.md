# 🔌 Port Scanner

> **Multi-Target Network Port Scanner with Banner Grabbing**  
> Author: **Vishal Rao** ([@Vishal-HaCkEr1910](https://github.com/Vishal-HaCkEr1910))

---

## ⚠️ Legal Disclaimer

> Only scan networks and hosts you own or have explicit written permission to test. Unauthorized port scanning is illegal in many jurisdictions.

---

## 🚀 What It Does

Scans a range of TCP ports on one or multiple targets (IP or domain), attempts to connect, and grabs service banners to identify running services.

---

## ✨ Features

- 🎯 **Multi-Target** — Scan multiple IPs/domains in one run (comma-separated)
- 🏷️ **Banner Grabbing** — Identifies services running on open ports
- 🌐 **Domain Resolution** — Auto-resolves domain names to IP addresses
- ⚡ **Fast Scanning** — Configurable port range

---

## 📦 Installation

```bash
cd port-scanner
pip3 install -r requirements.txt
```

---

## ⚡ Usage

```bash
python3 portscanner.py
```

You'll be prompted for:
1. **Target** — IP address or domain (comma-separated for multiple targets)
2. **Port range** — Number of ports to scan (e.g., `1000` scans ports 1-999)

### Example

```
ENTER TARGET: scanme.nmap.org
enter the ports you want to scan: 1000

[+] SCANNING TARGET 45.33.32.156
[+] PORT 22 IS OPEN
SSH-2.0-OpenSSH_6.6.1p1
[+] PORT 80 IS OPEN
```

---

## 📄 License

MIT — For authorized security testing only.
