# 🔌 Port Scanner

> **Multi-Target TCP Port Scanner with Banner Grabbing**  
> Author: **Vishal Rao** ([@Vishal-HaCkEr1910](https://github.com/Vishal-HaCkEr1910))

---

## ⚠️ Legal Disclaimer

> Only scan networks and hosts you own or have explicit written permission to test. Unauthorized port scanning is illegal in many jurisdictions.

---

## 🚀 What It Does

Scans a range of TCP ports on one or multiple targets (IP address or domain name), detects open ports, and grabs service banners to identify what software is running on each open port.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Multi-Target** | Scan multiple IPs/domains in a single run (comma-separated) |
| **Banner Grabbing** | Identifies services (SSH, HTTP, FTP, etc.) running on open ports |
| **Domain Resolution** | Auto-resolves domain names to IP addresses |
| **Configurable Range** | Scan any port range from 1 to 65535 |
| **IP Validation** | Detects whether input is an IP or domain and handles accordingly |

---

## 📦 Installation

```bash
cd port-scanner
pip3 install -r requirements.txt
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `IPy` | IP address validation and manipulation |

---

## ⚡ Usage

### Running the Scanner

```bash
python3 portscanner.py
```

The tool uses an **interactive prompt**:

```
enter multiple targets to scan ports (domain or ip) WITH
ENTER TARGET ( domain(www.xxx.com) or ip ) [+] scanme.nmap.org
enter the ports you want to scan (eg. 500- first 500 to be scanned) 1000
```

### Input Methods

| Input | Example | Description |
|-------|---------|-------------|
| **Single IP** | `192.168.1.1` | Scan one host |
| **Single Domain** | `scanme.nmap.org` | Auto-resolves to IP |
| **Multiple Targets** | `192.168.1.1,10.0.0.1,scanme.nmap.org` | Comma-separated, scans all |
| **Port Range** | `1000` | Scans ports 1 through 999 |

### Example Output

```
[+] SCANNING TARGET 45.33.32.156

[+] PORT 22 IS OPEN
SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13

[+] PORT 80 IS OPEN

[+] PORT 443 IS OPEN
```

---

## 📄 License

MIT — For authorized security testing only.
