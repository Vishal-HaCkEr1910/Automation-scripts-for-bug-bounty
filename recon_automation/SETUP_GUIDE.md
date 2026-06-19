# 🛡️ WebRecon Pro — Full Setup & Installation Guide

> **Author:** Vishal | **Tool:** WebRecon Pro Suite v2.0  
> **Purpose:** Advanced Web Pentesting & Bug Bounty Reconnaissance Framework  
> **OS:** Kali Linux / Ubuntu 20.04+ / Parrot OS (Debian-based recommended)

---

## 📁 Directory Structure

```
~/recon_suite/
├── SETUP_GUIDE.md          ← This file
├── webrecon.sh             ← Main interactive launcher
├── modules/
│   ├── 00_banner.sh        ← ASCII banner & color lib
│   ├── 01_subdomain.sh     ← Subdomain enumeration module
│   ├── 02_httpx_probe.sh   ← HTTP probing module
│   ├── 03_url_harvest.sh   ← URL & link harvesting module
│   ├── 04_vuln_scan.sh     ← Vulnerability scanning module
│   ├── 05_dir_brute.sh     ← Directory brute-force module
│   ├── 06_nmap_scan.sh     ← Nmap scanning module
│   └── 07_report.sh        ← Report generation module
├── wordlists/              ← Your wordlist directory (configure below)
│   ├── subdomains/
│   ├── directories/
│   └── parameters/
└── results/                ← All scan results land here (auto-created)
```

---

## 🔧 Tool Installation

### Step 1 — System Update

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git curl wget unzip python3 python3-pip golang-go nmap dirb wfuzz
```

### Step 2 — Go Environment Setup

```bash
# Add to ~/.bashrc or ~/.zshrc
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin

source ~/.bashrc   # or source ~/.zshrc
```

### Step 3 — Install Each Tool

#### 🔹 Subfinder (ProjectDiscovery)
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
# Binary: ~/go/bin/subfinder
```

#### 🔹 Amass (OWASP)
```bash
go install -v github.com/owasp-amass/amass/v4/...@master
# OR
sudo apt install amass -y
# Binary: ~/go/bin/amass  OR  /usr/bin/amass
```

#### 🔹 Assetfinder (Tom Hudson)
```bash
go install github.com/tomnomnom/assetfinder@latest
# Binary: ~/go/bin/assetfinder
```

#### 🔹 Sublist3r
```bash
cd /opt
sudo git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r
sudo pip3 install -r requirements.txt --break-system-packages
# Run: python3 /opt/Sublist3r/sublist3r.py
```

#### 🔹 Knockpy
```bash
cd /opt
sudo git clone https://github.com/guelfoweb/knock.git
cd knock
sudo pip3 install requests dnspython --break-system-packages
# Run: python3 /opt/knock/knockpy.py
```

#### 🔹 httpx (ProjectDiscovery)
```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
# Binary: ~/go/bin/httpx
```

#### 🔹 gau — Get All URLs
```bash
go install github.com/lc/gau/v2/cmd/gau@latest
# Binary: ~/go/bin/gau
```

#### 🔹 Gospider
```bash
go install github.com/jaeles-project/gospider@latest
# Binary: ~/go/bin/gospider
```

#### 🔹 qsreplace
```bash
go install github.com/tomnomnom/qsreplace@latest
# Binary: ~/go/bin/qsreplace
```

#### 🔹 ffuf — Fast Fuzzer
```bash
go install github.com/ffuf/ffuf/v2@latest
# Binary: ~/go/bin/ffuf
```

#### 🔹 Gobuster
```bash
go install github.com/OJ/gobuster/v3@latest
# Binary: ~/go/bin/gobuster
```

#### 🔹 Feroxbuster
```bash
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash
sudo mv feroxbuster /usr/local/bin/
# OR: cargo install feroxbuster
# Binary: /usr/local/bin/feroxbuster
```

#### 🔹 dirsearch
```bash
cd /opt
sudo git clone https://github.com/maurosoria/dirsearch.git
cd dirsearch
sudo pip3 install -r requirements.txt --break-system-packages
# Run: python3 /opt/dirsearch/dirsearch.py
```

#### 🔹 dirb (usually pre-installed on Kali)
```bash
sudo apt install dirb -y
# Binary: /usr/bin/dirb
```

#### 🔹 wfuzz (usually pre-installed on Kali)
```bash
sudo apt install wfuzz -y
# OR: pip3 install wfuzz --break-system-packages
# Binary: /usr/bin/wfuzz
```

#### 🔹 DirBuster (GUI — optional)
```bash
sudo apt install dirbuster -y
# Run: dirbuster (GUI)
# For CLI equivalent, use gobuster or feroxbuster
```

---

## 📚 Recommended Wordlists

### Install SecLists (Most Comprehensive)
```bash
cd /opt
sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git
```

### Key Wordlist Paths (SecLists)

| Purpose | Path |
|---|---|
| Subdomains (small) | `/opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt` |
| Subdomains (medium) | `/opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt` |
| Subdomains (large) | `/opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt` |
| Subdomains (amass) | `/opt/SecLists/Discovery/DNS/dns-Jhaddix.txt` |
| Directories (small) | `/opt/SecLists/Discovery/Web-Content/common.txt` |
| Directories (medium) | `/opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt` |
| Directories (big) | `/opt/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt` |
| Directories (lowercase) | `/opt/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt` |
| Parameters | `/opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt` |
| APIs | `/opt/SecLists/Discovery/Web-Content/api/api-endpoints.txt` |

### Install dirbuster Wordlists (Kali)
```bash
# Usually at: /usr/share/dirbuster/wordlists/
sudo apt install dirbuster -y
```

### Install dirb Wordlists (Kali)
```bash
# Usually at: /usr/share/dirb/wordlists/
sudo apt install dirb -y
```

---

## ⚙️ Tool Path Configuration

Open `webrecon.sh` and edit the `TOOL_PATHS` section at the top:

```bash
# ============================================================
# TOOL PATHS — EDIT THESE TO MATCH YOUR INSTALLATION
# ============================================================
SUBFINDER_PATH="$HOME/go/bin/subfinder"
AMASS_PATH="$(which amass 2>/dev/null || echo $HOME/go/bin/amass)"
ASSETFINDER_PATH="$HOME/go/bin/assetfinder"
SUBLIST3R_PATH="/opt/Sublist3r/sublist3r.py"
KNOCK_PATH="/opt/knock/knockpy.py"
HTTPX_PATH="$HOME/go/bin/httpx"
GAU_PATH="$HOME/go/bin/gau"
GOSPIDER_PATH="$HOME/go/bin/gospider"
QSREPLACE_PATH="$HOME/go/bin/qsreplace"
FFUF_PATH="$HOME/go/bin/ffuf"
GOBUSTER_PATH="$HOME/go/bin/gobuster"
FEROXBUSTER_PATH="/usr/local/bin/feroxbuster"
DIRSEARCH_PATH="/opt/dirsearch/dirsearch.py"
DIRB_PATH="$(which dirb)"
WFUZZ_PATH="$(which wfuzz)"
NMAP_PATH="$(which nmap)"

# WORDLIST PATHS
WORDLIST_SUBS_SMALL="/opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"
WORDLIST_SUBS_MEDIUM="/opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt"
WORDLIST_SUBS_LARGE="/opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt"
WORDLIST_DIRS_SMALL="/opt/SecLists/Discovery/Web-Content/common.txt"
WORDLIST_DIRS_MEDIUM="/opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt"
WORDLIST_DIRS_BIG="/opt/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt"
WORDLIST_DIRS_KALI="/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt"
WORDLIST_DIRB="/usr/share/dirb/wordlists/common.txt"
```

---

## 🚀 Running the Tool

```bash
# Make executable
chmod +x webrecon.sh

# Run
./webrecon.sh

# OR with sudo (for nmap SYN scan)
sudo ./webrecon.sh
```

---

## 🔑 API Keys (Optional but Recommended)

Some tools perform better with API keys. Set them in your environment:

```bash
# ~/.bashrc or ~/.zshrc
export SHODAN_API_KEY="your_shodan_key"
export VIRUSTOTAL_API_KEY="your_vt_key"
export SECURITYTRAILS_API_KEY="your_st_key"
export CENSYS_API_ID="your_censys_id"
export CENSYS_API_SECRET="your_censys_secret"

# Subfinder API keys config
subfinder -config ~/.config/subfinder/config.yaml
# Edit ~/.config/subfinder/provider-config.yaml to add API keys
```

---

## 🔒 Legal & Ethics Notice

> **Only use this tool on targets you have explicit permission to test.**  
> Unauthorized scanning is illegal under the Computer Fraud and Abuse Act (CFAA),  
> UK Computer Misuse Act, and similar laws worldwide.  
> The author is not responsible for misuse.

---

## 📝 Output File Naming Convention

All result files follow this pattern:  
`{TARGET}_{MODULE}_{TOOL}_{MODE}_{TIMESTAMP}.{ext}`

Example:  
`hackerone.com_subdomain_subfinder_passive_20240615_143022.txt`

A `RESULTS_INDEX.txt` file is auto-created in each scan directory explaining every output file.

---

*WebRecon Pro v2.0 — Built for serious bug hunters*
