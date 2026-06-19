# WebRecon Pro v2.0 — Complete Usage & Setup Guide

> **Author:** Vishal  
> **Version:** 2.0  
> **OS Tested On:** Kali Linux 2023+, Ubuntu 22.04/24.04, Parrot OS  
> **Shell:** Bash 5.x required  

---

## TABLE OF CONTENTS

1. [Before You Begin — Folder Setup](#1-before-you-begin)
2. [System Dependencies](#2-system-dependencies)
3. [Go Environment Setup](#3-go-environment-setup)
4. [Installing Every Tool (with verification)](#4-installing-every-tool)
5. [PATH & Environment Variables — Shell Config](#5-path--environment-variables)
6. [API Keys Setup (Subfinder, Amass, etc.)](#6-api-keys-setup)
7. [Wordlists — Install & Configure](#7-wordlists)
8. [Where to Edit Paths in Each File (exact lines)](#8-where-to-edit-paths-in-each-file)
9. [Running the Tool — All Modes Explained](#9-running-the-tool)
10. [Interactive Walkthrough — What Each Prompt Means](#10-interactive-walkthrough)
11. [Understanding Output Files & Naming](#11-output-files--naming)
12. [RESULTS_INDEX.txt — How to Read It](#12-results_indextxt)
13. [Post-Scan Workflow](#13-post-scan-workflow)
14. [Troubleshooting Common Errors](#14-troubleshooting)
15. [Tool-Specific Tips & Advanced Flags](#15-advanced-tips)
16. [Quick Reference Cheatsheet](#16-quick-reference-cheatsheet)

---

## 1. BEFORE YOU BEGIN

### Recommended Directory Layout

Place the entire `webrecon_pro/` folder anywhere on your machine. The recommended location:

```
$HOME/tools/webrecon_pro/
├── webrecon.sh              ← Main script (entry point)
├── SETUP_GUIDE.md
├── COMPLETE_USAGE_GUIDE.md  ← This file
└── modules/
    ├── 00_banner.sh
    ├── 01_subdomain.sh
    ├── 02_httpx_probe.sh
    ├── 03_04_url_vuln.sh
    ├── 05_dir_brute.sh
    ├── 06_nmap_scan.sh
    └── 07_report.sh
```

**Quick setup:**

```bash
# Move the folder to ~/tools/
mkdir -p ~/tools
mv webrecon_pro ~/tools/
cd ~/tools/webrecon_pro

# Make all scripts executable
chmod +x webrecon.sh modules/*.sh

# Verify
ls -la
ls -la modules/
```

All results will auto-save to `~/tools/webrecon_pro/results/<target>_<timestamp>/` by default. You can change this at runtime when the tool asks.

---

## 2. SYSTEM DEPENDENCIES

Run this first on a fresh Kali / Ubuntu / Parrot install:

```bash
# Core packages
sudo apt update && sudo apt upgrade -y

sudo apt install -y \
  git curl wget unzip \
  python3 python3-pip python3-venv \
  nmap dirb wfuzz dirbuster \
  dnsutils dig whois \
  jq xmlstarlet \
  libpcap-dev \
  build-essential \
  xsltproc \
  tree \
  net-tools

# Java (needed for DirBuster GUI)
sudo apt install -y default-jdk

# Rust (needed for Feroxbuster alternative install)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

**Verify essentials:**

```bash
python3 --version    # Should be 3.8+
nmap --version       # Should be 7.80+
java --version       # Optional, for DirBuster GUI
git --version
curl --version
```

---

## 3. GO ENVIRONMENT SETUP

Most tools (subfinder, httpx, gau, ffuf, gobuster, etc.) are Go binaries. Go must be set up before installing them.

### Install Go (if not already installed)

```bash
# Check if Go is already installed
go version

# If not installed, download latest Go
wget https://go.dev/dl/go1.22.3.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.22.3.linux-amd64.tar.gz
rm go1.22.3.linux-amd64.tar.gz
```

### Add Go to PATH — Edit `~/.bashrc` (or `~/.zshrc` if using zsh)

```bash
nano ~/.bashrc
```

Add these lines at the **bottom** of the file:

```bash
# ─── Go Environment ───────────────────────────────────────────
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin
# ──────────────────────────────────────────────────────────────
```

Save and reload:

```bash
source ~/.bashrc

# Verify Go is working
go version
# Expected: go version go1.22.x linux/amd64

# Check that ~/go/bin is in PATH
echo $PATH | grep go
```

### If You Use Zsh (Kali 2022+)

```bash
nano ~/.zshrc
# Add the same lines at the bottom
source ~/.zshrc
```

---

## 4. INSTALLING EVERY TOOL

### 4.1 — Subfinder

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Verify
subfinder -version
# Expected: subfinder v2.x.x

# Binary location
ls ~/go/bin/subfinder
```

### 4.2 — Amass

```bash
# Option A: via Go (recommended for latest version)
go install -v github.com/owasp-amass/amass/v4/...@master

# Option B: via apt (older but stable)
sudo apt install amass -y

# Verify
amass -version
# or
amass enum --help

# Binary location (Go install)
ls ~/go/bin/amass
# Binary location (apt install)
which amass   # → /usr/bin/amass
```

### 4.3 — Assetfinder

```bash
go install github.com/tomnomnom/assetfinder@latest

# Verify
assetfinder --help

# Binary location
ls ~/go/bin/assetfinder
```

### 4.4 — Sublist3r

```bash
cd /opt
sudo git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r

# Install Python dependencies
sudo pip3 install -r requirements.txt --break-system-packages

# Verify (will show help and version)
python3 /opt/Sublist3r/sublist3r.py --help
```

### 4.5 — Knockpy

```bash
cd /opt
sudo git clone https://github.com/guelfoweb/knock.git
cd knock

# Install dependencies
sudo pip3 install requests dnspython --break-system-packages

# Verify
python3 /opt/knock/knockpy.py --help
```

### 4.6 — httpx

```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Verify
httpx -version

# Binary location
ls ~/go/bin/httpx
```

### 4.7 — gau (Get All URLs)

```bash
go install github.com/lc/gau/v2/cmd/gau@latest

# Verify
gau --version

# Binary location
ls ~/go/bin/gau
```

### 4.8 — Gospider

```bash
go install github.com/jaeles-project/gospider@latest

# Verify
gospider version

# Binary location
ls ~/go/bin/gospider
```

### 4.9 — qsreplace

```bash
go install github.com/tomnomnom/qsreplace@latest

# Verify (no --version flag; just check it exists)
echo "test" | ~/go/bin/qsreplace "payload"
# Expected output: test (with no params to replace, passes through)

# Binary location
ls ~/go/bin/qsreplace
```

### 4.10 — ffuf

```bash
go install github.com/ffuf/ffuf/v2@latest

# Verify
ffuf -V

# Binary location
ls ~/go/bin/ffuf
```

### 4.11 — Gobuster

```bash
go install github.com/OJ/gobuster/v3@latest

# Verify
gobuster version

# Binary location
ls ~/go/bin/gobuster
```

### 4.12 — Feroxbuster

```bash
# Option A: Install script (recommended)
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash
sudo mv ./feroxbuster /usr/local/bin/

# Option B: via apt (Kali only)
sudo apt install feroxbuster -y

# Option C: via cargo (Rust)
cargo install feroxbuster

# Verify
feroxbuster --version

# Binary location
which feroxbuster     # → /usr/local/bin/feroxbuster
```

### 4.13 — dirsearch

```bash
cd /opt
sudo git clone https://github.com/maurosoria/dirsearch.git
cd dirsearch

# Install dependencies
sudo pip3 install -r requirements.txt --break-system-packages

# Verify
python3 /opt/dirsearch/dirsearch.py --help
```

### 4.14 — dirb

```bash
# Pre-installed on Kali. For Ubuntu:
sudo apt install dirb -y

# Verify
dirb --help
which dirb   # → /usr/bin/dirb
```

### 4.15 — wfuzz

```bash
# Option A: apt (Kali / Ubuntu)
sudo apt install wfuzz -y

# Option B: pip
sudo pip3 install wfuzz --break-system-packages

# Verify
wfuzz --help
which wfuzz   # → /usr/bin/wfuzz
```

### 4.16 — DirBuster (GUI only)

```bash
sudo apt install dirbuster -y

# Launch GUI
dirbuster &
# OR
java -jar /usr/share/dirbuster/DirBuster-1.0-RC1.jar

# Note: The tool uses gobuster/ffuf/feroxbuster as CLI equivalents.
# DirBuster GUI wordlists are at:
ls /usr/share/dirbuster/wordlists/
```

### 4.17 — Nmap (usually pre-installed)

```bash
# Kali: already installed
# Ubuntu:
sudo apt install nmap -y

# Verify
nmap --version
which nmap   # → /usr/bin/nmap
```

### Verify All Tools at Once

After installing everything, run this verification block:

```bash
echo "=== WebRecon Pro Tool Verification ==="

tools=(
  "subfinder:subfinder -version"
  "amass:amass -version"
  "assetfinder:assetfinder --help"
  "httpx:httpx -version"
  "gau:gau --version"
  "gospider:gospider version"
  "qsreplace:ls ~/go/bin/qsreplace"
  "ffuf:ffuf -V"
  "gobuster:gobuster version"
  "feroxbuster:feroxbuster --version"
  "dirb:dirb --help"
  "wfuzz:wfuzz --help"
  "nmap:nmap --version"
)

for entry in "${tools[@]}"; do
  name="${entry%%:*}"
  cmd="${entry##*:}"
  if eval "$cmd" &>/dev/null; then
    echo "  ✔ $name"
  else
    echo "  ✘ $name — NOT FOUND"
  fi
done

# Python tools
python3 /opt/Sublist3r/sublist3r.py --help &>/dev/null && echo "  ✔ sublist3r" || echo "  ✘ sublist3r"
python3 /opt/knock/knockpy.py --help &>/dev/null && echo "  ✔ knockpy"   || echo "  ✘ knockpy"
python3 /opt/dirsearch/dirsearch.py --help &>/dev/null && echo "  ✔ dirsearch" || echo "  ✘ dirsearch"
```

---

## 5. PATH & ENVIRONMENT VARIABLES

### The Full ~/.bashrc Block to Add

Open your shell config:

```bash
nano ~/.bashrc
# OR if you use zsh:
nano ~/.zshrc
```

Add this entire block at the bottom:

```bash
# ============================================================
# WebRecon Pro v2.0 — Environment Setup
# ============================================================

# ── Go Environment ──────────────────────────────────────────
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin

# ── Rust / Cargo (for feroxbuster) ──────────────────────────
export PATH=$PATH:$HOME/.cargo/bin

# ── Python Tool Aliases ──────────────────────────────────────
alias sublist3r='python3 /opt/Sublist3r/sublist3r.py'
alias knockpy='python3 /opt/knock/knockpy.py'
alias dirsearch='python3 /opt/dirsearch/dirsearch.py'

# ── API Keys (replace with your real keys) ──────────────────
export SHODAN_API_KEY="REPLACE_WITH_YOUR_SHODAN_KEY"
export VIRUSTOTAL_API_KEY="REPLACE_WITH_YOUR_VT_KEY"
export SECURITYTRAILS_API_KEY="REPLACE_WITH_YOUR_ST_KEY"
export CENSYS_API_ID="REPLACE_WITH_YOUR_CENSYS_ID"
export CENSYS_API_SECRET="REPLACE_WITH_YOUR_CENSYS_SECRET"
export CHAOS_KEY="REPLACE_WITH_YOUR_CHAOS_KEY"
export GITHUB_TOKEN="REPLACE_WITH_YOUR_GITHUB_PAT"

# ── Default Tool Paths (override if installed elsewhere) ─────
export WEBRECON_DIR="$HOME/tools/webrecon_pro"
export SECLISTS_DIR="/opt/SecLists"

# ── Quick Navigation ─────────────────────────────────────────
alias webrecon='cd $WEBRECON_DIR && bash webrecon.sh'
alias webrecon-sudo='cd $WEBRECON_DIR && sudo bash webrecon.sh'

# ── Subfinder Provider Config Path ───────────────────────────
export SUBFINDER_CONFIG="$HOME/.config/subfinder/provider-config.yaml"

# ============================================================
```

Reload your shell:

```bash
source ~/.bashrc
# or
source ~/.zshrc

# Test
echo $GOPATH      # Should be /home/youruser/go
echo $PATH | tr ':' '\n' | grep go   # Should see go/bin entries
```

---

## 6. API KEYS SETUP

API keys dramatically expand what tools like subfinder and amass can find. This is especially important for bug bounty work.

### 6.1 — Subfinder Provider Config

```bash
# Create the config directory
mkdir -p ~/.config/subfinder

# Create provider config (copy + edit)
nano ~/.config/subfinder/provider-config.yaml
```

Paste this template and fill in your keys:

```yaml
binaryedge:
  - REPLACE_WITH_BINARYEDGE_KEY
certspotter: []
chaos:
  - REPLACE_WITH_CHAOS_KEY
censys:
  - REPLACE_WITH_CENSYS_ID:REPLACE_WITH_CENSYS_SECRET
dnsdb: []
fofa:
  - REPLACE_WITH_FOFA_EMAIL:REPLACE_WITH_FOFA_KEY
github:
  - REPLACE_WITH_GITHUB_PAT
hunter:
  - REPLACE_WITH_HUNTER_KEY
intelx:
  - REPLACE_WITH_INTELX_KEY
passivetotal:
  - REPLACE_WITH_PT_USERNAME:REPLACE_WITH_PT_KEY
robtex: []
securitytrails:
  - REPLACE_WITH_ST_KEY
shodan:
  - REPLACE_WITH_SHODAN_KEY
spyse:
  - REPLACE_WITH_SPYSE_KEY
threatbook:
  - REPLACE_WITH_THREATBOOK_KEY
urlscan:
  - REPLACE_WITH_URLSCAN_KEY
virustotal:
  - REPLACE_WITH_VT_KEY
whoisxmlapi:
  - REPLACE_WITH_WHOISXML_KEY
zoomeye:
  - REPLACE_WITH_ZOOMEYE_KEY:REPLACE_WITH_ZOOMEYE_PASS
```

> **Free API Keys to Get:**
> - [VirusTotal](https://www.virustotal.com/gui/join-us) — free tier
> - [URLScan.io](https://urlscan.io/user/signup) — free tier
> - [Censys](https://accounts.censys.io/register) — free tier (250 queries/month)
> - [Shodan](https://account.shodan.io/register) — free tier (limited)
> - [SecurityTrails](https://securitytrails.com/app/signup) — free tier
> - [Chaos (ProjectDiscovery)](https://chaos.projectdiscovery.io/) — free for bug bounty

### 6.2 — Amass Config

```bash
mkdir -p ~/.config/amass
nano ~/.config/amass/config.ini
```

```ini
[data_sources.AlienVault]
[data_sources.AlienVault.Credentials]
apikey = REPLACE_WITH_OTX_KEY

[data_sources.BinaryEdge]
[data_sources.BinaryEdge.Credentials]
apikey = REPLACE_WITH_BINARYEDGE_KEY

[data_sources.Censys]
[data_sources.Censys.Credentials]
apikey = REPLACE_WITH_CENSYS_ID
secret = REPLACE_WITH_CENSYS_SECRET

[data_sources.GitHub]
[data_sources.GitHub.Credentials]
apikey = REPLACE_WITH_GITHUB_PAT

[data_sources.Shodan]
[data_sources.Shodan.Credentials]
apikey = REPLACE_WITH_SHODAN_KEY

[data_sources.SecurityTrails]
[data_sources.SecurityTrails.Credentials]
apikey = REPLACE_WITH_ST_KEY

[data_sources.VirusTotal]
[data_sources.VirusTotal.Credentials]
apikey = REPLACE_WITH_VT_KEY
```

### 6.3 — gau Config

```bash
nano ~/.gau.toml
```

```toml
[urlfilters]
  extensions = ["jpg", "jpeg", "gif", "png", "ico", "css", "eot", "woff", "woff2", "svg", "ttf", "mp4", "mp3"]

[providers]
  providers = ["wayback","otx","urlscan","commoncrawl"]

threads = 5
timeout = 30

[otx]
  apikey = "REPLACE_WITH_OTX_KEY"
```

---

## 7. WORDLISTS

### 7.1 — Install SecLists (Most Important)

```bash
cd /opt
sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git

# Verify
ls /opt/SecLists/Discovery/DNS/
ls /opt/SecLists/Discovery/Web-Content/
```

### 7.2 — Install dirbuster + dirb Wordlists

```bash
sudo apt install dirbuster dirb -y

# Check wordlists exist
ls /usr/share/dirbuster/wordlists/
ls /usr/share/dirb/wordlists/
```

### 7.3 — Additional Recommended Wordlists

```bash
# dns-Jhaddix (huge DNS wordlist from Jason Haddix)
ls /opt/SecLists/Discovery/DNS/dns-Jhaddix.txt

# Assetnote Wordlists (excellent for API endpoints)
mkdir -p ~/wordlists/assetnote
cd ~/wordlists/assetnote
wget https://wordlists-cdn.assetnote.io/data/automated/httparchive_directories_1m_2023_12_28.txt
wget https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2023_12_28.txt

# Commonspeak2 (frequency-based wordlists from real crawls)
mkdir -p ~/wordlists/commonspeak2
cd ~/wordlists/commonspeak2
wget https://raw.githubusercontent.com/assetnote/commonspeak2-wordlists/master/subdomains/subdomains.txt
```

### 7.4 — Wordlist Summary Table

| Wordlist | Path | Use For | Size |
|---|---|---|---|
| subdomains-top1million-5000 | `/opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt` | Fast subdomain brute | ~5k |
| subdomains-top1million-20000 | `/opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt` | Medium subdomain brute | ~20k |
| subdomains-top1million-110000 | `/opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt` | Deep subdomain brute | ~110k |
| dns-Jhaddix.txt | `/opt/SecLists/Discovery/DNS/dns-Jhaddix.txt` | Amass / comprehensive brute | ~1.8M |
| common.txt | `/opt/SecLists/Discovery/Web-Content/common.txt` | Fast dir brute | ~4.7k |
| directory-list-2.3-medium | `/opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt` | Standard dir brute | ~220k |
| directory-list-2.3-big | `/opt/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt` | Deep dir brute | ~1.2M |
| burp-parameter-names.txt | `/opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt` | Parameter fuzzing | ~6.5k |
| api-endpoints.txt | `/opt/SecLists/Discovery/Web-Content/api/api-endpoints.txt` | API route brute | ~14k |
| dirb common.txt | `/usr/share/dirb/wordlists/common.txt` | dirb default | ~4.6k |
| dirbuster medium | `/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt` | dirbuster default | ~220k |
| wfuzz general | `/usr/share/wfuzz/wordlist/general/common.txt` | wfuzz default | ~950 |


---

## 8. WHERE TO EDIT PATHS IN EACH FILE

This is the most important section. Every hardcoded path in the tool is documented here with exact file names and line numbers.

---

### 8.1 — `webrecon.sh` (MAIN FILE — Edit This One First)

**Location:** `~/tools/webrecon_pro/webrecon.sh`

Open it:
```bash
nano ~/tools/webrecon_pro/webrecon.sh
# OR
gedit ~/tools/webrecon_pro/webrecon.sh
```

**Lines 26–52 — TOOL PATHS SECTION:**

```bash
# ============================================================
# TOOL PATHS — EDIT THESE TO MATCH YOUR INSTALLATION
# ============================================================
SUBFINDER_PATH="${HOME}/go/bin/subfinder"       # ← Line 28
AMASS_PATH="..."                                 # ← Line 29 (auto-detected)
ASSETFINDER_PATH="${HOME}/go/bin/assetfinder"   # ← Line 30
SUBLIST3R_PATH="/opt/Sublist3r/sublist3r.py"    # ← Line 31 — change if you put it elsewhere
KNOCK_PATH="/opt/knock/knockpy.py"              # ← Line 32 — change if you put it elsewhere
HTTPX_PATH="${HOME}/go/bin/httpx"               # ← Line 33
GAU_PATH="${HOME}/go/bin/gau"                   # ← Line 34
GOSPIDER_PATH="${HOME}/go/bin/gospider"         # ← Line 35
QSREPLACE_PATH="${HOME}/go/bin/qsreplace"       # ← Line 36
FFUF_PATH="${HOME}/go/bin/ffuf"                 # ← Line 37
GOBUSTER_PATH="${HOME}/go/bin/gobuster"         # ← Line 38
FEROXBUSTER_PATH="..."                          # ← Line 39 (auto-detected, override if needed)
DIRSEARCH_PATH="/opt/dirsearch/dirsearch.py"    # ← Line 40 — change if elsewhere
DIRB_PATH="..."                                 # ← Line 41 (auto-detected)
WFUZZ_PATH="..."                                # ← Line 42 (auto-detected)
NMAP_PATH="..."                                 # ← Line 43 (auto-detected)
```

**Lines 46–52 — WORDLIST PATHS SECTION:**

```bash
WORDLIST_SUBS_SMALL="/opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"    # ← Line 46
WORDLIST_SUBS_MEDIUM="/opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt"  # ← Line 47
WORDLIST_SUBS_LARGE="/opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt"  # ← Line 48
WORDLIST_DIRS_SMALL="/opt/SecLists/Discovery/Web-Content/common.txt"                  # ← Line 49
WORDLIST_DIRS_MEDIUM="/opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt" # ← Line 50
WORDLIST_DIRS_BIG="/opt/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt"   # ← Line 51
WORDLIST_DIRB="/usr/share/dirb/wordlists/common.txt"                                  # ← Line 52
```

**Example: If you installed SecLists to a custom path:**

```bash
# Change line 46–51 from:
WORDLIST_SUBS_SMALL="/opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"

# To (if SecLists is in ~/wordlists/SecLists/):
WORDLIST_SUBS_SMALL="$HOME/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"
```

**Example: If Go tools are in /usr/local/bin instead of ~/go/bin:**

```bash
# Change:
SUBFINDER_PATH="${HOME}/go/bin/subfinder"
# To:
SUBFINDER_PATH="/usr/local/bin/subfinder"
```

---

### 8.2 — `modules/01_subdomain.sh`

**Additional hardcoded path on ~Line 74:**

```bash
# Line 74 — Default resolvers file path (only used if you choose Mode 5)
prompt_input "Path to resolvers file" "/opt/SecLists/Miscellaneous/dns-resolvers.txt" RESOLVERS_FILE
```

Change `/opt/SecLists/Miscellaneous/dns-resolvers.txt` to wherever your resolvers file is. This path is just a default suggestion shown in the prompt — you can override it at runtime by typing a different path.

**No other paths to change** — all tool paths come from `webrecon.sh` via exported variables.

---

### 8.3 — `modules/02_httpx_probe.sh`

**No hardcoded paths.** All paths come from environment variables exported by `webrecon.sh`. If httpx is not found, check:

```bash
echo $HTTPX_PATH
ls -la $HTTPX_PATH
```

---

### 8.4 — `modules/03_04_url_vuln.sh`

**No hardcoded tool paths** — all inherited from webrecon.sh exports.

These paths appear as **runtime prompts** (you type them during the scan):
- SSRF callback URL (your Burp Collaborator or interactsh)
- Log4Shell callback URL

---

### 8.5 — `modules/05_dir_brute.sh`

**Hardcoded path on ~Line 166 (default prompt value only):**

```bash
prompt_input "Parameter wordlist" "/opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt" PARAM_WL
```

**Hardcoded path on ~Line 341 (default prompt value only):**

```bash
prompt_input "API wordlist path" "/opt/SecLists/Discovery/Web-Content/api/api-endpoints.txt" API_WL
```

**Hardcoded path on ~Line 453:**

```bash
local api_wl="/opt/SecLists/Discovery/Web-Content/api/api-endpoints.txt"
```

If you have SecLists in a different location, change this line.

**Hardcoded path on ~Line 497 (wfuzz default wordlist):**

```bash
-w /usr/share/wfuzz/wordlist/general/common.txt \
```

Change to your wfuzz wordlist location if it differs:

```bash
# Find your wfuzz wordlists
find /usr /opt -name "*.txt" -path "*/wfuzz/*" 2>/dev/null

# Common locations:
# Kali:  /usr/share/wfuzz/wordlist/general/common.txt
# Other: /usr/lib/python3/dist-packages/wfuzz/wordlist/general/common.txt
```

---

### 8.6 — `modules/06_nmap_scan.sh`

**No hardcoded paths** — nmap is auto-detected via `$NMAP_PATH`. All tool paths from `webrecon.sh`.

---

### 8.7 — `modules/07_report.sh`

**No hardcoded paths** — reads from environment variables set by prior phases.

---

### Quick Find-and-Replace for Custom Paths

If you need to change `/opt/SecLists` everywhere at once:

```bash
# Preview what will change
grep -rn "/opt/SecLists" ~/tools/webrecon_pro/

# Replace /opt/SecLists with your custom path (e.g., ~/wordlists/SecLists)
NEWPATH="$HOME/wordlists/SecLists"
find ~/tools/webrecon_pro -name "*.sh" -exec \
  sed -i "s|/opt/SecLists|${NEWPATH}|g" {} \;

# Verify
grep -rn "SecLists" ~/tools/webrecon_pro/
```

Same for changing `/opt/Sublist3r` or `/opt/knock`:

```bash
sed -i "s|/opt/Sublist3r|/your/path/Sublist3r|g" ~/tools/webrecon_pro/webrecon.sh
sed -i "s|/opt/knock|/your/path/knock|g" ~/tools/webrecon_pro/webrecon.sh
sed -i "s|/opt/dirsearch|/your/path/dirsearch|g" ~/tools/webrecon_pro/webrecon.sh
```

---

## 9. RUNNING THE TOOL

### Basic Run

```bash
cd ~/tools/webrecon_pro
./webrecon.sh
```

### With sudo (Recommended — enables SYN scans, UDP, raw packet nmap)

```bash
sudo ./webrecon.sh
```

> Why sudo? Nmap's SYN scan (`-sS`), UDP scan (`-sU`), OS detection (`-O`), packet fragmentation, and several other modes require raw socket access, which requires root. Without sudo, nmap falls back to TCP connect scan (`-sT`), which is slower and more detectable.

### Running a Specific Phase Only

You don't have to run the full suite. At the scan mode selection screen, choose **[4] Custom Modules** and toggle only the phases you want.

Alternatively, you can call modules directly from bash (they share the same environment):

```bash
# Load environment and run just nmap
source ~/tools/webrecon_pro/modules/00_banner.sh
export TARGET="example.com"
export OUTPUT_DIR="/tmp/recon_example"
export LOG_FILE="$OUTPUT_DIR/error.log"
mkdir -p "$OUTPUT_DIR"
source ~/tools/webrecon_pro/modules/06_nmap_scan.sh
run_nmap_scan
```

### Scan Mode Summary

When the tool starts, it asks you to pick a mode:

| Mode | What It Runs | When to Use |
|---|---|---|
| **[1] Quick Recon** | Subdomain enum + httpx + gau only | Fastest overview, passive only |
| **[2] Standard Recon** | All phases, confirms each tool | Recommended default |
| **[3] Full Auto** | Everything, all default modes, minimal prompts | When you know the target well |
| **[4] Custom Modules** | You pick exactly which phases | Surgical — re-run one phase |
| **[5] Stealth Mode** | Passive only, rate-limited | WAF-aware targets, low noise |
| **[6] Bug Bounty Mode** | Passive recon + URL harvest + vuln scanning, no nmap | Classic BB workflow |
| **[7] Nmap Only** | Skips recon, jumps to nmap | When you already have a host list |
| **[8] Directory Only** | Skips recon, runs dir brute on a URL you provide | When you already have live hosts |

---

## 10. INTERACTIVE WALKTHROUGH

Here is what every prompt means and what you should enter:

### Prompt 1 — Target Domain

```
[TARGET] Enter target domain (without http/https):
```

Enter just the bare domain: `hackerone.com` or `bugcrowd.com`  
Do NOT include `https://` or a trailing slash.

---

### Prompt 2 — Output Directory

```
[?] Output directory path [press ENTER for default]:
```

Press **ENTER** to use the auto-generated path:  
`~/tools/webrecon_pro/results/hackerone.com_20240615_143022/`

Or enter a custom path:  
`/home/vishal/bb/hackerone/recon_june15`

---

### Prompt 3 — Tool Availability Check

The tool lists which tools are found / missing. You can continue with whatever is installed. Missing tools are skipped with a warning, not a crash.

---

### Prompt 4 — Wordlist Paths

```
[?] Subdomain wordlist (small ~5k) [default: /opt/SecLists/...]:
```

Press **ENTER** to accept the default, or type a custom path. If the path doesn't exist, the tool warns you and the affected scan is skipped.

---

### Prompt 5 — Scan Mode

Choose 1–8 as described in Section 9.

---

### Prompt 6 — Thread Preset

```
[1] Conservative  — 10 threads (stealth)
[2] Normal        — 50 threads (default)
[3] Aggressive    — 100 threads (fast, triggers WAF)
[4] Custom        — enter manually
```

For bug bounty: use **[1] Conservative** or **[2] Normal**.  
For CTF / lab environments: **[3] Aggressive** is fine.

---

### Per-Tool Prompts During Phase 1 (Subdomain)

For each tool and each mode, you'll see:

```
[?] Run Subfinder [Mode 1: Basic Passive]? [Y/n]
```

Press **ENTER** or type `y` to run, `n` to skip.

---

### Wordlist Prompt During Phase 5 (Directory Brute)

```
[?] Primary medium wordlist path [default: /opt/SecLists/.../directory-list-2.3-medium.txt]:
```

You can override with any wordlist path here. The path is validated; if not found, you're prompted again.

---

### Target URL Prompt During Phase 5

```
[?] Enter target URL for directory brute (or 'all' for every live host) [default: https://hackerone.com]:
```

- Type a specific URL: `https://api.hackerone.com`
- Type `all` to brute-force every live host found in Phase 2
- Press ENTER to use the default (main target)

---

### Nmap Target Prompt During Phase 6

```
[1] Target domain only: hackerone.com
[2] Target IP:          104.16.x.x
[3] Custom (enter manually)
```

For web bug bounty: choose **[1]** (domain).  
For network/infra recon: choose **[2]** (IP) or **[3]** for CIDR.

---

### Phase Pause

Between each phase you'll see:

```
Press ENTER to continue to Phase X, or Ctrl+C to stop...
```

This lets you review output before moving on. Press **ENTER** to continue or **Ctrl+C** to pause and later re-run from the post-scan menu.

---

### Post-Scan Menu

After all phases complete, you get:

```
[1] View final report
[2] View results index
[3] Show all output files
[4] Count total subdomains
[5] Show top 20 live hosts
[6] Show vulnerability candidates
[7] Show open Nmap ports
[8] Run a specific phase again
[9] Open output directory in file manager
[0] Exit
```

Use **[8]** to re-run any phase with different settings without starting over.

---

## 11. OUTPUT FILES & NAMING

### Naming Convention

Every output file follows this pattern:

```
{TARGET}_{TOOL}_{MODE}_{TIMESTAMP}.{ext}
```

Examples:

```
hackerone.com_subfinder_passive_basic_20240615_143022.txt
hackerone.com_amass_active_bruteforce_20240615_143156.txt
hackerone.com_httpx_allstatuscodes_20240615_144011.txt
hackerone.com_ffuf_dir_medium_20240615_150233.json
hackerone.com_nmap_02_full_syn_allports_20240615_152018.txt
```

This naming means:
- You instantly know **what tool** made the file
- You know **which mode** was used
- You know **when** it was made
- Multiple runs of the same scan don't overwrite each other

### Output Formats Per Tool

| Tool | Format | Key Fields |
|---|---|---|
| subfinder | `.txt` | One subdomain per line |
| amass | `.txt` + `.json` | Text = subdomains; JSON = full graph |
| assetfinder | `.txt` | One subdomain per line |
| sublist3r | `.txt` | One subdomain per line |
| knockpy | `.txt` | Parsed subdomains extracted |
| httpx | `.txt` + `.json` | URL + status + title + server + tech |
| gau | `.txt` | One URL per line |
| gospider | `.txt` | Extracted URLs from spider |
| ffuf | `.json` + `.txt` | JSON = raw; txt = parsed results |
| gobuster | `.txt` | Path + status code + size |
| feroxbuster | `.txt` | Path + status + size + words |
| dirb | `.txt` | `CODE:200` lines for matches |
| dirsearch | `.txt` | Status + path + size |
| wfuzz | `.txt` | Response line with status |
| nmap | `.txt` + `.xml` + `.gnmap` | All three formats always |

---

## 12. RESULTS_INDEX.TXT

Every scan auto-generates a `RESULTS_INDEX.txt` in the output directory. This file is your **map** of the entire scan.

### How to Read It

```
FILE PATH                                    | DESCRIPTION                          | HOW TO USE FURTHER
─────────────────────────────────────────────────────────────────────────────────────────────────────
hackerone.com_subfinder_passive_basic_*.txt  | Subfinder: basic passive enum        | Feed to httpx for live host check
hackerone.com_ALL_SUBDOMAINS_MERGED_*.txt    | MASTER: All tools merged subdomains  | cat file | httpx -silent
hackerone.com_httpx_LIVE_HOSTS_MASTER_*.txt  | MASTER live hosts                    | Input for gospider/ffuf
...
```

### View the Index

```bash
cat /path/to/output/RESULTS_INDEX.txt | column -t -s '|' | less
```

---

## 13. POST-SCAN WORKFLOW

Once the tool finishes, here's how to use the results:

### Step 1 — Subdomain Takeover Check

```bash
# Install subjack
go install github.com/haccer/subjack@latest

# Run against master subdomain list
subjack -w results/target/01_subdomains/*MERGED*.txt \
        -t 100 -timeout 30 -ssl -v -o takeover_candidates.txt

# Or use nuclei takeover templates
nuclei -l results/target/01_subdomains/*MERGED*.txt \
       -t ~/nuclei-templates/http/takeovers/ \
       -o nuclei_takeovers.txt
```

### Step 2 — Nuclei Scan on Live Hosts

```bash
# Install nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Run all severity templates on live hosts
nuclei -l results/target/02_httpx/*LIVE_HOSTS*txt \
       -t ~/nuclei-templates/ \
       -severity medium,high,critical \
       -o nuclei_findings.txt
```

### Step 3 — Parameter Discovery on Live URLs

```bash
# Install arjun
pip3 install arjun --break-system-packages

# Find hidden GET parameters
arjun -i results/target/03_urls/*URLs_with_parameters*.txt \
      -t 10 -o arjun_params.json
```

### Step 4 — JavaScript Analysis

```bash
# Install LinkFinder
cd /opt && sudo git clone https://github.com/GerbenJavado/LinkFinder.git
cd LinkFinder && pip3 install -r requirements.txt --break-system-packages

# Extract endpoints from JS files found in URL harvest
cat results/target/03_urls/*URL_MASTER*.txt | \
  grep -E "\.js($|\?)" | sort -u | \
  while read -r url; do
    python3 /opt/LinkFinder/linkfinder.py -i "$url" -o cli
  done 2>/dev/null | sort -u > js_endpoints.txt
```

### Step 5 — Secret Scanning in URLs

```bash
# Look for leaked tokens/keys in harvested URLs
cat results/target/03_urls/*URL_MASTER*.txt | \
  grep -iE 'token=|api_key=|secret=|password=|passwd=|auth=|key=|apikey=|access_token=' | \
  sort -u > possible_leaks.txt
```

### Step 6 — Import Nmap to Metasploit

```bash
msfconsole -q -x "
  workspace -a ${TARGET}
  db_import results/target/06_nmap/*.xml
  hosts
  services
  vulns
  exit
"
```

### Step 7 — 403 Bypass Testing

```bash
# Install 403bypass or use manual technique
# On all 403 paths found in directory brute:
grep "403" results/target/05_directories/*MASTER*.txt | \
  grep -oE 'https?://[^ ]+' | while read -r url; do
    echo "Testing: $url"
    # Try common 403 bypass headers
    curl -s -o /dev/null -w "%{http_code} $url\n" -H "X-Forwarded-For: 127.0.0.1" "$url"
    curl -s -o /dev/null -w "%{http_code} $url (rewrite)\n" "${url//\/\//\/\/.\/}"
  done
```

---

## 14. TROUBLESHOOTING

### "Permission denied" when running the script

```bash
chmod +x webrecon.sh modules/*.sh
```

### "subfinder: command not found" even after installing

```bash
# Check the binary exists
ls ~/go/bin/subfinder

# Check if GOPATH/bin is in PATH
echo $PATH | grep go

# If not, add it
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### "python3: No module named 'requests'" for Sublist3r / Knockpy

```bash
sudo pip3 install requests dnspython --break-system-packages
# OR use venv:
python3 -m venv /opt/Sublist3r/venv
source /opt/Sublist3r/venv/bin/activate
pip install -r /opt/Sublist3r/requirements.txt
```

### Nmap SYN scan requires root / drops to TCP connect

```bash
# Run the whole tool with sudo:
sudo ./webrecon.sh

# Or just re-run phase 6 with sudo:
sudo -E bash -c "source webrecon.sh" 
# (the -E flag preserves environment variables)
```

### "timeout: command not found"

```bash
sudo apt install coreutils -y
```

### ffuf shows no results / all filtered

```bash
# ffuf may be filtering by response size automatically. 
# During the interactive prompt, check ffuf output and look for:
# "Calibration" lines — ffuf auto-tunes to filter noise

# Manual fix: edit the ffuf command in 05_dir_brute.sh and add:
# -fs 0          (don't filter by size)
# -fc 404        (only filter 404s)
```

### gau returns zero results

```bash
# Test manually first:
gau example.com

# If no output, check internet/DNS:
dig example.com +short

# gau may need a config file for some providers:
gau --config ~/.gau.toml example.com
```

### Amass crashes or hangs

```bash
# Amass can be slow and memory-heavy. Try passive-only mode:
amass enum -passive -d target.com -o output.txt

# Or limit timeout:
timeout 120 amass enum -passive -d target.com -o output.txt
```

### Feroxbuster not found after install script

```bash
# Check if it was installed to current directory
ls ./feroxbuster

# Move it to /usr/local/bin
sudo mv ./feroxbuster /usr/local/bin/
sudo chmod +x /usr/local/bin/feroxbuster

# Update the path in webrecon.sh line 39:
FEROXBUSTER_PATH="/usr/local/bin/feroxbuster"
```

### "Set $GOPATH" error

```bash
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
```

### dirsearch SSL errors on HTTPS targets

```bash
# Add --disable-warnings to dirsearch in 05_dir_brute.sh
# Look for dirsearch calls and add:
# --disable-warnings --scheme https
```

### Script source error: "modules/00_banner.sh not found"

The script must be run from its own directory or the SCRIPT_DIR detection must work:

```bash
cd ~/tools/webrecon_pro
./webrecon.sh          # Always run from the suite's directory
```

---

## 15. ADVANCED TIPS

### Using Burp Suite as Proxy

During Phase 5 (directory brute), when prompted for tool modes, choose the **"Via Burp Proxy"** option in ffuf, feroxbuster, and dirsearch. Make sure Burp is running and listening on `127.0.0.1:8080`.

This lets you capture every request in Burp for replay and manual testing.

### Using interactsh for SSRF / OAST

For SSRF and Log4Shell detection, you need an out-of-band server:

```bash
# Install interactsh-client (ProjectDiscovery)
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Start listener (generates a unique URL)
interactsh-client

# Copy the generated URL (e.g., xyz123.oast.fun)
# Paste it when the tool asks for SSRF callback URL
```

### Subfinder with All API Sources

With API keys configured in `~/.config/subfinder/provider-config.yaml`, subfinder can query 40+ sources:

```bash
# See all sources subfinder is using
subfinder -d example.com -ls
```

### Running in a tmux Session (Recommended for Long Scans)

Long scans can run for hours. Use tmux so they survive SSH disconnects:

```bash
tmux new-session -s recon
cd ~/tools/webrecon_pro
sudo ./webrecon.sh

# Detach: Ctrl+B then D
# Reattach later:
tmux attach -t recon
```

### Saving Scan Config for Repeatable Scans

You can pre-set environment variables to avoid re-entering them every time:

```bash
# Create a per-target config file
cat > ~/bb/hackerone_config.sh << 'EOF'
export TARGET="hackerone.com"
export OUTPUT_DIR="/home/vishal/bb/hackerone/recon_$(date +%Y%m%d)"
export THREAD_COUNT=30
export WORDLIST_DIRS_MEDIUM="/opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt"
EOF

# Source it before running
source ~/bb/hackerone_config.sh
cd ~/tools/webrecon_pro
./webrecon.sh
```

### Converting Nmap XML to HTML Manually

```bash
# Convert any nmap XML to HTML
xsltproc /usr/share/nmap/nmap.xsl scan.xml > scan.html
firefox scan.html
```

### Extracting Clean Lists from Output

```bash
# Get just the URLs from httpx full-probe output
cat *httpx_fullprobe*.json | jq -r '.url' | sort -u > live_urls.txt

# Get just IPs from nmap grepable output
grep "Up" *.gnmap | awk '{print $2}' | sort -u > live_ips.txt

# Get only 200 status subdomains
grep "\[200\]" *httpx_allstatuscodes*.txt | awk '{print $1}' | sort -u
```

---

## 16. QUICK REFERENCE CHEATSHEET

### Setup in Order

```bash
# 1. Install Go
wget https://go.dev/dl/go1.22.3.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.3.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

# 2. Install all Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/owasp-amass/amass/v4/...@master
go install github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/jaeles-project/gospider@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/OJ/gobuster/v3@latest

# 3. Install Python tools
sudo apt install -y dirb wfuzz dirbuster nmap
cd /opt && sudo git clone https://github.com/aboul3la/Sublist3r.git
cd /opt && sudo git clone https://github.com/guelfoweb/knock.git
cd /opt && sudo git clone https://github.com/maurosoria/dirsearch.git
sudo pip3 install requests dnspython --break-system-packages
sudo pip3 install -r /opt/Sublist3r/requirements.txt --break-system-packages
sudo pip3 install -r /opt/dirsearch/requirements.txt --break-system-packages

# 4. Install Feroxbuster
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash
sudo mv feroxbuster /usr/local/bin/

# 5. Install SecLists
sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/SecLists

# 6. Place and run the tool
mkdir -p ~/tools && cd ~/tools
# (copy webrecon_pro here)
chmod +x webrecon_pro/webrecon.sh webrecon_pro/modules/*.sh
cd webrecon_pro
./webrecon.sh
```

### Files to Edit After Setup

| File | Lines | What to Change |
|---|---|---|
| `webrecon.sh` | 28–43 | Tool binary paths |
| `webrecon.sh` | 46–52 | Wordlist paths |
| `~/.bashrc` | bottom | Go PATH, API keys, aliases |
| `~/.config/subfinder/provider-config.yaml` | all | API keys per source |
| `~/.config/amass/config.ini` | all | API keys per source |
| `~/.gau.toml` | all | gau providers + OTX key |
| `modules/05_dir_brute.sh` | ~453 | api_wl path (if not at default) |

### Most Common Scan Commands After Setup

```bash
# Standard bug bounty scan
cd ~/tools/webrecon_pro && ./webrecon.sh
# → Choose mode [6] Bug Bounty Mode
# → Enter target, ENTER for defaults
# → Select y/n for each tool as they appear

# Full infra recon with nmap (needs root)
sudo ./webrecon.sh
# → Choose mode [2] Standard Recon

# Quick subdomain check only
./webrecon.sh
# → Mode [4] Custom → Enable only Phase 1

# Directory brute on a specific URL you already have
./webrecon.sh
# → Mode [8] Directory Only → Enter your URL
```

### Key Output Files to Always Check

```bash
ls results/<target>/01_subdomains/*MERGED*.txt       # All subdomains
ls results/<target>/02_httpx/*LIVE_HOSTS_MASTER*.txt # Live hosts
ls results/<target>/03_urls/*URL_MASTER*.txt         # All URLs
ls results/<target>/03_urls/*with_parameters*.txt    # Parameterized URLs
ls results/<target>/04_vulns/*VULN_MASTER*.txt       # Vuln candidates
ls results/<target>/05_directories/*MASTER*.txt      # Dir brute results
ls results/<target>/06_nmap/*MASTER*.txt             # Open ports
ls results/<target>/RESULTS_INDEX.txt                # Full map
ls results/<target>/*FINAL_REPORT*.md                # Markdown summary
```

---

*WebRecon Pro v2.0 — Complete Usage Guide*  
*Use only on targets you have explicit authorization to test.*

