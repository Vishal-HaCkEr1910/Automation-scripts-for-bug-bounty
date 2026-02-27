# 🎯 Low-Hanging Fruits — The Bug Bounty Quick-Win Playbook

> **5 Vulnerabilities That Pay Out With Minimal Effort**
> Broken Link Hijacking · Missing SPF Record · Origin IP Disclosure · Session Not Expiring After Logout · Long Password DoS
>
> Author: **Vishal** | Last Updated: February 2026
>
> _"The best bounties aren't always the hardest bugs. Sometimes the door is just… left open."_

---

## ⚠️ Legal Disclaimer

> Everything in this document is for **educational purposes** and **authorized security testing only**.
> Never test on systems you do not own or have **explicit written permission** to test.
> Unauthorized access to computer systems is a **criminal offense** under laws including the CFAA (US), IT Act (India), and Computer Misuse Act (UK).
> The author accepts **no liability** for any misuse of the techniques described here.

---

## 📋 Table of Contents

| # | Vulnerability | Severity | Typical Payout | Automation? |
|---|--------------|----------|----------------|-------------|
| 1 | [Broken Link Hijacking (BLH)](#1--broken-link-hijacking-blh) | Medium (P3-P4) | $50–$500 | ✅ Already built |
| 2 | [Missing SPF Record](#2--missing-spf-record) | Medium (P3-P4) | $50–$300 | ✅ `spf_checker.py` |
| 3 | [Origin IP Disclosure](#3--origin-ip-disclosure-behind-cdnwaf) | Medium–High (P2-P3) | $100–$1,000 | ✅ `origin_ip_finder.py` |
| 4 | [Session Not Expiring After Logout](#4--session-not-expiring-after-logout) | Medium (P3) | $100–$500 | ✅ `session_logout_tester.py` |
| 5 | [Long Password DoS](#5--long-password-dos-attack) | Low–Medium (P3-P4) | $50–$500 | ✅ `long_password_dos.py` |

---

---

# 1. 🔗 Broken Link Hijacking (BLH)

## What is it?

When a website links to an **external resource** (social media, GitHub repo, documentation, CDN) and that resource **no longer exists** or **the username/domain has been released**, an attacker can **claim ownership** of the dead resource and inject malicious content that appears to come from the trusted website.

## Why it's a Vulnerability

| Aspect | Impact |
|--------|--------|
| **Reputation** | Attacker controls a page that the target website links to |
| **Phishing** | Attacker can host phishing pages on a "trusted" linked domain |
| **Malware** | Inject malware downloads through trusted links |
| **SEO Poisoning** | Redirect link juice to attacker-controlled sites |
| **Supply Chain** | If the link loads JavaScript (CDN, npm), it's **RCE via supply chain** |

## What's Claimable?

| Dead Resource | How to Claim |
|---------------|-------------|
| Deleted GitHub repo/user | Create a GitHub account/repo with that name |
| Expired domain | Register the domain |
| Dead social profiles | Create an account with that username |
| Unclaimed S3 bucket | Create the bucket in your AWS account |
| Deleted npm package | Publish a package with that name |
| Dead Bitbucket/GitLab repos | Create the repo |
| Unused Shopify store | Claim the subdomain |

## How to Hunt

### Manual Method (Burp Suite)

```
1. Browse the entire target in Burp → Sitemap fills up
2. Right-click the target → "Engagement Tools" → "Find Links"
3. Copy all external links
4. Open each in a browser → look for 404, "page not found", dead pages
5. Try to claim the dead resource
```

### Automated Method

```bash
# Use our BLH tool (already built!)
python tools/broken-link-hijacker/blh.py -u https://target.com -d 3 -t 50

# Quick scan (depth 1, fewer threads)
python tools/broken-link-hijacker/blh.py -u https://target.com

# Full aggressive scan
python tools/broken-link-hijacker/blh.py -u https://target.com -d 5 -t 100 --ignore-robots
```

## Escalation Tips

| Escalation | How | Impact Increase |
|-----------|-----|----------------|
| **JS inclusion** | If the dead link is a `<script src>`, you control executed JS | → **P1 Critical (XSS/RCE)** |
| **CSS injection** | If `<link rel=stylesheet>` points to dead URL | → Data exfil via CSS |
| **Social impersonation** | Claim dead social profile, post as the brand | → Phishing amplification |
| **Supply chain** | Dead npm/pip package? Publish malicious version | → **P1 Critical** |

## Bug Report Template

```markdown
**Title:** Broken Link Hijacking — Claimable [GitHub repo/social profile/domain] on [target.com]

**Severity:** Medium (or Critical if JS/CSS inclusion)

**Description:**
The page [URL] on [target.com] contains a link to [dead-resource-URL].
This resource no longer exists and can be claimed by an attacker.
An attacker could claim this resource and host malicious content that
appears endorsed by [target.com].

**Steps to Reproduce:**
1. Visit [page-URL]
2. Observe the link to [dead-resource-URL]
3. Visit [dead-resource-URL] — note it returns 404/is available
4. The [resource type] can be registered/claimed at [platform]

**Impact:**
An attacker can claim [dead-resource] and serve phishing pages,
malware, or malicious JavaScript to users who trust [target.com].

**Proof of Concept:**
[Screenshot of the link on target.com]
[Screenshot of the 404/available status]
[WHOIS/availability check showing it's claimable]

**Remediation:**
- Remove or update the broken link
- Proactively claim the resource to prevent hijacking
```

---

---

# 2. 📧 Missing SPF Record

## What is it?

**SPF (Sender Policy Framework)** is a DNS TXT record that specifies **which mail servers are authorized** to send emails on behalf of a domain. Without it (or with a misconfigured one), anyone in the world can **spoof emails** that appear to come from `@target.com`.

## The DNS Record

```
target.com.  IN  TXT  "v=spf1 include:_spf.google.com include:sendgrid.net -all"
```

| Part | Meaning |
|------|---------|
| `v=spf1` | SPF version 1 (required) |
| `include:_spf.google.com` | Allow Google's mail servers to send |
| `include:sendgrid.net` | Allow SendGrid to send |
| `ip4:203.0.113.5` | Allow this specific IP |
| `-all` | **Hard fail** — reject everything else |
| `~all` | **Soft fail** — accept but mark as suspicious |
| `?all` | **Neutral** — don't check (useless!) |
| `+all` | **Allow all** — anyone can send (WORST!) |

## Vulnerability Levels

| Configuration | Risk Level | Spoofable? |
|--------------|------------|------------|
| **No SPF record at all** | 🔴 HIGH | Yes — completely |
| `v=spf1 +all` | 🔴 HIGH | Yes — explicitly allows everyone |
| `v=spf1 ?all` | 🟠 MEDIUM | Yes — no policy enforcement |
| `v=spf1 ~all` | 🟡 LOW-MED | Soft fail — many servers still accept |
| `v=spf1 ... -all` | 🟢 GOOD | Hard fail — properly configured |

## Also Check: DMARC and DKIM

SPF alone isn't enough. A complete email security posture requires all three:

| Record | Purpose | DNS Location |
|--------|---------|-------------|
| **SPF** | Authorize sending IPs | `target.com TXT` |
| **DKIM** | Cryptographically sign emails | `selector._domainkey.target.com TXT` |
| **DMARC** | Policy for SPF/DKIM failures | `_dmarc.target.com TXT` |

### DMARC Policies

```
_dmarc.target.com.  IN  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc@target.com"
```

| Policy `p=` | Meaning | Secure? |
|-------------|---------|---------|
| `p=none` | Monitor only, don't enforce | ❌ No |
| `p=quarantine` | Send to spam if fails | ⚠️ Partial |
| `p=reject` | Block email entirely | ✅ Yes |

## How to Hunt — Manual

```bash
# Check SPF record
dig +short TXT target.com | grep spf

# Check DMARC record
dig +short TXT _dmarc.target.com

# Check DKIM (you need the selector — check email headers)
dig +short TXT selector1._domainkey.target.com

# Using nslookup
nslookup -type=txt target.com
nslookup -type=txt _dmarc.target.com
```

## How to Hunt — Automated

```bash
python tools/spf-checker/spf_checker.py -d target.com

# Multiple domains
python tools/spf-checker/spf_checker.py -d target.com example.com

# From a file (one domain per line)
python tools/spf-checker/spf_checker.py -f domains.txt

# With email spoofing test (sends a test email)
python tools/spf-checker/spf_checker.py -d target.com --spoof-test --from admin@target.com --to your-email@gmail.com
```

## How to Prove Impact — Email Spoofing PoC

> ⚠️ **Do NOT send spoofed emails to real people.** Only send to your own inbox as a PoC.

### Method 1: Using `swaks` (Swiss Army Knife for SMTP)

```bash
# Install swaks
brew install swaks    # macOS
apt install swaks     # Linux

# Send spoofed email to YOUR inbox
swaks --to your-email@gmail.com \
      --from ceo@target.com \
      --header "Subject: Password Reset Required" \
      --body "This is a PoC for email spoofing vulnerability." \
      --server smtp.gmail.com:587 -tls
```

### Method 2: Using Python

```python
import smtplib
from email.mime.text import MIMEText

msg = MIMEText("This is a PoC. SPF record is missing for target.com")
msg["Subject"] = "[PoC] Email Spoofing - Missing SPF"
msg["From"] = "security@target.com"  # Spoofed!
msg["To"] = "your-email@gmail.com"

# Connect to an open relay or your SMTP server
with smtplib.SMTP("your-smtp-server", 587) as server:
    server.starttls()
    server.login("you@example.com", "password")
    server.send_message(msg)
```

### Method 3: Online Tools

| Tool | URL | What it Does |
|------|-----|-------------|
| **emkei.cz** | https://emkei.cz | Free fake mailer (for PoC only!) |
| **MXToolbox** | https://mxtoolbox.com/spf.aspx | SPF record check |
| **Mail-Tester** | https://www.mail-tester.com | Full email deliverability test |

## Escalation

| Escalation | Description |
|-----------|------------|
| **Phishing employees** | Spoof as CEO → send password reset to employees |
| **Customer phishing** | Spoof as support@target.com → steal customer credentials |
| **Password reset hijacking** | If combined with other vulns, spoof password reset emails |
| **Supply chain attacks** | Spoof as procurement → send fake invoices |
| **Domain reputation damage** | Spammers abuse the domain, it gets blacklisted |

## Bug Report Template

```markdown
**Title:** Missing/Misconfigured SPF Record Enables Email Spoofing for [target.com]

**Severity:** Medium (P3-P4)

**Description:**
The domain [target.com] does not have a properly configured SPF record.
This allows any attacker to send emails that appear to originate from
@target.com addresses, enabling phishing attacks against employees
and customers.

**Current DNS Configuration:**
- SPF: [none / "v=spf1 ~all" / etc.]
- DMARC: [none / "v=DMARC1; p=none" / etc.]
- DKIM: [not configured / configured]

**Steps to Reproduce:**
1. Run: `dig +short TXT target.com` — observe [missing/weak] SPF
2. Run: `dig +short TXT _dmarc.target.com` — observe [missing/weak] DMARC
3. Send a spoofed email using [swaks/Python/emkei.cz]:
   - From: ceo@target.com
   - To: [your test email]
4. Email arrives in inbox without any warning/spam flag

**Proof of Concept:**
[Screenshot of received spoofed email]
[Screenshot showing email passed SPF check / no SPF]
[Screenshot of dig output showing missing record]

**Impact:**
An attacker can send phishing emails as any @target.com address,
potentially leading to credential theft, financial fraud, or
reputational damage.

**Remediation:**
1. Add SPF record: `v=spf1 include:[mail-provider] -all`
2. Add DMARC record: `v=DMARC1; p=reject; rua=mailto:dmarc@target.com`
3. Configure DKIM signing on the mail server
```

---

---

# 3. 🌐 Origin IP Disclosure (Behind CDN/WAF)

## What is it?

Many websites sit behind a **CDN** (Cloudflare, Akamai, Fastly) or **WAF** (Web Application Firewall). The CDN/WAF acts as a reverse proxy — all traffic goes through it, and the **real server IP (origin IP) is hidden**.

If an attacker can **discover the origin IP**, they can:

```
Normal:  Attacker → [Cloudflare WAF] → Origin Server (protected)
Bypass:  Attacker → Origin Server directly (WAF bypassed!)
```

## Why it's Critical

| Impact | Description |
|--------|-------------|
| **WAF Bypass** | Attack the server directly, bypassing all WAF rules |
| **DDoS directly** | CDN absorbs DDoS — origin IP doesn't have that protection |
| **Exploit vulns** | WAF might block SQLi/XSS payloads — direct access doesn't |
| **IP-based attacks** | Port scanning, service enumeration on the actual server |
| **Full compromise** | Combined with other vulns, direct access = easier exploitation |

## Discovery Techniques

### 1. DNS History

Old DNS records often reveal the pre-CDN origin IP:

```bash
# SecurityTrails (free API)
curl "https://api.securitytrails.com/v1/history/target.com/dns/a" \
     -H "APIKEY: your-api-key"

# Online tools:
# - https://securitytrails.com/domain/target.com/history/a
# - https://viewdns.info/iphistory/?domain=target.com
# - https://completedns.com/dns-history/
```

### 2. Subdomain Scanning

Main domain is behind Cloudflare, but subdomains might not be:

```bash
# Find subdomains
subfinder -d target.com -silent | httpx -ip -silent

# Common exposed subdomains:
# mail.target.com    → often reveals origin IP (MX record)
# ftp.target.com     → file server, same IP as web
# cpanel.target.com  → hosting control panel
# staging.target.com → staging server, same IP
# dev.target.com     → development, often unprotected
# direct.target.com  → sometimes literally named
```

### 3. Email Headers

When the target sends you an email (password reset, newsletter), the email headers contain the **sending server's IP**:

```
Received: from mail.target.com (203.0.113.42) by ...
X-Originating-IP: [203.0.113.42]
```

**How to trigger emails:**
- Sign up for an account → welcome email
- Password reset → reset email
- Contact form → auto-reply
- Newsletter subscription → confirmation email

### 4. SSL Certificate Search

Search for SSL certificates issued to the target — they contain the server IP:

```bash
# Censys.io
# Search: parsed.names: target.com
# → Shows all IPs that have SSL certs for target.com

# Shodan
shodan search "ssl.cert.subject.cn:target.com" --fields ip_str

# crt.sh (Certificate Transparency)
curl -s "https://crt.sh/?q=target.com&output=json" | jq '.[].common_name'
```

### 5. Misconfigured Headers

Some servers leak their IP in response headers:

```bash
curl -sI https://target.com | grep -iE "x-real-ip|x-forwarded|x-host|x-origin|server|x-backend"
```

| Header | What it Reveals |
|--------|----------------|
| `X-Real-IP` | The actual server IP |
| `X-Forwarded-For` | IP chain — origin might be at the end |
| `X-Backend-Server` | Backend server hostname/IP |
| `X-Host` | Origin hostname |
| `Server: Apache/2.4.41 (Ubuntu)` | Server software (not IP, but useful) |

### 6. HTML/JS Source Code

```bash
# Search for hardcoded IPs in page source
curl -s https://target.com | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'

# Search JavaScript files
# Our JS Secrets Scanner can find these!
python tools/js-secrets-scanner/js_scanner.py -i https://target.com
```

### 7. Favicon Hash (Shodan)

```python
import mmh3, requests, codecs
response = requests.get("https://target.com/favicon.ico")
favicon_hash = mmh3.hash(codecs.lookup("base64").encode(response.content)[0])
print(f"Shodan dork: http.favicon.hash:{favicon_hash}")
# Search this hash on Shodan → find all servers with the same favicon
```

## How to Hunt — Automated

```bash
# Basic scan
python tools/origin-ip-finder/origin_ip_finder.py -d target.com

# With SecurityTrails API for DNS history
export SECURITYTRAILS_API_KEY=your_key_here
python tools/origin-ip-finder/origin_ip_finder.py -d target.com

# Aggressive mode (more techniques, slower)
python tools/origin-ip-finder/origin_ip_finder.py -d target.com --aggressive

# Scan multiple domains
python tools/origin-ip-finder/origin_ip_finder.py -d target.com example.com

# From file
python tools/origin-ip-finder/origin_ip_finder.py -f domains.txt
```

## Verification — Confirm the Origin IP

Once you find a candidate IP, verify it:

```bash
# 1. Direct HTTP request with Host header
curl -sI -H "Host: target.com" http://203.0.113.42/
# If you get the target's page → confirmed!

# 2. Compare page content
diff <(curl -s https://target.com) <(curl -s -H "Host: target.com" http://203.0.113.42/)

# 3. Check SSL certificate
echo | openssl s_client -connect 203.0.113.42:443 -servername target.com 2>/dev/null | openssl x509 -noout -subject
# If subject matches target.com → confirmed!
```

## Bug Report Template

```markdown
**Title:** Origin IP Disclosure — WAF/CDN Bypass for [target.com]

**Severity:** Medium-High (P2-P3)

**Description:**
The origin IP address of [target.com] is exposed despite being behind
[Cloudflare/Akamai/etc.]. This allows attackers to bypass the CDN/WAF
and directly access the origin server.

**Origin IP Found:** [203.0.113.42]
**Discovery Method:** [DNS history / email headers / subdomain / etc.]

**Steps to Reproduce:**
1. [Describe the discovery method used]
2. Found candidate IP: [IP]
3. Verified by sending request with Host header:
   `curl -H "Host: target.com" http://[IP]/`
4. Received the target website's content, confirming origin IP

**Impact:**
- WAF rules can be completely bypassed
- Server is vulnerable to direct DDoS attacks
- Port scanning reveals additional attack surface
- Any web application vulnerabilities can be exploited without WAF filtering

**Proof of Concept:**
[Screenshot of direct access via origin IP]
[Screenshot of curl response comparison]
[Screenshot of SSL cert verification]

**Remediation:**
1. Configure origin server firewall to ONLY accept connections from CDN IPs
2. Use Cloudflare Authenticated Origin Pulls (mTLS)
3. Remove DNS history by changing the origin IP (migrate to a new server)
4. Ensure no subdomains point directly to the origin
5. Remove origin IP from email server headers (use a separate mail server)
```

---

---

# 4. 🔐 Session Not Expiring After Logout

## What is it?

When a user clicks **"Logout"**, the application should **invalidate the session** on the server side. If the session token/cookie **remains valid** after logout, an attacker who captured the token (via XSS, network sniffing, or physical access) can **continue using it** even after the victim logged out.

## The Vulnerability

```
Normal (Secure) Logout:
1. User clicks Logout
2. Server destroys session ID "abc123" from the database
3. If attacker uses session "abc123" → Server rejects (401 Unauthorized)

Vulnerable Logout:
1. User clicks Logout
2. Server only clears the cookie on the client (or does nothing server-side)
3. If attacker uses session "abc123" → Server still accepts it! ⚠️
```

## Common Variations

| Variation | Description | Severity |
|-----------|-------------|----------|
| **Token still valid after logout** | Session cookie works even after clicking logout | Medium |
| **JWT with no server-side revocation** | JWTs are valid until expiry, logout doesn't invalidate them | Medium |
| **Session fixation + no rotation** | Session ID doesn't change after login → pre-auth token works post-login | High |
| **Long session timeout** | Session lasts days/weeks without activity timeout | Low-Med |
| **No session timeout at all** | Session never expires — even after days/weeks | Medium |
| **Cookie not cleared** | Logout page doesn't send `Set-Cookie` to clear the token | Low |
| **Multiple concurrent sessions** | Logging out on one device doesn't invalidate other sessions | Medium |

## How to Hunt — Manual (Burp Suite)

```
Step 1: Login to the target application
Step 2: Capture any authenticated request in Burp → Send to Repeater
Step 3: Note the session token (Cookie: session=abc123)
Step 4: Click Logout in the browser
Step 5: Go back to Burp Repeater → Replay the authenticated request
Step 6: If you get a 200 OK with the authenticated content → VULNERABLE!
```

### What to Check

| Check | How | Vulnerable If |
|-------|-----|--------------|
| **Session cookie after logout** | Replay old cookie in Burp Repeater | 200 OK with auth content |
| **JWT after logout** | Replay old JWT in Authorization header | Still returns data |
| **Session timeout** | Wait 30 min inactive, then replay token | Still works |
| **Password change invalidation** | Change password, then use old session | Old session still works |
| **Concurrent sessions** | Login on 2 browsers, logout on 1 | Other session still works |

## How to Hunt — Automated

```bash
# Test a single target
python tools/session-tester/session_logout_tester.py -u https://target.com

# With login credentials (form-based)
python tools/session-tester/session_logout_tester.py \
    -u https://target.com \
    --login-url https://target.com/login \
    --logout-url https://target.com/logout \
    --username testuser \
    --password testpass123

# With a pre-captured session cookie
python tools/session-tester/session_logout_tester.py \
    -u https://target.com/dashboard \
    --logout-url https://target.com/logout \
    --cookie "session=abc123def456"

# With a JWT token
python tools/session-tester/session_logout_tester.py \
    -u https://target.com/api/profile \
    --logout-url https://target.com/api/logout \
    --token "eyJhbGciOiJIUzI1NiIs..."
```

## Bug Report Template

```markdown
**Title:** Session Token Remains Valid After Logout on [target.com]

**Severity:** Medium (P3)

**Description:**
After logging out of [target.com], the session token is not invalidated
on the server side. An attacker who has captured a valid session token
(through XSS, network sniffing, or local access) can continue to use
it even after the victim has explicitly logged out.

**Steps to Reproduce:**
1. Login to [target.com] with valid credentials
2. Open browser DevTools → Application → Cookies → Note the session cookie value
3. Open Burp Suite → Capture a request to [authenticated-endpoint]
4. Send the request to Burp Repeater
5. Click "Logout" in the browser
6. In Burp Repeater, replay the captured request (with the old session cookie)
7. Observe: Response is 200 OK with authenticated content (should be 401/403)

**Impact:**
- An attacker with a stolen session token can maintain access indefinitely
- Logout provides a false sense of security to the user
- Violates OWASP Session Management guidelines
- If combined with XSS (session theft), logout doesn't mitigate the attack

**Proof of Concept:**
[Screenshot: Authenticated request in Repeater before logout → 200 OK]
[Screenshot: Same request replayed after logout → still 200 OK]
[Timestamps showing the request was made after logout]

**Remediation:**
1. Invalidate the session token server-side upon logout (delete from DB/cache)
2. For JWTs: Maintain a token blacklist/revocation list
3. Set appropriate session timeouts (15-30 min of inactivity)
4. Rotate session tokens on privilege level changes
5. Implement concurrent session controls (option to invalidate all sessions)
```

---

---

# 5. 💣 Long Password DoS Attack

## What is it?

When a user submits a password, the server typically **hashes** it using algorithms like **bcrypt, scrypt, PBKDF2, or Argon2**. These algorithms are intentionally slow (to resist brute-force attacks). However, if the server **doesn't limit the password length**, an attacker can submit an **extremely long password** (100KB–10MB) that causes the server to:

1. **Spend excessive CPU time** hashing the massive input
2. **Run out of memory** trying to process it
3. **Block the thread/process**, preventing other users from logging in

This is a **Denial of Service (DoS)** attack.

## The Technical Explanation

### Why Bcrypt is Especially Vulnerable

Bcrypt has a **72-byte internal limit** — it truncates passwords beyond 72 bytes. But many implementations **hash the entire input first** (e.g., `bcrypt(sha256(password))`) or the framework preprocesses the string before passing it to bcrypt.

The real problem is when the application:
1. Receives a 1MB password
2. Tries to process/validate/hash the **entire 1MB** before any truncation
3. This consumes massive CPU/memory

### CPU Cost Example

| Password Length | Bcrypt Hash Time (approx.) | Impact |
|----------------|---------------------------|--------|
| 8 characters | ~100ms | Normal |
| 1,000 characters | ~100ms (truncated at 72) | Negligible |
| 100,000 characters | ~1-5 seconds (preprocessing) | Noticeable |
| 1,000,000 characters | ~10-60 seconds | Server lag |
| 10,000,000 characters | Minutes / OOM | **DoS** |

### Affected Endpoints

| Endpoint | Why it's Vulnerable |
|----------|-------------------|
| `/login` | Password is hashed for comparison |
| `/register` | Password is hashed for storage |
| `/change-password` | Old + new password both hashed |
| `/reset-password` | New password hashed |
| `/api/auth` | API authentication endpoint |

## How to Hunt — Manual (Burp Suite)

```
Step 1: Go to the login/register page
Step 2: Intercept the request in Burp
Step 3: Replace the password field with a very long string:
        - Start with 10,000 characters (10KB) → measure response time
        - Increase to 100,000 characters (100KB) → measure response time
        - Increase to 1,000,000 characters (1MB) → measure response time
Step 4: If response time increases significantly → VULNERABLE
Step 5: Use Burp Intruder to send multiple concurrent long-password requests
Step 6: If the server becomes slow/unresponsive → DoS confirmed
```

### Quick Payload Generation

```bash
# Generate a 1MB password
python3 -c "print('A' * 1000000)" > long_password.txt

# Generate various sizes
python3 -c "print('A' * 10000)"    # 10KB
python3 -c "print('A' * 100000)"   # 100KB
python3 -c "print('A' * 1000000)"  # 1MB
python3 -c "print('A' * 10000000)" # 10MB
```

### Burp Intruder Setup

```
1. Send login request to Intruder
2. Set the password field as the insertion point
3. Payload type: "Character Frobber" or custom list of increasing-length strings
4. Set concurrent threads to 10-20
5. Run and observe server response times in the Results tab
6. If response times increase from 100ms to 5s+ → DoS confirmed
```

## How to Hunt — Automated

```bash
# Basic test
python tools/long-password-dos/long_password_dos.py -u https://target.com/login

# With custom field names
python tools/long-password-dos/long_password_dos.py \
    -u https://target.com/login \
    --password-field passwd \
    --username-field email \
    --username test@test.com

# Custom sizes to test (in characters)
python tools/long-password-dos/long_password_dos.py \
    -u https://target.com/login \
    --sizes 1000 10000 100000 500000 1000000

# API endpoint (JSON body)
python tools/long-password-dos/long_password_dos.py \
    -u https://target.com/api/login \
    --json \
    --username test@test.com

# With concurrency test (multiple simultaneous requests)
python tools/long-password-dos/long_password_dos.py \
    -u https://target.com/login \
    --concurrent 10
```

## What Makes a Good Finding

| Indicator | Minimum for Report |
|-----------|-------------------|
| **Response time increase** | Normal: <500ms → Long password: >5s |
| **Server error** | 500 Internal Server Error or timeout |
| **Memory spike** | If you can observe server memory (unlikely from outside) |
| **Other users affected** | Concurrent normal requests also slow down |
| **Reproducible** | Works consistently, not just a one-time slowdown |

## Escalation

| Technique | Description |
|-----------|------------|
| **Concurrent requests** | Send 20 simultaneous long-password requests → multiply the CPU load |
| **Multiple endpoints** | Hit login + register + change-password simultaneously |
| **Combine with rate-limit bypass** | If there's no rate limiting, the impact is worse |
| **Resource exhaustion** | Show that N requests can max out server CPU |

## Bug Report Template

```markdown
**Title:** Long Password Denial of Service on [target.com] Login Endpoint

**Severity:** Low-Medium (P3-P4)

**Description:**
The login endpoint at [URL] does not impose a maximum password length.
When a very long password (>100KB) is submitted, the server takes an
abnormally long time to respond, indicating excessive CPU consumption
during password hashing. Multiple concurrent requests with long
passwords can degrade service for all users.

**Steps to Reproduce:**
1. Navigate to [login-URL]
2. Submit a normal login request → observe response time (~200ms)
3. Submit the same request with a 100,000-character password:
   `python3 -c "print('A' * 100000)"` as the password
4. Observe response time: [X seconds] (expected: <500ms)
5. Submit 10 concurrent requests with 1MB passwords
6. Observe: Server response time degrades for all requests

**Response Time Comparison:**
| Password Length | Response Time |
|----------------|---------------|
| 8 chars (normal) | 200ms |
| 10,000 chars | [X]ms |
| 100,000 chars | [X]ms |
| 1,000,000 chars | [X]ms |

**Impact:**
An attacker can degrade or deny service to legitimate users by
sending concurrent requests with extremely long passwords,
consuming excessive server CPU during password hashing.

**Remediation:**
1. Implement a maximum password length (128-256 characters is reasonable)
2. Reject passwords exceeding the limit BEFORE hashing
3. Add rate limiting on authentication endpoints
4. Use request body size limits at the web server/load balancer level
```

---

---

# 📋 Master Checklist — Low-Hanging Fruit Hunt

Use this checklist when testing any new target:

```
☐ BROKEN LINK HIJACKING
  ☐ Run BLH tool: python tools/broken-link-hijacker/blh.py -u <target> -d 3
  ☐ Check BLH HTML report for claimable links
  ☐ Verify dead links are actually claimable
  ☐ Check if any dead links load JS/CSS (critical escalation)

☐ MISSING SPF RECORD
  ☐ Run: python tools/spf-checker/spf_checker.py -d <target>
  ☐ Check SPF record (-all vs ~all vs ?all vs missing)
  ☐ Check DMARC record (p=reject vs p=none vs missing)
  ☐ Send spoofed test email to YOUR inbox as PoC

☐ ORIGIN IP DISCLOSURE
  ☐ Run: python tools/origin-ip-finder/origin_ip_finder.py -d <target>
  ☐ Check DNS history (SecurityTrails, ViewDNS)
  ☐ Check subdomains for non-CDN IPs
  ☐ Check email headers for origin IP
  ☐ Verify: curl -H "Host: target.com" http://<found-ip>/

☐ SESSION NOT EXPIRING AFTER LOGOUT
  ☐ Login → capture session token
  ☐ Capture an authenticated request in Burp Repeater
  ☐ Logout → replay the request
  ☐ Check: does the old session still work?
  ☐ Run: python tools/session-tester/session_logout_tester.py -u <target>

☐ LONG PASSWORD DOS
  ☐ Find login/register/change-password endpoints
  ☐ Run: python tools/long-password-dos/long_password_dos.py -u <login-url>
  ☐ Compare response times: normal vs 100KB vs 1MB password
  ☐ Test concurrent requests for amplified impact
```

---

> **Built by Vishal** — Low-Hanging Fruits Playbook
> _"You don't need a zero-day to earn bounties. You just need to check what everyone else forgot."_
