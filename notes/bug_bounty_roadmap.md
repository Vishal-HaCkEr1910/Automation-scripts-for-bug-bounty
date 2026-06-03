# 🎯 Bug Bounty Roadmap: $1000 Target
### From Zero Revision to First Bounty — 3-Part Daily Schedule

> **Your Starting Point:** Already read *Real World Bug Bounty* + 3–4 PortSwigger Labs topics.  
> **Your Revision Book:** *Bug Bounty Bootcamp* by Vickie Li  
> **Goal:** $1,000 in bounties | Structured, step-by-step, no fluff.

---

## 📚 MASTER RESOURCE LIST (Read Before Anything Else)

### Books (Your Core Curriculum)
| Book | Purpose |
|------|---------|
| *Bug Bounty Bootcamp* – Vickie Li | Primary revision guide (you own this) |
| *Real World Bug Hunting* – Peter Yaworski | Case studies & recon mindset (you own this) |
| *The Web Application Hacker's Handbook* – Stuttard & Pinto | Deep technical reference |
| *Hacking: The Art of Exploitation* – Jon Erickson | Low-level fundamentals |

### Free Online Learning
| Resource | Link | What You Get |
|----------|------|-------------|
| PortSwigger Web Academy | https://portswigger.net/web-security | Labs for every vuln class |
| HackTricks | https://book.hacktricks.xyz | Cheatsheets & methodology |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings | Payload lists for every attack |
| OWASP Testing Guide | https://owasp.org/www-project-web-security-testing-guide/ | Industry-standard methodology |
| PentesterLand | https://pentester.land/writeups | Real bug bounty writeups |
| NahamSec Blog | https://www.nahamsec.com | Tips from top hunters |
| Jason Haddix (h1 talks) | https://github.com/jhaddix | Bug bounty methodology docs |

### Practice Platforms (In Order of Use)
| Platform | When to Use |
|----------|------------|
| PortSwigger Labs | Part 1 — skill revision |
| HackTheBox / TryHackMe | Part 1 — warm-up boxes |
| OWASP WebGoat / DVWA | Part 1 — local safe testing |
| HackerOne / Bugcrowd (public programs) | Part 2 & 3 — real targets |
| Intigriti | Part 3 — higher payouts |
| Synack / Cobalt (invite-only) | Future — after first bounty |

### Tools to Have Ready (Install Day 1)
```
Burp Suite Community/Pro    → Main proxy & scanner
ffuf / feroxbuster          → Directory & parameter fuzzing
nmap / masscan              → Port scanning
amass / subfinder           → Subdomain enumeration
httpx                       → HTTP probing
nuclei                      → Automated vuln templates
waybackurls / gau           → URL discovery
gf (tomnomnom)              → Pattern grep
sqlmap                      → SQL injection automation
dalfox                      → XSS automation
```

---

## 🗺️ THE 3-PART ROADMAP

---

## PART 1 — REVISION & FOUNDATIONS
### Duration: 7–10 Days | Goal: Revise all core vuln classes + methodology

> Re-read *Bug Bounty Bootcamp* chapter by chapter.  
> Pair each chapter with the matching PortSwigger lab.  
> No real targets yet — build muscle memory first.

---

### Day 1 — Setup & Recon Fundamentals

**Morning (2–3 hrs) — Environment Setup**
- [ ] Install and configure Burp Suite (set up browser proxy)
- [ ] Install: ffuf, amass, subfinder, httpx, nuclei, waybackurls, gf
- [ ] Set up DVWA locally (Docker: `docker run -d -p 80:80 vulnerables/web-dvwa`)
- [ ] Create accounts: HackerOne, Bugcrowd, PortSwigger
- [ ] Bookmark all resources from the master list above

**Afternoon (2–3 hrs) — Recon Theory**
- [ ] Read *Bug Bounty Bootcamp* — Chapter on Recon
- [ ] Read *Real World Bug Hunting* — Recon chapter recap
- [ ] Study: subdomain enumeration, Google dorks, Shodan, Censys
- [ ] Watch: NahamSec's live recon on YouTube (any recent stream)

**Evening (1 hr) — Hands-On**
- [ ] Run amass + subfinder on a dummy target (e.g., tesla.com scope)
- [ ] Practice Google dorks: `site:target.com filetype:pdf`, `site:target.com inurl:admin`
- [ ] Note your recon methodology in your own notes file

**Today's Key Concepts:**
- Passive vs active recon
- DNS enumeration, certificate transparency logs (crt.sh)
- JS file analysis for endpoints (linkfinder, secretfinder)

---

### Day 2 — XSS (Cross-Site Scripting)

**Morning — Theory Revision**
- [ ] *Bug Bounty Bootcamp* — XSS chapter (read fully, take notes)
- [ ] Review: reflected, stored, DOM-based XSS
- [ ] Study filter bypass techniques and polyglots

**Afternoon — PortSwigger Labs (XSS)**
- [ ] Lab: Reflected XSS into HTML context
- [ ] Lab: Stored XSS into HTML context
- [ ] Lab: DOM XSS using `document.write` sink
- [ ] Lab: XSS into attribute with angle brackets HTML-encoded
- [ ] Lab: XSS with event handlers and href attributes

**Evening — Tools & Automation**
- [ ] Learn dalfox basics: `dalfox url "http://target.com/search?q=TEST"`
- [ ] Study: CSP bypass techniques
- [ ] Review 3 XSS writeups on PentesterLand

**Today's Key Concepts:**
- XSS context (HTML, JS, attribute, URL)
- CSP bypass, dangling markup
- Impact: session hijack, keylogging, phishing

---

### Day 3 — SQLi (SQL Injection)

**Morning — Theory Revision**
- [ ] *Bug Bounty Bootcamp* — SQLi chapter
- [ ] Types: classic, blind boolean, blind time-based, error-based, OOB
- [ ] Study UNION-based extraction technique

**Afternoon — PortSwigger Labs (SQLi)**
- [ ] Lab: SQL injection WHERE clause (string)
- [ ] Lab: SQL injection UNION attack (number of columns)
- [ ] Lab: SQL injection UNION attack (finding text column)
- [ ] Lab: Blind SQL injection with conditional responses
- [ ] Lab: Blind SQL injection with time delays

**Evening — Tools**
- [ ] Practice sqlmap: `sqlmap -u "URL?id=1" --dbs`
- [ ] Learn manual testing approach (never rely on tools in bug bounty)
- [ ] Review 2 SQLi writeups from PentesterLand or HackerOne Hacktivity

**Today's Key Concepts:**
- WAF bypass techniques
- Second-order SQLi
- NoSQL injection (MongoDB `$where`, `$regex`)

---

### Day 4 — CSRF, SSRF & XXE

**Morning — Theory Revision**
- [ ] *Bug Bounty Bootcamp* — CSRF chapter
- [ ] *Bug Bounty Bootcamp* — SSRF chapter
- [ ] Study: CSRF token bypass techniques, SameSite cookies

**Afternoon — PortSwigger Labs**
- [ ] CSRF Lab: CSRF vulnerability with no defenses
- [ ] CSRF Lab: CSRF where token validation depends on request method
- [ ] SSRF Lab: Basic SSRF against the local server
- [ ] SSRF Lab: SSRF with blacklist-based input filter
- [ ] XXE Lab: Exploiting XXE using external entities

**Evening — Deep Dive**
- [ ] Study blind SSRF (use Burp Collaborator / interactsh)
- [ ] Study SSRF → internal service pivot methodology
- [ ] Read 2 SSRF writeups (these are high-paying bugs!)

**Today's Key Concepts:**
- CSRF: origin vs referer checks, pre-flight bypass
- SSRF: cloud metadata endpoints (169.254.169.254, IMDSv2)
- XXE: file read, SSRF via XXE, OOB XXE

---

### Day 5 — Authentication & Session Bugs

**Morning — Theory Revision**
- [ ] *Bug Bounty Bootcamp* — Authentication chapter
- [ ] Topics: broken login logic, password reset flaws, 2FA bypass
- [ ] Study: JWT attacks (none algorithm, key confusion)

**Afternoon — PortSwigger Labs**
- [ ] Lab: Username enumeration via different responses
- [ ] Lab: Broken brute-force protection (IP block bypass)
- [ ] Lab: 2FA simple bypass
- [ ] Lab: JWT authentication bypass via unverified signature
- [ ] Lab: JWT none algorithm bypass

**Evening — Practical Focus**
- [ ] Study: OAuth 2.0 flaws (state parameter, open redirect abuse)
- [ ] Review: password reset poisoning (host header injection)
- [ ] Read 2 auth bug writeups

**Today's Key Concepts:**
- Account takeover = highest impact auth bug
- Token predictability, insecure direct object reference in reset flows
- Remember: session fixation, cookie flags (HttpOnly, Secure, SameSite)

---

### Day 6 — IDOR & Access Control

**Morning — Theory Revision**
- [ ] *Bug Bounty Bootcamp* — IDOR chapter
- [ ] *Bug Bounty Bootcamp* — Broken Access Control chapter
- [ ] Types: horizontal privilege escalation, vertical escalation

**Afternoon — PortSwigger Labs**
- [ ] Lab: IDOR with direct reference to database object
- [ ] Lab: IDOR with unpredictable IDs (GUIDs)
- [ ] Lab: Referer-based access control
- [ ] Lab: URL-based access control can be circumvented

**Evening — Hunt Strategy**
- [ ] Study: finding IDORs in API endpoints (v1, v2 paths)
- [ ] Practice: change numeric IDs, UUIDs, email references in requests
- [ ] Read 3 IDOR writeups — this is the #1 most reported bug class

**Today's Key Concepts:**
- Always test: view, edit, delete, export functions for IDOR
- API versioning: older versions often lack authorization checks
- Parameter pollution, mass assignment

---

### Day 7 — Open Redirect, CORS, Subdomain Takeover

**Morning — Theory Revision**
- [ ] *Bug Bounty Bootcamp* — Open Redirect chapter
- [ ] Study: CORS misconfiguration (null origin, wildcard with credentials)
- [ ] Study: Subdomain takeover (dangling DNS, unclaimed cloud services)

**Afternoon — Labs & Practice**
- [ ] PortSwigger CORS Lab: Basic CORS vulnerability
- [ ] PortSwigger CORS Lab: CORS with trusted null origin
- [ ] Practice open redirect in Burp: look for `?redirect=`, `?next=`, `?url=`
- [ ] Run: `subjack -w subdomains.txt -t 100 -o results.txt` on a test scope

**Evening — Takeover Focus**
- [ ] Study: services vulnerable to subdomain takeover (GitHub Pages, Heroku, Netlify, AWS S3)
- [ ] Tool: subzy, can-i-take-over-xyz (GitHub resource list)
- [ ] Review 2 subdomain takeover writeups

**Today's Key Concepts:**
- Open redirect → chained with OAuth, SSRF, phishing
- CORS: only impactful if `Access-Control-Allow-Credentials: true`
- Subdomain takeover = easy P2/P3, good for first bounty

---

### Day 8 — HTTP Request Smuggling & Business Logic

**Morning — Theory Revision**
- [ ] *Bug Bounty Bootcamp* — Business Logic chapter
- [ ] PortSwigger HTTP Smuggling intro article (read, don't lab yet)
- [ ] Study: race conditions, workflow bypass, price manipulation

**Afternoon — Labs**
- [ ] Lab: Excessive trust in client-side controls (price tampering)
- [ ] Lab: High-level logic vulnerability
- [ ] Lab: Insufficient workflow validation
- [ ] Lab: Authentication bypass via flawed state machine

**Evening**
- [ ] Study: HTTP smuggling CL.TE vs TE.CL
- [ ] Burp extension: HTTP Request Smuggler
- [ ] Read 2 business logic bug writeups — these pay well and are rare

**Today's Key Concepts:**
- Business logic = understanding the app's intent, then breaking it
- Race conditions: concurrent requests on limited-use functions (promo codes, transfers)
- Negative values, integer overflow, skipping workflow steps

---

### Day 9 — Recon Deep Dive & Methodology Finalization

**Morning — Advanced Recon**
- [ ] Study: JS file hunting for API keys, endpoints, tokens
- [ ] Tools: LinkFinder, SecretFinder, truffleHog
- [ ] Google dorks mastery: `inurl:api_key site:`, `ext:env`, `ext:log`

**Afternoon — Build Your Own Methodology**
- [ ] Write out your personal bug hunting checklist (see template below)
- [ ] Set up your notes system (Obsidian, Notion, or plain markdown)
- [ ] Practice a full recon flow on a public program's scope in a notes-only mode

**Evening — Review**
- [ ] Go back to any PortSwigger labs you found difficult
- [ ] Re-read the most important chapters from *Bug Bounty Bootcamp*
- [ ] Prepare your Burp Suite extensions: Logger++, Turbo Intruder, Autorize

**Bug Hunting Checklist Template:**
```
TARGET: ___________
DATE:   ___________

[ ] Subdomain enumeration (amass, subfinder, crt.sh)
[ ] Port scan (nmap -sV top 1000)
[ ] Directory brute force (ffuf)
[ ] JS file analysis (LinkFinder)
[ ] Parameter discovery (arjun, x8)
[ ] Check login flows for auth bugs
[ ] Check all forms for XSS, SQLi
[ ] Check file uploads
[ ] Check API endpoints for IDOR
[ ] Check CORS headers
[ ] Check CSRF on state-changing requests
[ ] Check for open redirects (?next=, ?url=)
[ ] Check subdomains for takeover
[ ] Check S3 buckets
```

---

### Day 10 — Part 1 Review & Transition

**Full Day — Consolidation**
- [ ] Review all notes from Days 1–9
- [ ] Redo any labs you failed or partially completed
- [ ] Complete the PortSwigger "All labs" checklist for: XSS, SQLi, SSRF, Auth, IDOR
- [ ] Read: Jason Haddix's "The Bug Hunter's Methodology" (GitHub)
- [ ] Read: NahamSec's bug bounty guide
- [ ] Set up: Burp Suite project for your first real target (next part)

**Part 1 Exit Criteria (don't move on until you can answer YES to all):**
- [ ] Can you find and exploit all XSS types manually?
- [ ] Can you perform UNION-based SQLi without sqlmap?
- [ ] Can you identify and exploit IDOR in API responses?
- [ ] Can you set up SSRF to hit internal services or metadata?
- [ ] Do you have a personal hunting methodology written down?
- [ ] Is your Burp Suite configured with all key extensions?

---

## PART 2 — FIRST REAL TARGETS
### Duration: 10–14 Days | Goal: Submit 5–10 reports, get your first valid finding

> Start with public programs. Hunt easy-win bug classes first.  
> Focus: IDOR, XSS, Open Redirect, Subdomain Takeover, Information Disclosure  
> Build report-writing skills. Every submission counts.

---

### Week 1 of Part 2 — Picking Your Targets & Easy Wins

**Day 11–12: Choose Programs Wisely**

Criteria for your first target:
- [ ] **Large scope** (wildcard `*.target.com` preferred)
- [ ] **Low competition** (newer programs or less popular ones)
- [ ] **Accepts all bug classes** (not just critical only)
- [ ] **Active response** (last response < 30 days ago on HackerOne)

Recommended first programs (all on HackerOne public programs):
- Programs with large scopes in fintech, SaaS, e-commerce
- Look for programs with many resolved reports (they pay!) and moderate duplication rates

**Day 11–12 Actions:**
- [ ] Pick 2–3 programs from HackerOne/Bugcrowd public programs
- [ ] Read their entire policy, scope list, and out-of-scope rules
- [ ] Read their previously disclosed reports (go to hackerone.com/hacktivity)
- [ ] Set up a notes folder for each target

---

**Day 13–15: Hunt — Phase 1 (Recon)**

Full recon on your chosen target:
```bash
# Subdomain enum
subfinder -d target.com -o subs.txt
amass enum -d target.com >> subs.txt
sort -u subs.txt > final_subs.txt

# HTTP probe
cat final_subs.txt | httpx -o live_subs.txt

# Subdomain takeover check
subzy run --targets live_subs.txt

# Directory brute force on interesting subdomains
ffuf -w /usr/share/wordlists/dirb/big.txt -u https://sub.target.com/FUZZ

# JS file discovery
cat live_subs.txt | waybackurls | grep "\.js$" | sort -u > jsfiles.txt
```

What to look for immediately:
- [ ] Subdomains resolving to unclaimed services → subdomain takeover
- [ ] Admin panels on non-standard subdomains
- [ ] Dev/staging environments (`dev.`, `staging.`, `test.`, `beta.`)
- [ ] S3 buckets, Azure blobs in JS files
- [ ] API keys/tokens in JS files

---

**Day 16–17: Hunt — Phase 2 (Manual Testing)**

Focus on high-value low-hanging fruit:
- [ ] Test all login/signup flows for auth issues
- [ ] Test all `?redirect=`, `?next=`, `?url=` params for open redirect
- [ ] Test all API endpoints for IDOR (change IDs, swap tokens)
- [ ] Test CORS on authenticated endpoints
- [ ] Test file upload features for unrestricted upload, path traversal
- [ ] Test search/filter fields for XSS, SQLi

Burp Suite workflow:
```
1. Spider/crawl target with Burp
2. Review all requests in HTTP history
3. Send interesting requests to Repeater
4. Test for each vuln class manually
5. Use Turbo Intruder for parameter brute force
6. Use Autorize extension for auth testing
```

---

**Day 18–19: Write Your First Reports**

Report structure that gets paid:
```markdown
## Summary
One-paragraph description of the vulnerability, impact, and what an attacker can do.

## Vulnerability Details
- Type: [XSS / IDOR / SSRF / etc.]
- Endpoint: https://target.com/api/endpoint
- Parameter: id, user_id, redirect, etc.
- Severity: [Critical / High / Medium / Low]

## Steps to Reproduce
1. Log in as User A at https://target.com/login
2. Navigate to https://target.com/profile?id=123
3. Change the id parameter to 456 (another user's ID)
4. Observe that User B's private data is returned

## Proof of Concept
[Attach screenshots, HTTP requests/responses, video if complex]

## Impact
An attacker can [specific action] which results in [specific harm].
This affects [all users / admin accounts / data type].

## Suggested Fix
Validate that the authenticated user has authorization to access 
the requested resource before returning any data.
```

Tips:
- [ ] Always include a PoC (screenshot or screen recording for complex bugs)
- [ ] Be specific about impact — programs pay more when impact is clear
- [ ] Never exaggerate severity — triage teams will downgrade you anyway
- [ ] Mention CVSS score if you know it

---

**Day 20–21: Review, Resubmit, Learn**

- [ ] Wait for triage responses
- [ ] If duplicate: analyze what you missed, study the disclosed report
- [ ] If informative/N/A: ask politely for clarification and learn why
- [ ] If valid: celebrate, then keep hunting the same scope (you know it well now)
- [ ] Start hunting your second target while waiting for responses

**Mindset for Part 2:**
- Expect your first 5–10 reports to get N/A or duplicate
- Every N/A is a free lesson
- Duplication means you found a real bug — just slower
- First valid report = proof your skills work

---

## PART 3 — SCALING TO $1,000
### Duration: 2–4 Weeks | Goal: Chain bugs, escalate severity, hit the $1,000 target

> Now you know your programs. You know what they pay.  
> Focus: Higher severity bugs, bug chaining, private programs, efficiency.

---

### Week 1 of Part 3 — Escalation & Chaining

**Days 22–25: Learn to Chain Bugs**

Individual bugs become critical when chained. Study these combos:

| Chain | Result | Typical Payout |
|-------|--------|---------------|
| Open Redirect + OAuth | Account Takeover | $500–$5,000 |
| SSRF + Cloud Metadata | RCE/Full Compromise | $2,000–$10,000 |
| XSS + CSRF bypass | Account Takeover | $500–$2,000 |
| IDOR + PII Access | Data Breach | $500–$5,000 |
| Subdomain Takeover + Cookie Scope | Session Hijack | $500–$2,000 |
| XXE + SSRF | Internal Network Access | $1,000–$5,000 |

Actions:
- [ ] Review your previous findings — can any be chained?
- [ ] Study: open redirect → OAuth token stealing methodology
- [ ] Study: XSS → cookie theft → account takeover proof
- [ ] Read 5 chaining writeups from PentesterLand this week

---

**Days 26–28: Target Higher-Paying Programs**

Upgrade your program selection:
- [ ] Apply for **private programs** on HackerOne (programs invite top hunters)
- [ ] Check Intigriti for EU-based programs (often higher payouts)
- [ ] Focus on fintech, healthcare, crypto programs (highest payouts per severity)
- [ ] Look for programs with: $500+ average payout, < 10% duplicate rate

Payout reference by severity:
| Severity | CVSS | Typical Payout |
|----------|------|---------------|
| Informational | N/A | $0 |
| Low | 0.1–3.9 | $50–$150 |
| Medium | 4.0–6.9 | $150–$500 |
| High | 7.0–8.9 | $500–$2,000 |
| Critical | 9.0–10.0 | $2,000–$50,000+ |

**To hit $1,000 you need ONE of:**
- 1x Critical or High bug ($500–$1,000+)
- 2x Medium bugs ($300–$500 each)
- 1x High + 1x Low (combo)

---

**Days 29–32: Deep Dive on Your Best Programs**

You now know these programs' tech stack. Go deeper:
- [ ] Map all API endpoints (v1, v2, internal, mobile API)
- [ ] Look at their tech stack via Wappalyzer, HTTP headers
- [ ] Search GitHub for their repos, leaked keys, old endpoints
- [ ] Look at their mobile app (APKTool for Android, check iOS via Burp)
- [ ] Check their third-party integrations (OAuth providers, payment gateways)
- [ ] Test GraphQL introspection if applicable
- [ ] Look for race conditions on high-value features (payments, promotions)

Advanced techniques to try:
```
- HTTP Request Smuggling (Burp's HTTP Smuggler extension)
- Web Cache Poisoning (X-Forwarded-Host, X-Original-URL)
- Host Header Injection (password reset poisoning)
- Parameter Pollution (HPP on auth flows)
- GraphQL batching attacks
- JSON injection in SOAP/REST endpoints
- Template injection (SSTI in Jinja2, Twig, FreeMarker)
```

---

**Days 33–35: Final Push to $1,000**

- [ ] Prioritize any open reports awaiting triage response
- [ ] Follow up politely on reports older than 14 days
- [ ] Review disclosed reports from your target programs this month
- [ ] Hunt the exact type of bug they just fixed (often there are variants nearby)
- [ ] Try mobile app testing (Burp + Android emulator)
- [ ] Look at the program's changelog/release notes for new features

Approach for fast, high-impact finds:
1. New feature = new attack surface = less time to harden
2. API endpoints added in the last 3–6 months (waybackurls comparison)
3. Third-party integrations (webhooks, OAuth, payment) often have auth issues

---

## 📊 TRACKING YOUR PROGRESS

Use this table daily:

| Day | Target | Bug Type | Severity | Status | Payout |
|-----|--------|----------|----------|--------|--------|
| 11 | | | | Recon | — |
| 12 | | | | Recon | — |
| 13 | | | | Testing | — |
| ... | | | | | |

Running total: **$________ / $1,000**

---

## ⚠️ RULES YOU MUST NEVER BREAK

1. **Only test in-scope assets** — verify every subdomain/endpoint is in scope before testing
2. **Never use automated scanners aggressively** — rate limit all scans
3. **Never access/download user data** — stop at proof of concept
4. **Never test with real user accounts** — create test accounts
5. **Never test destructive payloads in production** — no `DROP TABLE`, no deletes
6. **Disclose only through the program's platform** — never public or social media
7. **If in doubt about scope** — email the program and ask first
8. **Keep all findings confidential** until disclosure is approved

---

## 🧠 MINDSET RULES

- Consistency beats intensity — 2 hours daily beats 14 hours on Sunday
- Document everything — your notes are your second brain
- Duplicates are free mentorship — analyze every one
- One good recon session > 10 random pokes at a target
- Specialize first — become the best at IDOR or XSS before trying everything
- Read 1 writeup per day — it's the fastest way to learn new techniques
- Your first valid bug will teach you more than 100 labs

---

## 📅 DAILY SCHEDULE TEMPLATE

```
07:00 – 07:30  Read one bug bounty writeup (PentesterLand / Hackerone Hacktivity)
07:30 – 09:00  PortSwigger lab (Part 1) OR active hunting (Part 2/3)
[Work / School break]
17:00 – 18:00  Theory reading (Bug Bounty Bootcamp chapter)
18:00 – 20:00  Active hunting or lab practice
20:00 – 20:30  Write up notes from today's session
20:30 – 21:00  Review program responses / submit reports
```

---

## 🎯 MILESTONE CHECKLIST

**Part 1 Complete when:**
- [ ] All core vuln classes revised (XSS, SQLi, SSRF, Auth, IDOR, CORS, CSRF)
- [ ] 25+ PortSwigger labs completed
- [ ] Personal methodology document written
- [ ] Burp Suite fully configured with extensions

**Part 2 Complete when:**
- [ ] 2+ programs selected and researched
- [ ] First 5 reports submitted
- [ ] At least 1 valid (non-N/A, non-duplicate) finding

**Part 3 Complete when:**
- [ ] $1,000 cumulative bounties received
- [ ] At least 1 High or Critical severity finding
- [ ] Applied to at least 1 private program

---

*Good luck. The $1,000 target is realistic within 6–10 weeks at this pace.*  
*The hunters who win are the ones who stay consistent and read one writeup every day.*
