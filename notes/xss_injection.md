# 🎯 XSS Injection — The Complete Bug Hunter's Playbook

> **From First `<script>alert(1)</script>` to $50K Bounties**
> Reflected · Stored · DOM · Blind · Mutation · Universal XSS
> Context-Aware Payloads | Filter Bypass Encyclopedia | WAF Evasion | CSP Defeat
> Real PoCs | Chaining to ATO | Report Writing | Automation
> Author: **Vishal** | For **authorized penetration testing only**

---

## ⚠️ Legal Disclaimer

> This guide is intended **exclusively for security professionals** and **authorized bug bounty hunters**.
> Testing any system without **explicit written permission** is **illegal** under the Computer Fraud and Abuse Act (CFAA), IT Act 2000 (India), and similar laws worldwide.
> The author accepts **no liability** for misuse of the techniques described herein.
> **Always** obtain written authorization before testing. Respect scope. Respect privacy.

---

## 📋 Table of Contents

### PART A — Foundations & Theory
1. [What is XSS — Really?](#1--what-is-xss--really)
2. [The Browser Trust Model — Why XSS Works](#2--the-browser-trust-model--why-xss-works)
3. [XSS Taxonomy — All 7 Types Explained](#3--xss-taxonomy--all-7-types-explained)
4. [Injection Contexts — The Key to Everything](#4--injection-contexts--the-key-to-everything)
5. [Encoding Deep Dive — HTML, URL, JS, Unicode](#5--encoding-deep-dive--html-url-js-unicode)

### PART B — Hunting Methodology
6. [Attack Surface Mapping for XSS](#6--attack-surface-mapping-for-xss)
7. [Tool Setup — Burp Suite, Browser DevTools, Extensions](#7--tool-setup--burp-suite-browser-devtools-extensions)
8. [The 10-Phase XSS Hunting Methodology](#8--the-10-phase-xss-hunting-methodology)
9. [Reflected XSS — Complete Hunting Guide](#9--reflected-xss--complete-hunting-guide)
10. [Stored XSS — Complete Hunting Guide](#10--stored-xss--complete-hunting-guide)
11. [DOM XSS — Complete Hunting Guide](#11--dom-xss--complete-hunting-guide)
12. [Blind XSS — Complete Hunting Guide](#12--blind-xss--complete-hunting-guide)

### PART C — Bypass & Evasion
13. [50 Filter Bypass Techniques](#13--50-filter-bypass-techniques)
14. [WAF Evasion — Cloudflare, Akamai, Imperva, AWS WAF](#14--waf-evasion--cloudflare-akamai-imperva-aws-waf)
15. [CSP Bypass — From Strict to Defeated](#15--csp-bypass--from-strict-to-defeated)
16. [HttpOnly / Secure Flag Bypass Strategies](#16--httponly--secure-flag-bypass-strategies)
17. [Mutation XSS (mXSS) — Browser Parser Tricks](#17--mutation-xss-mxss--browser-parser-tricks)

### PART D — Exploitation & Impact
18. [Cookie Theft & Session Hijacking](#18--cookie-theft--session-hijacking)
19. [Keylogging, Phishing, Clipboard Hijack via XSS](#19--keylogging-phishing-clipboard-hijack-via-xss)
20. [XSS to Account Takeover — Full Chain](#20--xss-to-account-takeover--full-chain)
21. [XSS Worm Construction](#21--xss-worm-construction)
22. [Chaining XSS with Other Vulns (CSRF, IDOR, SSRF)](#22--chaining-xss-with-other-vulns-csrf-idor-ssrf)

### PART E — Advanced & Modern
23. [XSS in Modern Frameworks — React, Angular, Vue](#23--xss-in-modern-frameworks--react-angular-vue)
24. [XSS in APIs — JSON, GraphQL, WebSocket](#24--xss-in-apis--json-graphql-websocket)
25. [XSS in Mobile WebViews](#25--xss-in-mobile-webviews)
26. [Prototype Pollution to XSS](#26--prototype-pollution-to-xss)
27. [PostMessage XSS & Window Reference Attacks](#27--postmessage-xss--window-reference-attacks)

### PART F — Automation, Reporting & Resources
28. [Python XSS Scanner Script](#28--python-xss-scanner-script)
29. [Bash One-Liners & Recon Pipelines](#29--bash-one-liners--recon-pipelines)
30. [Bug Bounty Report Template](#30--bug-bounty-report-template)
31. [5 Real-World Case Studies ($5K–$50K)](#31--5-real-world-case-studies-5k50k)
32. [Complete Hunting Checklist](#32--complete-hunting-checklist)
33. [Resources & Further Learning](#33--resources--further-learning)

---

# PART A

# PART B

# PART C

# PART D

# PART E

# PART F

---

> **Built by Vishal** — XSS Injection Complete Playbook
> *"Every input is a door. Every reflection is an opportunity. Every filter is a puzzle."*
