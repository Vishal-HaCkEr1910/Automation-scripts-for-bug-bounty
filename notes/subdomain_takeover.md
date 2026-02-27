# 🌐 Subdomain Takeover — The Complete Bug Hunter's Playbook

> **From Dangling DNS to Critical Takeovers — One of Bug Bounty's Easiest P1s**
> CNAME · NS · A Record · MX · S3 · Azure · GitHub Pages · Heroku · Shopify · Fastly
> DNS Mechanics | Fingerprinting | Exploitation | Automation | Real Case Studies
> Author: **Vishal** | For **authorized penetration testing only**

---

## ⚠️ Legal Disclaimer

> This guide is intended **exclusively for security professionals** and **authorized bug bounty hunters**.
> Claiming a subdomain that does not belong to you or your authorized scope **is illegal** and constitutes unauthorized access.
> Always verify the subdomain is **in scope** of a bug bounty program or you have **explicit written permission** from the domain owner.
> The author accepts **no liability** for misuse of the techniques described herein.

---

## 📋 Table of Contents

### PART A — Foundations & Theory
1. [What is Subdomain Takeover — Really?](#1--what-is-subdomain-takeover--really)
2. [DNS Deep Dive — How Subdomains Resolve](#2--dns-deep-dive--how-subdomains-resolve)
3. [Why Subdomains Get Abandoned — Root Causes](#3--why-subdomains-get-abandoned--root-causes)
4. [The Impact — Why This is Almost Always P1/Critical](#4--the-impact--why-this-is-almost-always-p1critical)
5. [Taxonomy — All Types of Subdomain Takeover](#5--taxonomy--all-types-of-subdomain-takeover)

### PART B — Reconnaissance & Discovery
6. [Subdomain Enumeration — Passive Techniques](#6--subdomain-enumeration--passive-techniques)
7. [Subdomain Enumeration — Active Techniques](#7--subdomain-enumeration--active-techniques)
8. [DNS Record Analysis — Finding Dangling Records](#8--dns-record-analysis--finding-dangling-records)
9. [Fingerprinting Vulnerable Services](#9--fingerprinting-vulnerable-services)
10. [Tool Arsenal — Complete Setup Guide](#10--tool-arsenal--complete-setup-guide)

### PART C — Exploitation by Service
11. [GitHub Pages Takeover](#11--github-pages-takeover)
12. [AWS S3 Bucket Takeover](#12--aws-s3-bucket-takeover)
13. [Azure Services Takeover](#13--azure-services-takeover)
14. [Heroku Takeover](#14--heroku-takeover)
15. [Shopify, Fastly, Pantheon, Surge & Others](#15--shopify-fastly-pantheon-surge--others)
16. [NS Delegation Takeover — The Nuclear Option](#16--ns-delegation-takeover--the-nuclear-option)
17. [MX Record Takeover — Email Hijacking](#17--mx-record-takeover--email-hijacking)
18. [Elastic Beanstalk & Cloud-Specific Takeovers](#18--elastic-beanstalk--cloud-specific-takeovers)

### PART D — Advanced Techniques
19. [Second-Order Subdomain Takeover](#19--second-order-subdomain-takeover)
20. [Race Condition Takeovers](#20--race-condition-takeovers)
21. [Same-Origin Policy Abuse via Takeover](#21--same-origin-policy-abuse-via-takeover)
22. [Cookie Stealing via Subdomain Takeover](#22--cookie-stealing-via-subdomain-takeover)
23. [Chaining Subdomain Takeover with Other Vulns](#23--chaining-subdomain-takeover-with-other-vulns)

### PART E — Automation, Reporting & Resources
24. [Python Subdomain Takeover Scanner](#24--python-subdomain-takeover-scanner)
25. [Bash Automation Pipeline](#25--bash-automation-pipeline)
26. [Bug Bounty Report Template](#26--bug-bounty-report-template)
27. [5 Real-World Case Studies ($500–$20K)](#27--5-real-world-case-studies-50020k)
28. [Complete Hunting Checklist](#28--complete-hunting-checklist)
29. [Resources & Further Learning](#29--resources--further-learning)

---

# PART A

# PART B

# PART C

# PART D

# PART E

---

> **Built by Vishal** — Subdomain Takeover Complete Playbook
> *"Every abandoned subdomain is a door left wide open. Your job is to find it before the attackers do."*
