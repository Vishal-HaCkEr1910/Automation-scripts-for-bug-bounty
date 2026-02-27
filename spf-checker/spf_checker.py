#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║              SPF / DMARC / DKIM Checker  v2.0.0                 ║
║          Email Security Misconfiguration Scanner                ║
║                                                                  ║
║  Author : Vishal Rao (@Vishal-HaCkEr1910)                      ║
║  License: MIT — For authorized security testing only            ║
╚══════════════════════════════════════════════════════════════════╝

Industry-standard email security scanner. Checks SPF (with recursive
include resolution & RFC 7208 10-lookup counting), DMARC (full tag
parsing), DKIM (50+ selectors with key analysis), BIMI, MX, and NS
records. Provides numeric risk scoring, spoofability verdicts, and
optional spoof PoC emails.

Usage:
    python spf_checker.py -d target.com
    python spf_checker.py -d target.com example.com --verbose
    python spf_checker.py -f domains.txt --quick-dkim
    python spf_checker.py -d target.com --spoof-test --from admin@target.com --to you@gmail.com
"""

import argparse
import dns.resolver
import json
import os
import re
import smtplib
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from email.mime.text import MIMEText
from typing import Optional

# ═══════════════════════════════════════════════════════════════
# COLOURS
# ═══════════════════════════════════════════════════════════════
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    R = Fore.RED; G = Fore.GREEN; Y = Fore.YELLOW; C = Fore.CYAN
    M = Fore.MAGENTA; W = Fore.WHITE; B = Style.BRIGHT; RST = Style.RESET_ALL
except ImportError:
    R = G = Y = C = M = W = B = RST = ""

BANNER = f"""{C}{B}
  ███████╗██████╗ ███████╗     ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗
  ██╔════╝██╔══██╗██╔════╝    ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝
  ███████╗██████╔╝█████╗      ██║     ███████║█████╗  ██║     █████╔╝
  ╚════██║██╔═══╝ ██╔══╝      ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗
  ███████║██║     ██║         ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗
  ╚══════╝╚═╝     ╚═╝          ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝
{RST}
  {Y}Email Security Misconfiguration Scanner v2.0.0{RST}
  {W}SPF · DMARC · DKIM · BIMI · MX · NS | Recursive Include Analysis{RST}
  {R}⚠  AUTHORIZED USE ONLY{RST}
"""


# ═══════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════
@dataclass
class SPFResult:
    record: Optional[str] = None
    exists: bool = False
    mechanism: str = "none"
    risk: str = "UNKNOWN"
    includes: list = field(default_factory=list)
    ip4s: list = field(default_factory=list)
    ip6s: list = field(default_factory=list)
    redirect: Optional[str] = None
    dns_lookup_count: int = 0
    too_many_lookups: bool = False
    void_lookups: int = 0
    include_tree: list = field(default_factory=list)
    warnings: list = field(default_factory=list)


@dataclass
class DMARCResult:
    record: Optional[str] = None
    exists: bool = False
    policy: str = "none"
    subdomain_policy: str = "none"
    pct: int = 100
    rua: Optional[str] = None
    ruf: Optional[str] = None
    adkim: str = "r"
    aspf: str = "r"
    fo: str = "0"
    ri: int = 86400
    risk: str = "UNKNOWN"
    warnings: list = field(default_factory=list)


@dataclass
class DKIMResult:
    exists: bool = False
    selectors_found: list = field(default_factory=list)
    selectors_missing: list = field(default_factory=list)
    key_details: list = field(default_factory=list)


@dataclass
class BIMIResult:
    exists: bool = False
    record: Optional[str] = None
    logo_url: Optional[str] = None
    vmc_url: Optional[str] = None


@dataclass
class DomainReport:
    domain: str = ""
    spf: SPFResult = field(default_factory=SPFResult)
    dmarc: DMARCResult = field(default_factory=DMARCResult)
    dkim: DKIMResult = field(default_factory=DKIMResult)
    bimi: BIMIResult = field(default_factory=BIMIResult)
    mx_records: list = field(default_factory=list)
    ns_records: list = field(default_factory=list)
    spoofable: bool = True
    risk_level: str = "UNKNOWN"
    risk_score: int = 0
    recommendations: list = field(default_factory=list)
    timestamp: str = ""
    scan_duration_s: float = 0.0


# ═══════════════════════════════════════════════════════════════
# DKIM SELECTORS
# ═══════════════════════════════════════════════════════════════
DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "k3",
    "mail", "smtp", "dkim", "s1", "s2", "s3", "sig1",
    "mandrill", "mailjet", "everlytickey1", "everlytickey2", "eversrv",
    "mxvault", "ses", "amazonses", "sendgrid", "sg1", "sg2",
    "cm", "sparkpost", "mailgun", "smtp2go", "smtpcom",
    "protonmail", "protonmail2", "protonmail3", "zoho",
    "postmark", "pm", "mailchimp", "mc",
    "zendesk", "zendesk1", "zendesk2", "turbo-smtp",
    "mimecast", "fm1", "fm2", "fm3",
    "dkim1", "dkim2", "email", "e1", "e2", "selector",
    "mx", "main", "krs", "global", "hs1", "hs2",
]

DKIM_SELECTORS_QUICK = [
    "default", "google", "selector1", "selector2", "k1",
    "mail", "smtp", "dkim", "s1", "s2", "mandrill",
    "ses", "sendgrid", "zoho", "mailgun"
]


# ═══════════════════════════════════════════════════════════════
# DNS HELPER
# ═══════════════════════════════════════════════════════════════
VERBOSE = False
DNS_TIMEOUT = 5.0


def dns_query(name: str, rdtype: str, timeout: float = None):
    timeout = timeout or DNS_TIMEOUT
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        answers = resolver.resolve(name, rdtype)
        return [str(rdata) for rdata in answers]
    except Exception:
        return []


def log_verbose(msg: str):
    if VERBOSE:
        print(f"    {W}[v] {msg}{RST}")


# ═══════════════════════════════════════════════════════════════
# SPF — RECURSIVE INCLUDE RESOLUTION (RFC 7208)
# ═══════════════════════════════════════════════════════════════
def resolve_spf_includes(domain: str, depth: int = 0, visited: set = None) -> tuple:
    """Recursively resolve SPF includes and count DNS lookups.
    RFC 7208: max 10 DNS mechanism lookups, max 2 void lookups."""
    if visited is None:
        visited = set()
    if domain in visited or depth > 10:
        return 0, 0, []
    visited.add(domain)

    lookups = 0
    void = 0
    tree = []

    txt_records = dns_query(domain, "TXT")
    spf_record = None
    for rec in txt_records:
        cleaned = rec.strip('"').strip("'")
        if cleaned.lower().startswith("v=spf1"):
            spf_record = cleaned
            break

    if not spf_record:
        void += 1
        return lookups, void, tree

    spf = spf_record.lower()

    # Each of these mechanisms triggers a DNS lookup (RFC 7208 §4.6.4)
    includes = re.findall(r'include:(\S+)', spf)
    a_mechs = re.findall(r'(?:^|\s)[+~?-]?a(?:[:/ ]|$)', spf)
    mx_mechs = re.findall(r'(?:^|\s)[+~?-]?mx(?:[:/ ]|$)', spf)
    ptr_mechs = re.findall(r'(?:^|\s)[+~?-]?ptr(?:[:/ ]|$)', spf)
    exists_mechs = re.findall(r'exists:(\S+)', spf)
    redirect = re.search(r'redirect=(\S+)', spf)

    lookups += len(includes) + len(a_mechs) + len(mx_mechs) + len(ptr_mechs) + len(exists_mechs)
    if redirect:
        lookups += 1

    for inc in includes:
        child_lookups, child_void, child_tree = resolve_spf_includes(inc, depth + 1, visited)
        lookups += child_lookups
        void += child_void
        tree.append({"domain": inc, "lookups": child_lookups, "children": child_tree})
        log_verbose(f"include:{inc} → +{child_lookups} lookups (depth {depth + 1})")

    return lookups, void, tree


def check_spf(domain: str) -> SPFResult:
    result = SPFResult()
    txt_records = dns_query(domain, "TXT")

    for rec in txt_records:
        cleaned = rec.strip('"').strip("'")
        if cleaned.lower().startswith("v=spf1"):
            result.record = cleaned
            result.exists = True
            break

    if not result.exists:
        result.risk = "HIGH"
        result.mechanism = "none"
        return result

    spf = result.record.lower()

    # Mechanism
    if "-all" in spf:
        result.mechanism = "-all"
        result.risk = "LOW"
    elif "~all" in spf:
        result.mechanism = "~all"
        result.risk = "MEDIUM"
    elif "?all" in spf:
        result.mechanism = "?all"
        result.risk = "HIGH"
    elif "+all" in spf:
        result.mechanism = "+all"
        result.risk = "CRITICAL"
    else:
        result.mechanism = "missing-all"
        result.risk = "HIGH"

    # Components
    result.includes = re.findall(r'include:(\S+)', spf)
    result.ip4s = re.findall(r'ip4:(\S+)', spf)
    result.ip6s = re.findall(r'ip6:(\S+)', spf)

    redirect_match = re.search(r'redirect=(\S+)', spf)
    if redirect_match:
        result.redirect = redirect_match.group(1)

    # Recursive DNS lookup count
    lookups, void, tree = resolve_spf_includes(domain)
    result.dns_lookup_count = lookups
    result.void_lookups = void
    result.include_tree = tree
    result.too_many_lookups = lookups > 10

    # Warnings
    if lookups > 10:
        result.warnings.append(f"SPF exceeds 10 DNS lookups ({lookups}) — RFC 7208 violation, will permerror")
    elif lookups > 7:
        result.warnings.append(f"SPF uses {lookups}/10 DNS lookups — nearing limit")
    if void > 2:
        result.warnings.append(f"SPF has {void} void lookups (max 2 recommended)")
    if result.mechanism == "+all":
        result.warnings.append("SPF +all allows ANY server to send — effectively zero protection")
    if result.redirect and result.includes:
        result.warnings.append("SPF has both 'include' and 'redirect' — redirect ignored per RFC 7208")
    if re.search(r'ptr(?:[:/ ]|$)', spf):
        result.warnings.append("SPF uses deprecated 'ptr' mechanism (RFC 7208 §5.5)")

    return result


# ═══════════════════════════════════════════════════════════════
# DMARC CHECK
# ═══════════════════════════════════════════════════════════════
def check_dmarc(domain: str) -> DMARCResult:
    result = DMARCResult()
    txt_records = dns_query(f"_dmarc.{domain}", "TXT")

    for rec in txt_records:
        cleaned = rec.strip('"').strip("'")
        if "v=dmarc1" in cleaned.lower():
            result.record = cleaned
            result.exists = True
            break

    if not result.exists:
        result.risk = "HIGH"
        return result

    dmarc = result.record.lower()

    # Policy
    p_match = re.search(r'p\s*=\s*(\w+)', dmarc)
    if p_match:
        result.policy = p_match.group(1)

    sp_match = re.search(r'sp\s*=\s*(\w+)', dmarc)
    if sp_match:
        result.subdomain_policy = sp_match.group(1)
    else:
        result.subdomain_policy = result.policy

    pct_match = re.search(r'pct\s*=\s*(\d+)', dmarc)
    if pct_match:
        result.pct = int(pct_match.group(1))

    rua_match = re.search(r'rua\s*=\s*([^;\s]+)', dmarc)
    if rua_match:
        result.rua = rua_match.group(1)
    ruf_match = re.search(r'ruf\s*=\s*([^;\s]+)', dmarc)
    if ruf_match:
        result.ruf = ruf_match.group(1)

    adkim_match = re.search(r'adkim\s*=\s*([rs])', dmarc)
    if adkim_match:
        result.adkim = adkim_match.group(1)
    aspf_match = re.search(r'aspf\s*=\s*([rs])', dmarc)
    if aspf_match:
        result.aspf = aspf_match.group(1)

    fo_match = re.search(r'fo\s*=\s*([^;\s]+)', dmarc)
    if fo_match:
        result.fo = fo_match.group(1)
    ri_match = re.search(r'ri\s*=\s*(\d+)', dmarc)
    if ri_match:
        result.ri = int(ri_match.group(1))

    # Risk
    if result.policy == "reject" and result.pct == 100:
        result.risk = "LOW"
    elif result.policy == "quarantine":
        result.risk = "MEDIUM"
    elif result.policy == "none":
        result.risk = "HIGH"
    else:
        result.risk = "MEDIUM"

    # Warnings
    if result.policy == "none":
        result.warnings.append("p=none only monitors — spoofed emails still delivered")
    if result.pct < 100:
        result.warnings.append(f"pct={result.pct} — only {result.pct}% of failing emails get the policy applied")
    if not result.rua:
        result.warnings.append("No rua= — you won't receive aggregate DMARC reports")
    if not result.ruf:
        result.warnings.append("No ruf= — you won't receive forensic failure reports")
    if result.subdomain_policy == "none" and result.policy != "none":
        result.warnings.append(f"sp=none — subdomains are unprotected even though p={result.policy}")

    return result


# ═══════════════════════════════════════════════════════════════
# DKIM CHECK
# ═══════════════════════════════════════════════════════════════
def check_dkim(domain: str, selectors: list = None) -> DKIMResult:
    result = DKIMResult()
    selectors = selectors or DKIM_SELECTORS

    for selector in selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        records = dns_query(dkim_domain, "TXT")
        if records:
            for rec in records:
                if "p=" in rec:
                    result.exists = True
                    result.selectors_found.append(selector)
                    key_info = {"selector": selector}
                    k_match = re.search(r'k=(\w+)', rec)
                    if k_match:
                        key_info["algorithm"] = k_match.group(1)
                    p_match = re.search(r'p=([A-Za-z0-9+/=]+)', rec)
                    if p_match:
                        key_len = len(p_match.group(1))
                        key_info["key_length_b64"] = key_len
                        estimated_bits = key_len * 6
                        key_info["estimated_bits"] = estimated_bits
                        if estimated_bits < 1024:
                            key_info["warning"] = "Key may be <1024 bits (weak)"
                    result.key_details.append(key_info)
                    break
        else:
            cnames = dns_query(dkim_domain, "CNAME")
            if cnames:
                result.exists = True
                result.selectors_found.append(f"{selector} (CNAME)")

    result.selectors_missing = [s for s in selectors
                                 if s not in result.selectors_found
                                 and f"{s} (CNAME)" not in result.selectors_found]
    return result


# ═══════════════════════════════════════════════════════════════
# BIMI CHECK
# ═══════════════════════════════════════════════════════════════
def check_bimi(domain: str) -> BIMIResult:
    result = BIMIResult()
    txt_records = dns_query(f"default._bimi.{domain}", "TXT")

    for rec in txt_records:
        cleaned = rec.strip('"').strip("'")
        if "v=bimi1" in cleaned.lower():
            result.record = cleaned
            result.exists = True
            l_match = re.search(r'l=(\S+)', cleaned, re.I)
            if l_match:
                result.logo_url = l_match.group(1).rstrip(";")
            a_match = re.search(r'a=(\S+)', cleaned, re.I)
            if a_match:
                result.vmc_url = a_match.group(1).rstrip(";")
            break
    return result


# ═══════════════════════════════════════════════════════════════
# MX / NS RECORDS
# ═══════════════════════════════════════════════════════════════
def check_mx(domain: str) -> list:
    records = dns_query(domain, "MX")
    mx_list = []
    for rec in records:
        parts = rec.split()
        if len(parts) >= 2:
            mx_list.append({"priority": parts[0], "host": parts[1].rstrip(".")})
    return sorted(mx_list, key=lambda x: int(x["priority"]))


def check_ns(domain: str) -> list:
    records = dns_query(domain, "NS")
    return [r.rstrip(".") for r in records]


# ═══════════════════════════════════════════════════════════════
# OVERALL ASSESSMENT
# ═══════════════════════════════════════════════════════════════
def assess_domain(domain: str, quick_dkim: bool = False) -> DomainReport:
    start_time = time.time()
    report = DomainReport(domain=domain, timestamp=datetime.now().isoformat())

    print(f"\n{C}{B}{'═' * 65}{RST}")
    print(f"{C}{B}  Scanning: {domain}{RST}")
    print(f"{C}{B}{'═' * 65}{RST}\n")

    # SPF
    print(f"  {Y}[1/6]{RST} Checking SPF record...", end=" ", flush=True)
    report.spf = check_spf(domain)
    if report.spf.exists:
        risk_color = G if report.spf.risk == "LOW" else (Y if report.spf.risk == "MEDIUM" else R)
        print(f"{risk_color}{report.spf.risk}{RST}")
        print(f"        Record: {W}{report.spf.record}{RST}")
        print(f"        Mechanism: {report.spf.mechanism}  |  DNS lookups: {report.spf.dns_lookup_count}/10")
        if report.spf.includes:
            print(f"        Includes: {', '.join(report.spf.includes)}")
        if report.spf.ip4s:
            print(f"        IP4: {', '.join(report.spf.ip4s)}")
        if report.spf.ip6s:
            print(f"        IP6: {', '.join(report.spf.ip6s)}")
        if report.spf.redirect:
            print(f"        Redirect: {report.spf.redirect}")
        for w in report.spf.warnings:
            print(f"        {Y}⚠ {w}{RST}")
    else:
        print(f"{R}MISSING ⚠{RST}")
        print(f"        {R}No SPF record — domain can be spoofed by anyone!{RST}")

    # DMARC
    print(f"  {Y}[2/6]{RST} Checking DMARC record...", end=" ", flush=True)
    report.dmarc = check_dmarc(domain)
    if report.dmarc.exists:
        risk_color = G if report.dmarc.risk == "LOW" else (Y if report.dmarc.risk == "MEDIUM" else R)
        print(f"{risk_color}{report.dmarc.risk}{RST}")
        print(f"        Record: {W}{report.dmarc.record}{RST}")
        print(f"        Policy: p={report.dmarc.policy}  |  sp={report.dmarc.subdomain_policy}  |  pct={report.dmarc.pct}%")
        print(f"        Alignment: adkim={report.dmarc.adkim}  aspf={report.dmarc.aspf}")
        if report.dmarc.rua:
            print(f"        Aggregate reports → {report.dmarc.rua}")
        if report.dmarc.ruf:
            print(f"        Forensic reports  → {report.dmarc.ruf}")
        for w in report.dmarc.warnings:
            print(f"        {Y}⚠ {w}{RST}")
    else:
        print(f"{R}MISSING ⚠{RST}")
        print(f"        {R}No DMARC record — no email authentication policy!{RST}")

    # DKIM
    print(f"  {Y}[3/6]{RST} Checking DKIM selectors...", end=" ", flush=True)
    dkim_sels = DKIM_SELECTORS_QUICK if quick_dkim else DKIM_SELECTORS
    report.dkim = check_dkim(domain, dkim_sels)
    if report.dkim.exists:
        print(f"{G}FOUND ({len(report.dkim.selectors_found)} selectors){RST}")
        for sel in report.dkim.selectors_found:
            print(f"        ✓ {sel}")
        for kd in report.dkim.key_details:
            algo = kd.get("algorithm", "rsa")
            bits = kd.get("estimated_bits", "?")
            warn = kd.get("warning", "")
            print(f"          {kd['selector']}: {algo} ~{bits}b {R + warn + RST if warn else ''}")
    else:
        print(f"{Y}NOT FOUND{RST}")
        print(f"        {Y}Checked {len(dkim_sels)} common selectors — none found{RST}")

    # BIMI
    print(f"  {Y}[4/6]{RST} Checking BIMI record...", end=" ", flush=True)
    report.bimi = check_bimi(domain)
    if report.bimi.exists:
        print(f"{G}FOUND{RST}")
        if report.bimi.logo_url:
            print(f"        Logo: {report.bimi.logo_url}")
        if report.bimi.vmc_url:
            print(f"        VMC:  {report.bimi.vmc_url}")
    else:
        print(f"{W}NOT CONFIGURED{RST}")

    # MX
    print(f"  {Y}[5/6]{RST} Checking MX records...", end=" ", flush=True)
    report.mx_records = check_mx(domain)
    if report.mx_records:
        print(f"{G}FOUND ({len(report.mx_records)} records){RST}")
        for mx in report.mx_records:
            print(f"        [{mx['priority']}] {mx['host']}")
    else:
        print(f"{Y}NONE{RST}")

    # NS
    print(f"  {Y}[6/6]{RST} Checking NS records...", end=" ", flush=True)
    report.ns_records = check_ns(domain)
    if report.ns_records:
        print(f"{G}FOUND ({len(report.ns_records)} servers){RST}")
        for ns in report.ns_records:
            print(f"        {ns}")
    else:
        print(f"{Y}NONE{RST}")

    # ═══ RISK SCORING (0-100) ═══
    score = 0
    if not report.spf.exists:
        score += 30
    elif report.spf.mechanism == "+all":
        score += 30
    elif report.spf.mechanism == "?all":
        score += 25
    elif report.spf.mechanism == "~all":
        score += 15
    elif report.spf.mechanism == "missing-all":
        score += 25
    if report.spf.too_many_lookups:
        score += 10

    if not report.dmarc.exists:
        score += 30
    elif report.dmarc.policy == "none":
        score += 20
    elif report.dmarc.policy == "quarantine":
        score += 10
    if report.dmarc.exists and report.dmarc.pct < 100:
        score += 5

    if not report.dkim.exists:
        score += 15
    if not report.mx_records:
        score += 5

    report.risk_score = min(score, 100)
    report.spoofable = (
        not report.spf.exists or
        report.spf.mechanism in ("+all", "?all", "~all", "missing-all") or
        not report.dmarc.exists or
        report.dmarc.policy == "none"
    )

    if score >= 60:
        report.risk_level = "CRITICAL"
    elif score >= 40:
        report.risk_level = "HIGH"
    elif score >= 20:
        report.risk_level = "MEDIUM"
    else:
        report.risk_level = "LOW"

    # Recommendations
    if not report.spf.exists:
        report.recommendations.append("Add SPF record: v=spf1 include:<mail-provider> -all")
    elif report.spf.mechanism != "-all":
        report.recommendations.append(f"Harden SPF: change '{report.spf.mechanism}' to '-all' (hard fail)")
    if report.spf.too_many_lookups:
        report.recommendations.append(f"Flatten SPF includes — {report.spf.dns_lookup_count} exceeds 10-lookup RFC limit")

    if not report.dmarc.exists:
        report.recommendations.append(f"Add DMARC: v=DMARC1; p=reject; rua=mailto:dmarc@{domain}")
    elif report.dmarc.policy == "none":
        report.recommendations.append("Upgrade DMARC: p=none → p=quarantine → p=reject")
    elif report.dmarc.policy == "quarantine":
        report.recommendations.append("Upgrade DMARC: p=quarantine → p=reject")
    if report.dmarc.exists and report.dmarc.pct < 100:
        report.recommendations.append(f"Increase DMARC pct from {report.dmarc.pct}% to 100%")
    if report.dmarc.exists and not report.dmarc.rua:
        report.recommendations.append(f"Add aggregate reporting: rua=mailto:dmarc-reports@{domain}")

    if not report.dkim.exists:
        report.recommendations.append("Configure DKIM signing on your mail server")

    if not report.bimi.exists and report.dmarc.exists and report.dmarc.policy in ("quarantine", "reject"):
        report.recommendations.append("Consider adding BIMI record for brand logo in email clients")

    # Print summary
    risk_color = R if report.risk_level in ("CRITICAL", "HIGH") else (Y if report.risk_level == "MEDIUM" else G)
    spoof_text = f"{R}YES — EMAIL SPOOFING POSSIBLE" if report.spoofable else f"{G}NO — PROPERLY PROTECTED"
    report.scan_duration_s = round(time.time() - start_time, 2)

    print(f"\n  {B}{'─' * 55}{RST}")
    print(f"  {B}VERDICT:{RST}")
    print(f"    Overall Risk:   {risk_color}{B}{report.risk_level}{RST} (score: {report.risk_score}/100)")
    print(f"    Spoofable:      {spoof_text}{RST}")
    print(f"    SPF lookups:    {report.spf.dns_lookup_count}/10")
    print(f"    Scan time:      {report.scan_duration_s}s")
    if report.recommendations:
        print(f"    {Y}Recommendations:{RST}")
        for rec in report.recommendations:
            print(f"      • {rec}")
    print(f"  {B}{'─' * 55}{RST}")

    return report


# ═══════════════════════════════════════════════════════════════
# SPOOF TEST
# ═══════════════════════════════════════════════════════════════
def send_spoof_test(from_addr: str, to_addr: str, domain: str,
                    smtp_server: str = None, smtp_port: int = 25):
    print(f"\n{Y}{B}  📧 Sending spoof test email...{RST}")
    print(f"     From: {from_addr}")
    print(f"     To:   {to_addr}")

    msg = MIMEText(
        f"This is a Proof-of-Concept email demonstrating that emails can be "
        f"spoofed as {from_addr} due to missing/misconfigured SPF/DMARC records "
        f"on {domain}.\n\nSent by SPF Checker v2.0.0 during authorized assessment.\n"
        f"Timestamp: {datetime.now().isoformat()}"
    )
    msg["Subject"] = f"[PoC] Email Spoofing Test — {domain}"
    msg["From"] = from_addr
    msg["To"] = to_addr

    if not smtp_server:
        mx_records = check_mx(domain)
        if mx_records:
            smtp_server = mx_records[0]["host"]
            print(f"     SMTP:  {smtp_server}:{smtp_port} (from MX)")
        else:
            print(f"     {R}✗ No MX records. Use --smtp-server.{RST}")
            return False

    try:
        with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as server:
            server.ehlo()
            try:
                server.starttls()
                server.ehlo()
            except Exception:
                pass
            server.sendmail(from_addr, [to_addr], msg.as_string())
        print(f"     {G}✓ Email sent! Check inbox (and spam).{RST}")
        return True
    except smtplib.SMTPRecipientsRefused:
        print(f"     {R}✗ Recipient refused — server validates sender.{RST}")
    except smtplib.SMTPSenderRefused:
        print(f"     {R}✗ Sender refused — SPF blocked the spoof.{RST}")
    except smtplib.SMTPConnectError:
        print(f"     {R}✗ Connection refused by SMTP server.{RST}")
    except Exception as e:
        print(f"     {R}✗ Failed: {e}{RST}")
    return False


# ═══════════════════════════════════════════════════════════════
# SAVE REPORTS
# ═══════════════════════════════════════════════════════════════
def save_report(reports: list, output_dir: str = "output"):
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_path = os.path.join(output_dir, f"spf_report_{ts}.json")
    with open(json_path, "w") as f:
        json.dump([asdict(r) for r in reports], f, indent=2, default=str)
    print(f"\n  {G}✓ JSON report: {json_path}{RST}")

    html_path = os.path.join(output_dir, f"spf_report_{ts}.html")
    with open(html_path, "w") as f:
        f.write(generate_html_report(reports))
    print(f"  {G}✓ HTML report: {html_path}{RST}")


def generate_html_report(reports: list) -> str:
    rows = ""
    for r in reports:
        risk_color = "#ff4444" if r.risk_level in ("CRITICAL", "HIGH") else (
            "#ffaa00" if r.risk_level == "MEDIUM" else "#44ff44")
        spf_status = r.spf.record or "MISSING"
        dmarc_status = r.dmarc.record or "MISSING"
        dkim_status = ", ".join(r.dkim.selectors_found) if r.dkim.selectors_found else "NOT FOUND"
        bimi_status = "✓" if r.bimi.exists else "—"
        recs = "<br>".join(f"• {rec}" for rec in r.recommendations) if r.recommendations else "None"
        spf_warns = "<br>".join(f"⚠ {w}" for w in r.spf.warnings) if r.spf.warnings else ""
        dmarc_warns = "<br>".join(f"⚠ {w}" for w in r.dmarc.warnings) if r.dmarc.warnings else ""

        rows += f"""<tr>
            <td><strong>{r.domain}</strong></td>
            <td style="background:{risk_color};color:#fff;font-weight:bold;text-align:center">{r.risk_level}<br><small>{r.risk_score}/100</small></td>
            <td><code style="font-size:11px;word-break:break-all">{spf_status}</code><br>Mechanism: <strong>{r.spf.mechanism}</strong><br>Lookups: <strong>{r.spf.dns_lookup_count}/10</strong>
                {f'<br><span style="color:#ffaa00;font-size:11px">{spf_warns}</span>' if spf_warns else ''}</td>
            <td><code style="font-size:11px;word-break:break-all">{dmarc_status}</code><br>p={r.dmarc.policy} | sp={r.dmarc.subdomain_policy} | pct={r.dmarc.pct}%
                {f'<br><span style="color:#ffaa00;font-size:11px">{dmarc_warns}</span>' if dmarc_warns else ''}</td>
            <td>{dkim_status}</td>
            <td>{bimi_status}</td>
            <td>{"🔴 YES" if r.spoofable else "🟢 NO"}</td>
            <td style="font-size:12px">{recs}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Email Security Report</title>
<style>
body{{font-family:-apple-system,sans-serif;background:#0a0a0a;color:#e0e0e0;padding:30px;max-width:1400px;margin:0 auto}}
h1{{color:#00d4ff;border-bottom:2px solid #00d4ff;padding-bottom:10px}}
table{{border-collapse:collapse;width:100%;margin:20px 0}}
th{{background:#1a1a2e;color:#00d4ff;padding:12px;text-align:left;border:1px solid #333}}
td{{padding:10px;border:1px solid #333;vertical-align:top}}
tr:nth-child(even){{background:#111}}
code{{background:#1a1a2e;padding:2px 6px;border-radius:3px}}
.legend{{background:#1a1a2e;padding:15px;border-radius:8px;margin:15px 0;font-size:13px}}
</style></head><body>
<h1>📧 Email Security Report — SPF / DMARC / DKIM / BIMI</h1>
<p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | Tool: SPF Checker v2.0.0</p>
<div class="legend">
<strong>Risk Scoring:</strong> CRITICAL (60-100) · HIGH (40-59) · MEDIUM (20-39) · LOW (0-19)<br>
<strong>SPF mechanisms:</strong> -all (hard fail ✓) · ~all (soft fail ⚠) · ?all (neutral ✗) · +all (pass all ✗✗)
</div>
<table>
<tr><th>Domain</th><th>Risk</th><th>SPF</th><th>DMARC</th><th>DKIM</th><th>BIMI</th><th>Spoofable?</th><th>Recommendations</th></tr>
{rows}
</table>
<p style="color:#666;font-size:12px">⚠ For authorized security testing only.</p>
</body></html>"""


# ═══════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════
def main():
    global VERBOSE, DNS_TIMEOUT
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="SPF/DMARC/DKIM/BIMI Email Security Checker v2.0.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -d target.com
  %(prog)s -d target1.com target2.com --verbose
  %(prog)s -f domains.txt --quick-dkim
  %(prog)s -d target.com --spoof-test --from ceo@target.com --to you@gmail.com

Bug Bounty Tips:
  SPF ~all + DMARC p=none     → Spoofable → report as "Email Spoofing"
  No SPF + No DMARC           → Critical  → report as "Missing Email Auth"
  SPF >10 lookups             → permerror → report as "SPF Misconfiguration"
        """
    )
    parser.add_argument("-d", "--domains", nargs="+", help="One or more domains to check")
    parser.add_argument("-f", "--file", help="File with domains (one per line)")
    parser.add_argument("--quick-dkim", action="store_true",
                        help="Check only 15 most common DKIM selectors (faster)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show detailed include resolution")
    parser.add_argument("--spoof-test", action="store_true",
                        help="Send a test spoofed email (to YOUR inbox only!)")
    parser.add_argument("--from", dest="from_addr", help="Spoofed sender address")
    parser.add_argument("--to", dest="to_addr", help="Your email to receive the test")
    parser.add_argument("--smtp-server", help="SMTP server (auto-detected from MX)")
    parser.add_argument("--smtp-port", type=int, default=25, help="SMTP port (default: 25)")
    parser.add_argument("-o", "--output-dir", default="output", help="Output directory")
    parser.add_argument("--json-only", action="store_true", help="Skip HTML report")
    parser.add_argument("--timeout", type=float, default=5.0, help="DNS timeout seconds (default: 5)")
    parser.add_argument("--crawl-subs", action="store_true",
                        help="Auto-discover subdomains and check SPF on each")
    parser.add_argument("--sub-threads", type=int, default=20,
                        help="Threads for subdomain crawler (default: 20)")
    parser.add_argument("--deep-subs", action="store_true",
                        help="Use extended subdomain wordlist (250+ prefixes)")

    args = parser.parse_args()
    VERBOSE = args.verbose
    DNS_TIMEOUT = args.timeout

    domains = []
    if args.domains:
        domains.extend(args.domains)
    if args.file:
        try:
            with open(args.file) as f:
                domains.extend(l.strip() for l in f if l.strip() and not l.startswith("#"))
        except FileNotFoundError:
            print(f"{R}✗ File not found: {args.file}{RST}")
            sys.exit(1)

    if not domains:
        parser.print_help()
        print(f"\n{R}✗ Provide at least one domain with -d or -f{RST}")
        sys.exit(1)

    # Subdomain crawling — discover subdomains to also scan
    if args.crawl_subs:
        try:
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "subdomain-crawler"))
            from subdomain_crawler import SubdomainCrawler
            extra_domains = []
            for domain in list(domains):
                domain = domain.strip().lower()
                if domain.startswith("http"):
                    from urllib.parse import urlparse as _up
                    domain = _up(domain).hostname or domain
                print(f"\n  {M}{B}🔍 Crawling subdomains of {domain} for SPF scan...{RST}")
                crawler = SubdomainCrawler(
                    domain=domain, threads=args.sub_threads,
                    deep=args.deep_subs, check_alive=False, find_logins=False
                )
                results = crawler.run()
                for r in results:
                    sub = r.subdomain
                    if sub not in domains and sub not in extra_domains:
                        extra_domains.append(sub)
                print(f"  {G}✓ Added {len(extra_domains)} subdomains to SPF scan queue{RST}")
            domains.extend(extra_domains)
        except ImportError:
            print(f"  {Y}⚠ subdomain_crawler not found. Run without --crawl-subs or install it.{RST}")

    reports = []
    for domain in domains:
        domain = domain.strip().lower()
        if domain.startswith("http"):
            from urllib.parse import urlparse
            domain = urlparse(domain).hostname or domain
        reports.append(assess_domain(domain, quick_dkim=args.quick_dkim))

    if args.spoof_test:
        if not args.from_addr or not args.to_addr:
            print(f"\n{R}✗ --spoof-test requires --from and --to{RST}")
        else:
            d = args.from_addr.split("@")[1] if "@" in args.from_addr else domains[0]
            send_spoof_test(args.from_addr, args.to_addr, d, args.smtp_server, args.smtp_port)

    save_report(reports, args.output_dir)

    vuln_count = sum(1 for r in reports if r.spoofable)
    total = len(reports)
    avg_score = sum(r.risk_score for r in reports) / total if total else 0
    print(f"\n{B}{'═' * 65}{RST}")
    print(f"  {B}SCAN COMPLETE{RST}")
    print(f"  Domains scanned:  {total}")
    print(f"  Spoofable:        {R}{vuln_count}{RST} / {total}")
    print(f"  Safe:             {G}{total - vuln_count}{RST} / {total}")
    print(f"  Avg risk score:   {avg_score:.0f}/100")
    print(f"{B}{'═' * 65}{RST}\n")


if __name__ == "__main__":
    main()
