#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║          ORIGIN IP FINDER  v2.0.0                               ║
║     Discover Real Server IPs Behind CDN/WAF                     ║
║                                                                  ║
║  Author : Vishal Rao (@Vishal-HaCkEr1910)                      ║
║  License: MIT — For authorized security testing only            ║
╚══════════════════════════════════════════════════════════════════╝

Industry-standard origin IP discovery tool. Uses 8 techniques:
CDN detection, DNS history (SecurityTrails API + ViewDNS), 60+
subdomain brute-force, MX record analysis, SPF record IP extraction,
TXT record analysis, response header leak detection, SSL cert
verification, and direct HTTP Host-header verification.

Usage:
    python origin_ip_finder.py -d target.com
    python origin_ip_finder.py -d target.com --aggressive
    python origin_ip_finder.py -f domains.txt -o results/
"""

import argparse
import dns.resolver
import json
import os
import re
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
   ██████╗ ██████╗ ██╗ ██████╗ ██╗███╗   ██╗    ██╗██████╗
  ██╔═══██╗██╔══██╗██║██╔════╝ ██║████╗  ██║    ██║██╔══██╗
  ██║   ██║██████╔╝██║██║  ███╗██║██╔██╗ ██║    ██║██████╔╝
  ██║   ██║██╔══██╗██║██║   ██║██║██║╚██╗██║    ██║██╔═══╝
  ╚██████╔╝██║  ██║██║╚██████╔╝██║██║ ╚████║    ██║██║
   ╚═════╝ ╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝    ╚═╝╚═╝
{RST}
  {Y}Origin IP Finder v2.0.0{RST}
  {W}DNS History · Subdomains · SPF · SSL Certs · Headers · Verification{RST}
  {R}⚠  AUTHORIZED USE ONLY{RST}
"""

COMMON_SUBDOMAINS = [
    "mail", "ftp", "cpanel", "webmail", "direct", "origin", "staging",
    "stage", "dev", "development", "test", "testing", "api", "backend",
    "admin", "panel", "old", "legacy", "backup", "ns1", "ns2", "smtp",
    "pop", "imap", "mx", "vpn", "remote", "ssh", "git", "ci", "jenkins",
    "grafana", "monitor", "monitoring", "db", "database", "mysql",
    "postgres", "redis", "elastic", "kibana", "phpmyadmin", "crm",
    "erp", "portal", "intranet", "internal", "cdn", "static", "assets",
    "media", "img", "images", "files", "download", "upload", "www2",
    "app", "m", "mobile", "shop", "store", "blog", "forum", "wiki",
    "docs", "help", "support", "status", "demo", "sandbox", "preprod",
    "uat", "prod", "live", "web", "www1", "proxy", "gateway",
]


# ═══════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════
@dataclass
class IPCandidate:
    ip: str
    source: str
    confidence: str = "LOW"
    verified: bool = False
    details: str = ""


@dataclass
class DomainReport:
    domain: str = ""
    is_behind_cdn: bool = False
    cdn_provider: str = "Unknown"
    current_ips: list = field(default_factory=list)
    candidates: list = field(default_factory=list)
    verified_origins: list = field(default_factory=list)
    mx_records: list = field(default_factory=list)
    techniques_used: list = field(default_factory=list)
    timestamp: str = ""
    scan_duration_s: float = 0.0


# ═══════════════════════════════════════════════════════════════
# DNS HELPERS
# ═══════════════════════════════════════════════════════════════
DNS_TIMEOUT = 5.0


def dns_query(name: str, rdtype: str, timeout: float = None) -> list:
    timeout = timeout or DNS_TIMEOUT
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        return [str(rdata) for rdata in resolver.resolve(name, rdtype)]
    except Exception:
        return []


def resolve_ip(hostname: str) -> list:
    try:
        return list(set(info[4][0] for info in socket.getaddrinfo(hostname, None, socket.AF_INET)))
    except Exception:
        return []


def is_cdn_ip(ip: str) -> bool:
    try:
        hostname = socket.gethostbyaddr(ip)[0].lower()
        cdn_kw = ["cloudflare", "akamai", "fastly", "cloudfront",
                   "incapsula", "sucuri", "stackpath", "cdn", "edgecast"]
        return any(kw in hostname for kw in cdn_kw)
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════
# TECHNIQUE 1: CDN DETECTION
# ═══════════════════════════════════════════════════════════════
def detect_cdn(domain: str) -> tuple:
    try:
        resp = requests.head(f"https://{domain}", timeout=10, allow_redirects=True, verify=False)
        hl = {k.lower(): v.lower() for k, v in resp.headers.items()}

        if "cf-ray" in hl or hl.get("server", "") == "cloudflare":
            return True, "Cloudflare"
        if "x-fastly-request-id" in hl or "fastly" in hl.get("via", ""):
            return True, "Fastly"
        if any("akamai" in v for v in hl.values()):
            return True, "Akamai"
        if "x-amz-cf-id" in hl or "x-amz-cf-pop" in hl:
            return True, "AWS CloudFront"
        if "x-vercel-id" in hl:
            return True, "Vercel"
        if "x-sucuri-id" in hl:
            return True, "Sucuri"
        if any("incapsula" in v for v in hl.values()):
            return True, "Imperva/Incapsula"
        if "x-cdn" in hl:
            return True, hl.get("x-cdn", "Unknown CDN")

        # CNAME check
        cnames = dns_query(domain, "CNAME")
        for cn in cnames:
            cl = cn.lower()
            for kw, name in [("cloudflare", "Cloudflare"), ("fastly", "Fastly"),
                             ("akamai", "Akamai"), ("cloudfront", "AWS CloudFront"),
                             ("incapsula", "Imperva"), ("sucuri", "Sucuri"),
                             ("edgecast", "Edgecast"), ("stackpath", "StackPath")]:
                if kw in cl:
                    return True, name
    except Exception:
        pass
    return False, "None"


# ═══════════════════════════════════════════════════════════════
# TECHNIQUE 2: DNS HISTORY
# ═══════════════════════════════════════════════════════════════
def check_dns_history(domain: str) -> list:
    candidates = []
    api_key = os.environ.get("SECURITYTRAILS_API_KEY")

    if api_key:
        try:
            url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
            resp = requests.get(url, headers={"APIKEY": api_key}, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for record in data.get("records", []):
                    for val in record.get("values", []):
                        ip = val.get("ip", "")
                        if ip and not is_cdn_ip(ip):
                            candidates.append(IPCandidate(
                                ip=ip, source="dns_history", confidence="MEDIUM",
                                details=f"SecurityTrails historical A record (first seen: {record.get('first_seen', '?')})"
                            ))
        except Exception:
            pass

    # ViewDNS fallback (scraping)
    try:
        resp = requests.get(
            f"https://viewdns.info/iphistory/?domain={domain}",
            headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
            timeout=10
        )
        if resp.status_code == 200:
            ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', resp.text)
            seen = set()
            for ip in ips:
                if ip not in seen and not ip.startswith("0.") and not ip.startswith("127."):
                    seen.add(ip)
                    candidates.append(IPCandidate(
                        ip=ip, source="dns_history", confidence="LOW",
                        details="ViewDNS IP History"
                    ))
    except Exception:
        pass

    return candidates


# ═══════════════════════════════════════════════════════════════
# TECHNIQUE 3: SUBDOMAIN ENUMERATION (threaded)
# ═══════════════════════════════════════════════════════════════
def _resolve_subdomain(sub: str, domain: str, cdn_ips: set) -> list:
    results = []
    fqdn = f"{sub}.{domain}"
    ips = resolve_ip(fqdn)
    for ip in ips:
        if ip and ip not in cdn_ips and not is_cdn_ip(ip):
            results.append(IPCandidate(
                ip=ip, source="subdomain", confidence="MEDIUM",
                details=f"Resolved from {fqdn}"
            ))
    return results


def check_subdomains(domain: str, cdn_ips: set, threads: int = 10) -> list:
    candidates = []

    # Try to use shared subdomain crawler for crt.sh + extended wordlist
    try:
        _crawler_path = os.path.join(os.path.dirname(__file__), "..", "subdomain-crawler")
        sys.path.insert(0, _crawler_path)
        from subdomain_crawler import SubdomainCrawler
        crawler = SubdomainCrawler(domain=domain, threads=threads,
                                    deep=False, check_alive=False, find_logins=False,
                                    verbose=False)
        results = crawler.run(silent=True)
        for r in results:
            for ip in r.ips:
                if ip and ip not in cdn_ips and not is_cdn_ip(ip):
                    candidates.append(IPCandidate(
                        ip=ip, source="subdomain", confidence="MEDIUM",
                        details=f"Resolved from {r.subdomain} (via {r.source})"
                    ))
        return candidates
    except ImportError:
        pass

    # Fallback: built-in brute-force only
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_resolve_subdomain, sub, domain, cdn_ips): sub
                   for sub in COMMON_SUBDOMAINS}
        for future in as_completed(futures):
            try:
                candidates.extend(future.result())
            except Exception:
                pass
    return candidates


# ═══════════════════════════════════════════════════════════════
# TECHNIQUE 4: MX RECORD ANALYSIS
# ═══════════════════════════════════════════════════════════════
def check_mx_records(domain: str, cdn_ips: set) -> list:
    candidates = []
    mx_records = dns_query(domain, "MX")
    for rec in mx_records:
        parts = rec.split()
        if len(parts) >= 2:
            mx_host = parts[1].rstrip(".")
            ips = resolve_ip(mx_host)
            for ip in ips:
                if ip and ip not in cdn_ips:
                    candidates.append(IPCandidate(
                        ip=ip, source="mx_record", confidence="LOW",
                        details=f"MX: {mx_host}"
                    ))
    return candidates


# ═══════════════════════════════════════════════════════════════
# TECHNIQUE 5: SPF RECORD IP EXTRACTION
# ═══════════════════════════════════════════════════════════════
def check_spf_ips(domain: str, cdn_ips: set) -> list:
    candidates = []
    txt_records = dns_query(domain, "TXT")
    for rec in txt_records:
        if "v=spf1" in rec.lower():
            # Extract ip4: and ip6: entries
            ip4s = re.findall(r'ip4:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', rec)
            for ip in ip4s:
                if ip not in cdn_ips:
                    candidates.append(IPCandidate(
                        ip=ip, source="spf_record", confidence="MEDIUM",
                        details=f"ip4 in SPF record"
                    ))
            # Extract include: domains and resolve them
            includes = re.findall(r'include:(\S+)', rec.lower())
            for inc in includes:
                ips = resolve_ip(inc)
                for ip in ips:
                    if ip not in cdn_ips and not is_cdn_ip(ip):
                        candidates.append(IPCandidate(
                            ip=ip, source="spf_record", confidence="LOW",
                            details=f"Resolved from SPF include:{inc}"
                        ))
    return candidates


# ═══════════════════════════════════════════════════════════════
# TECHNIQUE 6: RESPONSE HEADER LEAKS
# ═══════════════════════════════════════════════════════════════
def check_headers(domain: str) -> list:
    candidates = []
    leak_headers = [
        "x-real-ip", "x-forwarded-for", "x-backend-server", "x-host",
        "x-origin-server", "x-served-by", "x-backend", "x-upstream",
        "x-forwarded-host", "x-server-addr", "x-debug-server",
        "x-powered-by-server", "via", "x-cache",
    ]
    try:
        resp = requests.get(f"https://{domain}", timeout=10, allow_redirects=True, verify=False)
        for hdr in leak_headers:
            val = resp.headers.get(hdr, "")
            if val:
                ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', val)
                for ip in ips:
                    candidates.append(IPCandidate(
                        ip=ip, source="header_leak", confidence="HIGH",
                        details=f"Leaked via: {hdr}: {val}"
                    ))
    except Exception:
        pass

    # Also check error pages that may leak info
    try:
        resp = requests.get(f"https://{domain}/this-page-doesnt-exist-xyz123",
                           timeout=10, verify=False)
        ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', resp.text)
        for ip in ips:
            if not ip.startswith("0.") and not ip.startswith("127."):
                candidates.append(IPCandidate(
                    ip=ip, source="error_page", confidence="LOW",
                    details="IP found in error page body"
                ))
    except Exception:
        pass

    return candidates


# ═══════════════════════════════════════════════════════════════
# TECHNIQUE 7: SSL CERTIFICATE CHECK
# ═══════════════════════════════════════════════════════════════
def check_ssl_cert(ip: str, domain: str) -> bool:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((ip, 443))
            cert = s.getpeercert(binary_form=False)
            if cert:
                subject = dict(x[0] for x in cert.get("subject", ()))
                cn = subject.get("commonName", "")
                sans = [e[1] for e in cert.get("subjectAltName", ())]
                for name in [cn] + sans:
                    if domain in name or name.replace("*.", "") in domain:
                        return True
    except Exception:
        pass

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(socket.socket()) as s:
            s.settimeout(5)
            s.connect((ip, 443))
            cert_bin = s.getpeercert(binary_form=True)
            if cert_bin and domain.encode() in cert_bin:
                return True
    except Exception:
        pass
    return False


# ═══════════════════════════════════════════════════════════════
# TECHNIQUE 8: DIRECT HTTP VERIFICATION
# ═══════════════════════════════════════════════════════════════
def verify_origin(ip: str, domain: str) -> bool:
    for scheme in ["https", "http"]:
        try:
            resp = requests.get(
                f"{scheme}://{ip}/",
                headers={"Host": domain},
                timeout=10, verify=False, allow_redirects=False
            )
            if resp.status_code < 500:
                try:
                    real_resp = requests.get(f"https://{domain}/", timeout=10, verify=False)
                    real_len = len(real_resp.text)
                    test_len = len(resp.text)
                    if real_len > 0 and abs(real_len - test_len) / max(real_len, 1) < 0.3:
                        return True
                except Exception:
                    pass
                if resp.status_code == 200 and len(resp.text) > 500:
                    return True
        except Exception:
            continue
    return False


# ═══════════════════════════════════════════════════════════════
# MAIN SCANNER
# ═══════════════════════════════════════════════════════════════
def scan_domain(domain: str, aggressive: bool = False, threads: int = 10) -> DomainReport:
    start_time = time.time()
    report = DomainReport(domain=domain, timestamp=datetime.now().isoformat())

    print(f"\n{C}{B}{'═' * 65}{RST}")
    print(f"{C}{B}  Scanning: {domain}{RST}")
    print(f"{C}{B}{'═' * 65}{RST}\n")

    # Current IPs
    report.current_ips = resolve_ip(domain)
    cdn_ips = set(report.current_ips)
    print(f"  {Y}[1/7]{RST} Current A records: {W}{', '.join(report.current_ips) or 'None'}{RST}")

    # CDN detection
    print(f"  {Y}[2/7]{RST} CDN detection...", end=" ", flush=True)
    report.is_behind_cdn, report.cdn_provider = detect_cdn(domain)
    if report.is_behind_cdn:
        print(f"{Y}Behind {report.cdn_provider}{RST}")
    else:
        print(f"{G}No CDN detected{RST}")
        print(f"        {W}Current IPs may already be the origin.{RST}")

    all_candidates = []

    # DNS History
    print(f"  {Y}[3/7]{RST} DNS history lookup...", end=" ", flush=True)
    history = check_dns_history(domain)
    all_candidates.extend(history)
    report.techniques_used.append("dns_history")
    print(f"Found {G}{len(history)}{RST} candidate(s)")

    # Subdomains (threaded)
    print(f"  {Y}[4/7]{RST} Subdomain enumeration ({len(COMMON_SUBDOMAINS)} subs, {threads} threads)...", end=" ", flush=True)
    subs = check_subdomains(domain, cdn_ips, threads=threads)
    all_candidates.extend(subs)
    report.techniques_used.append("subdomain_enum")
    print(f"Found {G}{len(subs)}{RST} candidate(s)")

    # MX Records
    print(f"  {Y}[5/7]{RST} MX record analysis...", end=" ", flush=True)
    mx = check_mx_records(domain, cdn_ips)
    all_candidates.extend(mx)
    report.techniques_used.append("mx_records")
    print(f"Found {G}{len(mx)}{RST} candidate(s)")
    report.mx_records = [c.details for c in mx]

    # SPF Record IPs
    print(f"  {Y}[6/7]{RST} SPF record IP extraction...", end=" ", flush=True)
    spf = check_spf_ips(domain, cdn_ips)
    all_candidates.extend(spf)
    report.techniques_used.append("spf_ips")
    print(f"Found {G}{len(spf)}{RST} candidate(s)")

    # Response Headers
    print(f"  {Y}[7/7]{RST} Response header & error page analysis...", end=" ", flush=True)
    hdrs = check_headers(domain)
    all_candidates.extend(hdrs)
    report.techniques_used.append("headers")
    print(f"Found {G}{len(hdrs)}{RST} candidate(s)")

    # Deduplicate
    seen_ips = set()
    unique_candidates = []
    for c in all_candidates:
        if c.ip not in seen_ips:
            seen_ips.add(c.ip)
            unique_candidates.append(c)

    # Remove current CDN IPs
    unique_candidates = [c for c in unique_candidates if c.ip not in cdn_ips]

    print(f"\n  {B}Total unique candidates: {len(unique_candidates)}{RST}")

    # Verify
    if unique_candidates:
        print(f"\n  {Y}Verifying candidates...{RST}")
        for c in unique_candidates:
            print(f"    Testing {c.ip} ({c.source})...", end=" ", flush=True)
            ssl_match = check_ssl_cert(c.ip, domain)
            if ssl_match:
                c.confidence = "HIGH"
                c.details += " | SSL cert matches"

            http_match = verify_origin(c.ip, domain)
            if http_match:
                c.verified = True
                c.confidence = "HIGH"
                c.details += " | HTTP verification confirmed"
                print(f"{G}✓ VERIFIED ORIGIN!{RST}")
                report.verified_origins.append(c.ip)
            elif ssl_match:
                print(f"{Y}SSL match (unverified HTTP){RST}")
            else:
                print(f"{W}Unverified{RST}")

    report.candidates = [asdict(c) for c in unique_candidates]
    report.scan_duration_s = round(time.time() - start_time, 2)

    # Summary
    print(f"\n  {B}{'─' * 55}{RST}")
    if report.verified_origins:
        print(f"  {G}{B}✓ ORIGIN IP(s) FOUND:{RST}")
        for ip in report.verified_origins:
            print(f"    {G}{B}→ {ip}{RST}")
        print(f"\n  {W}Manual verification:{RST}")
        print(f"    curl -sI -H \"Host: {domain}\" http://{report.verified_origins[0]}/")
    elif unique_candidates:
        print(f"  {Y}Candidate IPs (unverified):{RST}")
        for c in unique_candidates:
            print(f"    → {c.ip} ({c.source}, {c.confidence})")
        print(f"\n  {W}Try manually:{RST}")
        for c in unique_candidates[:3]:
            print(f"    curl -sI -H \"Host: {domain}\" http://{c.ip}/")
    else:
        print(f"  {R}✗ No origin IP candidates found.{RST}")
        print(f"  {W}Suggestions:{RST}")
        print(f"    • Check email headers from password reset emails")
        print(f"    • Shodan: ssl.cert.subject.cn:\"{domain}\"")
        print(f"    • Censys: services.tls.certificates.leaf.names:{domain}")
        print(f"    • Set SECURITYTRAILS_API_KEY for DNS history")
    print(f"  Scan time: {report.scan_duration_s}s")
    print(f"  {B}{'─' * 55}{RST}")

    return report


# ═══════════════════════════════════════════════════════════════
# SAVE REPORTS
# ═══════════════════════════════════════════════════════════════
def save_reports(reports: list, output_dir: str = "output"):
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_path = os.path.join(output_dir, f"origin_ip_{ts}.json")
    with open(json_path, "w") as f:
        json.dump([asdict(r) for r in reports], f, indent=2, default=str)
    print(f"\n  {G}✓ JSON report: {json_path}{RST}")

    html_path = os.path.join(output_dir, f"origin_ip_{ts}.html")
    with open(html_path, "w") as f:
        f.write(generate_html(reports))
    print(f"  {G}✓ HTML report: {html_path}{RST}")


def generate_html(reports: list) -> str:
    rows = ""
    for r in reports:
        verified = ", ".join(r.verified_origins) if r.verified_origins else "—"
        cands = "<br>".join(f"{c['ip']} ({c['source']}, {c['confidence']})"
                           for c in r.candidates[:10]) or "None found"
        color = "#44ff44" if r.verified_origins else ("#ffaa00" if r.candidates else "#ff4444")
        status = "FOUND" if r.verified_origins else ("CANDIDATES" if r.candidates else "NOT FOUND")

        rows += f"""<tr>
            <td><strong>{r.domain}</strong></td>
            <td>{"Yes — " + r.cdn_provider if r.is_behind_cdn else "No"}</td>
            <td>{', '.join(r.current_ips)}</td>
            <td style="background:{color};color:#000;font-weight:bold;text-align:center">{status}</td>
            <td><strong>{verified}</strong></td>
            <td style="font-size:11px">{cands}</td>
            <td>{', '.join(r.techniques_used)}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Origin IP Report</title>
<style>
body{{font-family:-apple-system,sans-serif;background:#0a0a0a;color:#e0e0e0;padding:30px;max-width:1400px;margin:0 auto}}
h1{{color:#00d4ff;border-bottom:2px solid #00d4ff;padding-bottom:10px}}
table{{border-collapse:collapse;width:100%;margin:20px 0}}
th{{background:#1a1a2e;color:#00d4ff;padding:12px;text-align:left;border:1px solid #333}}
td{{padding:10px;border:1px solid #333;vertical-align:top}}
tr:nth-child(even){{background:#111}}
</style></head><body>
<h1>🌐 Origin IP Disclosure Report</h1>
<p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | Tool: Origin IP Finder v2.0.0</p>
<table>
<tr><th>Domain</th><th>CDN?</th><th>CDN IPs</th><th>Status</th><th>Verified Origin</th><th>All Candidates</th><th>Techniques</th></tr>
{rows}
</table>
</body></html>"""


# ═══════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════
def main():
    global DNS_TIMEOUT
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Origin IP Finder v2.0.0 — Discover real IPs behind CDN/WAF",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -d target.com
  %(prog)s -d target.com --aggressive --threads 20
  %(prog)s -f domains.txt -o results/

Environment Variables:
  SECURITYTRAILS_API_KEY  — DNS history lookups (free tier available)

Bug Bounty Tips:
  Verified origin IP + bypassed WAF = High severity CDN bypass
  Use: curl -sI -H "Host: target.com" http://ORIGIN_IP/
        """
    )
    parser.add_argument("-d", "--domains", nargs="+", help="Domains to scan")
    parser.add_argument("-f", "--file", help="File with domains (one per line)")
    parser.add_argument("--aggressive", action="store_true", help="More thorough scanning")
    parser.add_argument("--threads", type=int, default=10, help="Subdomain scan threads (default: 10)")
    parser.add_argument("--timeout", type=float, default=5.0, help="DNS timeout seconds (default: 5)")
    parser.add_argument("-o", "--output-dir", default="output", help="Output directory")

    args = parser.parse_args()
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

    reports = []
    for domain in domains:
        domain = domain.strip().lower()
        if domain.startswith("http"):
            domain = urlparse(domain).hostname or domain
        reports.append(scan_domain(domain, aggressive=args.aggressive, threads=args.threads))

    save_reports(reports, args.output_dir)

    print(f"\n{B}{'═' * 65}{RST}")
    print(f"  {B}SCAN COMPLETE — {len(reports)} domain(s){RST}")
    found = sum(1 for r in reports if r.verified_origins)
    print(f"  Origins found:    {G}{found}{RST} / {len(reports)}")
    cands = sum(len(r.candidates) for r in reports)
    print(f"  Total candidates: {cands}")
    print(f"{B}{'═' * 65}{RST}\n")


if __name__ == "__main__":
    main()
