#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║           SUBDOMAIN CRAWLER  v1.0.0                             ║
║     Shared Subdomain Discovery Module for All Tools             ║
║                                                                  ║
║  Author : Vishal Rao (@Vishal-HaCkEr1910)                      ║
║  License: MIT — For authorized security testing only            ║
╚══════════════════════════════════════════════════════════════════╝

Reusable subdomain enumeration module. Combines:
  1. DNS brute-force (150+ common prefixes, threaded)
  2. crt.sh certificate transparency logs
  3. DNS zone transfer attempts (AXFR)
  4. TXT/SPF record subdomain extraction

Used by: SPF Checker, Origin IP Finder, Session Tester, Long Password DoS

Usage as standalone:
    python subdomain_crawler.py -d target.com
    python subdomain_crawler.py -d target.com --threads 30 --deep
    python subdomain_crawler.py -d target.com -o output/

Usage as library:
    from subdomain_crawler import SubdomainCrawler
    crawler = SubdomainCrawler("target.com", threads=20)
    subs = crawler.run()   # returns list of {"subdomain": "x.target.com", "ips": [...], "source": "..."}
"""

import argparse
import json
import os
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    R = Fore.RED; G = Fore.GREEN; Y = Fore.YELLOW; C = Fore.CYAN
    M = Fore.MAGENTA; W = Fore.WHITE; B = Style.BRIGHT; RST = Style.RESET_ALL
except ImportError:
    R = G = Y = C = M = W = B = RST = ""

BANNER = f"""{C}{B}
  ███████╗██╗   ██╗██████╗     ██████╗██████╗  █████╗ ██╗    ██╗██╗
  ██╔════╝██║   ██║██╔══██╗   ██╔════╝██╔══██╗██╔══██╗██║    ██║██║
  ███████╗██║   ██║██████╔╝   ██║     ██████╔╝███████║██║ █╗ ██║██║
  ╚════██║██║   ██║██╔══██╗   ██║     ██╔══██╗██╔══██║██║███╗██║██║
  ███████║╚██████╔╝██████╔╝   ╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗
  ╚══════╝ ╚═════╝ ╚═════╝     ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝
{RST}
  {Y}Subdomain Crawler v1.0.0{RST}
  {W}DNS Brute · crt.sh · Zone Transfer · SPF Extraction{RST}
  {R}⚠  AUTHORIZED USE ONLY{RST}
"""

# ═══════════════════════════════════════════════════════════════
# WORDLIST — 150+ common subdomain prefixes
# ═══════════════════════════════════════════════════════════════
COMMON_SUBS = [
    # Infrastructure
    "www", "www1", "www2", "www3", "mail", "email", "webmail", "smtp",
    "pop", "pop3", "imap", "mx", "mx1", "mx2",
    # Services
    "ftp", "sftp", "ssh", "vpn", "remote", "rdp", "git", "svn",
    "jenkins", "ci", "cd", "gitlab", "bitbucket",
    # Admin / Management
    "admin", "administrator", "panel", "cpanel", "whm", "plesk",
    "manage", "manager", "dashboard", "portal", "cms",
    # Development
    "dev", "development", "staging", "stage", "test", "testing",
    "qa", "uat", "sandbox", "demo", "beta", "alpha", "preview",
    "preprod", "pre-prod", "canary",
    # Production variants
    "app", "application", "api", "api2", "api3", "apis",
    "rest", "graphql", "gateway", "proxy", "load", "lb",
    # Subdomains
    "m", "mobile", "wap", "mobi",
    "blog", "forum", "forums", "community", "social",
    "shop", "store", "cart", "ecommerce", "pay", "payment",
    "help", "support", "helpdesk", "ticket", "tickets",
    "docs", "doc", "documentation", "wiki", "kb", "knowledge",
    "status", "health", "uptime", "monitor", "monitoring",
    # Database / Storage
    "db", "database", "mysql", "postgres", "pgsql", "mongo",
    "redis", "elastic", "elasticsearch", "kibana", "grafana",
    "solr", "memcache", "cache",
    # Auth
    "auth", "login", "sso", "oauth", "id", "identity", "accounts",
    "signup", "register",
    # CDN / Static
    "cdn", "static", "assets", "media", "images", "img", "files",
    "download", "downloads", "upload", "uploads", "content",
    # Old / Backup
    "old", "legacy", "backup", "bak", "archive", "temp",
    # DNS
    "ns", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
    # Network
    "direct", "origin", "real", "backend", "internal", "intranet",
    "private", "corp", "corporate", "office",
    # Security
    "secure", "ssl", "waf", "firewall",
    # Analytics
    "analytics", "tracking", "stats", "log", "logs", "syslog",
    # Services
    "crm", "erp", "hr", "jira", "confluence", "slack", "chat",
    # Cloud
    "aws", "azure", "gcp", "cloud", "s3", "storage",
    # Misc
    "web", "web1", "web2", "server", "server1", "server2",
    "node", "node1", "node2", "host", "host1",
    "new", "v2", "v3", "next", "prod", "live",
]

# Extended wordlist for --deep mode
DEEP_SUBS = COMMON_SUBS + [
    "autodiscover", "autoconfig", "exchange", "owa", "outlook",
    "lyncdiscover", "sip", "meet", "dial", "voip", "pbx",
    "citrix", "ica", "terminal", "rds", "bastion", "jump",
    "nagios", "zabbix", "prometheus", "datadog", "newrelic",
    "splunk", "logstash", "graylog", "sentry",
    "sonar", "sonarqube", "nexus", "artifactory", "harbor",
    "vault", "consul", "terraform", "ansible", "puppet",
    "docker", "k8s", "kubernetes", "rancher", "portainer",
    "minio", "rabbitmq", "kafka", "activemq", "nats",
    "proxy1", "proxy2", "haproxy", "nginx", "apache", "traefik",
    "www-test", "www-dev", "www-staging", "api-dev", "api-staging",
    "api-test", "app-dev", "app-staging", "app-test",
    "dev1", "dev2", "dev3", "stage1", "stage2",
    "int", "integration", "perf", "performance", "stress",
    "dr", "disaster", "failover", "mirror", "replica",
    "report", "reports", "reporting", "bi", "tableau", "metabase",
    "survey", "feedback", "review", "reviews",
    "booking", "reservation", "calendar", "event", "events",
    "news", "press", "media2", "video", "stream", "streaming",
    "podcast", "radio", "tv",
    "jobs", "careers", "hiring", "recruit",
    "partner", "partners", "affiliate", "affiliates", "reseller",
    "investor", "ir", "compliance", "legal", "privacy",
    "sandbox1", "sandbox2", "lab", "labs", "research",
    "edu", "learn", "learning", "training", "academy", "course",
    "marketplace", "market", "auction",
]


# ═══════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════
@dataclass
class SubdomainResult:
    subdomain: str
    ips: list = field(default_factory=list)
    source: str = ""
    alive: bool = False
    http_status: int = 0
    title: str = ""
    server: str = ""
    has_login: bool = False
    login_url: str = ""


@dataclass
class CrawlReport:
    domain: str = ""
    total_found: int = 0
    alive_count: int = 0
    sources: dict = field(default_factory=dict)
    subdomains: list = field(default_factory=list)
    login_endpoints: list = field(default_factory=list)
    timestamp: str = ""
    scan_duration_s: float = 0.0


# ═══════════════════════════════════════════════════════════════
# SUBDOMAIN CRAWLER CLASS
# ═══════════════════════════════════════════════════════════════
class SubdomainCrawler:
    def __init__(self, domain: str, threads: int = 20, timeout: float = 5.0,
                 deep: bool = False, check_alive: bool = True,
                 find_logins: bool = False, verbose: bool = False):
        self.domain = domain.strip().lower()
        self.threads = threads
        self.timeout = timeout
        self.wordlist = DEEP_SUBS if deep else COMMON_SUBS
        self.check_alive = check_alive
        self.find_logins = find_logins
        self.verbose = verbose
        self.found = {}  # subdomain -> SubdomainResult

    def _log(self, msg: str):
        if self.verbose:
            print(f"    {W}[v] {msg}{RST}")

    # ─── DNS Brute Force ───
    def _resolve_sub(self, prefix: str) -> Optional[SubdomainResult]:
        fqdn = f"{prefix}.{self.domain}"
        try:
            ips = list(set(
                info[4][0] for info in socket.getaddrinfo(fqdn, None, socket.AF_INET)
            ))
            if ips:
                return SubdomainResult(subdomain=fqdn, ips=ips, source="dns_brute")
        except (socket.gaierror, OSError):
            pass
        return None

    def dns_bruteforce(self) -> list:
        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._resolve_sub, prefix): prefix
                       for prefix in self.wordlist}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        self._log(f"DNS: {result.subdomain} → {', '.join(result.ips)}")
                except Exception:
                    pass
        return results

    # ─── crt.sh Certificate Transparency ───
    def crtsh_lookup(self) -> list:
        results = []
        if not HAS_REQUESTS:
            return results
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{self.domain}&output=json",
                timeout=15,
                headers={"User-Agent": "Mozilla/5.0 (Security Audit)"}
            )
            if resp.status_code == 200:
                data = resp.json()
                seen = set()
                for entry in data:
                    name = entry.get("name_value", "").strip().lower()
                    # crt.sh can return multiple names separated by newlines
                    for sub in name.split("\n"):
                        sub = sub.strip().lstrip("*.")
                        if sub.endswith(f".{self.domain}") and sub not in seen:
                            seen.add(sub)
                            # Resolve IP
                            ips = []
                            try:
                                ips = list(set(
                                    info[4][0] for info in socket.getaddrinfo(sub, None, socket.AF_INET)
                                ))
                            except Exception:
                                pass
                            if ips:
                                results.append(SubdomainResult(
                                    subdomain=sub, ips=ips, source="crt.sh"
                                ))
                                self._log(f"crt.sh: {sub} → {', '.join(ips)}")
        except Exception as e:
            self._log(f"crt.sh error: {e}")
        return results

    # ─── DNS Zone Transfer (AXFR) ───
    def zone_transfer(self) -> list:
        results = []
        if not HAS_DNS:
            return results
        try:
            ns_records = dns.resolver.resolve(self.domain, "NS")
            for ns in ns_records:
                ns_str = str(ns).rstrip(".")
                try:
                    import dns.zone
                    import dns.query
                    zone = dns.zone.from_xfr(
                        dns.query.xfr(ns_str, self.domain, timeout=self.timeout)
                    )
                    for name, node in zone.nodes.items():
                        fqdn = f"{name}.{self.domain}".strip(".")
                        if fqdn != self.domain:
                            ips = []
                            try:
                                ips = list(set(
                                    info[4][0] for info in socket.getaddrinfo(fqdn, None, socket.AF_INET)
                                ))
                            except Exception:
                                pass
                            results.append(SubdomainResult(
                                subdomain=fqdn, ips=ips, source="zone_transfer"
                            ))
                            self._log(f"AXFR: {fqdn}")
                except Exception:
                    pass
        except Exception:
            pass
        return results

    # ─── SPF/TXT Record Subdomain Extraction ───
    def spf_extraction(self) -> list:
        results = []
        if not HAS_DNS:
            return results
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            txt_records = resolver.resolve(self.domain, "TXT")
            for rec in txt_records:
                txt = str(rec).strip('"')
                # Extract include: domains that may be subdomains
                includes = re.findall(r'include:(\S+)', txt, re.I)
                for inc in includes:
                    if inc.endswith(f".{self.domain}"):
                        ips = []
                        try:
                            ips = list(set(
                                info[4][0] for info in socket.getaddrinfo(inc, None, socket.AF_INET)
                            ))
                        except Exception:
                            pass
                        results.append(SubdomainResult(
                            subdomain=inc, ips=ips, source="spf_record"
                        ))
                        self._log(f"SPF: {inc}")
        except Exception:
            pass
        return results

    # ─── HTTP Alive Check + Login Detection ───
    def _check_alive(self, result: SubdomainResult) -> SubdomainResult:
        if not HAS_REQUESTS:
            return result
        for scheme in ["https", "http"]:
            try:
                resp = requests.get(
                    f"{scheme}://{result.subdomain}",
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False,
                    headers={"User-Agent": "Mozilla/5.0 (Security Audit)"}
                )
                result.alive = True
                result.http_status = resp.status_code
                result.server = resp.headers.get("Server", "")

                # Extract title
                title_match = re.search(r'<title[^>]*>([^<]+)</title>', resp.text, re.I)
                if title_match:
                    result.title = title_match.group(1).strip()[:100]

                # Detect login forms
                if self.find_logins:
                    login_patterns = [
                        r'<form[^>]*(?:login|signin|auth|log-in|sign-in)',
                        r'<input[^>]*type=["\']password["\']',
                        r'name=["\'](?:username|email|login|user)["\'].*name=["\'](?:password|passwd|pass)["\']',
                        r'(?:login|signin|log-in|sign-in|authenticate)',
                    ]
                    text_lower = resp.text.lower()
                    for pattern in login_patterns:
                        if re.search(pattern, text_lower):
                            result.has_login = True
                            result.login_url = f"{scheme}://{result.subdomain}"
                            break

                    # Also check common login paths
                    if not result.has_login:
                        login_paths = ["/login", "/signin", "/auth/login", "/admin/login",
                                      "/user/login", "/account/login", "/api/login",
                                      "/wp-login.php", "/admin", "/panel"]
                        for path in login_paths:
                            try:
                                r2 = requests.get(
                                    f"{scheme}://{result.subdomain}{path}",
                                    timeout=self.timeout // 2,
                                    allow_redirects=True,
                                    verify=False,
                                    headers={"User-Agent": "Mozilla/5.0"}
                                )
                                if r2.status_code == 200 and (
                                    'type="password"' in r2.text.lower() or
                                    'type=\'password\'' in r2.text.lower()
                                ):
                                    result.has_login = True
                                    result.login_url = f"{scheme}://{result.subdomain}{path}"
                                    self._log(f"Login found: {result.login_url}")
                                    break
                            except Exception:
                                pass

                break  # Only need one successful scheme
            except Exception:
                continue
        return result

    # ─── Main Run ───
    def run(self, silent: bool = False) -> list:
        start_time = time.time()
        all_results = {}

        if not silent:
            print(f"\n  {C}{B}Subdomain Enumeration: {self.domain}{RST}")
            print(f"  Wordlist: {len(self.wordlist)} prefixes | Threads: {self.threads}")

        # Phase 1: DNS brute force
        if not silent:
            print(f"  {Y}[1/4]{RST} DNS brute-force ({len(self.wordlist)} subs)...", end=" ", flush=True)
        dns_results = self.dns_bruteforce()
        for r in dns_results:
            if r.subdomain not in all_results:
                all_results[r.subdomain] = r
        if not silent:
            print(f"{G}{len(dns_results)} found{RST}")

        # Phase 2: crt.sh
        if not silent:
            print(f"  {Y}[2/4]{RST} crt.sh certificate transparency...", end=" ", flush=True)
        crt_results = self.crtsh_lookup()
        for r in crt_results:
            if r.subdomain not in all_results:
                all_results[r.subdomain] = r
        if not silent:
            print(f"{G}{len(crt_results)} found ({len(all_results)} unique total){RST}")

        # Phase 3: Zone transfer
        if not silent:
            print(f"  {Y}[3/4]{RST} DNS zone transfer attempt...", end=" ", flush=True)
        zt_results = self.zone_transfer()
        for r in zt_results:
            if r.subdomain not in all_results:
                all_results[r.subdomain] = r
        if not silent:
            transferred = "protected" if not zt_results else f"{len(zt_results)} found!"
            print(f"{G if not zt_results else R}{transferred}{RST}")

        # Phase 4: SPF extraction
        if not silent:
            print(f"  {Y}[4/4]{RST} SPF/TXT record extraction...", end=" ", flush=True)
        spf_results = self.spf_extraction()
        for r in spf_results:
            if r.subdomain not in all_results:
                all_results[r.subdomain] = r
        if not silent:
            print(f"{G}{len(spf_results)} found{RST}")

        results_list = list(all_results.values())

        # Alive check
        if self.check_alive and results_list:
            if not silent:
                print(f"\n  {Y}Checking {len(results_list)} subdomains alive...{RST}")
            with ThreadPoolExecutor(max_workers=self.threads) as pool:
                futures = {pool.submit(self._check_alive, r): r for r in results_list}
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception:
                        pass

        alive = [r for r in results_list if r.alive]
        logins = [r for r in results_list if r.has_login]
        elapsed = round(time.time() - start_time, 2)

        if not silent:
            print(f"\n  {B}{'─' * 55}{RST}")
            print(f"  {B}Total subdomains: {len(results_list)}{RST}")
            print(f"  {B}Alive (HTTP):     {G}{len(alive)}{RST}")
            if logins:
                print(f"  {B}Login endpoints:  {Y}{len(logins)}{RST}")
                for l in logins:
                    print(f"    → {l.login_url}")
            print(f"  Scan time: {elapsed}s")
            print(f"  {B}{'─' * 55}{RST}")

        return results_list

    def get_alive_subdomains(self) -> list:
        """Return only alive subdomain FQDNs."""
        results = self.run(silent=True)
        return [r.subdomain for r in results if r.alive]

    def get_login_endpoints(self) -> list:
        """Return login URLs discovered on subdomains."""
        self.find_logins = True
        results = self.run(silent=True)
        return [r.login_url for r in results if r.has_login and r.login_url]

    def get_all_domains_for_spf(self) -> list:
        """Return domain + all alive subdomains for SPF scanning."""
        results = self.run(silent=True)
        domains = [self.domain]
        for r in results:
            # Extract the subdomain prefix for email-related scanning
            sub = r.subdomain
            if sub != self.domain and r.alive:
                domains.append(sub)
        return domains


# ═══════════════════════════════════════════════════════════════
# SAVE REPORTS
# ═══════════════════════════════════════════════════════════════
def save_report(report: CrawlReport, output_dir: str = "output"):
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_path = os.path.join(output_dir, f"subdomains_{report.domain}_{ts}.json")
    with open(json_path, "w") as f:
        json.dump(asdict(report), f, indent=2, default=str)
    print(f"\n  {G}✓ JSON report: {json_path}{RST}")

    html_path = os.path.join(output_dir, f"subdomains_{report.domain}_{ts}.html")
    with open(html_path, "w") as f:
        f.write(generate_html(report))
    print(f"  {G}✓ HTML report: {html_path}{RST}")


def generate_html(report: CrawlReport) -> str:
    rows = ""
    for s in report.subdomains:
        if isinstance(s, dict):
            sub = s.get("subdomain", "?")
            ips = ", ".join(s.get("ips", []))
            source = s.get("source", "?")
            alive = s.get("alive", False)
            status = s.get("http_status", 0)
            title = s.get("title", "")
            server = s.get("server", "")
            login = s.get("login_url", "")
        else:
            sub, ips, source = s.subdomain, ", ".join(s.ips), s.source
            alive, status, title = s.alive, s.http_status, s.title
            server, login = s.server, s.login_url

        color = "#44ff44" if alive else "#666"
        login_badge = f' <span style="background:#ff4444;padding:2px 6px;border-radius:3px;font-size:11px">LOGIN</span>' if login else ""

        rows += f"""<tr>
            <td><strong style="color:{color}">{sub}</strong>{login_badge}</td>
            <td>{ips}</td>
            <td>{source}</td>
            <td>{'✅' if alive else '❌'}</td>
            <td>{status or '—'}</td>
            <td>{title or '—'}</td>
            <td>{server or '—'}</td>
            <td>{login or '—'}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Subdomain Report — {report.domain}</title>
<style>
body{{font-family:-apple-system,sans-serif;background:#0a0a0a;color:#e0e0e0;padding:30px;max-width:1600px;margin:0 auto}}
h1{{color:#00d4ff;border-bottom:2px solid #00d4ff;padding-bottom:10px}}
table{{border-collapse:collapse;width:100%;margin:20px 0}}
th{{background:#1a1a2e;color:#00d4ff;padding:12px;text-align:left;border:1px solid #333}}
td{{padding:8px;border:1px solid #333;vertical-align:top;font-size:13px}}
tr:nth-child(even){{background:#111}}
.stats{{display:flex;gap:30px;margin:20px 0}}
.stat{{background:#1a1a2e;padding:15px 25px;border-radius:8px;text-align:center}}
.stat h2{{color:#00d4ff;margin:0;font-size:28px}}
.stat p{{margin:5px 0 0;color:#aaa;font-size:13px}}
</style></head><body>
<h1>🌐 Subdomain Report — {report.domain}</h1>
<p>Generated: {report.timestamp} | Scan time: {report.scan_duration_s}s</p>
<div class="stats">
<div class="stat"><h2>{report.total_found}</h2><p>Total Found</p></div>
<div class="stat"><h2>{report.alive_count}</h2><p>Alive</p></div>
<div class="stat"><h2>{len(report.login_endpoints)}</h2><p>Login Endpoints</p></div>
</div>
<table>
<tr><th>Subdomain</th><th>IPs</th><th>Source</th><th>Alive</th><th>HTTP</th><th>Title</th><th>Server</th><th>Login URL</th></tr>
{rows}
</table>
<p style="color:#666;font-size:12px">⚠ For authorized security testing only.</p>
</body></html>"""


# ═══════════════════════════════════════════════════════════════
# CLI (standalone mode)
# ═══════════════════════════════════════════════════════════════
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Subdomain Crawler v1.0.0 — Multi-source subdomain enumeration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -d target.com
  %(prog)s -d target.com --deep --threads 30
  %(prog)s -d target.com --find-logins
  %(prog)s -d target.com -o results/ --verbose

Sources:
  DNS brute-force (150+ prefixes) | crt.sh | Zone transfer | SPF records
        """
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("--threads", type=int, default=20, help="Thread count (default: 20)")
    parser.add_argument("--timeout", type=float, default=5.0, help="Timeout seconds (default: 5)")
    parser.add_argument("--deep", action="store_true", help="Use extended wordlist (250+ prefixes)")
    parser.add_argument("--no-alive", action="store_true", help="Skip HTTP alive check")
    parser.add_argument("--find-logins", action="store_true", help="Detect login forms on subdomains")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("-o", "--output-dir", default="output", help="Output directory")

    args = parser.parse_args()

    domain = args.domain.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).hostname or domain

    crawler = SubdomainCrawler(
        domain=domain,
        threads=args.threads,
        timeout=args.timeout,
        deep=args.deep,
        check_alive=not args.no_alive,
        find_logins=args.find_logins,
        verbose=args.verbose
    )

    results = crawler.run()

    # Build report
    report = CrawlReport(
        domain=domain,
        total_found=len(results),
        alive_count=sum(1 for r in results if r.alive),
        subdomains=[asdict(r) for r in results],
        login_endpoints=[r.login_url for r in results if r.has_login],
        timestamp=datetime.now().isoformat(),
        scan_duration_s=round(time.time() - time.time(), 2)
    )

    # Source stats
    for r in results:
        src = r.source
        report.sources[src] = report.sources.get(src, 0) + 1

    # Print table
    print(f"\n  {C}{B}{'Subdomain':<45} {'IPs':<20} {'Source':<12} {'Alive':<6} {'HTTP':<5} {'Title'}{RST}")
    print(f"  {'─' * 120}")
    for r in sorted(results, key=lambda x: (not x.alive, x.subdomain)):
        alive_str = f"{G}✓{RST}" if r.alive else f"{R}✗{RST}"
        ip_str = ", ".join(r.ips[:2]) + ("..." if len(r.ips) > 2 else "")
        login_badge = f" {R}[LOGIN]{RST}" if r.has_login else ""
        print(f"  {r.subdomain:<45} {ip_str:<20} {r.source:<12} {alive_str:<6} "
              f"{r.http_status or '—':<5} {r.title[:40]}{login_badge}")

    # Save
    save_report(report, args.output_dir)

    print(f"\n{B}{'═' * 65}{RST}")
    print(f"  {B}SCAN COMPLETE{RST}")
    print(f"  Domain:      {domain}")
    print(f"  Total found: {len(results)}")
    print(f"  Alive:       {report.alive_count}")
    print(f"  Logins:      {len(report.login_endpoints)}")
    print(f"  Sources:     {report.sources}")
    print(f"{B}{'═' * 65}{RST}\n")


if __name__ == "__main__":
    main()
