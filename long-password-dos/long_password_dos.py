#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║         LONG PASSWORD DoS TESTER  v2.0.0                        ║
║      Detect Password Length-Based Denial of Service             ║
║                                                                  ║
║  Author : Vishal Rao (@Vishal-HaCkEr1910)                      ║
║  License: MIT — For authorized security testing only            ║
╚══════════════════════════════════════════════════════════════════╝

Industry-standard long password DoS detector. Tests login/register
endpoints for denial-of-service via extremely long passwords. Features:
  - Escalating password sizes (10 → 1M chars)
  - Baseline comparison with timing analysis
  - Request body size tracking
  - Multiple-run averaging for accuracy
  - Concurrency stress test (ThreadPoolExecutor)
  - Custom headers, proxy, and delay support
  - JSON + HTML reports with timing tables

Usage:
    python long_password_dos.py -u https://target.com/login
    python long_password_dos.py -u https://target.com/api/login --json --username test@test.com
    python long_password_dos.py -u https://target.com/login --concurrent 10 --proxy http://127.0.0.1:8080
"""

import argparse
import json
import os
import sys
import time
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    R = Fore.RED; G = Fore.GREEN; Y = Fore.YELLOW; C = Fore.CYAN
    M = Fore.MAGENTA; W = Fore.WHITE; B = Style.BRIGHT; RST = Style.RESET_ALL
except ImportError:
    R = G = Y = C = M = W = B = RST = ""

BANNER = f"""{C}{B}
  ██████╗  ██████╗ ███████╗    ██████╗  █████╗ ███████╗███████╗
  ██╔══██╗██╔═══██╗██╔════╝    ██╔══██╗██╔══██╗██╔════╝██╔════╝
  ██║  ██║██║   ██║███████╗    ██████╔╝███████║███████╗███████╗
  ██║  ██║██║   ██║╚════██║    ██╔═══╝ ██╔══██║╚════██║╚════██║
  ██████╔╝╚██████╔╝███████║    ██║     ██║  ██║███████║███████║
  ╚═════╝  ╚═════╝ ╚══════╝    ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝
{RST}
  {Y}Long Password DoS Tester v2.0.0{RST}
  {W}Timing Analysis · Body Size · Concurrency · Multi-Run Averaging{RST}
  {R}⚠  AUTHORIZED USE ONLY — Do not overwhelm target servers{RST}
"""

DEFAULT_SIZES = [10, 100, 1000, 5000, 10000, 50000, 100000, 500000, 1000000]


# ═══════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════
@dataclass
class SizeResult:
    size: int
    size_human: str
    response_time_ms: float
    status_code: int
    response_length: int
    request_body_size: int = 0
    slowdown_factor: float = 0.0
    error: str = ""
    timed_out: bool = False


@dataclass
class ConcurrencyResult:
    concurrent_requests: int
    password_size: int
    avg_response_ms: float
    max_response_ms: float
    min_response_ms: float
    errors: int = 0
    timeouts: int = 0
    slowdown_factor: float = 0.0


@dataclass
class DoSReport:
    target_url: str = ""
    method: str = "POST"
    content_type: str = ""
    baseline_ms: float = 0.0
    baseline_runs: int = 3
    results: list = field(default_factory=list)
    concurrency_results: list = field(default_factory=list)
    vulnerable: bool = False
    severity: str = "NONE"
    max_slowdown_factor: float = 1.0
    password_length_limit: str = "NONE"
    recommendations: list = field(default_factory=list)
    timestamp: str = ""
    scan_duration_s: float = 0.0


# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════
def human_size(chars: int) -> str:
    if chars >= 1_000_000:
        return f"{chars/1_000_000:.1f}M"
    elif chars >= 1_000:
        return f"{chars/1_000:.0f}K"
    return str(chars)


def generate_password(length: int) -> str:
    chunk = "Aa1!Bb2@Cc3#Dd4$Ee5%Ff6^Gg7&Hh8*"
    repeats = (length // len(chunk)) + 1
    return (chunk * repeats)[:length]


# ═══════════════════════════════════════════════════════════════
# SINGLE REQUEST
# ═══════════════════════════════════════════════════════════════
def send_login_request(url: str, username: str, password: str,
                       username_field: str, password_field: str,
                       use_json: bool, timeout: int,
                       extra_headers: dict = None,
                       proxy: dict = None) -> SizeResult:
    size = len(password)
    result = SizeResult(
        size=size, size_human=human_size(size),
        response_time_ms=0, status_code=0, response_length=0
    )

    headers = {"User-Agent": "Mozilla/5.0 (Security Audit)"}
    if extra_headers:
        headers.update(extra_headers)

    try:
        start = time.perf_counter()

        if use_json:
            headers["Content-Type"] = "application/json"
            body = json.dumps({username_field: username, password_field: password})
            result.request_body_size = len(body)
            resp = requests.post(url, data=body, headers=headers,
                                timeout=timeout, verify=False, proxies=proxy)
        else:
            data = {username_field: username, password_field: password}
            result.request_body_size = sum(len(k) + len(v) + 2 for k, v in data.items())
            resp = requests.post(url, data=data, headers=headers,
                                timeout=timeout, verify=False, proxies=proxy)

        elapsed = time.perf_counter() - start
        result.response_time_ms = round(elapsed * 1000, 2)
        result.status_code = resp.status_code
        result.response_length = len(resp.text)

    except requests.exceptions.Timeout:
        result.timed_out = True
        result.error = "TIMEOUT"
        result.response_time_ms = timeout * 1000
    except requests.exceptions.ConnectionError as e:
        result.error = f"Connection error: {str(e)[:80]}"
    except Exception as e:
        result.error = str(e)[:100]

    return result


# ═══════════════════════════════════════════════════════════════
# MAIN SCANNER
# ═══════════════════════════════════════════════════════════════
class DoSTester:
    def __init__(self, url: str, username: str = "test@test.com",
                 username_field: str = "username", password_field: str = "password",
                 use_json: bool = False, timeout: int = 30,
                 delay: float = 0.5, runs: int = 3,
                 proxy: str = None, headers: dict = None):
        self.url = url
        self.username = username
        self.username_field = username_field
        self.password_field = password_field
        self.use_json = use_json
        self.timeout = timeout
        self.delay = delay
        self.runs = max(1, runs)
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.extra_headers = headers or {}
        self.report = DoSReport(
            target_url=url,
            method="POST",
            content_type="application/json" if use_json else "application/x-www-form-urlencoded",
            baseline_runs=self.runs,
            timestamp=datetime.now().isoformat()
        )

    def _avg_request(self, password: str) -> SizeResult:
        """Send multiple requests and average the timing for accuracy."""
        times = []
        last_result = None
        for _ in range(self.runs):
            result = send_login_request(
                self.url, self.username, password,
                self.username_field, self.password_field,
                self.use_json, self.timeout,
                self.extra_headers, self.proxy
            )
            if not result.error:
                times.append(result.response_time_ms)
            last_result = result
            if self.delay > 0:
                time.sleep(self.delay)

        if times and last_result:
            last_result.response_time_ms = round(statistics.mean(times), 2)
        return last_result

    def run_size_test(self, sizes: list = None) -> list:
        sizes = sizes or DEFAULT_SIZES
        results = []

        print(f"\n  {C}{B}Phase 1: Password Length vs Response Time{RST}")
        print(f"  Averaging {self.runs} run(s) per size | Delay: {self.delay}s")
        print(f"  {'─' * 70}")
        print(f"  {'Size':>10} │ {'Body (KB)':>10} │ {'Time (ms)':>12} │ {'Slowdown':>9} │ {'Status':>7} │ {'Notes'}")
        print(f"  {'─' * 70}")

        # Baseline
        baseline_result = self._avg_request("normalPassword123!")
        self.report.baseline_ms = baseline_result.response_time_ms if baseline_result else 0
        base_ms = self.report.baseline_ms
        body_kb = (baseline_result.request_body_size / 1024) if baseline_result else 0
        print(f"  {'8 (base)':>10} │ {body_kb:>8.1f}KB │ {base_ms:>10.1f}ms │ {'1.0x':>9} │ "
              f"HTTP {baseline_result.status_code if baseline_result else '???':>3} │ Baseline")

        if not baseline_result or baseline_result.error:
            print(f"\n  {R}✗ Baseline request failed: {baseline_result.error if baseline_result else 'unknown'}{RST}")
            print(f"  {Y}Check the URL, fields, and content type.{RST}")
            return results

        for size in sizes:
            password = generate_password(size)
            result = self._avg_request(password)
            if not result:
                continue

            # Calculate slowdown
            if base_ms > 0:
                result.slowdown_factor = round(result.response_time_ms / base_ms, 2)

            results.append(result)

            # Notes
            if result.timed_out:
                note = f"{R}⚠ TIMEOUT!{RST}"
            elif result.error:
                note = f"{R}{result.error[:30]}{RST}"
            elif result.slowdown_factor > 10:
                note = f"{R}⚠ {result.slowdown_factor}x slower!{RST}"
            elif result.slowdown_factor > 3:
                note = f"{Y}⚠ {result.slowdown_factor}x slower{RST}"
            elif result.status_code in (413, 414, 400):
                note = f"{G}Server rejects (limit){RST}"
            else:
                note = ""

            body_kb = result.request_body_size / 1024
            time_color = R if result.response_time_ms > 5000 else (
                Y if result.response_time_ms > 2000 else W)
            slow_color = R if result.slowdown_factor > 10 else (
                Y if result.slowdown_factor > 3 else W)

            print(f"  {human_size(size):>10} │ {body_kb:>8.1f}KB │ "
                  f"{time_color}{result.response_time_ms:>10.1f}ms{RST} │ "
                  f"{slow_color}{result.slowdown_factor:>8.1f}x{RST} │ "
                  f"HTTP {result.status_code:>3} │ {note}")

            if result.status_code in (413, 414, 400):
                self.report.password_length_limit = f"Rejected at {human_size(size)} (HTTP {result.status_code})"
                print(f"\n  {G}✓ Server enforces password length limit — stopping{RST}")
                break

            if result.timed_out:
                print(f"\n  {R}⚠ Server timed out at {human_size(size)} — stopping{RST}")
                break

            if self.delay > 0:
                time.sleep(self.delay)

        print(f"  {'─' * 70}")
        self.report.results = [asdict(r) for r in results]
        return results

    def run_concurrency_test(self, concurrent: int = 5,
                              password_size: int = 100000) -> ConcurrencyResult:
        print(f"\n  {C}{B}Phase 2: Concurrency Test ({concurrent} simultaneous requests){RST}")
        print(f"  Password size: {human_size(password_size)} chars")

        password = generate_password(password_size)
        times = []
        errors = 0
        timeouts = 0

        with ThreadPoolExecutor(max_workers=concurrent) as pool:
            futures = []
            for _ in range(concurrent):
                f = pool.submit(
                    send_login_request,
                    self.url, self.username, password,
                    self.username_field, self.password_field,
                    self.use_json, self.timeout,
                    self.extra_headers, self.proxy
                )
                futures.append(f)

            for f in as_completed(futures):
                result = f.result()
                if result.error:
                    errors += 1
                    if result.timed_out:
                        timeouts += 1
                else:
                    times.append(result.response_time_ms)

        avg_ms = statistics.mean(times) if times else 0
        max_ms = max(times) if times else 0
        min_ms = min(times) if times else 0
        slowdown = round(avg_ms / self.report.baseline_ms, 2) if self.report.baseline_ms > 0 else 0

        cr = ConcurrencyResult(
            concurrent_requests=concurrent,
            password_size=password_size,
            avg_response_ms=round(avg_ms, 2),
            max_response_ms=round(max_ms, 2),
            min_response_ms=round(min_ms, 2),
            errors=errors, timeouts=timeouts,
            slowdown_factor=slowdown
        )
        self.report.concurrency_results.append(asdict(cr))

        print(f"\n  Results:")
        if times:
            print(f"    Avg response: {Y}{avg_ms:.0f}ms{RST}  ({slowdown}x baseline)")
            print(f"    Max response: {R if max_ms > 5000 else Y}{max_ms:.0f}ms{RST}")
            print(f"    Min response: {min_ms:.0f}ms")
        print(f"    Errors: {errors}  |  Timeouts: {timeouts}")

        if slowdown > 5:
            print(f"    {R}⚠ Concurrent long passwords cause {slowdown}x slowdown!{RST}")

        return cr

    def analyze(self):
        if not self.report.results:
            return

        results = [SizeResult(**r) if isinstance(r, dict) else r for r in self.report.results]
        baseline = self.report.baseline_ms
        self.report.scan_duration_s = round(time.time() - time.time(), 2)  # Will be set by caller

        if baseline <= 0:
            self.report.severity = "INCONCLUSIVE"
            return

        valid_results = [r for r in results if not r.error]
        if not valid_results:
            self.report.severity = "INCONCLUSIVE"
            return

        max_time = max(r.response_time_ms for r in valid_results)
        self.report.max_slowdown_factor = round(max_time / baseline, 2) if baseline > 0 else 0

        if self.report.password_length_limit != "NONE":
            self.report.vulnerable = False
            self.report.severity = "NONE"
            self.report.recommendations = ["Server enforces password length limit ✓"]
        elif any(r.timed_out for r in results):
            self.report.vulnerable = True
            self.report.severity = "HIGH"
            self.report.recommendations = [
                "Implement max password length (128-256 chars) BEFORE hashing",
                "Add request body size limits at web server level (nginx: client_max_body_size)",
                "Add rate limiting on authentication endpoints",
                "Consider pre-hashing (SHA-256) before bcrypt to cap input size",
            ]
        elif self.report.max_slowdown_factor > 10:
            self.report.vulnerable = True
            self.report.severity = "MEDIUM"
            self.report.recommendations = [
                "Implement max password length (128-256 chars)",
                "Reject oversized passwords before hashing",
                "Add rate limiting on auth endpoints",
            ]
        elif self.report.max_slowdown_factor > 3:
            self.report.vulnerable = True
            self.report.severity = "LOW"
            self.report.recommendations = [
                "Consider implementing a max password length",
                "Monitor for abuse on authentication endpoints",
            ]
        else:
            self.report.vulnerable = False
            self.report.severity = "NONE"

        # Concurrency verdict
        for cr_dict in self.report.concurrency_results:
            cr = ConcurrencyResult(**cr_dict) if isinstance(cr_dict, dict) else cr_dict
            if cr.timeouts > 0 or cr.slowdown_factor > 10:
                if self.report.severity == "NONE":
                    self.report.severity = "MEDIUM"
                    self.report.vulnerable = True
                    self.report.recommendations.append(
                        "Concurrent long-password requests cause significant server load"
                    )

        vuln_color = R if self.report.vulnerable else G
        sev_color = R if self.report.severity in ("HIGH", "MEDIUM") else (
            Y if self.report.severity == "LOW" else G)

        print(f"\n  {B}{'═' * 60}{RST}")
        print(f"  {B}VERDICT{RST}")
        print(f"    Vulnerable:     {vuln_color}{B}{'YES' if self.report.vulnerable else 'NO'}{RST}")
        print(f"    Severity:       {sev_color}{B}{self.report.severity}{RST}")
        print(f"    Max slowdown:   {self.report.max_slowdown_factor}x baseline")
        print(f"    Baseline:       {self.report.baseline_ms:.0f}ms (avg of {self.report.baseline_runs} runs)")
        print(f"    Length limit:   {self.report.password_length_limit}")
        if self.report.recommendations:
            print(f"\n    {Y}Recommendations:{RST}")
            for rec in self.report.recommendations:
                print(f"      • {rec}")
        print(f"  {B}{'═' * 60}{RST}")


# ═══════════════════════════════════════════════════════════════
# SAVE REPORTS
# ═══════════════════════════════════════════════════════════════
def save_report(report: DoSReport, output_dir: str = "output"):
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_path = os.path.join(output_dir, f"dos_test_{ts}.json")
    with open(json_path, "w") as f:
        json.dump(asdict(report), f, indent=2, default=str)
    print(f"\n  {G}✓ JSON report: {json_path}{RST}")

    html_path = os.path.join(output_dir, f"dos_test_{ts}.html")
    with open(html_path, "w") as f:
        f.write(generate_html(report))
    print(f"  {G}✓ HTML report: {html_path}{RST}")


def generate_html(report: DoSReport) -> str:
    rows = ""
    for r in report.results:
        if isinstance(r, dict):
            size_h, time_ms, status, error = r.get("size_human",""), r.get("response_time_ms",0), r.get("status_code",0), r.get("error","")
            body_kb, slowdown = r.get("request_body_size", 0) / 1024, r.get("slowdown_factor", 0)
        else:
            size_h, time_ms, status, error = r.size_human, r.response_time_ms, r.status_code, r.error
            body_kb, slowdown = r.request_body_size / 1024, r.slowdown_factor

        color = "#ff4444" if time_ms > 5000 else ("#ffaa00" if time_ms > 2000 else "#44ff44")
        rows += f"""<tr>
            <td>{size_h}</td>
            <td>{body_kb:.1f}KB</td>
            <td style="color:{color};font-weight:bold">{time_ms:.0f}ms</td>
            <td>{slowdown:.1f}x</td>
            <td>{status}</td>
            <td>{error or '—'}</td>
        </tr>"""

    sev_color = "#ff4444" if report.severity in ("HIGH", "MEDIUM") else (
        "#ffaa00" if report.severity == "LOW" else "#44ff44")

    conc_rows = ""
    for cr in report.concurrency_results:
        conc_rows += f"""<tr>
            <td>{cr.get('concurrent_requests', '?')}</td>
            <td>{human_size(cr.get('password_size', 0))}</td>
            <td>{cr.get('avg_response_ms', 0):.0f}ms</td>
            <td>{cr.get('max_response_ms', 0):.0f}ms</td>
            <td>{cr.get('slowdown_factor', 0):.1f}x</td>
            <td>{cr.get('errors', 0)} / {cr.get('timeouts', 0)}</td>
        </tr>"""

    conc_html = f"""<h2>Concurrency Test</h2>
    <table>
    <tr><th>Threads</th><th>Size</th><th>Avg</th><th>Max</th><th>Slowdown</th><th>Errors/Timeouts</th></tr>
    {conc_rows}
    </table>""" if conc_rows else ""

    recs = "".join(f"<li>{r}</li>" for r in report.recommendations) if report.recommendations else "<li>None</li>"

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Long Password DoS Report</title>
<style>
body{{font-family:-apple-system,sans-serif;background:#0a0a0a;color:#e0e0e0;padding:30px;max-width:1200px;margin:0 auto}}
h1{{color:#00d4ff;border-bottom:2px solid #00d4ff;padding-bottom:10px}}
h2{{color:#ffaa00;margin-top:30px}}
table{{border-collapse:collapse;width:100%;margin:20px 0}}
th{{background:#1a1a2e;color:#00d4ff;padding:12px;text-align:left;border:1px solid #333}}
td{{padding:10px;border:1px solid #333}}
tr:nth-child(even){{background:#111}}
.verdict{{background:#1a1a2e;padding:20px;border-radius:8px;margin:20px 0;border-left:4px solid {sev_color}}}
.verdict h3{{color:{sev_color};margin:0 0 10px 0}}
</style></head><body>
<h1>💣 Long Password DoS Report</h1>
<p>Target: <code>{report.target_url}</code> | Method: {report.method} | Content-Type: {report.content_type}</p>
<p>Generated: {report.timestamp} | Baseline: {report.baseline_ms:.0f}ms (avg of {report.baseline_runs} runs)</p>

<div class="verdict">
<h3>Severity: {report.severity}</h3>
<p>Vulnerable: <strong>{'YES' if report.vulnerable else 'NO'}</strong> |
   Max Slowdown: <strong>{report.max_slowdown_factor}x</strong> |
   Length Limit: <strong>{report.password_length_limit}</strong></p>
</div>

<h2>Response Time vs Password Length</h2>
<table>
<tr><th>Size</th><th>Body</th><th>Time</th><th>Slowdown</th><th>HTTP</th><th>Notes</th></tr>
{rows}
</table>

{conc_html}

<h2>Recommendations</h2>
<ul>{recs}</ul>

<p style="color:#666;font-size:12px">⚠ For authorized security testing only.</p>
</body></html>"""


# ═══════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Long Password DoS Tester v2.0.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u https://target.com/login
  %(prog)s -u https://target.com/login --username test@test.com --runs 5
  %(prog)s -u https://target.com/api/login --json --proxy http://127.0.0.1:8080
  %(prog)s -u https://target.com/login --sizes 100 1000 10000 100000
  %(prog)s -u https://target.com/login --concurrent 10

Bug Bounty Tips:
  >10x slowdown = reportable DoS via long password (CWE-400)
  Timeout = critical — server hashing unbounded input
  Server rejects at 72 chars? That's bcrypt's built-in limit = SAFE
        """
    )
    parser.add_argument("-u", "--url", help="Login/register endpoint URL")
    parser.add_argument("-d", "--domain", help="Domain to crawl subdomains and auto-find login endpoints")
    parser.add_argument("--username", default="test@test.com", help="Username to send")
    parser.add_argument("--username-field", default="username", help="Form field for username")
    parser.add_argument("--password-field", default="password", help="Form field for password")
    parser.add_argument("--json", dest="use_json", action="store_true", help="Send as JSON")
    parser.add_argument("--sizes", nargs="+", type=int, help="Custom password sizes (in chars)")
    parser.add_argument("--concurrent", type=int, default=0, help="Concurrency test threads (default: 0=skip)")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout seconds")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests (default: 0.5s)")
    parser.add_argument("--runs", type=int, default=3, help="Runs per size for averaging (default: 3)")
    parser.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--header", action="append", help="Custom header (e.g. 'X-Token: abc')")
    parser.add_argument("--sub-threads", type=int, default=20, help="Subdomain crawler threads (default: 20)")
    parser.add_argument("--deep-subs", action="store_true", help="Extended subdomain wordlist")
    parser.add_argument("-o", "--output-dir", default="output", help="Output directory")

    args = parser.parse_args()

    # Determine target URLs
    target_urls = []

    if args.domain:
        # Crawl subdomains to find login endpoints
        try:
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "subdomain-crawler"))
            from subdomain_crawler import SubdomainCrawler
            print(f"  {M}{B}🔍 Crawling subdomains of {args.domain} to find login endpoints...{RST}")
            crawler = SubdomainCrawler(
                domain=args.domain, threads=args.sub_threads,
                deep=args.deep_subs, check_alive=True, find_logins=True
            )
            results = crawler.run()
            for r in results:
                if r.has_login and r.login_url:
                    target_urls.append(r.login_url)
            if target_urls:
                print(f"\n  {G}✓ Found {len(target_urls)} login endpoint(s) to test:{RST}")
                for u in target_urls:
                    print(f"    → {u}")
            else:
                print(f"\n  {Y}⚠ No login endpoints found on subdomains. Use -u to specify one.{RST}")
                sys.exit(1)
        except ImportError:
            print(f"  {R}✗ subdomain_crawler module not found. Use -u instead.{RST}")
            sys.exit(1)
    elif args.url:
        target_urls = [args.url]
    else:
        parser.print_help()
        print(f"\n{R}✗ Provide -u <url> or -d <domain>{RST}")
        sys.exit(1)

    # Custom headers
    headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

    start = time.time()

    for url in target_urls:
        print(f"\n  {C}{B}{'═' * 60}{RST}")
        print(f"  {C}{B}  Testing: {url}{RST}")
        print(f"  {C}{B}{'═' * 60}{RST}")

        tester = DoSTester(
            url=url,
            username=args.username,
            username_field=args.username_field,
            password_field=args.password_field,
            use_json=args.use_json,
            timeout=args.timeout,
            delay=args.delay,
            runs=args.runs,
            proxy=args.proxy,
            headers=headers
        )

        # Phase 1
        sizes = args.sizes or DEFAULT_SIZES
        tester.run_size_test(sizes)

        # Phase 2 (optional)
        if args.concurrent > 0:
            best_size = 100000
            for r in reversed(tester.report.results):
                r_dict = r if isinstance(r, dict) else asdict(r)
                if not r_dict.get("timed_out") and not r_dict.get("error"):
                    best_size = r_dict["size"]
                    break
            tester.run_concurrency_test(args.concurrent, best_size)

        # Analyze
        tester.report.scan_duration_s = round(time.time() - start, 2)
        tester.analyze()

        # Save
        save_report(tester.report, args.output_dir)


if __name__ == "__main__":
    main()
