#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║        SESSION LOGOUT TESTER  v2.0.0                            ║
║   Verify Session Invalidation After Logout                      ║
║                                                                  ║
║  Author : Vishal Rao (@Vishal-HaCkEr1910)                      ║
║  License: MIT — For authorized security testing only            ║
╚══════════════════════════════════════════════════════════════════╝

Industry-standard session security tester. Checks:
  1. Session token validity after logout (replay attack)
  2. Cookie security flags (HttpOnly, Secure, SameSite, Path)
  3. Session timeout & cache control headers
  4. Multiple logout method support (GET/POST)
  5. CSRF token auto-extraction for login forms

Supports: Cookie auth, JWT/Bearer tokens, custom headers, proxy.

Usage:
    python session_logout_tester.py -u https://target.com/dashboard --logout-url /logout --cookie "session=abc"
    python session_logout_tester.py -u https://target.com --login-url /login --logout-url /logout --username admin --password pass
"""

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional
from urllib.parse import urljoin, urlparse

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
  ███████╗███████╗███████╗███████╗██╗ ██████╗ ███╗   ██╗
  ██╔════╝██╔════╝██╔════╝██╔════╝██║██╔═══██╗████╗  ██║
  ███████╗█████╗  ███████╗███████╗██║██║   ██║██╔██╗ ██║
  ╚════██║██╔══╝  ╚════██║╚════██║██║██║   ██║██║╚██╗██║
  ███████║███████╗███████║███████║██║╚██████╔╝██║ ╚████║
  ╚══════╝╚══════╝╚══════╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝
{RST}
  {Y}Session Logout Tester v2.0.0{RST}
  {W}Session Replay · Cookie Flags · Timeout · Cache-Control{RST}
  {R}⚠  AUTHORIZED USE ONLY{RST}
"""


# ═══════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════
@dataclass
class TestResult:
    test_name: str
    status: str = "INCONCLUSIVE"   # VULNERABLE, SECURE, ERROR, INCONCLUSIVE
    severity: str = "INFO"         # CRITICAL, HIGH, MEDIUM, LOW, INFO
    details: str = ""
    before_status: int = 0
    after_status: int = 0
    before_length: int = 0
    after_length: int = 0
    evidence: list = field(default_factory=list)


@dataclass
class SessionReport:
    target_url: str = ""
    logout_url: str = ""
    auth_method: str = ""
    tests: list = field(default_factory=list)
    overall_verdict: str = ""
    vulnerable: bool = False
    vulnerability_count: int = 0
    timestamp: str = ""
    scan_duration_s: float = 0.0
    recommendations: list = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════
# SESSION TESTER
# ═══════════════════════════════════════════════════════════════
class SessionTester:
    def __init__(self, target_url: str, logout_url: str, timeout: int = 15,
                 proxy: str = None, headers: dict = None):
        self.target_url = target_url
        self.logout_url = logout_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers["User-Agent"] = (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        if headers:
            self.session.headers.update(headers)

        self.report = SessionReport(
            target_url=target_url,
            logout_url=logout_url,
            timestamp=datetime.now().isoformat()
        )

    # ─── CSRF Token Extraction ───
    def _extract_csrf_token(self, url: str) -> dict:
        """Try to extract CSRF token from the login page."""
        extra = {}
        try:
            resp = self.session.get(url, timeout=self.timeout)
            # Common CSRF field patterns
            patterns = [
                r'name=["\']csrf[_-]?token["\'][^>]*value=["\']([^"\']+)["\']',
                r'name=["\']_token["\'][^>]*value=["\']([^"\']+)["\']',
                r'name=["\']csrfmiddlewaretoken["\'][^>]*value=["\']([^"\']+)["\']',
                r'name=["\']authenticity_token["\'][^>]*value=["\']([^"\']+)["\']',
                r'name=["\']__RequestVerificationToken["\'][^>]*value=["\']([^"\']+)["\']',
            ]
            field_names = [
                "csrf_token", "_token", "csrfmiddlewaretoken",
                "authenticity_token", "__RequestVerificationToken",
            ]
            for pattern, field_name in zip(patterns, field_names):
                match = re.search(pattern, resp.text, re.I)
                if match:
                    extra[field_name] = match.group(1)
                    print(f"      {G}✓ Found CSRF token: {field_name}={match.group(1)[:30]}...{RST}")
                    break

            # Also try value=... before name=... (reversed attribute order)
            if not extra:
                for pattern2 in [
                    r'value=["\']([^"\']+)["\'][^>]*name=["\']csrf[_-]?token["\']',
                    r'value=["\']([^"\']+)["\'][^>]*name=["\']_token["\']',
                ]:
                    match = re.search(pattern2, resp.text, re.I)
                    if match:
                        extra["_token"] = match.group(1)
                        print(f"      {G}✓ Found CSRF token: _token={match.group(1)[:30]}...{RST}")
                        break
        except Exception:
            pass
        return extra

    # ─── Login via form ───
    def login_form(self, login_url: str, username: str, password: str,
                   username_field: str = "username", password_field: str = "password",
                   extra_data: dict = None, method: str = "POST"):
        print(f"  {Y}[LOGIN]{RST} Attempting form login at {login_url}...")

        # Auto-extract CSRF token
        csrf = self._extract_csrf_token(login_url)

        data = {username_field: username, password_field: password}
        data.update(csrf)
        if extra_data:
            data.update(extra_data)

        try:
            if method.upper() == "POST":
                resp = self.session.post(login_url, data=data, timeout=self.timeout,
                                         allow_redirects=True)
            else:
                resp = self.session.get(login_url, params=data, timeout=self.timeout,
                                        allow_redirects=True)

            cookies = dict(self.session.cookies)
            if cookies:
                print(f"    {G}✓ Login successful — {len(cookies)} cookie(s){RST}")
                for name, val in cookies.items():
                    print(f"      {name} = {val[:50]}{'...' if len(val) > 50 else ''}")
                self.report.auth_method = "cookie"
                return True
            elif resp.status_code < 400:
                print(f"    {Y}⚠ Got {resp.status_code} but no cookies — may use different auth{RST}")
                return True
            else:
                print(f"    {R}✗ Login failed — HTTP {resp.status_code}{RST}")
                return False
        except Exception as e:
            print(f"    {R}✗ Login error: {e}{RST}")
            return False

    # ─── Set cookie manually ───
    def set_cookie(self, cookie_string: str):
        print(f"  {Y}[COOKIE]{RST} Setting manual cookie...")
        for pair in cookie_string.split(";"):
            pair = pair.strip()
            if "=" in pair:
                name, val = pair.split("=", 1)
                self.session.cookies.set(name.strip(), val.strip())
                print(f"    Set: {name.strip()} = {val.strip()[:50]}...")
        self.report.auth_method = "cookie"

    # ─── Set JWT / Bearer token ───
    def set_token(self, token: str):
        print(f"  {Y}[TOKEN]{RST} Setting Authorization: Bearer header...")
        self.session.headers["Authorization"] = f"Bearer {token}"
        print(f"    Token: {token[:50]}...")
        self.report.auth_method = "jwt"

    # ─── Set custom header ───
    def set_custom_header(self, header: str):
        if ":" in header:
            name, val = header.split(":", 1)
            self.session.headers[name.strip()] = val.strip()
            print(f"  {Y}[HEADER]{RST} Set: {name.strip()}: {val.strip()[:50]}...")
            self.report.auth_method = "header"

    # ─── Authenticated request ───
    def authenticated_request(self, url: str = None) -> tuple:
        url = url or self.target_url
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            return resp.status_code, len(resp.text), resp
        except Exception:
            return 0, 0, None

    # ─── Logout ───
    def perform_logout(self, method: str = "auto"):
        print(f"\n  {Y}[LOGOUT]{RST} Performing logout at {self.logout_url}...")
        try:
            if method in ("auto", "GET"):
                resp = self.session.get(self.logout_url, timeout=self.timeout, allow_redirects=True)
                print(f"    GET logout: HTTP {resp.status_code}")
                if resp.status_code < 400 and method == "auto":
                    return True

            if method in ("auto", "POST"):
                resp = self.session.post(self.logout_url, timeout=self.timeout, allow_redirects=True)
                print(f"    POST logout: HTTP {resp.status_code}")

            return True
        except Exception as e:
            print(f"    {R}✗ Logout error: {e}{RST}")
            return False

    # ═════════════════════════════════════════════════════════
    # TEST 1: Session token valid after logout
    # ═════════════════════════════════════════════════════════
    def test_session_after_logout(self) -> TestResult:
        test = TestResult(test_name="Session Token Valid After Logout", severity="HIGH")
        print(f"\n  {C}{B}TEST 1: Session token validity after logout{RST}")

        # Before logout
        print(f"    [Before Logout] Requesting {self.target_url}...", end=" ")
        status_before, len_before, resp_before = self.authenticated_request()
        test.before_status = status_before
        test.before_length = len_before
        print(f"HTTP {status_before} ({len_before} bytes)")

        if status_before >= 400 or status_before == 0:
            test.status = "ERROR"
            test.details = f"Pre-logout request failed (HTTP {status_before}). Check authentication."
            print(f"    {R}✗ Not authenticated — cannot test{RST}")
            return test

        # Save credentials for replay
        saved_cookies = dict(self.session.cookies)
        saved_auth = self.session.headers.get("Authorization", "")

        # Logout
        self.perform_logout()

        # Create replay session with OLD credentials
        replay = requests.Session()
        replay.verify = False
        replay.headers.update(self.session.headers)
        if saved_cookies:
            for name, val in saved_cookies.items():
                replay.cookies.set(name, val)
        if saved_auth:
            replay.headers["Authorization"] = saved_auth

        # Replay
        print(f"    [After Logout] Replaying with old token...", end=" ")
        try:
            resp_after = replay.get(self.target_url, timeout=self.timeout, allow_redirects=False)
            test.after_status = resp_after.status_code
            test.after_length = len(resp_after.text)
            print(f"HTTP {resp_after.status_code} ({test.after_length} bytes)")
        except Exception as e:
            test.status = "ERROR"
            test.details = f"Replay failed: {e}"
            return test

        # Analyze
        if test.after_status in (200, 201, 204):
            if test.before_length > 0 and abs(test.before_length - test.after_length) / max(test.before_length, 1) < 0.5:
                test.status = "VULNERABLE"
                test.severity = "HIGH"
                test.details = (f"Session token still valid after logout! "
                               f"Before: HTTP {test.before_status} ({test.before_length}b) → "
                               f"After: HTTP {test.after_status} ({test.after_length}b)")
                test.evidence.append(f"Old cookies still work post-logout")
                test.evidence.append(f"Response length similarity: {test.before_length}b vs {test.after_length}b")
                print(f"    {R}{B}⚠ VULNERABLE — Session NOT invalidated!{RST}")
            else:
                test.status = "INCONCLUSIVE"
                test.details = f"200 OK but content differs. Before: {test.before_length}b, After: {test.after_length}b"
                print(f"    {Y}⚠ Inconclusive — 200 but different content{RST}")
        elif test.after_status in (301, 302, 303, 307, 308):
            location = resp_after.headers.get("Location", "")
            if "login" in location.lower() or "signin" in location.lower() or "auth" in location.lower():
                test.status = "SECURE"
                test.details = f"Redirected to login ({location}) — session invalidated"
                print(f"    {G}✓ SECURE — Redirected to login{RST}")
            else:
                test.status = "INCONCLUSIVE"
                test.details = f"Redirected to {location}"
                print(f"    {Y}⚠ Redirected to {location}{RST}")
        elif test.after_status in (401, 403):
            test.status = "SECURE"
            test.details = f"HTTP {test.after_status} — session properly invalidated"
            print(f"    {G}✓ SECURE — Access denied after logout{RST}")
        else:
            test.status = "INCONCLUSIVE"
            test.details = f"HTTP {test.after_status} — manual verification needed"
            print(f"    {Y}⚠ HTTP {test.after_status} — check manually{RST}")

        return test

    # ═════════════════════════════════════════════════════════
    # TEST 2: Cookie security flags
    # ═════════════════════════════════════════════════════════
    def test_cookie_flags(self) -> TestResult:
        test = TestResult(test_name="Cookie Security Flags", severity="MEDIUM")
        print(f"\n  {C}{B}TEST 2: Cookie security flags{RST}")

        issues = []
        try:
            resp = self.session.get(self.target_url, timeout=self.timeout)

            if not resp.headers.get("Set-Cookie") and not self.session.cookies:
                test.status = "INCONCLUSIVE"
                test.details = "No cookies found to analyze"
                print(f"    {Y}No cookies to analyze{RST}")
                return test

            # Get raw Set-Cookie headers
            cookies_raw = []
            if hasattr(resp.raw, '_original_response'):
                raw_headers = resp.raw._original_response.msg.get_all("Set-Cookie") or []
                cookies_raw = raw_headers
            if not cookies_raw:
                sc = resp.headers.get("Set-Cookie", "")
                if sc:
                    cookies_raw = [sc]

            for cookie_str in cookies_raw:
                if not cookie_str:
                    continue
                name = cookie_str.split("=")[0].strip()
                lower = cookie_str.lower()

                # HttpOnly
                if "httponly" not in lower:
                    issues.append(f"'{name}' missing HttpOnly (XSS can steal it)")
                    test.evidence.append(f"Cookie '{name}': no HttpOnly flag")
                    print(f"    {R}✗ {name}: Missing HttpOnly{RST}")
                else:
                    print(f"    {G}✓ {name}: HttpOnly present{RST}")

                # Secure
                if "secure" not in lower:
                    issues.append(f"'{name}' missing Secure (sent over HTTP)")
                    test.evidence.append(f"Cookie '{name}': no Secure flag")
                    print(f"    {R}✗ {name}: Missing Secure{RST}")
                else:
                    print(f"    {G}✓ {name}: Secure present{RST}")

                # SameSite
                if "samesite" not in lower:
                    issues.append(f"'{name}' missing SameSite (CSRF risk)")
                    test.evidence.append(f"Cookie '{name}': no SameSite attribute")
                    print(f"    {Y}⚠ {name}: Missing SameSite{RST}")
                else:
                    ss_match = re.search(r'samesite\s*=\s*(\w+)', lower)
                    ss_val = ss_match.group(1) if ss_match else "?"
                    if ss_val == "none":
                        issues.append(f"'{name}' SameSite=None (cross-site requests allowed)")
                        print(f"    {Y}⚠ {name}: SameSite=None{RST}")
                    else:
                        print(f"    {G}✓ {name}: SameSite={ss_val}{RST}")

                # Path
                if "path=/" in lower and "path=/;" not in lower:
                    # path=/ is typical but path could be more restrictive
                    pass  # Not a vulnerability per se

        except Exception as e:
            test.status = "ERROR"
            test.details = str(e)
            return test

        if issues:
            test.status = "VULNERABLE"
            test.details = "; ".join(issues)
        else:
            test.status = "SECURE"
            test.details = "All cookie security flags properly set"

        return test

    # ═════════════════════════════════════════════════════════
    # TEST 3: Session timeout & cache control
    # ═════════════════════════════════════════════════════════
    def test_session_timeout(self) -> TestResult:
        test = TestResult(test_name="Session Timeout & Cache Control", severity="LOW")
        print(f"\n  {C}{B}TEST 3: Session timeout & cache control{RST}")

        issues = []
        try:
            resp = self.session.get(self.target_url, timeout=self.timeout)
            cache_control = resp.headers.get("Cache-Control", "")
            pragma = resp.headers.get("Pragma", "")

            # Cache-Control checks
            if not cache_control:
                issues.append("No Cache-Control header on authenticated page")
                print(f"    {Y}⚠ No Cache-Control header{RST}")
            else:
                print(f"    Cache-Control: {cache_control}")
                if "no-store" in cache_control:
                    print(f"    {G}✓ no-store present{RST}")
                else:
                    issues.append("Missing 'no-store' in Cache-Control")
                    print(f"    {Y}⚠ Missing no-store{RST}")
                if "no-cache" in cache_control:
                    print(f"    {G}✓ no-cache present{RST}")
                else:
                    issues.append("Missing 'no-cache' in Cache-Control")

            if pragma:
                print(f"    Pragma: {pragma}")

            # Cookie max-age / expires
            set_cookie = resp.headers.get("Set-Cookie", "")
            if "max-age" in set_cookie.lower():
                age_match = re.search(r'max-age\s*=\s*(\d+)', set_cookie, re.I)
                if age_match:
                    max_age = int(age_match.group(1))
                    hours = max_age / 3600
                    days = hours / 24
                    if hours > 24:
                        issues.append(f"Session max-age is {days:.1f} days (>24h is excessive)")
                        test.evidence.append(f"Cookie max-age: {max_age}s ({days:.1f} days)")
                        print(f"    {Y}⚠ Cookie max-age: {days:.1f} days — excessive{RST}")
                    else:
                        print(f"    {G}✓ Cookie max-age: {hours:.1f} hours{RST}")

            if "expires" in set_cookie.lower():
                exp_match = re.search(r'expires\s*=\s*([^;]+)', set_cookie, re.I)
                if exp_match:
                    print(f"    Cookie expires: {exp_match.group(1).strip()}")

            # Security headers on authenticated page
            security_headers = {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY|SAMEORIGIN",
                "Strict-Transport-Security": None,
            }
            for hdr, expected in security_headers.items():
                val = resp.headers.get(hdr, "")
                if val:
                    print(f"    {G}✓ {hdr}: {val}{RST}")
                else:
                    print(f"    {Y}⚠ Missing {hdr}{RST}")

        except Exception as e:
            test.status = "ERROR"
            test.details = str(e)
            return test

        if issues:
            test.status = "VULNERABLE"
            test.severity = "LOW"
            test.details = "; ".join(issues)
        else:
            test.status = "SECURE"
            test.details = "Cache control and session timeout properly configured"

        return test

    # ═════════════════════════════════════════════════════════
    # RUN ALL TESTS
    # ═════════════════════════════════════════════════════════
    def run_all_tests(self):
        start_time = time.time()
        results = []

        results.append(self.test_session_after_logout())
        results.append(self.test_cookie_flags())
        results.append(self.test_session_timeout())

        self.report.tests = [asdict(t) for t in results]
        self.report.scan_duration_s = round(time.time() - start_time, 2)

        vulns = [t for t in results if t.status == "VULNERABLE"]
        self.report.vulnerability_count = len(vulns)

        if vulns:
            self.report.vulnerable = True
            high_vulns = [t for t in vulns if t.severity in ("HIGH", "CRITICAL")]
            if high_vulns:
                self.report.overall_verdict = "VULNERABLE"
            else:
                self.report.overall_verdict = "WEAK"
            self.report.recommendations = [
                "Invalidate session tokens server-side upon logout",
                "For JWTs: implement token blacklist/revocation",
                "Set session timeout to 15-30 min idle",
                "Add HttpOnly, Secure, SameSite=Strict to all session cookies",
                "Add Cache-Control: no-store, no-cache to authenticated pages",
                "Rotate session tokens after privilege changes",
            ]
        else:
            self.report.overall_verdict = "SECURE" if all(
                t.status == "SECURE" for t in results) else "INCONCLUSIVE"

        # Print summary
        print(f"\n  {B}{'═' * 55}{RST}")
        print(f"  {B}RESULTS SUMMARY{RST}")
        for t in results:
            color = R if t.status == "VULNERABLE" else (G if t.status == "SECURE" else Y)
            sev = f" [{t.severity}]" if t.status == "VULNERABLE" else ""
            print(f"    {color}[{t.status}]{RST}{sev} {t.test_name}")
            if t.evidence:
                for ev in t.evidence:
                    print(f"      → {ev}")

        verdict_color = R if self.report.vulnerable else G
        print(f"\n  Overall: {verdict_color}{B}{self.report.overall_verdict}{RST}")
        print(f"  Vulnerabilities: {self.report.vulnerability_count}")
        print(f"  Scan time: {self.report.scan_duration_s}s")

        if self.report.recommendations:
            print(f"\n  {Y}Recommendations:{RST}")
            for rec in self.report.recommendations:
                print(f"    • {rec}")
        print(f"  {B}{'═' * 55}{RST}")

        return self.report


# ═══════════════════════════════════════════════════════════════
# SAVE REPORTS
# ═══════════════════════════════════════════════════════════════
def save_report(report: SessionReport, output_dir: str = "output"):
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # JSON
    json_path = os.path.join(output_dir, f"session_test_{ts}.json")
    with open(json_path, "w") as f:
        json.dump(asdict(report), f, indent=2, default=str)
    print(f"\n  {G}✓ JSON report: {json_path}{RST}")

    # HTML
    html_path = os.path.join(output_dir, f"session_test_{ts}.html")
    with open(html_path, "w") as f:
        f.write(generate_html(report))
    print(f"  {G}✓ HTML report: {html_path}{RST}")


def generate_html(report: SessionReport) -> str:
    rows = ""
    for t in report.tests:
        color = "#ff4444" if t["status"] == "VULNERABLE" else (
            "#44ff44" if t["status"] == "SECURE" else "#ffaa00")
        evidence = "<br>".join(t.get("evidence", [])) or "—"
        rows += f"""<tr>
            <td>{t['test_name']}</td>
            <td style="background:{color};color:#fff;font-weight:bold;text-align:center">{t['status']}</td>
            <td>{t.get('severity', 'INFO')}</td>
            <td>{t['details']}</td>
            <td style="font-size:11px">{evidence}</td>
        </tr>"""

    recs = "".join(f"<li>{r}</li>" for r in report.recommendations) if report.recommendations else "<li>None</li>"

    verdict_color = "#ff4444" if report.vulnerable else "#44ff44"
    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Session Security Report</title>
<style>
body{{font-family:-apple-system,sans-serif;background:#0a0a0a;color:#e0e0e0;padding:30px;max-width:1200px;margin:0 auto}}
h1{{color:#00d4ff;border-bottom:2px solid #00d4ff;padding-bottom:10px}}
table{{border-collapse:collapse;width:100%;margin:20px 0}}
th{{background:#1a1a2e;color:#00d4ff;padding:12px;text-align:left;border:1px solid #333}}
td{{padding:10px;border:1px solid #333;vertical-align:top}}
tr:nth-child(even){{background:#111}}
.verdict{{background:#1a1a2e;padding:20px;border-radius:8px;margin:20px 0;border-left:4px solid {verdict_color}}}
.verdict h3{{color:{verdict_color};margin:0 0 10px 0}}
</style></head><body>
<h1>🔐 Session Security Report</h1>
<p>Target: <code>{report.target_url}</code> | Logout: <code>{report.logout_url}</code></p>
<p>Auth Method: {report.auth_method} | Generated: {report.timestamp}</p>

<div class="verdict">
<h3>{report.overall_verdict}</h3>
<p>Vulnerabilities Found: <strong>{report.vulnerability_count}</strong> | Scan Time: {report.scan_duration_s}s</p>
</div>

<table>
<tr><th>Test</th><th>Status</th><th>Severity</th><th>Details</th><th>Evidence</th></tr>
{rows}
</table>

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
        description="Session Logout Tester v2.0.0 — Verify session invalidation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # With pre-captured cookie
  %(prog)s -u https://target.com/dashboard --logout-url /logout --cookie "session=abc123"

  # With login credentials
  %(prog)s -u https://target.com/dashboard --login-url /login --logout-url /logout \\
      --username admin --password pass

  # With JWT token
  %(prog)s -u https://target.com/api/me --logout-url /api/logout --token "eyJhbGci..."

  # With custom header + proxy
  %(prog)s -u https://target.com/dashboard --logout-url /logout \\
      --header "X-API-Key: secret123" --proxy http://127.0.0.1:8080

Bug Bounty Tips:
  Session valid after logout = "Insufficient Session Expiration" (CWE-613)
  Missing HttpOnly on session cookie = "Missing Cookie Flag" (P4)
        """
    )
    parser.add_argument("-u", "--url", help="Authenticated page URL to test")
    parser.add_argument("-d", "--domain", help="Crawl subdomains to discover login endpoints first")
    parser.add_argument("--login-url", help="Login endpoint URL")
    parser.add_argument("--logout-url", help="Logout endpoint URL")
    parser.add_argument("--username", help="Login username")
    parser.add_argument("--password", help="Login password")
    parser.add_argument("--username-field", default="username", help="Form field for username")
    parser.add_argument("--password-field", default="password", help="Form field for password")
    parser.add_argument("--cookie", help="Pre-captured session cookie (e.g. 'session=abc')")
    parser.add_argument("--token", help="Pre-captured JWT/Bearer token")
    parser.add_argument("--header", action="append", help="Custom header (e.g. 'X-API-Key: val')")
    parser.add_argument("--extra-data", help="Extra form data as JSON (e.g. '{\"remember\":\"1\"}')")
    parser.add_argument("--logout-method", choices=["auto", "GET", "POST"], default="auto",
                        help="HTTP method for logout (default: auto)")
    parser.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout seconds")
    parser.add_argument("--sub-threads", type=int, default=20, help="Subdomain crawler threads")
    parser.add_argument("--deep-subs", action="store_true", help="Extended subdomain wordlist")
    parser.add_argument("-o", "--output-dir", default="output", help="Output directory")

    args = parser.parse_args()

    # ─── Subdomain crawl mode: discover login endpoints ───
    if args.domain and not args.url:
        try:
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "subdomain-crawler"))
            from subdomain_crawler import SubdomainCrawler
            print(f"  {M}{B}🔍 Crawling subdomains of {args.domain} to find login endpoints...{RST}")
            crawler = SubdomainCrawler(
                domain=args.domain, threads=args.sub_threads,
                deep=args.deep_subs, check_alive=True, find_logins=True
            )
            results = crawler.run()
            logins = [r for r in results if r.has_login]
            if logins:
                print(f"\n  {G}{B}✓ Found {len(logins)} subdomain(s) with login forms:{RST}")
                for r in logins:
                    print(f"    → {Y}{r.login_url}{RST}  ({r.subdomain})")
                print(f"\n  {W}To test each, run:{RST}")
                for r in logins:
                    print(f"    python session_logout_tester.py -u {r.login_url}/dashboard "
                          f"--login-url {r.login_url} --logout-url {r.login_url.rstrip('/')}/logout "
                          f"--username USER --password PASS")
                # If cookie is provided, test all of them
                if args.cookie and args.logout_url:
                    print(f"\n  {C}{B}Testing all discovered endpoints with provided cookie...{RST}")
                    for r in logins:
                        target = r.login_url.rstrip("/login").rstrip("/signin") or r.login_url
                        logout = urljoin(target + "/", args.logout_url.lstrip("/"))
                        custom_headers = {}
                        if args.header:
                            for h in args.header:
                                if ":" in h:
                                    k, v = h.split(":", 1)
                                    custom_headers[k.strip()] = v.strip()
                        tester = SessionTester(target, logout, args.timeout,
                                               proxy=args.proxy, headers=custom_headers)
                        tester.set_cookie(args.cookie)
                        report = tester.run_all_tests()
                        save_report(report, args.output_dir)
            else:
                print(f"\n  {Y}⚠ No login endpoints found on subdomains.{RST}")
                print(f"  Use -u to specify the URL directly.")
        except ImportError:
            print(f"  {R}✗ subdomain_crawler module not found. Use -u instead.{RST}")
        sys.exit(0)

    if not args.url:
        parser.print_help()
        print(f"\n{R}✗ Provide -u <url> or -d <domain>{RST}")
        sys.exit(1)

    if not args.logout_url:
        parser.print_help()
        print(f"\n{R}✗ --logout-url is required when using -u{RST}")
        sys.exit(1)

    # Resolve relative URLs
    parsed = urlparse(args.url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    logout_url = args.logout_url
    if logout_url.startswith("/"):
        logout_url = urljoin(base_url, logout_url)

    login_url = args.login_url
    if login_url and login_url.startswith("/"):
        login_url = urljoin(base_url, login_url)

    # Custom headers
    custom_headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                custom_headers[k.strip()] = v.strip()

    # Create tester
    tester = SessionTester(args.url, logout_url, args.timeout,
                           proxy=args.proxy, headers=custom_headers)

    # Authenticate
    if args.cookie:
        tester.set_cookie(args.cookie)
    elif args.token:
        tester.set_token(args.token)
    elif login_url and args.username and args.password:
        extra = json.loads(args.extra_data) if args.extra_data else None
        success = tester.login_form(login_url, args.username, args.password,
                                     args.username_field, args.password_field,
                                     extra_data=extra)
        if not success:
            print(f"\n{R}✗ Login failed. Try --cookie with a pre-captured token instead.{RST}")
            sys.exit(1)
    elif args.header:
        pass  # Custom headers already set
    else:
        print(f"{R}✗ Provide authentication: --cookie, --token, --header, or --login-url with credentials{RST}")
        sys.exit(1)

    # Run tests
    report = tester.run_all_tests()

    # Save
    save_report(report, args.output_dir)


if __name__ == "__main__":
    main()
