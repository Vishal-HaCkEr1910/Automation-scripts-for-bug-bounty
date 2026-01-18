#!/usr/bin/env python3
"""
Advanced GitHub Reconnaissance Tool
Professional-grade recon for bug bounty hunters and security researchers
"""
import argparse
import requests
import re
import json
import os
import sys
import time
import base64
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
from urllib.parse import quote
import concurrent.futures
from collections import defaultdict

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION & PATTERNS
# ═══════════════════════════════════════════════════════════════════════════

class Config:
    """Configuration management"""
    OUTPUT_DIR = "github_recon_results"
    MAX_RESULTS = 100
    RATE_LIMIT_DELAY = 2  # seconds
    MAX_WORKERS = 5
    TIMEOUT = 10
    
    # External tools (optional)
    EXTERNAL_TOOLS = {
        "gitleaks": "gitleaks",
        "trufflehog": "trufflehog",
        "git-secrets": "git-secrets"
    }

class Patterns:
    """Comprehensive secret and sensitive data patterns"""
    
    SECRET_PATTERNS = {
        # API Keys & Tokens
        "AWS Access Key": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "AWS Secret Key": r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]",
        "GitHub Token": r"(?i)github[_\s]?(?:token|pat|key)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_]{40})",
        "GitHub Personal Access Token": r"ghp_[0-9a-zA-Z]{36}",
        "GitHub OAuth Token": r"gho_[0-9a-zA-Z]{36}",
        "GitHub App Token": r"(?:ghu|ghs)_[0-9a-zA-Z]{36}",
        "Slack Token": r"xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24,32}",
        "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
        "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
        "Google OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
        "Firebase": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
        "Generic API Key": r"(?i)api[_\s]?key['\"]?\s*[:=]\s*['\"]?([0-9a-zA-Z\-_]{20,})",
        "Bearer Token": r"bearer\s+[a-zA-Z0-9\-_\.=]{20,}",
        "JWT Token": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        
        # Cloud Providers
        "Azure Client Secret": r"(?i)azure[_\s]?(?:client|secret)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9\-_~\.]{32,})",
        "Heroku API Key": r"[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
        "DigitalOcean Token": r"(?i)do_[a-z0-9]{64}",
        
        # Databases
        "MongoDB Connection String": r"mongodb(?:\+srv)?://[^\s]+",
        "PostgreSQL Connection String": r"postgres(?:ql)?://[^\s]+",
        "MySQL Connection String": r"mysql://[^\s]+",
        "Redis Connection String": r"redis://[^\s]+",
        
        # Private Keys
        "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
        "DSA Private Key": r"-----BEGIN DSA PRIVATE KEY-----",
        "EC Private Key": r"-----BEGIN EC PRIVATE KEY-----",
        "PGP Private Key": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "OpenSSH Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
        
        # Payment & Services
        "Stripe API Key": r"(?:r|s)k_live_[0-9a-zA-Z]{24,}",
        "Stripe Restricted Key": r"rk_live_[0-9a-zA-Z]{24,}",
        "Square Access Token": r"sq0atp-[0-9A-Za-z\-_]{22}",
        "Square OAuth Secret": r"sq0csp-[0-9A-Za-z\-_]{43}",
        "PayPal Braintree": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
        "Twilio API Key": r"SK[0-9a-fA-F]{32}",
        
        # Other
        "SendGrid API Key": r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
        "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
        "NPM Token": r"npm_[A-Za-z0-9]{36}",
        "Docker Hub Token": r"dckr_pat_[a-zA-Z0-9\-_]{32,}",
        "Password in URL": r"[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}",
    }
    
    SENSITIVE_FILENAMES = [
        # Environment & Config
        ".env", ".env.local", ".env.production", ".env.development",
        "config.json", "config.yaml", "config.yml", "settings.py",
        "secrets.yml", "secrets.yaml", "credentials.json",
        
        # Keys
        "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
        "private.key", "server.key", "client.key",
        ".ssh/id_rsa", ".ssh/known_hosts",
        
        # Database
        "database.yml", "db.yml", "database.json",
        ".pgpass", "my.cnf", ".my.cnf",
        
        # Cloud
        ".aws/credentials", ".boto", ".s3cfg",
        "gcloud.json", "service-account.json",
        
        # Application
        "application.properties", "application.yml",
        "web.config", "app.config", "production.json",
        "docker-compose.yml", "docker-compose.yaml",
        
        # Other
        ".htpasswd", ".netrc", "wp-config.php",
        "LocalSettings.php", "settings.php"
    ]
    
    SENSITIVE_KEYWORDS = [
        "password", "passwd", "pwd", "secret", "api_key", "apikey",
        "access_token", "auth_token", "private_key", "client_secret",
        "encryption_key", "master_key", "oauth", "credentials",
        "database_password", "db_password", "admin_password"
    ]
    
    SENSITIVE_EXTENSIONS = [
        ".pem", ".key", ".p12", ".pfx", ".cer", ".crt",
        ".ovpn", ".keystore", ".jks", ".pkcs12"
    ]

# ═══════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

class Colors:
    """Terminal colors for better output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def print_banner():
    """Display tool banner"""
    banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   {Colors.BOLD}GitHub Advanced Reconnaissance Tool{Colors.END}{Colors.CYAN}                     ║
║   {Colors.YELLOW}Professional Bug Bounty & Security Research{Colors.END}{Colors.CYAN}             ║
║                                                              ║
║   {Colors.GREEN}✓ Multi-tool Integration{Colors.END}{Colors.CYAN}                                ║
║   {Colors.GREEN}✓ Intelligent Pattern Matching{Colors.END}{Colors.CYAN}                          ║
║   {Colors.GREEN}✓ False Positive Filtering{Colors.END}{Colors.CYAN}                              ║
║   {Colors.GREEN}✓ Comprehensive Reporting{Colors.END}{Colors.CYAN}                               ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{Colors.END}
    """
    print(banner)

def log(message, level="INFO"):
    """Structured logging"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    colors = {
        "INFO": Colors.BLUE,
        "SUCCESS": Colors.GREEN,
        "WARNING": Colors.YELLOW,
        "ERROR": Colors.RED,
        "HEADER": Colors.CYAN
    }
    color = colors.get(level, Colors.END)
    print(f"{color}[{timestamp}] [{level}] {message}{Colors.END}")

def check_tool_installed(tool_name):
    """Check if external tool is installed"""
    try:
        result = subprocess.run(
            [tool_name, "--version"],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False

# ═══════════════════════════════════════════════════════════════════════════
# GITHUB API HANDLER
# ═══════════════════════════════════════════════════════════════════════════

class GitHubRecon:
    """Main reconnaissance class"""
    
    def __init__(self, token: str, target_org: str):
        self.token = token
        self.target_org = target_org
        self.headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.findings = []
        self.rate_limit_remaining = None
        
        # Setup output directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = Path(Config.OUTPUT_DIR) / f"{target_org}_{timestamp}"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def check_rate_limit(self):
        """Check GitHub API rate limit"""
        try:
            r = self.session.get("https://api.github.com/rate_limit", timeout=Config.TIMEOUT)
            if r.status_code == 200:
                data = r.json()
                self.rate_limit_remaining = data['resources']['core']['remaining']
                reset_time = datetime.fromtimestamp(data['resources']['core']['reset'])
                log(f"Rate limit: {self.rate_limit_remaining} remaining (resets at {reset_time})", "INFO")
                return self.rate_limit_remaining > 10
            return False
        except Exception as e:
            log(f"Rate limit check failed: {e}", "ERROR")
            return False
    
    def verify_token(self):
        """Verify GitHub token is valid"""
        try:
            r = self.session.get("https://api.github.com/user", timeout=Config.TIMEOUT)
            if r.status_code == 200:
                user = r.json()['login']
                log(f"Authenticated as: {user}", "SUCCESS")
                return True
            else:
                log(f"Token verification failed: {r.status_code}", "ERROR")
                return False
        except Exception as e:
            log(f"Token verification error: {e}", "ERROR")
            return False
    
    def search_code(self, query: str, max_results: int = Config.MAX_RESULTS) -> List[Dict]:
        """Search GitHub code"""
        results = []
        page = 1
        
        while len(results) < max_results:
            try:
                url = f"https://api.github.com/search/code"
                params = {
                    "q": query,
                    "per_page": min(100, max_results - len(results)),
                    "page": page
                }
                
                r = self.session.get(url, params=params, timeout=Config.TIMEOUT)
                
                if r.status_code == 200:
                    data = r.json()
                    items = data.get("items", [])
                    
                    if not items:
                        break
                    
                    results.extend(items)
                    
                    if len(items) < 100:
                        break
                    
                    page += 1
                    time.sleep(Config.RATE_LIMIT_DELAY)
                    
                elif r.status_code == 403:
                    # Rate limit hit - show clear message
                    reset_time = int(r.headers.get('X-RateLimit-Reset', 0))
                    if reset_time:
                        reset_dt = datetime.fromtimestamp(reset_time)
                        wait_seconds = (reset_dt - datetime.now()).total_seconds()
                        
                        if wait_seconds > 0:
                            print(f"\n{Colors.YELLOW}⏸  Rate limit reached. Resuming at {reset_dt.strftime('%H:%M:%S')} ({int(wait_seconds)}s wait){Colors.END}")
                            time.sleep(wait_seconds + 2)
                            print(f"{Colors.GREEN}▶  Resuming scan...{Colors.END}\n")
                        else:
                            time.sleep(60)
                    else:
                        time.sleep(60)
                elif r.status_code == 422:
                    # Validation failed - query too complex
                    break
                else:
                    break
                    
            except Exception as e:
                log(f"Search error: {e}", "ERROR")
                break
        
        return results
    
    def fetch_file_content(self, url: str) -> Optional[str]:
        """Fetch file content from GitHub API"""
        try:
            r = self.session.get(url, timeout=Config.TIMEOUT)
            if r.status_code == 200:
                content = r.json().get("content", "")
                if content:
                    return base64.b64decode(content).decode('utf-8', errors='ignore')
        except Exception as e:
            log(f"Error fetching {url}: {e}", "ERROR")
        return None
    
    def scan_content_for_secrets(self, content: str, source_url: str) -> List[Dict]:
        """Scan content for secret patterns"""
        findings = []
        
        for name, pattern in Patterns.SECRET_PATTERNS.items():
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                # Get surrounding context
                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 50)
                context = content[start:end].replace('\n', ' ')
                
                findings.append({
                    "type": "Secret Pattern",
                    "category": name,
                    "url": source_url,
                    "match": match.group(0)[:50] + "..." if len(match.group(0)) > 50 else match.group(0),
                    "context": context,
                    "severity": "HIGH",
                    "timestamp": datetime.now().isoformat()
                })
        
        return findings
    
    def enumerate_repos(self) -> List[Dict]:
        """Enumerate organization repositories"""
        repos = []
        page = 1
        
        print(f"{Colors.YELLOW}Discovering repositories...{Colors.END}", end='', flush=True)
        
        while True:
            try:
                url = f"https://api.github.com/orgs/{self.target_org}/repos"
                params = {"per_page": 100, "page": page}
                
                r = self.session.get(url, params=params, timeout=Config.TIMEOUT)
                
                if r.status_code == 200:
                    data = r.json()
                    if not data:
                        break
                    repos.extend(data)
                    
                    # Update progress
                    print(f"\r{Colors.YELLOW}Discovering repositories... {len(repos)} found{Colors.END}", end='', flush=True)
                    
                    page += 1
                    time.sleep(Config.RATE_LIMIT_DELAY)
                else:
                    break
                    
            except Exception as e:
                log(f"Repo enumeration error: {e}", "ERROR")
                break
        
        print(f"\r{Colors.GREEN}✓ Repository Discovery Complete: {len(repos)} repositories found{Colors.END}\n")
        
        # Show repository list
        if repos:
            print(f"\n{Colors.CYAN}Repositories to be scanned:{Colors.END}")
            for idx, repo in enumerate(repos[:10], 1):  # Show first 10
                print(f"  {idx}. {repo.get('name')} ({repo.get('stargazers_count', 0)} ⭐)")
            if len(repos) > 10:
                print(f"  ... and {len(repos) - 10} more")
        
        return repos
    
    def search_sensitive_files(self):
        """Search for sensitive filenames"""
        total_files = len(Patterns.SENSITIVE_FILENAMES)
        
        print(f"\n{Colors.CYAN}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}📁 Scanning {total_files} Sensitive Filenames{Colors.END}")
        print(f"{Colors.CYAN}{'='*70}{Colors.END}\n")
        
        for idx, filename in enumerate(Patterns.SENSITIVE_FILENAMES, 1):
            # Progress indicator
            progress_percent = (idx / total_files) * 100
            progress_bar = "█" * int(progress_percent / 5) + "░" * (20 - int(progress_percent / 5))
            
            # Show what we're about to scan
            print(f"[{progress_bar}] {progress_percent:.1f}% | {Colors.YELLOW}Scanning: {filename:30s}{Colors.END}", end='', flush=True)
            
            query = f'org:{self.target_org} filename:{filename}'
            results = self.search_code(query)
            
            # Clear the line and show result
            if results:
                print(f"\r[{progress_bar}] {progress_percent:.1f}% | {Colors.GREEN}✓ {filename:30s} - Found {len(results):2d} files{Colors.END}")
            else:
                print(f"\r[{progress_bar}] {progress_percent:.1f}% | {Colors.BLUE}○ {filename:30s} - No results{Colors.END}")
                
            for item in results:
                self.findings.append({
                    "type": "Sensitive File",
                    "category": filename,
                    "url": item.get("html_url"),
                    "repo": item.get("repository", {}).get("full_name"),
                    "path": item.get("path"),
                    "severity": "MEDIUM",
                    "timestamp": datetime.now().isoformat()
                })
        
        total_found = len([f for f in self.findings if f['type'] == 'Sensitive File'])
        print(f"\n{Colors.GREEN}{'─'*70}{Colors.END}")
        print(f"{Colors.GREEN}✓ Sensitive file scan complete: {total_found} findings{Colors.END}")
        print(f"{Colors.GREEN}{'─'*70}{Colors.END}\n")
    
    def search_sensitive_extensions(self):
        """Search for files with sensitive extensions"""
        total_exts = len(Patterns.SENSITIVE_EXTENSIONS)
        
        print(f"\n{Colors.CYAN}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}🔐 Scanning {total_exts} Sensitive File Extensions{Colors.END}")
        print(f"{Colors.CYAN}{'='*70}{Colors.END}\n")
        
        for idx, ext in enumerate(Patterns.SENSITIVE_EXTENSIONS, 1):
            progress_percent = (idx / total_exts) * 100
            progress_bar = "█" * int(progress_percent / 5) + "░" * (20 - int(progress_percent / 5))
            
            # Show what we're scanning
            print(f"[{progress_bar}] {progress_percent:.1f}% | {Colors.YELLOW}Scanning: {ext:15s}{Colors.END}", end='', flush=True)
            
            query = f'org:{self.target_org} extension:{ext.replace(".", "")}'
            results = self.search_code(query)
            
            # Clear and show result
            if results:
                print(f"\r[{progress_bar}] {progress_percent:.1f}% | {Colors.GREEN}✓ {ext:15s} - Found {len(results):2d} files{Colors.END}")
            else:
                print(f"\r[{progress_bar}] {progress_percent:.1f}% | {Colors.BLUE}○ {ext:15s} - No results{Colors.END}")
            
            for item in results:
                self.findings.append({
                    "type": "Sensitive Extension",
                    "category": ext,
                    "url": item.get("html_url"),
                    "repo": item.get("repository", {}).get("full_name"),
                    "path": item.get("path"),
                    "severity": "MEDIUM",
                    "timestamp": datetime.now().isoformat()
                })
        
        total_found = len([f for f in self.findings if f['type'] == 'Sensitive Extension'])
        print(f"\n{Colors.GREEN}{'─'*70}{Colors.END}")
        print(f"{Colors.GREEN}✓ Extension scan complete: {total_found} findings{Colors.END}")
        print(f"{Colors.GREEN}{'─'*70}{Colors.END}\n")
    
    def search_keywords(self):
        """Search for sensitive keywords in code"""
        total_keywords = len(Patterns.SENSITIVE_KEYWORDS)
        
        print(f"\n{Colors.CYAN}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}🔍 Deep Scanning {total_keywords} Keywords Across All Repositories{Colors.END}")
        print(f"{Colors.CYAN}{'='*70}{Colors.END}\n")
        
        for idx, keyword in enumerate(Patterns.SENSITIVE_KEYWORDS, 1):
            progress_percent = (idx / total_keywords) * 100
            progress_bar = "█" * int(progress_percent / 5) + "░" * (20 - int(progress_percent / 5))
            
            # Show what we're scanning
            print(f"[{progress_bar}] {progress_percent:.1f}% | {Colors.YELLOW}Keyword: {keyword:20s}{Colors.END}", end='', flush=True)
            
            query = f'org:{self.target_org} "{keyword}"'
            results = self.search_code(query, max_results=50)
            
            files_scanned = 0
            secrets_found = 0
            
            for item in results:
                files_scanned += 1
                
                # Fetch and scan content
                file_url = item.get("url")
                html_url = item.get("html_url")
                
                content = self.fetch_file_content(file_url)
                if content:
                    secret_findings = self.scan_content_for_secrets(content, html_url)
                    secrets_found += len(secret_findings)
                    self.findings.extend(secret_findings)
            
            # Clear and show result
            if secrets_found > 0:
                print(f"\r[{progress_bar}] {progress_percent:.1f}% | {Colors.RED}⚠️  {keyword:20s} - {secrets_found} secrets in {files_scanned} files{Colors.END}")
            elif files_scanned > 0:
                print(f"\r[{progress_bar}] {progress_percent:.1f}% | {Colors.GREEN}✓ {keyword:20s} - {files_scanned} files scanned (clean){Colors.END}")
            else:
                print(f"\r[{progress_bar}] {progress_percent:.1f}% | {Colors.BLUE}○ {keyword:20s} - No results{Colors.END}")
            
            time.sleep(Config.RATE_LIMIT_DELAY)
        
        total_secrets = len([f for f in self.findings if f['type'] == 'Secret Pattern'])
        print(f"\n{Colors.GREEN}{'─'*70}{Colors.END}")
        print(f"{Colors.GREEN}✓ Keyword scan complete: {total_secrets} secrets discovered{Colors.END}")
        print(f"{Colors.GREEN}{'─'*70}{Colors.END}\n")
    
    def run_gitleaks(self, repo_url: str, repo_name: str):
        """Run Gitleaks on a repository"""
        if not check_tool_installed("gitleaks"):
            return
        
        log(f"Running Gitleaks on {repo_name}...", "INFO")
        output_file = self.output_dir / f"gitleaks_{repo_name.replace('/', '_')}.json"
        
        try:
            cmd = [
                "gitleaks",
                "detect",
                "--source", repo_url,
                "--report-format", "json",
                "--report-path", str(output_file)
            ]
            subprocess.run(cmd, capture_output=True, timeout=300)
            
            if output_file.exists():
                with open(output_file, 'r') as f:
                    results = json.load(f)
                    log(f"  Gitleaks found {len(results)} issues", "SUCCESS")
        except Exception as e:
            log(f"  Gitleaks error: {e}", "ERROR")
    
    def run_trufflehog(self, repo_url: str, repo_name: str):
        """Run TruffleHog on a repository"""
        if not check_tool_installed("trufflehog"):
            return
        
        log(f"Running TruffleHog on {repo_name}...", "INFO")
        output_file = self.output_dir / f"trufflehog_{repo_name.replace('/', '_')}.json"
        
        try:
            cmd = [
                "trufflehog",
                "git", repo_url,
                "--json",
                "--output", str(output_file)
            ]
            subprocess.run(cmd, capture_output=True, timeout=300)
            
            if output_file.exists():
                log(f"  TruffleHog results saved", "SUCCESS")
        except Exception as e:
            log(f"  TruffleHog error: {e}", "ERROR")
    
    def generate_report(self):
        """Generate comprehensive report"""
        log("Generating reports...", "HEADER")
        
        # Save raw findings
        raw_file = self.output_dir / "raw_findings.json"
        with open(raw_file, 'w') as f:
            json.dump(self.findings, f, indent=2)
        
        # Generate summary
        summary = {
            "organization": self.target_org,
            "scan_time": datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "by_severity": {},
            "by_type": {},
            "by_category": {}
        }
        
        for finding in self.findings:
            severity = finding.get("severity", "UNKNOWN")
            ftype = finding.get("type", "UNKNOWN")
            category = finding.get("category", "UNKNOWN")
            
            summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1
            summary["by_type"][ftype] = summary["by_type"].get(ftype, 0) + 1
            summary["by_category"][category] = summary["by_category"].get(category, 0) + 1
        
        summary_file = self.output_dir / "summary.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        # Generate HTML report
        self.generate_html_report(summary)
        
        log(f"Reports saved to: {self.output_dir}", "SUCCESS")
    
    def generate_html_report(self, summary: Dict):
        """Generate HTML report"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>GitHub Recon Report - {self.target_org}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; }}
        h1 {{ color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }}
        .summary {{ background: #e8f5e9; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .finding {{ background: #fff3e0; padding: 10px; margin: 10px 0; border-left: 4px solid #ff9800; }}
        .high {{ border-left-color: #f44336; }}
        .medium {{ border-left-color: #ff9800; }}
        .low {{ border-left-color: #4caf50; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #4CAF50; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>GitHub Reconnaissance Report</h1>
        <div class="summary">
            <h2>Summary</h2>
            <p><strong>Organization:</strong> {self.target_org}</p>
            <p><strong>Scan Time:</strong> {summary['scan_time']}</p>
            <p><strong>Total Findings:</strong> {summary['total_findings']}</p>
        </div>
        
        <h2>Findings by Severity</h2>
        <table>
            <tr><th>Severity</th><th>Count</th></tr>
"""
        
        for severity, count in summary['by_severity'].items():
            html += f"<tr><td>{severity}</td><td>{count}</td></tr>"
        
        html += """
        </table>
        
        <h2>Top Categories</h2>
        <table>
            <tr><th>Category</th><th>Count</th></tr>
"""
        
        for category, count in sorted(summary['by_category'].items(), key=lambda x: x[1], reverse=True)[:10]:
            html += f"<tr><td>{category}</td><td>{count}</td></tr>"
        
        html += """
        </table>
    </div>
</body>
</html>
"""
        
        report_file = self.output_dir / "report.html"
        with open(report_file, 'w') as f:
            f.write(html)
    
    def validate_findings(self):
        """Interactive validation of findings"""
        if not self.findings:
            log("No findings to validate", "INFO")
            return
        
        log("\n" + "="*60, "HEADER")
        log("VALIDATION PHASE - Human-in-the-Loop", "HEADER")
        log("="*60, "HEADER")
        
        confirmed = []
        false_positives = []
        
        # Group findings by type for better UX
        grouped = defaultdict(list)
        for finding in self.findings:
            grouped[finding.get('type', 'Unknown')].append(finding)
        
        for ftype, items in grouped.items():
            log(f"\n{ftype} ({len(items)} findings)", "INFO")
            
            for idx, finding in enumerate(items, 1):
                print(f"\n{Colors.CYAN}Finding {idx}/{len(items)}{Colors.END}")
                print(f"  Type: {Colors.YELLOW}{finding.get('category', 'N/A')}{Colors.END}")
                print(f"  URL: {Colors.BLUE}{finding.get('url', 'N/A')}{Colors.END}")
                
                if 'match' in finding:
                    print(f"  Match: {Colors.RED}{finding['match']}{Colors.END}")
                if 'context' in finding:
                    print(f"  Context: {finding['context']}")
                
                while True:
                    decision = input(f"\n  {Colors.BOLD}Valid? (y/n/s=skip all {ftype}): {Colors.END}").lower()
                    
                    if decision == 'y':
                        confirmed.append(finding)
                        break
                    elif decision == 'n':
                        false_positives.append(finding)
                        break
                    elif decision == 's':
                        break
                    else:
                        print("  Invalid input. Use y/n/s")
                
                if decision == 's':
                    break
        
        # Save validated results
        confirmed_file = self.output_dir / "confirmed_findings.json"
        with open(confirmed_file, 'w') as f:
            json.dump(confirmed, f, indent=2)
        
        fp_file = self.output_dir / "false_positives.json"
        with open(fp_file, 'w') as f:
            json.dump(false_positives, f, indent=2)
        
        log(f"\n{Colors.GREEN}Validation complete!{Colors.END}", "SUCCESS")
        log(f"Confirmed: {len(confirmed)}", "SUCCESS")
        log(f"False Positives: {len(false_positives)}", "INFO")
    
    def run_full_scan(self):
        """Execute full reconnaissance workflow"""
        scan_start_time = datetime.now()
        
        print(f"\n{Colors.CYAN}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}🚀 INITIATING COMPREHENSIVE GITHUB RECONNAISSANCE{Colors.END}")
        print(f"{Colors.CYAN}{'='*70}{Colors.END}")
        print(f"{Colors.YELLOW}Target Organization: {Colors.BOLD}{self.target_org}{Colors.END}")
        print(f"{Colors.YELLOW}Scan Started: {scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}")
        print(f"{Colors.YELLOW}Output Directory: {Colors.BOLD}{self.output_dir}{Colors.END}")
        print(f"{Colors.CYAN}{'='*70}{Colors.END}\n")
        
        if not self.verify_token():
            log("Invalid GitHub token. Exiting.", "ERROR")
            return False
        
        if not self.check_rate_limit():
            log("Insufficient rate limit. Try again later.", "WARNING")
            return False
        
        # Phase 1: Repository enumeration
        print(f"\n{Colors.BOLD}{'─'*70}{Colors.END}")
        print(f"{Colors.CYAN}PHASE 1/4: REPOSITORY ENUMERATION{Colors.END}")
        print(f"{Colors.BOLD}{'─'*70}{Colors.END}")
        repos = self.enumerate_repos()
        print(f"{Colors.GREEN}✓ Phase 1 Complete: {len(repos)} repositories discovered{Colors.END}\n")
        
        # Phase 2: Sensitive file detection
        print(f"\n{Colors.BOLD}{'─'*70}{Colors.END}")
        print(f"{Colors.CYAN}PHASE 2/4: SENSITIVE FILE DETECTION{Colors.END}")
        print(f"{Colors.BOLD}{'─'*70}{Colors.END}")
        self.search_sensitive_files()
        print(f"{Colors.GREEN}✓ Phase 2 Complete{Colors.END}\n")
        
        # Phase 3: Sensitive extension detection
        print(f"\n{Colors.BOLD}{'─'*70}{Colors.END}")
        print(f"{Colors.CYAN}PHASE 3/4: SENSITIVE EXTENSION DETECTION{Colors.END}")
        print(f"{Colors.BOLD}{'─'*70}{Colors.END}")
        self.search_sensitive_extensions()
        print(f"{Colors.GREEN}✓ Phase 3 Complete{Colors.END}\n")
        
        # Phase 4: Keyword search
        print(f"\n{Colors.BOLD}{'─'*70}{Colors.END}")
        print(f"{Colors.CYAN}PHASE 4/4: DEEP SECRET PATTERN ANALYSIS{Colors.END}")
        print(f"{Colors.BOLD}{'─'*70}{Colors.END}")
        self.search_keywords()
        print(f"{Colors.GREEN}✓ Phase 4 Complete{Colors.END}\n")
        
        # Phase 5: External tool integration (optional)
        external_tools_available = any(
            check_tool_installed(tool) 
            for tool in Config.EXTERNAL_TOOLS.values()
        )
        
        if external_tools_available and repos:
            print(f"\n{Colors.BOLD}{'─'*70}{Colors.END}")
            print(f"{Colors.CYAN}BONUS PHASE: EXTERNAL TOOL DEEP SCAN{Colors.END}")
            print(f"{Colors.BOLD}{'─'*70}{Colors.END}\n")
            log("External tools detected. Running deep scans on top 5 repos...", "HEADER")
            
            for idx, repo in enumerate(repos[:5], 1):
                repo_url = repo.get('clone_url')
                repo_name = repo.get('full_name')
                
                print(f"{Colors.YELLOW}[{idx}/5] Scanning repository: {repo_name}{Colors.END}")
                
                if check_tool_installed("gitleaks"):
                    self.run_gitleaks(repo_url, repo_name)
                
                if check_tool_installed("trufflehog"):
                    self.run_trufflehog(repo_url, repo_name)
            
            print(f"\n{Colors.GREEN}✓ External tool scans complete{Colors.END}\n")
        
        # Phase 6: Generate reports
        print(f"\n{Colors.BOLD}{'─'*70}{Colors.END}")
        print(f"{Colors.CYAN}FINAL PHASE: REPORT GENERATION{Colors.END}")
        print(f"{Colors.BOLD}{'─'*70}{Colors.END}\n")
        self.generate_report()
        
        # Scan summary
        scan_end_time = datetime.now()
        scan_duration = (scan_end_time - scan_start_time).total_seconds()
        
        print(f"\n{Colors.CYAN}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}📊 SCAN COMPLETE - SUMMARY{Colors.END}")
        print(f"{Colors.CYAN}{'='*70}{Colors.END}")
        print(f"{Colors.GREEN}Total Findings: {Colors.BOLD}{len(self.findings)}{Colors.END}")
        print(f"{Colors.GREEN}Repositories Scanned: {Colors.BOLD}{len(repos)}{Colors.END}")
        print(f"{Colors.GREEN}Scan Duration: {Colors.BOLD}{scan_duration/60:.1f} minutes{Colors.END}")
        print(f"{Colors.GREEN}Results Saved To: {Colors.BOLD}{self.output_dir}{Colors.END}")
        print(f"{Colors.CYAN}{'='*70}{Colors.END}\n")
        
        # File locations
        print(f"{Colors.YELLOW}📁 Output Files:{Colors.END}")
        print(f"  {Colors.CYAN}├─ {Colors.END}HTML Report: {Colors.BOLD}{self.output_dir / 'report.html'}{Colors.END}")
        print(f"  {Colors.CYAN}├─ {Colors.END}Raw Findings: {Colors.BOLD}{self.output_dir / 'raw_findings.json'}{Colors.END}")
        print(f"  {Colors.CYAN}├─ {Colors.END}Summary: {Colors.BOLD}{self.output_dir / 'summary.json'}{Colors.END}")
        print(f"  {Colors.CYAN}└─ {Colors.END}Open report: {Colors.BOLD}open {self.output_dir / 'report.html'}{Colors.END}\n")
        
        # Findings breakdown
        if self.findings:
            print(f"{Colors.YELLOW}🔍 Findings Breakdown:{Colors.END}")
            by_severity = {}
            for finding in self.findings:
                severity = finding.get("severity", "UNKNOWN")
                by_severity[severity] = by_severity.get(severity, 0) + 1
            
            for severity, count in sorted(by_severity.items(), key=lambda x: x[1], reverse=True):
                color = Colors.RED if severity == "HIGH" else Colors.YELLOW if severity == "MEDIUM" else Colors.GREEN
                print(f"  {color}● {severity}: {count} findings{Colors.END}")
        
        print(f"\n{Colors.GREEN}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.GREEN}✓ Reconnaissance Complete! Review findings above.{Colors.END}")
        print(f"{Colors.GREEN}{'='*70}{Colors.END}\n")
        
        return True

# ═══════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════

def main():
    """Main entry point"""
    print_banner()
    
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description='GitHub Advanced Reconnaissance Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 github_recon.py --token "ghp_..." --org "microsoft"
  python3 github_recon.py --aggressive
  python3 github_recon.py --conservative --no-validation
        """
    )
    
    parser.add_argument('-t', '--token', help='GitHub Personal Access Token')
    parser.add_argument('-o', '--org', help='Target organization name')
    parser.add_argument('--aggressive', action='store_true', help='Fast mode (0.5s delay, 10 workers)')
    parser.add_argument('--conservative', action='store_true', help='Slow mode (3s delay, 2 workers)')
    parser.add_argument('--delay', type=float, help='Custom delay between requests')
    parser.add_argument('--workers', type=int, help='Number of parallel workers')
    parser.add_argument('--no-validation', action='store_true', help='Skip manual validation')
    
    args = parser.parse_args()
    
    # Apply performance mode
    if args.aggressive:
        Config.RATE_LIMIT_DELAY = 0.5
        Config.MAX_WORKERS = 10
        log("⚡ Aggressive mode enabled", "WARNING")
    elif args.conservative:
        Config.RATE_LIMIT_DELAY = 3
        Config.MAX_WORKERS = 2
        log("🐢 Conservative mode enabled", "INFO")
    
    # Apply custom settings
    if args.delay:
        Config.RATE_LIMIT_DELAY = args.delay
    if args.workers:
        Config.MAX_WORKERS = args.workers
    
    log(f"Configuration: Delay={Config.RATE_LIMIT_DELAY}s, Workers={Config.MAX_WORKERS}", "INFO")
    
    # Get token
    token = args.token
    if not token:
        token = input(f"{Colors.CYAN}Enter GitHub Personal Access Token: {Colors.END}").strip()
    
    if not token:
        log("Token is required. Exiting.", "ERROR")
        sys.exit(1)
    
    # Get organization
    target_org = args.org
    if not target_org:
        target_org = input(f"{Colors.CYAN}Enter target organization name: {Colors.END}").strip()
    
    if not target_org:
        log("Organization name is required. Exiting.", "ERROR")
        sys.exit(1)
    
    # Initialize and run
    recon = GitHubRecon(token=token, target_org=target_org)
    
    success = recon.run_full_scan()
    
    if success and not args.no_validation:
        validate_choice = input(f"\n{Colors.CYAN}Run validation workflow? (y/n): {Colors.END}").lower()
        if validate_choice == 'y':
            recon.validate_findings()
    
    print(f"\n{Colors.GREEN}Thank you for using GitHub Advanced Reconnaissance Tool!{Colors.END}\n")

if __name__ == "__main__":
    main()
