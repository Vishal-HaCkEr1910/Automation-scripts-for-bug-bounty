#!/usr/bin/env python3
"""
Advanced JavaScript Reconnaissance & Secrets Discovery Tool
A comprehensive framework for JS file discovery, analysis, and secret extraction
"""

import subprocess
import os
import hashlib
import json
import re
import time
from multiprocessing import Pool, cpu_count
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime
from collections import defaultdict
import argparse

# --- ANSI COLOR CODES ---
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# --- CONFIGURATION ---
class Config:
    INPUT_FILE = "subdomains.txt"
    THREADS = min(cpu_count() * 2, 30)  # Optimal threading
    NUCLEI_TEMPLATES = "/path/to/nuclei-templates/http/exposures/"
    TIMEOUT = 20
    MAX_RETRIES = 3
    
    # Advanced noise filtering patterns
    VENDOR_PATTERNS = [
        'jquery', 'bootstrap', 'wp-includes', 'node_modules',
        'google-analytics', 'gtag', 'cloudflare', 'recaptcha',
        'polyfill', 'fontawesome', 'cdn.jsdelivr', 'unpkg.com',
        'analytics.js', 'gtm.js', 'facebook.net', 'doubleclick',
        'modernizr', 'lodash', 'moment.js', 'chart.js'
    ]
    
    # Enhanced regex patterns for secret detection
    SECRET_PATTERNS = {
        'AWS Access Key': r'AKIA[0-9A-Z]{16}',
        'AWS Secret Key': r'(?i)aws(.{0,20})?["\'][0-9a-zA-Z\/+]{40}["\']',
        'GitHub Token': r'ghp_[0-9a-zA-Z]{36}',
        'GitHub OAuth': r'gho_[0-9a-zA-Z]{36}',
        'GitHub App Token': r'(ghu|ghs)_[0-9a-zA-Z]{36}',
        'Generic API Key': r'(?i)(api[_-]?key|apikey)[\s]*[=:]+[\s]*[\'"]([0-9a-zA-Z\-_]{20,})[\'"]',
        'Generic Secret': r'(?i)(secret|token|password)[\s]*[=:]+[\s]*[\'"]([^\'"]{8,})[\'"]',
        'Slack Token': r'xox[baprs]-[0-9a-zA-Z]{10,72}',
        'Stripe Key': r'(?i)(sk|pk)_(live|test)_[0-9a-zA-Z]{24,}',
        'Firebase': r'(?i)firebase[_-]?api[_-]?key[\s]*[=:]+[\s]*[\'"]([^\'"]+)[\'"]',
        'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
        'Google OAuth': r'ya29\.[0-9A-Za-z\-_]+',
        'Heroku API Key': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
        'MailChimp API Key': r'[0-9a-f]{32}-us[0-9]{1,2}',
        'Mailgun API Key': r'key-[0-9a-zA-Z]{32}',
        'PayPal/Braintree': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
        'Picatic API Key': r'sk_live_[0-9a-z]{32}',
        'SendGrid API Key': r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',
        'Square Access Token': r'sq0atp-[0-9A-Za-z\-_]{22}',
        'Square OAuth Secret': r'sq0csp-[0-9A-Za-z\-_]{43}',
        'Twilio API Key': r'SK[0-9a-fA-F]{32}',
        'Twitter Access Token': r'[1-9][0-9]+-[0-9a-zA-Z]{40}',
        'JWT Token': r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
        'S3 Bucket': r'(?i)s3\.amazonaws\.com[/:]([a-zA-Z0-9.\-_]+)',
        'Azure Storage': r'(?i)(DefaultEndpointsProtocol|AccountName|AccountKey|BlobEndpoint)',
        'RSA Private Key': r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        'SSH Private Key': r'-----BEGIN OPENSSH PRIVATE KEY-----',
        'PGP Private Key': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
        'Generic Password': r'(?i)(password|passwd|pwd)[\s]*[=:]+[\s]*[\'"]([^\'"]{6,})[\'"]',
        'Database Connection': r'(?i)(mongodb|mysql|postgres|redis)://[^\s\'"]+',
        'Bearer Token': r'(?i)bearer[\s]+[a-zA-Z0-9\-._~+/]+=*',
        'Authorization Header': r'(?i)authorization[\s]*:[\s]*[\'"]?([^\s\'"]+)[\'"]?',
    }

# --- DIRECTORY STRUCTURE ---
class DirectoryManager:
    DIRS = {
        'recon': 'recon_output',
        'js': 'js_storage',
        'maps': 'js_maps',
        'source': 'source_code',
        'results': 'final_results',
        'logs': 'logs',
        'metadata': 'metadata'
    }
    
    @classmethod
    def setup(cls):
        for dir_path in cls.DIRS.values():
            Path(dir_path).mkdir(exist_ok=True)
        print(f"{Colors.GREEN}[✓] Directory structure created{Colors.END}")

# --- UTILITY FUNCTIONS ---
class Utils:
    @staticmethod
    def run_cmd(cmd, timeout=Config.TIMEOUT, capture=True):
        """Execute shell command with error handling"""
        try:
            if capture:
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, 
                    text=True, timeout=timeout, check=False
                )
                return result.stdout, result.stderr
            else:
                subprocess.run(cmd, shell=True, timeout=timeout, check=False)
                return None, None
        except subprocess.TimeoutExpired:
            print(f"{Colors.YELLOW}[!] Command timeout: {cmd[:50]}...{Colors.END}")
            return None, "Timeout"
        except Exception as e:
            print(f"{Colors.RED}[!] Command failed: {str(e)}{Colors.END}")
            return None, str(e)
    
    @staticmethod
    def is_noise(url):
        """Advanced noise filtering"""
        url_lower = url.lower()
        
        # Check vendor patterns
        if any(vendor in url_lower for vendor in Config.VENDOR_PATTERNS):
            return True
        
        # Filter by file extension
        noise_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', 
                           '.woff', '.woff2', '.ttf', '.eot', '.ico', '.mp4', 
                           '.mp3', '.pdf', '.zip']
        if any(url_lower.endswith(ext) for ext in noise_extensions):
            return True
        
        # Filter minified vendor files (common pattern)
        if re.search(r'(vendor|bundle|chunk)\.[a-f0-9]{8,}\.js', url_lower):
            return True
            
        return False
    
    @staticmethod
    def generate_filename(url):
        """Generate unique filename from URL"""
        parsed = urlparse(url)
        path_hash = hashlib.md5(url.encode()).hexdigest()[:12]
        domain = parsed.netloc.replace('.', '_')
        return f"{domain}_{path_hash}.js"
    
    @staticmethod
    def log_finding(category, url, finding, severity="INFO"):
        """Log findings with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            'timestamp': timestamp,
            'category': category,
            'url': url,
            'finding': finding,
            'severity': severity
        }
        
        log_file = f"{DirectoryManager.DIRS['logs']}/{category}.json"
        
        try:
            with open(log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to log: {e}{Colors.END}")

# --- PHASE 1: DISCOVERY ---
class Discovery:
    @staticmethod
    def run_all(input_file):
        """Run all discovery tools in parallel where possible"""
        print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*70}")
        print(f"PHASE 1: BROAD DISCOVERY")
        print(f"{'='*70}{Colors.END}\n")
        
        tools = {
            'katana': Discovery.katana,
            'gau': Discovery.gau,
            'waybackurls': Discovery.waybackurls,
            'hakrawler': Discovery.hakrawler,
            'subjs': Discovery.subjs,
            'gospider': Discovery.gospider,
            'getJS': Discovery.getjs,
        }
        
        results = {}
        for name, func in tools.items():
            print(f"{Colors.CYAN}[→] Running {name}...{Colors.END}")
            count = func(input_file)
            results[name] = count
            print(f"{Colors.GREEN}[✓] {name}: Found {count} URLs{Colors.END}\n")
        
        return results
    
    @staticmethod
    def katana(input_file):
        output = f"{DirectoryManager.DIRS['recon']}/katana_js.txt"
        Utils.run_cmd(f"katana -list {input_file} -jc -d 3 -kf all -silent -o {output}")
        return Discovery._count_lines(output)
    
    @staticmethod
    def gau(input_file):
        output = f"{DirectoryManager.DIRS['recon']}/gau_js.txt"
        Utils.run_cmd(f"cat {input_file} | gau --subs --blacklist png,jpg,gif,svg,css,woff,woff2,ttf | grep '\\.js' > {output}")
        return Discovery._count_lines(output)
    
    @staticmethod
    def waybackurls(input_file):
        output = f"{DirectoryManager.DIRS['recon']}/wayback_js.txt"
        Utils.run_cmd(f"cat {input_file} | waybackurls | grep '\\.js' > {output}")
        return Discovery._count_lines(output)
    
    @staticmethod
    def hakrawler(input_file):
        output = f"{DirectoryManager.DIRS['recon']}/hakrawler_js.txt"
        Utils.run_cmd(f"cat {input_file} | hakrawler -js -depth 3 -plain > {output}")
        return Discovery._count_lines(output)
    
    @staticmethod
    def subjs(input_file):
        output = f"{DirectoryManager.DIRS['recon']}/subjs_js.txt"
        Utils.run_cmd(f"cat {input_file} | subjs > {output}")
        return Discovery._count_lines(output)
    
    @staticmethod
    def gospider(input_file):
        output = f"{DirectoryManager.DIRS['recon']}/gospider_js.txt"
        Utils.run_cmd(f"gospider -S {input_file} -d 3 -t 20 --js | grep '\\.js' > {output}")
        return Discovery._count_lines(output)
    
    @staticmethod
    def getjs(input_file):
        output = f"{DirectoryManager.DIRS['recon']}/getjs_js.txt"
        Utils.run_cmd(f"cat {input_file} | getJS --complete > {output}")
        return Discovery._count_lines(output)
    
    @staticmethod
    def _count_lines(filepath):
        try:
            with open(filepath, 'r') as f:
                return len([line for line in f if line.strip()])
        except:
            return 0

# --- PHASE 2: DOWNLOAD & PROCESSING ---
class Downloader:
    @staticmethod
    def download_and_process(url):
        """Download JS file, recover source maps, and beautify"""
        url = url.strip()
        if not url or Utils.is_noise(url):
            return None
        
        try:
            fname = Utils.generate_filename(url)
            fpath = f"{DirectoryManager.DIRS['js']}/{fname}"
            
            # Download with proper headers
            headers = [
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept: application/javascript, */*",
                "Accept-Encoding: gzip, deflate",
                "Connection: keep-alive"
            ]
            
            header_str = " -H ".join([f'"{h}"' for h in headers])
            download_cmd = f"curl -skL -H {header_str} '{url}' -o {fpath} --retry {Config.MAX_RETRIES} --max-time {Config.TIMEOUT}"
            
            stdout, stderr = Utils.run_cmd(download_cmd)
            
            # Verify download
            if not os.path.exists(fpath) or os.path.getsize(fpath) < 100:
                return None
            
            # Source map recovery
            Downloader._recover_source_map(url, fname)
            
            # Beautification
            Utils.run_cmd(f"js-beautify -r {fpath}", timeout=10)
            
            # Save metadata
            metadata = {
                'url': url,
                'filename': fname,
                'size': os.path.getsize(fpath),
                'timestamp': datetime.now().isoformat()
            }
            
            with open(f"{DirectoryManager.DIRS['metadata']}/{fname}.json", 'w') as f:
                json.dump(metadata, f, indent=2)
            
            return fpath
            
        except Exception as e:
            Utils.log_finding('download_errors', url, str(e), 'ERROR')
            return None
    
    @staticmethod
    def _recover_source_map(url, fname):
        """Attempt to recover source maps"""
        map_url = url + ".map"
        
        # Check if source map exists
        stdout, _ = Utils.run_cmd(f"curl -skI '{map_url}'", timeout=5)
        
        if stdout and "200 OK" in stdout:
            map_path = f"{DirectoryManager.DIRS['maps']}/{fname}.map"
            Utils.run_cmd(f"curl -skL '{map_url}' -o {map_path}", timeout=15)
            
            # Extract source code using sourcemapper
            Utils.run_cmd(f"sourcemapper -url {map_url} -output {DirectoryManager.DIRS['source']}/{fname.replace('.js', '')}", timeout=30)
            
            return True
        return False

# --- PHASE 3: ANALYSIS ---
class Analyzer:
    def __init__(self):
        self.findings = defaultdict(list)
    
    def run_all(self):
        """Execute all analysis tools"""
        print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*70}")
        print(f"PHASE 3: MULTI-STAGE ANALYSIS")
        print(f"{'='*70}{Colors.END}\n")
        
        analyses = [
            ('LinkFinder', self.linkfinder),
            ('Jsluice (Secrets)', self.jsluice_secrets),
            ('Jsluice (URLs)', self.jsluice_urls),
            ('SecretFinder', self.secretfinder),
            ('Nuclei', self.nuclei),
            ('Trufflehog', self.trufflehog),
            ('Custom Regex', self.custom_regex),
            ('Retire.js', self.retirejs),
        ]
        
        for name, func in analyses:
            print(f"{Colors.CYAN}[→] Running {name}...{Colors.END}")
            count = func()
            print(f"{Colors.GREEN}[✓] {name}: {count} findings{Colors.END}\n")
    
    def linkfinder(self):
        output = f"{DirectoryManager.DIRS['results']}/endpoints.txt"
        Utils.run_cmd(f"python3 /opt/LinkFinder/linkfinder.py -i '{DirectoryManager.DIRS['js']}/*.js' -o cli > {output}", timeout=300)
        return self._count_file_lines(output)
    
    def jsluice_secrets(self):
        output = f"{DirectoryManager.DIRS['results']}/jsluice_secrets.txt"
        Utils.run_cmd(f"find {DirectoryManager.DIRS['js']}/ -name '*.js' | xargs -P {Config.THREADS} -I% jsluice secrets % >> {output}", timeout=300)
        return self._count_file_lines(output)
    
    def jsluice_urls(self):
        output = f"{DirectoryManager.DIRS['results']}/jsluice_urls.txt"
        Utils.run_cmd(f"find {DirectoryManager.DIRS['js']}/ -name '*.js' | xargs -P {Config.THREADS} -I% jsluice urls % >> {output}", timeout=300)
        return self._count_file_lines(output)
    
    def secretfinder(self):
        output = f"{DirectoryManager.DIRS['results']}/secretfinder_results.txt"
        Utils.run_cmd(f"find {DirectoryManager.DIRS['js']}/ -name '*.js' | xargs -I% python3 /opt/SecretFinder/SecretFinder.py -i % -o cli >> {output}", timeout=300)
        return self._count_file_lines(output)
    
    def nuclei(self):
        output = f"{DirectoryManager.DIRS['results']}/nuclei_verified.txt"
        Utils.run_cmd(f"nuclei -target {DirectoryManager.DIRS['js']}/ -t {Config.NUCLEI_TEMPLATES} -silent -o {output}", timeout=600)
        return self._count_file_lines(output)
    
    def trufflehog(self):
        """Use Trufflehog for advanced secret scanning"""
        output = f"{DirectoryManager.DIRS['results']}/trufflehog_secrets.json"
        Utils.run_cmd(f"trufflehog filesystem {DirectoryManager.DIRS['js']}/ --json > {output}", timeout=600)
        return self._count_file_lines(output)
    
    def retirejs(self):
        """Scan for vulnerable JavaScript libraries"""
        output = f"{DirectoryManager.DIRS['results']}/retirejs_vulnerabilities.json"
        Utils.run_cmd(f"retire --path {DirectoryManager.DIRS['js']}/ --outputformat json --outputpath {output}", timeout=300)
        return self._count_file_lines(output)
    
    def custom_regex(self):
        """Custom regex-based secret detection with detailed output"""
        print(f"{Colors.CYAN}  [*] Running custom regex patterns...{Colors.END}")
        
        findings_count = 0
        output_file = f"{DirectoryManager.DIRS['results']}/custom_regex_secrets.json"
        
        js_files = list(Path(DirectoryManager.DIRS['js']).glob('*.js'))
        
        for js_file in js_files:
            try:
                with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Get original URL from metadata
                metadata_file = f"{DirectoryManager.DIRS['metadata']}/{js_file.name}.json"
                original_url = str(js_file)
                
                if os.path.exists(metadata_file):
                    with open(metadata_file, 'r') as mf:
                        metadata = json.load(mf)
                        original_url = metadata.get('url', str(js_file))
                
                for secret_type, pattern in Config.SECRET_PATTERNS.items():
                    matches = re.finditer(pattern, content)
                    
                    for match in matches:
                        finding = {
                            'type': secret_type,
                            'url': original_url,
                            'file': str(js_file),
                            'match': match.group(0)[:100],  # Truncate long matches
                            'line_number': content[:match.start()].count('\n') + 1
                        }
                        
                        self.findings[secret_type].append(finding)
                        findings_count += 1
                        
                        # Log finding
                        Utils.log_finding('custom_regex', original_url, 
                                        f"{secret_type}: {match.group(0)[:50]}...", 
                                        'HIGH')
            
            except Exception as e:
                continue
        
        # Save findings to JSON
        with open(output_file, 'w') as f:
            json.dump(dict(self.findings), f, indent=2)
        
        return findings_count
    
    @staticmethod
    def _count_file_lines(filepath):
        try:
            with open(filepath, 'r') as f:
                return len([line for line in f if line.strip()])
        except:
            return 0

# --- PHASE 4: REPORTING ---
class Reporter:
    def __init__(self, analyzer):
        self.analyzer = analyzer
    
    def generate_report(self):
        """Generate comprehensive colored output report"""
        print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*70}")
        print(f"FINAL RESULTS SUMMARY")
        print(f"{'='*70}{Colors.END}\n")
        
        # Group findings by severity
        high_severity = ['AWS Access Key', 'AWS Secret Key', 'GitHub Token', 
                        'Stripe Key', 'RSA Private Key', 'SSH Private Key']
        
        print(f"{Colors.RED}{Colors.BOLD}HIGH SEVERITY FINDINGS:{Colors.END}\n")
        high_count = 0
        
        for secret_type in high_severity:
            if secret_type in self.analyzer.findings:
                findings = self.analyzer.findings[secret_type]
                print(f"{Colors.RED}● {secret_type}: {len(findings)} found{Colors.END}")
                
                for finding in findings[:5]:  # Show first 5
                    print(f"  {Colors.YELLOW}├─ URL:{Colors.END} {Colors.CYAN}{finding['url']}{Colors.END}")
                    print(f"  {Colors.YELLOW}└─ Match:{Colors.END} {finding['match']}\n")
                    high_count += len(findings)
                
                if len(findings) > 5:
                    print(f"  {Colors.YELLOW}... and {len(findings) - 5} more{Colors.END}\n")
        
        print(f"\n{Colors.YELLOW}{Colors.BOLD}MEDIUM SEVERITY FINDINGS:{Colors.END}\n")
        medium_count = 0
        
        for secret_type, findings in self.analyzer.findings.items():
            if secret_type not in high_severity:
                print(f"{Colors.YELLOW}● {secret_type}: {len(findings)} found{Colors.END}")
                medium_count += len(findings)
                
                for finding in findings[:3]:  # Show first 3
                    print(f"  {Colors.CYAN}├─ URL:{Colors.END} {finding['url']}")
                    print(f"  {Colors.CYAN}└─ Match:{Colors.END} {finding['match'][:80]}...\n")
                
                if len(findings) > 3:
                    print(f"  {Colors.YELLOW}... and {len(findings) - 3} more{Colors.END}\n")
        
        # Summary statistics
        print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*70}")
        print(f"STATISTICS")
        print(f"{'='*70}{Colors.END}\n")
        
        print(f"{Colors.GREEN}Total High Severity: {high_count}{Colors.END}")
        print(f"{Colors.YELLOW}Total Medium Severity: {medium_count}{Colors.END}")
        print(f"{Colors.CYAN}Total Findings: {high_count + medium_count}{Colors.END}")
        
        # File locations
        print(f"\n{Colors.BOLD}Detailed results saved to:{Colors.END}")
        print(f"  • Custom Regex: {Colors.CYAN}{DirectoryManager.DIRS['results']}/custom_regex_secrets.json{Colors.END}")
        print(f"  • All Results: {Colors.CYAN}{DirectoryManager.DIRS['results']}/{Colors.END}")
        print(f"  • Logs: {Colors.CYAN}{DirectoryManager.DIRS['logs']}/{Colors.END}\n")

# --- MAIN ORCHESTRATOR ---
def main():
    parser = argparse.ArgumentParser(
        description='Advanced JavaScript Reconnaissance & Secrets Discovery Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -i domains.txt
  %(prog)s -i domains.txt -t 40 --skip-download
  %(prog)s -i domains.txt --templates /path/to/nuclei-templates
        """
    )
    
    parser.add_argument('-i', '--input', required=True, help='Input file with domains/subdomains')
    parser.add_argument('-t', '--threads', type=int, default=Config.THREADS, help=f'Number of threads (default: {Config.THREADS})')
    parser.add_argument('--templates', default=Config.NUCLEI_TEMPLATES, help='Path to Nuclei templates')
    parser.add_argument('--skip-download', action='store_true', help='Skip download phase (analyze existing files)')
    parser.add_argument('--skip-discovery', action='store_true', help='Skip discovery phase')
    
    args = parser.parse_args()
    
    # Update config
    Config.INPUT_FILE = args.input
    Config.THREADS = args.threads
    Config.NUCLEI_TEMPLATES = args.templates
    
    # Banner
    print(f"{Colors.HEADER}{Colors.BOLD}")
    print(r"""
    ╔═══════════════════════════════════════════════════════════════╗
    ║  JS RECON & SECRETS SCANNER v2.0                             ║
    ║  Advanced JavaScript Analysis Framework                       ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    print(f"{Colors.END}")
    
    start_time = time.time()
    
    # Setup
    DirectoryManager.setup()
    
    # Phase 1: Discovery
    if not args.skip_discovery:
        discovery_results = Discovery.run_all(Config.INPUT_FILE)
        
        # Merge and deduplicate
        print(f"{Colors.CYAN}[→] Merging and deduplicating results...{Colors.END}")
        Utils.run_cmd(f"cat {DirectoryManager.DIRS['recon']}/*.txt | sort -u | grep '\\.js$' | grep -ivE '(.png|.jpg|.svg|.css|.gif|.woff)' > target_js_links.txt")
        
        with open('target_js_links.txt', 'r') as f:
            total_unique = len([line for line in f if line.strip()])
        
        print(f"{Colors.GREEN}[✓] Total unique JS URLs: {total_unique}{Colors.END}\n")
    
    # Phase 2: Download
    if not args.skip_download:
        with open('target_js_links.txt', 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        print(f"{Colors.HEADER}{Colors.BOLD}{'='*70}")
        print(f"PHASE 2: DOWNLOAD & PROCESSING")
        print(f"{'='*70}{Colors.END}\n")
        
        print(f"{Colors.CYAN}[→] Downloading {len(urls)} JS files with {Config.THREADS} threads...{Colors.END}")
        
        with Pool(Config.THREADS) as pool:
            results = pool.map(Downloader.download_and_process, urls)
        
        successful = len([r for r in results if r is not None])
        print(f"{Colors.GREEN}[✓] Successfully downloaded: {successful}/{len(urls)}{Colors.END}\n")
    
    # Phase 3: Analysis
    analyzer = Analyzer()
    analyzer.run_all()
    
    # Phase 4: Reporting
    reporter = Reporter(analyzer)
    reporter.generate_report()
    
    # Final timing
    elapsed = time.time() - start_time
    print(f"\n{Colors.GREEN}{Colors.BOLD}[✓] Scan completed in {elapsed:.2f} seconds{Colors.END}\n")

if __name__ == "__main__":
    main()