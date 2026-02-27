# 🔍 Advanced GitHub Reconnaissance Tool

> **Professional-grade GitHub reconnaissance for bug bounty hunters and security researchers**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/Security-Research-red.svg)]()

A comprehensive, modular Python tool designed for ethical security research and bug bounty reconnaissance. This tool performs **passive GitHub reconnaissance**, aggregates findings intelligently, and implements a human-in-the-loop validation workflow to minimize false positives.

---

## ⚡ Features

### 🎯 **Core Capabilities**
- ✅ **60+ Secret Pattern Detection** - AWS keys, API tokens, JWTs, private keys, database credentials
- ✅ **Sensitive File Discovery** - `.env`, `config.json`, SSH keys, database configs
- ✅ **Organization-Wide Scanning** - Automated repository enumeration
- ✅ **Keyword Intelligence** - Context-aware scanning for passwords, secrets, tokens
- ✅ **Multi-Tool Integration** - Gitleaks, TruffleHog, Git-secrets support
- ✅ **Rate Limit Management** - Intelligent API throttling
- ✅ **Interactive Validation** - Human-in-the-loop false positive filtering
- ✅ **Comprehensive Reporting** - JSON + HTML reports with severity classification

### 🛡️ **Security & Quality**
- 🔒 **No Credential Hardcoding** - Interactive token input
- 🔒 **Token Verification** - Validates GitHub token before scanning
- 🔒 **HTTPS-Only** - Secure communication
- 🔒 **Error Handling** - Graceful failure management
- 🔒 **Timeout Protection** - Prevents hanging requests

### 📊 **Output & Reporting**
- 📁 **Timestamped Results** - Organized output directories
- 📁 **JSON Reports** - Machine-readable findings
- 📁 **HTML Dashboards** - Visual summary reports
- 📁 **Categorized Findings** - Grouped by type, severity, category
- 📁 **External Tool Results** - Gitleaks/TruffleHog integration

---

## 📋 Table of Contents

- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Examples](#-usage-examples)
- [Configuration](#-configuration)
- [Pattern Detection](#-pattern-detection)
- [External Tools](#-external-tools)
- [Output Structure](#-output-structure)
- [Best Practices](#-best-practices)
- [Troubleshooting](#-troubleshooting)
- [Legal & Ethics](#-legal--ethics)
- [Contributing](#-contributing)

---

## 🚀 Installation

### **Prerequisites**
- Python 3.8 or higher
- GitHub Personal Access Token
- Git (optional, for external tools)

### **Step 1: Clone the Repository**
```bash
git clone https://github.com/yourusername/github-recon-tool.git
cd github-recon-tool
```

### **Step 2: Install Python Dependencies**
```bash
pip install -r requirements.txt
```

**`requirements.txt`:**
```
requests>=2.31.0
```

### **Step 3: Install Optional External Tools**

#### **Gitleaks** (Recommended)
```bash
# macOS
brew install gitleaks

# Linux
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz
tar -xzf gitleaks_8.18.0_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/

# Windows
choco install gitleaks
```

#### **TruffleHog** (Recommended)
```bash
# macOS
brew install trufflesecurity/trufflehog/trufflehog

# Linux/Windows
pip install trufflehog
```

#### **Git-secrets** (Optional)
```bash
# macOS
brew install git-secrets

# Linux
git clone https://github.com/awslabs/git-secrets.git
cd git-secrets
sudo make install
```

---

## 🎯 Quick Start

### **1. Generate GitHub Personal Access Token**

1. Go to GitHub Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Click "Generate new token (classic)"
3. Select scopes:
   - ✅ `repo` (all)
   - ✅ `read:org`
   - ✅ `read:user`
4. Generate and **copy the token** (you won't see it again!)

### **2. Run the Tool**

```bash
python github_recon.py
```

**Interactive Prompts:**
```
Enter GitHub Personal Access Token: ghp_xxxxxxxxxxxxxxxxxxxx
Enter target organization name: target-company
Enable validation mode? (y/n): y
```

### **3. Review Results**

Results are saved in:
```
github_recon_results/
└── target-company_20250117_143022/
    ├── raw_findings.json
    ├── confirmed_findings.json
    ├── false_positives.json
    ├── summary.json
    ├── report.html
    ├── gitleaks_*.json
    └── trufflehog_*.json
```

---

# 🛠️ Usage Guide

This guide covers all usage modes, command-line arguments, and performance configurations for the GitHub Advanced Reconnaissance Tool.

---

## 📋 Table of Contents

- [Interactive Mode](#1-interactive-mode)
- [CLI Automation Mode](#2-cli-automation-mode)
- [Performance Modes](#3-performance-modes)
- [Command Line Arguments](#️-command-line-arguments)
- [Output Structure](#-output-structure)
- [Recommended Settings](#-recommended-settings-by-scenario)
- [Advanced Examples](#-advanced-usage-examples)

---

## 1. Interactive Mode

Simply run the script, and it will prompt you for the Token and Organization.

```bash
python3 github_recon.py
```

**Interactive Prompts:**

```
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   GitHub Advanced Reconnaissance Tool                        ║
║   Professional Bug Bounty & Security Research                ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

[14:30:22] [HEADER] Configuration Setup
Enter GitHub Personal Access Token: ghp_xxxxxxxxxxxxxxxxxxxx
Enter target organization name: tesla
Enable validation mode? (y/n): y

[14:30:25] [SUCCESS] Authenticated as: researcher_username
[14:30:26] [INFO] Starting comprehensive GitHub reconnaissance...
```

**When to Use:**
- ✅ First-time users
- ✅ One-off manual scans
- ✅ Learning and testing
- ✅ When you need validation workflow

---

## 2. CLI Automation Mode

Pass arguments directly to bypass prompts. Perfect for **cron jobs** or **automation scripts**.

```bash
python3 github_recon.py --token "ghp_YOURTOKEN" --org "tesla" --no-validation
```

### **Examples:**

#### Basic Automated Scan
```bash
python3 github_recon.py \
  --token "ghp_1234567890abcdef" \
  --org "microsoft"
```

#### Silent Background Scan
```bash
python3 github_recon.py \
  --token "ghp_1234567890abcdef" \
  --org "google" \
  --no-validation \
  > scan.log 2>&1 &
```

#### Scheduled Cron Job
```bash
# Add to crontab: Daily scan at 2 AM
0 2 * * * /usr/bin/python3 /path/to/github_recon.py --token "$GITHUB_TOKEN" --org "target-org" --no-validation
```

**When to Use:**
- ✅ Automated scanning pipelines
- ✅ Scheduled reconnaissance
- ✅ CI/CD integration
- ✅ Batch processing multiple organizations

---

## 3. Performance Modes

### 🏎️ **Aggressive Mode (Fast & Noisy)**

Uses **10 workers** and **minimal delay (0.5s)**. Use this if you don't care about rate limits or noise.

```bash
python3 github_recon.py \
  --token "ghp_..." \
  --org "target" \
  --aggressive
```

**Configuration:**
- **Workers:** 10 parallel threads
- **Delay:** 0.5 seconds between requests
- **Max Results:** 100 per query
- **Speed:** ⚡⚡⚡ Fast
- **Stealth:** 🔊 Noisy

**Best For:**
- Small organizations (<10 repos)
- Time-critical scans
- When you have high rate limits
- Testing environments

**⚠️ Warning:** May exhaust rate limits quickly on large organizations!

---

### 🥷 **Conservative Mode (Stealthy)**

Uses **2 workers** and **long delays (3s)**. Use this to avoid hitting API rate limits during large scans.

```bash
python3 github_recon.py \
  --token "ghp_..." \
  --org "target" \
  --conservative
```

**Configuration:**
- **Workers:** 2 parallel threads
- **Delay:** 3 seconds between requests
- **Max Results:** 50 per query
- **Speed:** 🐢 Slow
- **Stealth:** 🤫 Quiet

**Best For:**
- Large organizations (200+ repos)
- Rate-limited tokens
- Long-running scans
- Production environments
- Avoiding detection

---

### ⚖️ **Balanced Mode (Default)**

Optimal balance between speed and safety.

```bash
python3 github_recon.py \
  --token "ghp_..." \
  --org "target"
```

**Configuration:**
- **Workers:** 5 parallel threads
- **Delay:** 2 seconds between requests
- **Max Results:** 100 per query
- **Speed:** ⚡⚡ Medium
- **Stealth:** 🔇 Moderate

**Best For:**
- Most use cases
- Medium organizations (10-50 repos)
- First-time scans

---

## ⚙️ Command Line Arguments

### **Full Argument Reference**

| Argument | Short | Type | Description | Default |
|----------|-------|------|-------------|---------|
| `--token` | `-t` | `string` | Your GitHub Personal Access Token | Interactive |
| `--org` | `-o` | `string` | The Target Organization Name | Interactive |
| `--aggressive` | | `flag` | Sets delay to 0.5s, Workers to 10 | `False` |
| `--conservative` | | `flag` | Sets delay to 3.0s, Workers to 2 | `False` |
| `--delay` | `-d` | `float` | Custom delay between requests (seconds) | `2.0` |
| `--workers` | `-w` | `int` | Number of parallel threads | `5` |
| `--max-results` | `-m` | `int` | Maximum results per query | `100` |
| `--no-validation` | | `flag` | Skip the manual "Yes/No" validation step | `False` |
| `--output` | | `string` | Custom output directory path | `github_recon_results` |
| `--verbose` | `-v` | `flag` | Enable verbose logging | `False` |
| `--quiet` | `-q` | `flag` | Minimal output (errors only) | `False` |

### **Usage Examples:**

#### Custom Delay
```bash
python3 github_recon.py --token "ghp_..." --org "target" --delay 5.0
```

#### Custom Workers
```bash
python3 github_recon.py --token "ghp_..." --org "target" --workers 8
```

#### Combined Custom Settings
```bash
python3 github_recon.py \
  --token "ghp_..." \
  --org "target" \
  --delay 1.5 \
  --workers 7 \
  --max-results 75
```

#### Verbose Mode
```bash
python3 github_recon.py --token "ghp_..." --org "target" --verbose
```

#### Quiet Mode (Logging Only)
```bash
python3 github_recon.py --token "ghp_..." --org "target" --quiet > scan.log
```

#### Custom Output Directory
```bash
python3 github_recon.py \
  --token "ghp_..." \
  --org "target" \
  --output "/path/to/custom/results"
```

---

## 📂 Output Structure

All results are saved in the `github_recon_results/` directory, organized by target and timestamp.

```
github_recon_results/
└── tesla_20250117_143022/
    ├── report.html                  # 📊 Summary dashboard (Open in browser)
    ├── raw_findings.json            # 📄 All raw data for parsing
    ├── confirmed_findings.json      # ✅ Manually verified results
    ├── false_positives.json         # ❌ Marked as false positives
    ├── summary.json                 # 📈 Statistical summary
    ├── gitleaks_repo1.json          # 🔍 Gitleaks deep scan results
    └── trufflehog_repo2.json        # 🔍 TruffleHog deep scan results
```

### **File Descriptions:**

| File | Description | When to Use |
|------|-------------|-------------|
| **report.html** | Visual HTML dashboard with charts and summaries | Quick overview, presentations |
| **raw_findings.json** | All findings before validation | Automated processing, scripts |
| **confirmed_findings.json** | User-validated true positives | Final reporting, bug bounty submissions |
| **false_positives.json** | Findings marked as FP during validation | Pattern refinement, ML training |
| **summary.json** | Aggregate statistics and counts | Quick stats, dashboards |
| **gitleaks_*.json** | External tool results (if installed) | Deep analysis, cross-validation |
| **trufflehog_*.json** | External tool results (if installed) | Deep analysis, cross-validation |

### **Opening Reports:**

```bash
# Open HTML report in browser
open github_recon_results/tesla_20250117_143022/report.html

# Or on Linux
xdg-open github_recon_results/tesla_20250117_143022/report.html

# Or on Windows
start github_recon_results/tesla_20250117_143022/report.html
```

### **Processing JSON Results:**

```bash
# Pretty print findings
cat github_recon_results/tesla_*/raw_findings.json | jq .

# Count findings by severity
cat github_recon_results/tesla_*/summary.json | jq '.by_severity'

# Extract all URLs
cat github_recon_results/tesla_*/confirmed_findings.json | jq -r '.[].url'

# Filter HIGH severity findings
cat github_recon_results/tesla_*/raw_findings.json | jq '[.[] | select(.severity == "HIGH")]'
```

---

## 🎯 Recommended Settings by Scenario

### **Small Organization (<10 repos)**

**Settings:**
```bash
python3 github_recon.py \
  --token "ghp_..." \
  --org "small-startup" \
  --delay 1 \
  --workers 5
```

| Parameter | Value | Reason |
|-----------|-------|--------|
| `delay` | 1s | Fast scanning, low API usage |
| `workers` | 5 | Parallel processing without overwhelming |
| `max-results` | 100 | Complete coverage |

**Estimated Time:** 5-10 minutes  
**Estimated API Calls:** 500-1,000

---

### **Medium Organization (10-50 repos)**

**Settings:**
```bash
python3 github_recon.py \
  --token "ghp_..." \
  --org "medium-company" \
  --delay 2 \
  --workers 5
```

| Parameter | Value | Reason |
|-----------|-------|--------|
| `delay` | 2s | Balanced speed and safety |
| `workers` | 5 | Optimal parallelism |
| `max-results` | 100 | Comprehensive results |

**Estimated Time:** 15-30 minutes  
**Estimated API Calls:** 1,000-2,500

---

### **Large Organization (50-200 repos)**

**Settings:**
```bash
python3 github_recon.py \
  --token "ghp_..." \
  --org "large-corp" \
  --delay 3 \
  --workers 3
```

| Parameter | Value | Reason |
|-----------|-------|--------|
| `delay` | 3s | Conservative to avoid rate limits |
| `workers` | 3 | Reduced parallelism |
| `max-results` | 50 | Focused results |

**Estimated Time:** 45-90 minutes  
**Estimated API Calls:** 2,500-4,000

---

### **Enterprise Organization (200+ repos)**

**Settings:**
```bash
python3 github_recon.py \
  --token "ghp_..." \
  --org "enterprise-giant" \
  --conservative
```

| Parameter | Value | Reason |
|-----------|-------|--------|
| `delay` | 5s | Maximum rate limit protection |
| `workers` | 2 | Minimal parallelism |
| `max-results` | 50 | Selective targeting |

**Estimated Time:** 2-4 hours  
**Estimated API Calls:** 4,000-5,000

**💡 Pro Tip:** For enterprise scans, consider splitting into multiple sessions or using GitHub App tokens (15,000 requests/hour).

---

## 🚀 Advanced Usage Examples

### **1. Multi-Organization Batch Scan**

Create a bash script for multiple targets:

```bash
#!/bin/bash
# batch_scan.sh

TARGETS=("org1" "org2" "org3" "org4")
TOKEN="ghp_your_token_here"

for org in "${TARGETS[@]}"; do
    echo "Scanning: $org"
    python3 github_recon.py \
        --token "$TOKEN" \
        --org "$org" \
        --conservative \
        --no-validation
    
    # Wait 1 hour between organizations
    sleep 3600
done
```

Run:
```bash
chmod +x batch_scan.sh
./batch_scan.sh
```

---

### **2. Scheduled Daily Reconnaissance**

Add to crontab (`crontab -e`):

```bash
# Daily scan at 2 AM
0 2 * * * cd /path/to/tool && /usr/bin/python3 github_recon.py --token "$GITHUB_TOKEN" --org "target" --no-validation >> /var/log/github_recon.log 2>&1

# Weekly deep scan on Sundays at 3 AM
0 3 * * 0 cd /path/to/tool && /usr/bin/python3 github_recon.py --token "$GITHUB_TOKEN" --org "target" --conservative --no-validation
```

---

### **3. Continuous Monitoring with Alerting**

```bash
#!/bin/bash
# monitor.sh - Run every 6 hours and alert on new findings

python3 github_recon.py \
    --token "$GITHUB_TOKEN" \
    --org "target" \
    --no-validation

# Count findings
FINDINGS=$(cat github_recon_results/*/summary.json | jq '.total_findings')

# Alert if > 10 findings
if [ "$FINDINGS" -gt 10 ]; then
    echo "⚠️ Found $FINDINGS issues!" | mail -s "GitHub Recon Alert" you@example.com
fi
```

---

### **4. Integration with CI/CD**

**GitHub Actions Example:**

```yaml
name: GitHub Recon Scan

on:
  schedule:
    - cron: '0 0 * * *'  # Daily at midnight
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      
      - name: Install dependencies
        run: pip install -r requirements.txt
      
      - name: Run GitHub Recon
        env:
          GITHUB_TOKEN: ${{ secrets.RECON_TOKEN }}
        run: |
          python3 github_recon.py \
            --token "$GITHUB_TOKEN" \
            --org "target-org" \
            --no-validation
      
      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: recon-results
          path: github_recon_results/
```

---

### **5. Docker Container Deployment**

```bash
# Build container
docker build -t github-recon .

# Run scan
docker run --rm \
  -e GITHUB_TOKEN="ghp_..." \
  -v $(pwd)/results:/app/github_recon_results \
  github-recon \
  --org "target" \
  --conservative \
  --no-validation
```

---

## 💡 Tips & Best Practices

### **Performance Optimization**

1. **Use `--no-validation` for automation** - Skip interactive prompts
2. **Adjust workers based on network** - More workers ≠ faster on slow connections
3. **Monitor rate limits** - Check GitHub API quota before large scans
4. **Use conservative mode** - For organizations with 100+ repos

### **Accuracy Improvement**

1. **Enable validation mode** - Review findings manually for first scan
2. **Customize patterns** - Add company-specific secret patterns
3. **Cross-reference with external tools** - Gitleaks/TruffleHog for verification
4. **Review false positives** - Refine patterns based on FP data

### **Security & Stealth**

1. **Use environment variables** - Never hardcode tokens
2. **Rotate tokens regularly** - Change every 30-90 days
3. **Use dedicated tokens** - Separate tokens for different scopes
4. **Conservative mode for production** - Avoid detection

---


### **Scan Specific Organization**
```python
from github_recon import GitHubRecon

recon = GitHubRecon(
    token="ghp_your_token_here",
    target_org="microsoft"
)

recon.run_full_scan()
recon.validate_findings()
```

### **Programmatic Usage**
```python
# Custom workflow
recon = GitHubRecon(token="...", target_org="...")

# Individual phases
repos = recon.enumerate_repos()
recon.search_sensitive_files()
recon.search_keywords()
recon.generate_report()
```

### **Batch Scanning**
```python
targets = ["company1", "company2", "company3"]

for org in targets:
    recon = GitHubRecon(token=TOKEN, target_org=org)
    recon.run_full_scan()
```

---

## ⚙️ Configuration

### **Customizing Scan Parameters**

Edit the `Config` class in `github_recon.py`:

```python
class Config:
    OUTPUT_DIR = "github_recon_results"
    MAX_RESULTS = 100          # Max results per query
    RATE_LIMIT_DELAY = 2       # Seconds between requests
    MAX_WORKERS = 5            # Parallel threads
    TIMEOUT = 10               # Request timeout
```

### **Adding Custom Patterns**

Add to `Patterns.SECRET_PATTERNS`:

```python
"Custom API Key": r"custom_[a-zA-Z0-9]{32}",
"Internal Token": r"int_tok_[0-9A-Fa-f]{40}",
```

### **Adding Sensitive Files**

Add to `Patterns.SENSITIVE_FILENAMES`:

```python
"custom_config.yml",
"internal_secrets.json",
".company_credentials"
```

---

## 🔍 Pattern Detection

### **Currently Detected Secrets (60+)**

| Category | Examples |
|----------|----------|
| **Cloud Providers** | AWS Access/Secret Keys, Azure Client Secrets, Google API Keys, DigitalOcean Tokens, Heroku API Keys |
| **Version Control** | GitHub Tokens (PAT, OAuth, App), GitLab Tokens |
| **Communication** | Slack Tokens, Slack Webhooks, Twilio API Keys |
| **Databases** | MongoDB, PostgreSQL, MySQL, Redis Connection Strings |
| **Private Keys** | RSA, DSA, EC, PGP, OpenSSH Private Keys |
| **Payment Services** | Stripe API Keys, Square Tokens, PayPal Braintree |
| **Email/SMS** | SendGrid, Mailgun, Twilio API Keys |
| **Development** | NPM Tokens, Docker Hub Tokens, JWT Tokens |
| **Generic** | API Keys, Bearer Tokens, Password in URLs |

### **Pattern Examples**

```regex
AWS Access Key:    AKIA[0-9A-Z]{16}
GitHub Token:      ghp_[0-9a-zA-Z]{36}
JWT:               eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+
MongoDB:           mongodb://[^\s]+
Private Key:       -----BEGIN RSA PRIVATE KEY-----
```

---

## 🛠️ External Tools

### **Gitleaks Integration**

Automatically runs if installed:
```bash
gitleaks detect --source <repo_url> --report-format json
```

**Output:** `gitleaks_repo-name.json`

### **TruffleHog Integration**

Automatically runs if installed:
```bash
trufflehog git <repo_url> --json
```

**Output:** `trufflehog_repo-name.json`

### **Manual Tool Usage**

```bash
# Gitleaks on cloned repo
gitleaks detect --source ./my-repo --report-path results.json

# TruffleHog on specific repo
trufflehog git https://github.com/org/repo --json > findings.json
```

---

## 📂 Output Structure

### **Directory Layout**

```
github_recon_results/
└── target-company_20250117_143022/
    ├── raw_findings.json           # All findings before validation
    ├── confirmed_findings.json     # User-validated true positives
    ├── false_positives.json        # User-marked false positives
    ├── summary.json                # Statistical summary
    ├── report.html                 # Visual HTML dashboard
    ├── gitleaks_repo1.json         # Gitleaks results
    └── trufflehog_repo2.json       # TruffleHog results
```

### **Finding Structure**

```json
{
  "type": "Secret Pattern",
  "category": "AWS Access Key",
  "url": "https://github.com/org/repo/blob/main/config.py",
  "match": "AKIAIOSFODNN7EXAMPLE",
  "context": "aws_key = 'AKIAIOSFODNN7EXAMPLE' # Production",
  "severity": "HIGH",
  "timestamp": "2025-01-17T14:30:22.123456"
}
```

### **Summary Report**

```json
{
  "organization": "target-company",
  "scan_time": "2025-01-17T14:30:22",
  "total_findings": 42,
  "by_severity": {
    "HIGH": 15,
    "MEDIUM": 20,
    "LOW": 7
  },
  "by_type": {
    "Secret Pattern": 18,
    "Sensitive File": 24
  }
}
```

---

## 🎓 Best Practices

### **Rate Limiting**
- GitHub allows **5,000 requests/hour** for authenticated users
- Tool automatically monitors rate limits
- Implements intelligent delays between requests
- Pauses when rate limit is low

### **Token Security**
- **Never commit tokens** to version control
- Use environment variables:
  ```bash
  export GITHUB_TOKEN="ghp_xxxxxxxxxxxx"
  ```
- Rotate tokens regularly
- Use tokens with **minimum required permissions**

### **Validation Workflow**
1. Run initial scan (generates `raw_findings.json`)
2. Enable validation mode
3. Review each finding interactively
4. Mark as valid (`y`) or false positive (`n`)
5. Use skip (`s`) for bulk operations
6. Review `confirmed_findings.json`

### **Batch Scanning**
```python
# Efficient multi-org scanning
organizations = ["org1", "org2", "org3"]

for org in organizations:
    recon = GitHubRecon(token=TOKEN, target_org=org)
    
    if recon.check_rate_limit():
        recon.run_full_scan()
    else:
        print(f"Rate limit low, skipping {org}")
```

### **Custom Reporting**
```python
# Export to CSV
import csv

with open('findings.csv', 'w') as f:
    writer = csv.DictWriter(f, fieldnames=['type', 'url', 'severity'])
    writer.writeheader()
    writer.writerows(recon.findings)
```

---

## 🐛 Troubleshooting

### **Common Issues**

#### **1. Authentication Failed**
```
ERROR: Token verification failed: 401
```
**Solution:** Check token validity, regenerate if needed

#### **2. Rate Limit Exceeded**
```
WARNING: Rate limit exceeded. Waiting...
```
**Solution:** Tool auto-waits; check limit with:
```bash
curl -H "Authorization: token YOUR_TOKEN" https://api.github.com/rate_limit
```

#### **3. No Results Found**
```
INFO: Found 0 repositories
```
**Solutions:**
- Verify organization name is correct
- Check token has `read:org` permission
- Organization may have no public repositories

#### **4. External Tools Not Found**
```
INFO: Gitleaks not installed
```
**Solution:** Install optional tools (see [Installation](#-installation))

#### **5. SSL Certificate Errors**
```bash
# Temporary workaround (not recommended for production)
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
```

### **Debug Mode**

Add verbose logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

---

## ⚖️ Legal & Ethics

### **⚠️ Important Disclaimer**

This tool is intended for:
- ✅ **Authorized security research**
- ✅ **Bug bounty programs**
- ✅ **Educational purposes**
- ✅ **Your own repositories/organizations**
- ✅ **Public information gathering**

### **Usage Guidelines**

1. **Get Permission** - Always obtain authorization before scanning
2. **Follow Scope** - Respect bug bounty program scopes
3. **Report Responsibly** - Disclose findings ethically
4. **Respect Privacy** - Don't expose sensitive data publicly
5. **Comply with Laws** - Follow CFAA, GDPR, and local regulations

### **Prohibited Uses**

- ❌ Scanning without authorization
- ❌ Exploiting discovered vulnerabilities
- ❌ Selling or weaponizing findings
- ❌ Harassing organizations
- ❌ Violating terms of service

### **GitHub ToS Compliance**

This tool:
- ✅ Uses official GitHub API
- ✅ Respects rate limits
- ✅ Operates within API terms
- ✅ Performs **passive reconnaissance only**
- ✅ Does **not** exploit, attack, or modify repositories

**You are responsible for ensuring your usage complies with GitHub's Acceptable Use Policies.**

---

## 📚 Additional Resources

### **GitHub API Documentation**
- [REST API](https://docs.github.com/en/rest)
- [Search API](https://docs.github.com/en/rest/search)
- [Rate Limiting](https://docs.github.com/en/rest/overview/resources-in-the-rest-api#rate-limiting)

### **Bug Bounty Platforms**
- [HackerOne](https://www.hackerone.com/)
- [Bugcrowd](https://www.bugcrowd.com/)
- [Intigriti](https://www.intigriti.com/)
- [YesWeHack](https://www.yeswehack.com/)

### **Related Tools**
- [Gitleaks](https://github.com/gitleaks/gitleaks) - Secret scanner
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - Credential scanner
- [GitDorker](https://github.com/obheda12/GitDorker) - GitHub dork scanner
- [GitRob](https://github.com/michenriksen/gitrob) - GitHub organization analyzer

---

## 🤝 Contributing

Contributions are welcome! Here's how:

### **1. Fork & Clone**
```bash
git clone https://github.com/yourusername/github-recon-tool.git
cd github-recon-tool
```

### **2. Create Feature Branch**
```bash
git checkout -b feature/new-pattern-detection
```

### **3. Make Changes**
- Add new secret patterns
- Improve error handling
- Enhance reporting
- Add tests

### **4. Submit Pull Request**
- Describe your changes
- Include examples
- Update documentation

### **Ideas for Contribution**
- 🎯 Additional secret patterns
- 🎯 New external tool integrations
- 🎯 CSV/Excel export formats
- 🎯 Slack/Discord notifications
- 🎯 Machine learning false positive filtering
- 🎯 Historical change tracking
- 🎯 Scheduled scanning

---

## 📜 License

```
MIT License

Copyright (c) 2025 GitHub Recon Tool

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## 🙏 Acknowledgments

- GitHub API Team
- Gitleaks maintainers
- TruffleHog Security
- Bug bounty community
- Open source security researchers

---

## 📞 Support

- 📧 **Email:** vishalrao191004@gmail.com,24427@iiitu.ac.in

---

## 🔄 Changelog

### **v1.0.0** (2025-01-17)
- ✨ Initial release
- ✨ 60+ secret patterns
- ✨ Multi-tool integration
- ✨ Interactive validation
- ✨ HTML/JSON reporting

---

<div align="center">

**⭐ Star this repo if you find it useful! ⭐**

Made with ❤️ by security researchers, for security researchers

[Report Bug](https://github.com/Vishal-HaCkEr1910/github-recon-tool/issues) · [Request Feature](https://github.com/Vishal-HaCkEr1910/github-recon-tool/issues) · [Documentation](https://github.com/Vishal-HaCkEr1910/github-recon-tool/wiki)

</div>
