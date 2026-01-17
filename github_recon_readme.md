# 🔍 Advanced GitHub Reconnaissance Tool

> **Professional-grade GitHub reconnaissance for bug bounty hunters and security researchers**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
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

## 📖 Usage Examples

### **Basic Scan**
```bash
python github_recon.py
# Follow interactive prompts
```

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

- 📧 **Email:** vishalrao191004@gmail.co,24427@iiitu.ac.in

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
