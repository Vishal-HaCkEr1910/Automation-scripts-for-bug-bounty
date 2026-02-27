# 🔍 GitHub Recon Tool

> **Professional-Grade GitHub Reconnaissance for Bug Bounty Hunters**  
> 60+ Secret Patterns · Org-Wide Scanning · Gitleaks/TruffleHog · Interactive Validation  
> Author: **Vishal Rao** ([@Vishal-HaCkEr1910](https://github.com/Vishal-HaCkEr1910))

---

## ⚠️ Legal Disclaimer

> This tool is for **authorized security research only**. Only scan GitHub organizations and repositories you have explicit permission to test. The author accepts no liability for misuse.

---

## 🚀 What It Does

Performs passive GitHub reconnaissance — scans repositories and organizations for exposed secrets, API keys, credentials, sensitive files, and misconfigurations using 60+ regex pattern signatures. Integrates with Gitleaks and TruffleHog for deep secret detection, and includes an interactive human-in-the-loop validation workflow to minimize false positives.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **60+ Secret Patterns** | AWS keys, GitHub tokens, Google API keys, Stripe keys, JWTs, private SSH keys, DB connection strings, and more |
| **Sensitive File Discovery** | `.env`, `config.json`, `id_rsa`, `credentials.xml`, database configs |
| **Org-Wide Scanning** | Automatically enumerates all repositories in a GitHub organization |
| **Keyword Intelligence** | Context-aware scanning for passwords, secrets, tokens, credentials |
| **Multi-Tool Integration** | Gitleaks, TruffleHog, Git-secrets support (if installed) |
| **Rate Limit Management** | Intelligent GitHub API throttling with configurable delays |
| **Interactive Validation** | Human-in-the-loop review — manually confirm/reject each finding |
| **Performance Modes** | Aggressive (fast), Conservative (safe), or Custom tuning |
| **Reports** | JSON + HTML dashboard reports with severity classification |

### Detected Secret Types

| Category | Patterns |
|----------|----------|
| **Cloud** | AWS Access Key, AWS Secret Key, GCP API Key, Azure Connection String |
| **API Tokens** | GitHub Token, Google API Key, Stripe Key, Twilio Key, SendGrid, Mailgun |
| **Auth** | JWT tokens, OAuth secrets, Basic Auth credentials |
| **Database** | MongoDB URI, PostgreSQL URI, MySQL connection strings |
| **Keys** | RSA/DSA/EC private keys, PGP private blocks |
| **Payment** | Stripe Live Key, PayPal Braintree Token, Square Access Token |
| **Communication** | Slack Webhook, Discord Token, Telegram Bot Token |
| **Generic** | Passwords, secrets, API keys matched by context patterns |

---

## 📦 Installation

```bash
cd github-recon-tool
pip3 install -r requirements.txt
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `requests` | GitHub API communication |

### Optional External Tools

These are automatically used if installed:

| Tool | Purpose | Install |
|------|---------|---------|
| Gitleaks | Git history secret scanning | `brew install gitleaks` or [GitHub](https://github.com/gitleaks/gitleaks) |
| TruffleHog | Deep entropy-based secret detection | `pip3 install trufflehog` |
| Git-secrets | AWS credential prevention | `brew install git-secrets` |

---

## 🔑 GitHub Token Setup

A **GitHub Personal Access Token** is required for API access.

### Create a Token

1. Go to [github.com/settings/tokens](https://github.com/settings/tokens)
2. Click **"Generate new token (classic)"**
3. Select scopes: `repo`, `read:org` (minimum)
4. Copy the token (starts with `ghp_`)

### Provide the Token

```bash
# Method 1: CLI flag
python3 github_secrets_finding.py --token "ghp_your_token_here" --org "target-org"

# Method 2: Interactive prompt (more secure — no token in shell history)
python3 github_secrets_finding.py --org "target-org"
# → You'll be prompted: "Enter GitHub Personal Access Token: "
```

---

## ⚡ Usage

### Basic Commands

```bash
# Scan an organization (interactive token prompt)
python3 github_secrets_finding.py --org "microsoft"

# Scan with token on CLI
python3 github_secrets_finding.py --token "ghp_xxx" --org "target-org"

# Aggressive mode (fast: 0.5s delay, 10 workers)
python3 github_secrets_finding.py --org "target-org" --aggressive

# Conservative mode (safe: 3s delay, 2 workers)
python3 github_secrets_finding.py --org "target-org" --conservative

# Skip manual validation (auto-accept all findings)
python3 github_secrets_finding.py --org "target-org" --no-validation

# Custom tuning
python3 github_secrets_finding.py --org "target-org" --delay 1.5 --workers 5
```

### CLI Reference

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-t, --token` | string | interactive prompt | GitHub Personal Access Token |
| `-o, --org` | string | interactive prompt | Target organization name |
| `--aggressive` | flag | | Fast mode: 0.5s delay, 10 parallel workers |
| `--conservative` | flag | | Safe mode: 3s delay, 2 parallel workers |
| `--delay` | float | `2.0` | Custom delay between API requests (seconds) |
| `--workers` | int | auto | Number of parallel workers |
| `--no-validation` | flag | | Skip interactive finding validation |

### Performance Modes

| Mode | Delay | Workers | Use When |
|------|-------|---------|----------|
| **Default** | 2.0s | CPU-based | Normal scanning |
| **Aggressive** | 0.5s | 10 | You have high rate limits or paid token |
| **Conservative** | 3.0s | 2 | Avoiding rate limit bans |
| **Custom** | `--delay N` | `--workers N` | Fine-tuned control |

---

## 📊 Output

Reports are saved to `github_recon_results/`:

| File | Format | Content |
|------|--------|---------|
| `github_recon_results/<timestamp>/findings.json` | JSON | All findings with severity, file paths, line numbers |
| `github_recon_results/<timestamp>/report.html` | HTML | Visual dashboard grouped by severity and type |
| `github_recon_results/<timestamp>/gitleaks_*.json` | JSON | Gitleaks output (if installed) |
| `github_recon_results/<timestamp>/trufflehog_*.json` | JSON | TruffleHog output (if installed) |

For detailed usage guide, see [github_recon_readme.md](github_recon_readme.md).

---

## 📄 License

MIT — For authorized security research only.
