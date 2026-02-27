# 🔍 GitHub Recon Tool

> **Professional-Grade GitHub Reconnaissance for Bug Bounty Hunters**  
> 60+ Secret Patterns · Org-Wide Scanning · Interactive Validation · HTML Reports  
> Author: **Vishal Rao** ([@Vishal-HaCkEr1910](https://github.com/Vishal-HaCkEr1910))

---

## ⚠️ Legal Disclaimer

> This tool is for **authorized security research only**. Only scan GitHub organizations and repositories you have explicit permission to test. The author accepts no liability for misuse.

---

## 🚀 What It Does

Performs passive GitHub reconnaissance — scans repositories and organizations for exposed secrets, API keys, credentials, sensitive files, and misconfigurations using 60+ pattern signatures with interactive false-positive filtering.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **60+ Secret Patterns** | AWS keys, API tokens, JWTs, private keys, DB credentials |
| **Sensitive File Discovery** | `.env`, `config.json`, SSH keys, database configs |
| **Org-Wide Scanning** | Automated repository enumeration across organizations |
| **Multi-Tool Integration** | Gitleaks, TruffleHog, Git-secrets support |
| **Interactive Validation** | Human-in-the-loop false positive filtering |
| **Rate Limit Management** | Intelligent GitHub API throttling |
| **Reports** | JSON + HTML dashboard reports with severity classification |

---

## 📦 Installation

```bash
cd github-recon-tool
pip3 install -r requirements.txt
```

### GitHub Token

You'll need a GitHub personal access token. The tool will prompt you interactively (no hardcoding).

---

## ⚡ Usage

See [github_recon_readme.md](github_recon_readme.md) for detailed usage guide.

---

## 📄 License

MIT — For authorized security research only.
