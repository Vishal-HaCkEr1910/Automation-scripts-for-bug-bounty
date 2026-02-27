# 🔐 SSH Bruteforcer

> **Dictionary-Based SSH Password Cracker**  
> Author: **Vishal Rao** ([@Vishal-HaCkEr1910](https://github.com/Vishal-HaCkEr1910))

---

## ⚠️ Legal Disclaimer

> This tool is for **authorized penetration testing only**. Brute-forcing SSH credentials on systems you do not own or have explicit permission to test is **illegal** and a criminal offense. The author accepts no liability for misuse.

---

## 🚀 What It Does

Performs dictionary-based SSH brute force attacks against a target host. Reads passwords from a wordlist file and attempts to authenticate over SSH until the correct password is found.

---

## ✨ Features

- 🔑 **Dictionary Attack** — Tries passwords from a wordlist file
- 🌐 **Any SSH Host** — Works against any SSH-enabled server
- ✅ **Success Detection** — Reports correct credentials immediately
- 🔴 **Offline Detection** — Detects if target is unreachable

---

## 📦 Installation

```bash
cd ssh-bruteforcer
pip3 install -r requirements.txt
```

---

## ⚡ Usage

```bash
python3 ssh_Bruteforcer.py
```

You'll be prompted for:
1. **Host** — Target IP or hostname
2. **Username** — SSH username to brute force
3. **Wordlist** — Path to password file (one password per line)

### Example

```
Enter the host: 192.168.1.100
ENTER THE USERNAME: admin
enter the file for passwords: /usr/share/wordlists/rockyou.txt

incorrect password : password123
incorrect password : admin
FOUND PASSWORD $$ [+ successful connection] ssh admin@192.168.1.100:secretpass
```

---

## 📄 License

MIT — For authorized penetration testing only.
