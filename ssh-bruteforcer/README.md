# 🔐 SSH Bruteforcer

> **Dictionary-Based SSH Password Cracker using Paramiko**  
> Author: **Vishal Rao** ([@Vishal-HaCkEr1910](https://github.com/Vishal-HaCkEr1910))

---

## ⚠️ Legal Disclaimer

> This tool is for **authorized penetration testing only**. Brute-forcing SSH credentials on systems you do not own or have explicit written permission to test is **illegal** and a criminal offense under the CFAA (US), IT Act (India), and similar laws. The author accepts no liability for misuse.

---

## 🚀 What It Does

Performs dictionary-based SSH brute force attacks against a target host using the Paramiko SSH library. Reads passwords from a wordlist file and attempts to authenticate until the correct password is found or the wordlist is exhausted.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Dictionary Attack** | Reads passwords from any wordlist file (one per line) |
| **SSH via Paramiko** | Pure Python SSH2 implementation — no external SSH client needed |
| **Real-Time Feedback** | Shows each attempted password and result |
| **Success Detection** | Immediately reports correct credentials with connection string |
| **Offline Detection** | Detects if target is unreachable and exits cleanly |
| **Auto Key Policy** | Automatically accepts unknown host keys |

---

## 📦 Installation

```bash
cd ssh-bruteforcer
pip3 install -r requirements.txt
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `paramiko` | SSH2 protocol library for Python |
| `termcolor` | Colored terminal output for success highlighting |

---

## ⚡ Usage

### Running the Tool

```bash
python3 ssh_Bruteforcer.py
```

The tool uses an **interactive prompt**:

```
Enter the host you want to connect : 192.168.1.100
ENTER THE USERNAME FOR TARGET MACHINE : admin
enter the file you want to use for passwords : /usr/share/wordlists/rockyou.txt
```

### Input Parameters

| Prompt | Description | Example |
|--------|-------------|---------|
| **Host** | Target IP address or hostname | `192.168.1.100`, `target.local` |
| **Username** | SSH username to brute force | `root`, `admin`, `ubuntu` |
| **Wordlist** | Path to password file (one per line) | `/usr/share/wordlists/rockyou.txt` |

### Wordlist Sources

| Wordlist | Location | Description |
|----------|----------|-------------|
| `rockyou.txt` | `/usr/share/wordlists/rockyou.txt` (Kali) | 14M+ passwords from RockYou breach |
| `common-passwords.txt` | [SecLists](https://github.com/danielmiessler/SecLists) | Common passwords sorted by frequency |
| Custom | Create your own | One password per line in a `.txt` file |

### Example Output

```
Enter the host you want to connect : 192.168.1.100
ENTER THE USERNAME FOR TARGET MACHINE : admin
enter the file you want to use for passwords : passwords.txt

incorrect password : password123
incorrect password : admin
incorrect password : letmein
FOUND PASSWORD $$ [+ successful connection] ssh admin@192.168.1.100:secretpass
```

### Error States

| Output | Meaning |
|--------|---------|
| `incorrect password : xyz` | Password tried, authentication failed |
| `FOUND PASSWORD $$` | Correct password found — shows SSH connection string |
| `Can't connect : possibly target OFFLINE` | Target host unreachable |
| `The file you entered doesn't exist!!!!` | Wordlist file path is wrong |

---

## 📄 License

MIT — For authorized penetration testing only.
