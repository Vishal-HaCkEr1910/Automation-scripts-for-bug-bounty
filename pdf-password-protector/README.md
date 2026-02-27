# 🔒 PDF Password Protector

> **Encrypt PDF Files with Password Protection**  
> Author: **Vishal Rao** ([@Vishal-HaCkEr1910](https://github.com/Vishal-HaCkEr1910))

---

## 🚀 What It Does

Takes any PDF file and creates a password-protected copy. Uses AES encryption via PyPDF2 to secure PDF documents.

---

## ✨ Features

- 🔐 **AES Encryption** — Industry-standard PDF encryption
- 📄 **Any PDF** — Works with any valid PDF file
- ⚡ **CLI Usage** — Simple command-line interface
- 🪶 **Lightweight** — Single dependency

---

## 📦 Installation

```bash
cd pdf-password-protector
pip3 install -r requirements.txt
```

---

## ⚡ Usage

```bash
python3 pdf_pass.py <input.pdf> <output.pdf> <password>
```

### Example

```bash
python3 pdf_pass.py report.pdf report_secured.pdf MyStr0ngP@ss
# Output: Password protected PDF saved as report_secured.pdf
```

---

## 📄 License

MIT
