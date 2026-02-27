# 🔒 PDF Password Protector

> **Encrypt PDF Files with AES Password Protection**  
> Author: **Vishal Rao** ([@Vishal-HaCkEr1910](https://github.com/Vishal-HaCkEr1910))

---

## 🚀 What It Does

Takes any PDF file and creates a password-protected copy using AES encryption via PyPDF2. The encrypted PDF will require the password to open in any PDF reader.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **AES Encryption** | Industry-standard PDF encryption via PyPDF2 |
| **Any PDF** | Works with any valid PDF file (reports, invoices, documents) |
| **CLI Interface** | Simple 3-argument command-line usage |
| **Error Handling** | File not found, invalid PDF, and general error detection |
| **Lightweight** | Single dependency, runs instantly |

---

## 📦 Installation

```bash
cd pdf-password-protector
pip3 install -r requirements.txt
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `PyPDF2` | PDF reading, writing, and encryption |

---

## ⚡ Usage

### Command Format

```bash
python3 pdf_pass.py <input_pdf> <output_pdf> <password>
```

| Argument | Description | Example |
|----------|-------------|---------|
| `input_pdf` | Path to the original PDF file | `report.pdf` |
| `output_pdf` | Path for the encrypted output PDF | `report_secured.pdf` |
| `password` | Password to encrypt with | `MyStr0ngP@ss` |

### Examples

```bash
# Protect a report
python3 pdf_pass.py report.pdf report_secured.pdf MyPassword123

# Protect a document in another directory
python3 pdf_pass.py /path/to/invoice.pdf /path/to/invoice_locked.pdf S3cur3P@ss!

# Same directory, different name
python3 pdf_pass.py document.pdf document_encrypted.pdf hunter2
```

### Example Output

```
Password protected PDF saved as report_secured.pdf
```

### Error Messages

| Error | Cause |
|-------|-------|
| `Usage: python pdf_pass.py <input_pdf> <output_pdf> <password>` | Wrong number of arguments |
| `The file X not found !!!!!` | Input PDF path doesn't exist |
| `The file X is not a valid pdf !!!!!!` | Input file is not a valid PDF |

---

## 📄 License

MIT
