# ⌨️ Keylogger

> **Lightweight Keyboard Input Monitor using pynput**  
> Author: **Vishal Rao** ([@Vishal-HaCkEr1910](https://github.com/Vishal-HaCkEr1910))

---

## ⚠️ Legal Disclaimer

> This tool is for **educational purposes and authorized security testing only**. Using a keylogger on systems or people without explicit consent is **illegal** and a serious criminal offense under computer misuse laws worldwide. The author accepts no liability for misuse.

---

## 🚀 What It Does

Captures all keyboard input in real-time and logs it to a text file. Handles special keys (space, enter, tab, backspace, shift) with human-readable formatting for clean, readable output.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Real-Time Capture** | Logs every keystroke the moment it happens |
| **Readable Output** | Spaces rendered as ` `, Enter as newlines, Backspace as `[BACKSPACE]`, Tab as `[tab]` |
| **Special Key Handling** | Shift key suppressed (no noise), other special keys formatted |
| **File Logging** | All keystrokes appended to `logs.txt` in the current directory |
| **Lightweight** | Single dependency, minimal resource usage, runs silently |
| **Cross-Platform** | Works on macOS, Linux, and Windows (via pynput) |

---

## 📦 Installation

```bash
cd keylogger
pip3 install -r requirements.txt
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `pynput` | Cross-platform keyboard input monitoring |

### macOS Note

On macOS, you need to grant **Accessibility** or **Input Monitoring** permissions:

> System Settings → Privacy & Security → Input Monitoring → Add Terminal/iTerm2

---

## ⚡ Usage

### Start Logging

```bash
python3 keylogger.py
```

The keylogger runs silently in the foreground. All keystrokes are written to `logs.txt`.

### Stop Logging

Press `Ctrl+C` in the terminal to stop.

### View Logs

```bash
cat logs.txt
```

### Key Mappings

| Key Pressed | Logged As |
|-------------|-----------|
| Regular keys (`a`, `1`, `@`) | Character itself |
| Space | ` ` (space character) |
| Enter | `\n` (new line) |
| Tab | `[tab]` |
| Backspace | `[BACKSPACE]` |
| Shift | (suppressed — not logged) |

### Output File

| File | Location | Description |
|------|----------|-------------|
| `logs.txt` | Current working directory | Append-mode text file with all captured keystrokes |

---

## 📄 License

MIT — For authorized security research and educational use only.
