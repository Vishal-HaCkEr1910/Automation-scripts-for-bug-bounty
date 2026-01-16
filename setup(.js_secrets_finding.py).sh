#!/bin/bash

# ===============================
# JS Recon & Secrets Scanner v2.0
# Auto Setup Script
# Author: You
# ===============================

set -e

echo "[+] Updating system..."
sudo apt update -y && sudo apt upgrade -y

echo "[+] Installing base dependencies..."
sudo apt install -y \
    git curl wget unzip \
    python3 python3-pip \
    build-essential \
    nodejs npm \
    jq

# -------------------------------
# Install Go
# -------------------------------
if ! command -v go &>/dev/null; then
    echo "[+] Installing Go..."
    GO_VERSION="1.22.0"
    wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
    rm go${GO_VERSION}.linux-amd64.tar.gz

    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
fi

echo "[+] Go version:"
go version

# -------------------------------
# Python Dependencies
# -------------------------------
echo "[+] Installing Python dependencies..."
pip3 install --upgrade pip
pip3 install requests argparse trufflehog

# -------------------------------
# Node Utilities
# -------------------------------
echo "[+] Installing Node.js tools..."
npm install -g js-beautify retire

# -------------------------------
# Install Recon Tools (Go)
# -------------------------------
echo "[+] Installing Go-based recon tools..."

go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/lc/subjs@latest
go install github.com/jaeles-project/gospider@latest
go install github.com/003random/getJS@latest

# -------------------------------
# Install Analysis Tools
# -------------------------------
echo "[+] Installing analysis tools..."

# Nuclei
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# jsluice
go install github.com/BishopFox/jsluice/cmd/jsluice@latest

# sourcemapper
go install github.com/denandz/sourcemapper@latest

# -------------------------------
# Update Nuclei Templates
# -------------------------------
echo "[+] Updating Nuclei templates..."
nuclei -update-templates

# -------------------------------
# LinkFinder
# -------------------------------
echo "[+] Installing LinkFinder..."
sudo mkdir -p /opt/LinkFinder
sudo git clone https://github.com/GerbenJavado/LinkFinder.git /opt/LinkFinder
pip3 install -r /opt/LinkFinder/requirements.txt

# -------------------------------
# SecretFinder
# -------------------------------
echo "[+] Installing SecretFinder..."
sudo mkdir -p /opt/SecretFinder
sudo git clone https://github.com/m4ll0k/SecretFinder.git /opt/SecretFinder
pip3 install -r /opt/SecretFinder/requirements.txt

# -------------------------------
# Final Checks
# -------------------------------
echo "[+] Verifying installations..."

TOOLS=(
katana gau waybackurls hakrawler subjs gospider getJS
nuclei jsluice js-beautify retire
)

for tool in "${TOOLS[@]}"; do
    if command -v $tool &>/dev/null; then
        echo "[✓] $tool installed"
    else
        echo "[✗] $tool NOT found"
    fi
done

echo
echo "[🔥] Setup completed successfully!"
echo "Restart your terminal or run: source ~/.bashrc"
