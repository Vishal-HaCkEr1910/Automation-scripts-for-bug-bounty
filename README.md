
JS Recon & Secrets Scanner v2.0
JS Recon & Secrets Scanner is an advanced automated framework designed for bug bounty hunters and security researchers. It orchestrates a multi-phase pipeline to discover, download, and analyze JavaScript files across a large number of subdomains to find hidden API endpoints, hardcoded secrets, and vulnerable libraries.

🚀 Features
Multi-Tool Discovery: Aggregates results from 7 different discovery tools (Katana, GAU, Waybackurls, etc.).

Intelligent Filtering: Automatically skips vendor noise (jQuery, Bootstrap) to focus on custom application logic.

Source Map Recovery: Automatically detects .js.map files and attempts to reconstruct the original source tree.

Deep Structural Analysis: Uses jsluice to parse the Abstract Syntax Tree (AST) of JavaScript for logic-based secret hunting.

Automated Verification: Integrates Nuclei to verify findings against known vulnerability signatures.

Categorized Reporting: Generates a structured summary of findings grouped by severity (High/Medium/Info).

🛠️ Requirements
To use the full potential of this script, you must have the following tools installed in your system's $PATH.

1. Discovery Phase Tools
Katana

GAU (Get All URLs)

Waybackurls

Hakrawler

Subjs

Gospider

getJS

2. Analysis Phase Tools
Nuclei

Jsluice

Trufflehog

Retire.js

LinkFinder (Expected at /opt/LinkFinder/linkfinder.py)

SecretFinder (Expected at /opt/SecretFinder/SecretFinder.py)

3. Utility Tools
Node.js & NPM: Required for js-beautify.

npm install -g js-beautify

Go: Required for installing many of the discovery tools and sourcemapper.

Curl: For file downloading.

📥 Installation
**Clone the Scanner**
  
Install Python Dependencies:

Bash

 ** pip3 install requests argparse**
  Ensure Nuclei Templates are up to date:

Bash

  **nuclei -update-templates**
  
📖 Usage
Basic Scan
Provide a list of subdomains in a .txt file:

Bash

  **python3 scanner.py -i subdomains.txt**
Advanced Options
Increase Threads: Use more threads for faster downloading (default is based on CPU count).

Bash

  **python3 scanner.py -i subdomains.txt -t 50**
Analyze Existing Files: If you have already downloaded JS files and just want to re-run the analysis:

Bash

  **python3 scanner.py -i subdomains.txt --skip-discovery --skip-download**
Custom Nuclei Templates: Specify a custom path for your exposure templates:

Bash

  **python3 scanner.py -i subdomains.txt --templates /home/user/my-custom-templates/**
  
📂 Output Structure
The script organizes its output into several directories:

**recon_output/: Raw output from discovery tools (Katana, GAU, etc.).

js_storage/: Downloaded and beautified .js files (hashed filenames).

js_maps/: Found JavaScript Source Maps.

source_code/: Reconstructed source code from maps using sourcemapper.

final_results/: Final text/JSON reports from scanners (Endpoints, Secrets, Nuclei).

metadata/: JSON files mapping hashed filenames back to their original source URLs.
**
⚠️ Disclaimer
This tool is for educational purposes and authorized security testing only. Performing reconnaissance or scanning against targets without explicit permission is illegal and unethical. The developer assumes no liability for misuse or damage caused by this program.

Happy Hunting! 🎯

Would you like me to help you create a setup script (a .sh file) that automatically installs all these Go and Python dependencies for you on a fresh Linux VPS?
