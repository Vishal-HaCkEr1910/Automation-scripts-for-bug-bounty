🔍 JS Recon & Secrets Scanner v2.0

JS Recon & Secrets Scanner is an advanced automated reconnaissance and JavaScript analysis framework built for bug bounty hunters, red teamers, and security researchers.

It performs large-scale JavaScript discovery, deep static analysis, source map reconstruction, and secret detection across multiple subdomains using a multi-phase pipeline.

⸻

🚀 Key Features

🔎 Multi-Source JavaScript Discovery

Aggregates JavaScript URLs using 7 powerful recon tools:
	•	Katana
	•	GAU (GetAllURLs)
	•	Waybackurls
	•	Hakrawler
	•	Subjs
	•	Gospider
	•	getJS

⸻

🧠 Intelligent Noise Filtering
	•	Automatically skips vendor and framework noise
(jQuery, Bootstrap, React bundles, analytics)
	•	Focuses only on custom application logic

⸻

🗺️ Source Map Recovery
	•	Detects .js.map files
	•	Reconstructs original source code using sourcemapper

⸻

🧬 Deep JavaScript Analysis
	•	Parses JavaScript AST (Abstract Syntax Tree) using jsluice
	•	Extracts:
	•	Hidden API endpoints
	•	Tokens & secrets
	•	Auth logic
	•	Hardcoded credentials

⸻

✅ Automated Vulnerability Verification
	•	Integrates Nuclei
	•	Verifies exposed secrets & JS issues using templates

⸻

📊 Structured Reporting
	•	Findings categorized by severity:
	•	High
	•	Medium
	•	Informational
	•	Output formats:
	•	TXT
	•	JSON

⸻

🛠️ Requirements

⚠️ All tools must be available in $PATH

🔹 Discovery Tools
	•	Katana
	•	GAU
	•	Waybackurls
	•	Hakrawler
	•	Subjs
	•	Gospider
	•	getJS

🔹 Analysis Tools
	•	Nuclei
	•	Jsluice
	•	TruffleHog
	•	Retire.js
	•	LinkFinder
📍 /opt/LinkFinder/linkfinder.py
	•	SecretFinder
📍 /opt/SecretFinder/SecretFinder.py

🔹 Utility Tools
	•	Go
	•	Python 3
	•	Node.js & NPM
	•	Curl

⸻

⚡ Installation (Recommended)

✅ Auto Install (Fresh VPS / Kali / Ubuntu)

The fastest and safest way to install everything is using the provided setup.sh.

git clone https://github.com/yourusername/js-recon-secrets-scanner.git
cd js-recon-secrets-scanner
chmod +x setup.sh
./setup.sh

After installation:

source ~/.bashrc

✔ Installs Go, Node, Python, all recon & analysis tools
✔ Updates Nuclei templates
✔ Sets correct paths automatically

⸻

📖 Usage

🔹 Basic Scan

Provide a list of subdomains:

python3 scanner.py -i subdomains.txt


⸻

🔹 Increase Download Threads

(Default: CPU cores)

python3 scanner.py -i subdomains.txt -t 50


⸻

🔹 Analyze Existing JS Files Only

Skip discovery & downloading:

python3 scanner.py -i subdomains.txt --skip-discovery --skip-download


⸻

🔹 Use Custom Nuclei Templates

python3 scanner.py -i subdomains.txt --templates /home/user/custom-templates/


⸻

📂 Output Structure

recon_output/
 ├── katana.txt
 ├── gau.txt
 ├── wayback.txt

js_storage/
 └── beautified JS files (hashed)

js_maps/
 └── discovered .js.map files

source_code/
 └── reconstructed source from maps

final_results/
 ├── endpoints.txt
 ├── secrets.json
 ├── nuclei_findings.txt

metadata/
 └── hash → original URL mappings


⸻

⚠️ Legal Disclaimer

This tool is strictly for educational purposes and authorized security testing.

	•	❌ Do NOT scan targets without permission
	•	❌ Unauthorized reconnaissance is illegal
	•	✅ Use only on assets you own or are authorized to test

The developer assumes no liability for misuse.

⸻

🎯 Roadmap (Planned)
	•	HTML report dashboard
	•	Docker support
	•	Headless browser JS execution
	•	Live secret validation
	•	CI/CD recon mode

⸻

⭐ Support

If this tool helps you:
	•	Star the repo ⭐
	•	Share feedback
	•	Submit PRs

⸻

Happy Hunting & Happy Hacking 👾

If you want next:
	•	🐳 Dockerfile
	•	📊 HTML reporting
	•	🧠 AI-based JS secret classification
	•	🧪 Bug-bounty optimized presets

Just say the word 👊
