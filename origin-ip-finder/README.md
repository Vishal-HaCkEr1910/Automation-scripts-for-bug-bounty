# 🌐 Origin IP Finder v2.0.0

Discover real server IPs hidden behind CDN/WAF (Cloudflare, Akamai, Fastly, etc).

## Features

- **8 Detection Techniques**: CDN detection, DNS history, subdomain enumeration, MX records, SPF IP extraction, response header leaks, SSL certificate verification, HTTP Host-header verification
- **crt.sh Integration** — Certificate Transparency logs via shared subdomain crawler
- **Threaded Scanning** — Fast subdomain brute-force with configurable threads
- **CDN Detection** — Cloudflare, Akamai, Fastly, CloudFront, Vercel, Sucuri, Imperva, Edgecast
- **SecurityTrails API** — Optional DNS history lookups
- **Auto-Verification** — SSL cert matching + HTTP response comparison
- **HTML + JSON Reports**

## Usage

```bash
# Single domain
python origin_ip_finder.py -d target.com

# Aggressive with more threads
python origin_ip_finder.py -d target.com --aggressive --threads 20

# From file
python origin_ip_finder.py -f domains.txt -o results/
```

## Options

| Flag | Description |
|------|-------------|
| `-d` | One or more domains |
| `-f` | File with domains |
| `--aggressive` | More thorough scanning |
| `--threads` | Subdomain scan threads (default: 10) |
| `--timeout` | DNS timeout (default: 5s) |
| `-o` | Output directory |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SECURITYTRAILS_API_KEY` | DNS history API key (free tier available) |

## Bug Bounty Tips

- Verified origin IP + bypassed WAF = **High severity CDN bypass**
- `curl -sI -H "Host: target.com" http://ORIGIN_IP/`
- Check email headers from password reset emails for origin IP
- Use Shodan: `ssl.cert.subject.cn:"target.com"`

## Requirements

```
requests
dnspython
colorama
```
