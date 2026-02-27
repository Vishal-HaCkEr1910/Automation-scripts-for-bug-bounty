#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║            BROKEN LINK HIJACKER (BLH) v1.0.0                   ║
║        Automated Broken Link Takeover Scanner                   ║
║                                                                  ║
║  Author : Vishal Rao (@Vishal-HaCkEr1910)                      ║
║  License: MIT — For authorized security testing only            ║
╚══════════════════════════════════════════════════════════════════╝

Crawls a target website, finds all external links, checks if they're
dead, and determines if the dead resources are CLAIMABLE (expired
domains, deleted GitHub repos/pages, unclaimed S3 buckets, dangling
CNAMEs, dead social profiles, etc.).

Usage:
    python blh.py -u https://example.com
    python blh.py -u https://example.com --depth 3 --threads 50
    python blh.py -u https://example.com --full --output report
"""

# ═══════════════════════════════════════════════════════════════
# SECTION 1 — IMPORTS
# ═══════════════════════════════════════════════════════════════

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import signal
import socket
import ssl
import sys
import time
import warnings
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs

import aiohttp
import certifi
import tldextract
from bs4 import BeautifulSoup
from colorama import Fore, Style, init as colorama_init
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    Progress, SpinnerColumn, BarColumn, TextColumn,
    TimeElapsedColumn, TimeRemainingColumn, MofNCompleteColumn
)
from rich.table import Table
from rich.text import Text
from fake_useragent import UserAgent

warnings.filterwarnings("ignore")
colorama_init(autoreset=True)

# ═══════════════════════════════════════════════════════════════
# SECTION 2 — CONSTANTS & CONFIG
# ═══════════════════════════════════════════════════════════════

VERSION = "1.0.0"
AUTHOR = "Vishal Rao"
console = Console()

# Status code categories
DEAD_CODES = {404, 410, 451, 521, 522, 523, 530}
REDIRECT_CODES = {301, 302, 303, 307, 308}
ERROR_CODES = {500, 502, 503, 504}

# Default concurrency limits
DEFAULT_CRAWL_CONCURRENCY = 40
DEFAULT_CHECK_CONCURRENCY = 100
DEFAULT_CRAWL_DEPTH = 3
DEFAULT_TIMEOUT = 15
MAX_PAGES_DEFAULT = 5000

# Domains that are pure INFRASTRUCTURE / analytics — never contain user-claimable content
# Social media profiles are NOT included because they CAN be dead/claimable
FALSE_POSITIVE_DOMAINS = {
    # Google infrastructure (analytics, tag managers, CDNs)
    "googletagmanager.com", "www.googletagmanager.com",
    "firebase.googleapis.com",
    "gstatic.com",
    "recaptcha.net",
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "google-analytics.com",
    "analytics.google.com",
    "fonts.googleapis.com",
    "ajax.googleapis.com",
    # Tracking / analytics SDKs
    "cdn.moengage.com", "moengage.com",
    "connect.facebook.net",       # Facebook SDK — not a profile page
    # Error reporting
    "sentry.io",
    # Ad networks
    "ads.google.com",
}

# URL patterns for pure infrastructure (NOT social media profiles)
FALSE_POSITIVE_URL_PATTERNS = [
    r"https?://(?:www\.)?googletagmanager\.com",
    r"https?://(?:[\w\-]+\.)?sentry\.io",
    r"https?://connect\.facebook\.net",
    r"https?://cdn\.moengage\.com",
    r"https?://firebase\.googleapis\.com",
    r"https?://fonts\.googleapis\.com",
    r"https?://ajax\.googleapis\.com",
]

# Known claimable service fingerprints
# Maps: service_name → (url_pattern_regex, dead_response_fingerprint)
CLAIMABLE_FINGERPRINTS: dict[str, dict] = {
    # ── GitHub ──
    "github_pages": {
        "url_pattern": r"([\w\-]+)\.github\.io",
        "body_match": [
            "There isn't a GitHub Pages site here",
            "Site not found",
            "404 — File not found"
        ],
        "severity": "HIGH",
        "type": "Subdomain Takeover via GitHub Pages"
    },
    "github_repo": {
        "url_pattern": r"github\.com/([\w\-]+)/([\w\-]+)",
        "status_codes": [404],
        "body_match": ["This is not the web page you are looking for"],
        "severity": "MEDIUM",
        "type": "Broken GitHub Repository Link"
    },
    "github_raw": {
        "url_pattern": r"raw\.githubusercontent\.com/([\w\-]+)/([\w\-]+)",
        "status_codes": [404],
        "body_match": ["404: Not Found"],
        "severity": "MEDIUM",
        "type": "Dead GitHub Raw Content"
    },

    # ── AWS S3 ──
    "aws_s3": {
        "url_pattern": r"([\w\-]+)\.s3[\.\-][\w\-]*\.?amazonaws\.com",
        "body_match": [
            "NoSuchBucket",
            "The specified bucket does not exist",
            "AccessDenied"
        ],
        "severity": "CRITICAL",
        "type": "Unclaimed AWS S3 Bucket"
    },
    "aws_s3_path": {
        "url_pattern": r"s3[\.\-][\w\-]*\.?amazonaws\.com/([\w\-]+)",
        "body_match": ["NoSuchBucket", "NoSuchKey"],
        "severity": "CRITICAL",
        "type": "Unclaimed AWS S3 Bucket (path-style)"
    },

    # ── Azure ──
    "azure_blob": {
        "url_pattern": r"([\w\-]+)\.blob\.core\.windows\.net",
        "body_match": [
            "BlobNotFound",
            "ContainerNotFound",
            "The specified container does not exist",
            "ResourceNotFound"
        ],
        "severity": "HIGH",
        "type": "Unclaimed Azure Blob Storage"
    },
    "azure_websites": {
        "url_pattern": r"([\w\-]+)\.azurewebsites\.net",
        "body_match": [
            "404 Web Site not found",
            "Microsoft Azure App Service"
        ],
        "severity": "HIGH",
        "type": "Unclaimed Azure Web App"
    },
    "azure_cloudapp": {
        "url_pattern": r"([\w\-]+)\.cloudapp\.azure\.com",
        "status_codes": [404],
        "severity": "HIGH",
        "type": "Unclaimed Azure Cloud App"
    },
    "azure_trafficmanager": {
        "url_pattern": r"([\w\-]+)\.trafficmanager\.net",
        "body_match": ["404 Web Site not found"],
        "severity": "HIGH",
        "type": "Unclaimed Azure Traffic Manager"
    },

    # ── GCP ──
    "gcp_storage": {
        "url_pattern": r"storage\.googleapis\.com/([\w\-\.]+)",
        "body_match": [
            "NoSuchBucket",
            "The specified bucket does not exist"
        ],
        "severity": "HIGH",
        "type": "Unclaimed GCP Storage Bucket"
    },
    "gcp_appspot": {
        "url_pattern": r"([\w\-]+)\.appspot\.com",
        "status_codes": [404],
        "body_match": ["The requested URL was not found on this server"],
        "severity": "HIGH",
        "type": "Unclaimed GCP App Engine"
    },
    "firebase_hosting": {
        "url_pattern": r"([\w\-]+)\.firebaseapp\.com|\.web\.app",
        "body_match": ["Site Not Found", "Firebase Hosting Setup"],
        "severity": "HIGH",
        "type": "Unclaimed Firebase Hosting"
    },

    # ── Heroku ──
    "heroku": {
        "url_pattern": r"([\w\-]+)\.herokuapp\.com",
        "body_match": [
            "no-such-app",
            "There is no app configured at that hostname",
            "herokucdn.com/error-pages"
        ],
        "severity": "HIGH",
        "type": "Unclaimed Heroku App"
    },

    # ── Shopify ──
    "shopify": {
        "url_pattern": r"([\w\-]+)\.myshopify\.com",
        "body_match": [
            "Sorry, this shop is currently unavailable",
            "Only one step left"
        ],
        "severity": "MEDIUM",
        "type": "Unclaimed Shopify Store"
    },

    # ── WordPress ──
    "wordpress": {
        "url_pattern": r"([\w\-]+)\.wordpress\.com",
        "body_match": [
            "doesn&#8217;t exist",
            "This site is no longer available"
        ],
        "severity": "MEDIUM",
        "type": "Unclaimed WordPress.com Blog"
    },

    # ── Bitbucket ──
    "bitbucket": {
        "url_pattern": r"bitbucket\.org/([\w\-]+)/([\w\-]+)",
        "status_codes": [404],
        "body_match": ["Repository not found"],
        "severity": "MEDIUM",
        "type": "Deleted Bitbucket Repository"
    },

    # ── NPM / Package Registries ──
    "npm_package": {
        "url_pattern": r"(?:www\.)?npmjs\.com/package/([\w\-\.@/]+)",
        "status_codes": [404],
        "body_match": ["Cannot find package"],
        "severity": "CRITICAL",
        "type": "Unclaimed NPM Package (Dependency Confusion)"
    },
    "pypi_package": {
        "url_pattern": r"pypi\.org/project/([\w\-]+)",
        "status_codes": [404],
        "body_match": ["Not Found"],
        "severity": "CRITICAL",
        "type": "Unclaimed PyPI Package"
    },

    # ── Social Media ──
    "twitter_profile": {
        "url_pattern": r"(?:twitter|x)\.com/([\w]+)$",
        "status_codes": [404],
        "body_match": [
            "This account doesn't exist",
            "Hmm...this page doesn't exist",
            "Something went wrong"
        ],
        "severity": "MEDIUM",
        "type": "Unclaimed Twitter/X Profile"
    },
    "instagram_profile": {
        "url_pattern": r"instagram\.com/([\w\.]+)/?$",
        "body_match": [
            "Sorry, this page isn't available",
            "The link you followed may be broken"
        ],
        "severity": "MEDIUM",
        "type": "Unclaimed Instagram Profile"
    },
    "linkedin_company": {
        "url_pattern": r"linkedin\.com/company/([\w\-]+)",
        "status_codes": [404],
        "body_match": ["Page not found"],
        "severity": "MEDIUM",
        "type": "Dead LinkedIn Company Page"
    },
    "youtube_channel": {
        "url_pattern": r"youtube\.com/(?:c/|channel/|@)([\w\-]+)",
        "status_codes": [404],
        "body_match": ["This page isn't available"],
        "severity": "LOW",
        "type": "Dead YouTube Channel"
    },
    "facebook_page": {
        "url_pattern": r"facebook\.com/([\w\.]+)/?$",
        "body_match": [
            "This content isn't available",
            "Page not found",
            "This page may have been removed"
        ],
        "severity": "MEDIUM",
        "type": "Unclaimed Facebook Page"
    },
    "tiktok_profile": {
        "url_pattern": r"tiktok\.com/@([\w\.]+)",
        "body_match": [
            "Couldn't find this account",
            "This account doesn't exist"
        ],
        "severity": "LOW",
        "type": "Unclaimed TikTok Profile"
    },

    # ── CDN / JS Libraries ──
    "jsdelivr": {
        "url_pattern": r"cdn\.jsdelivr\.net/(?:npm|gh)/([\w\-@/\.]+)",
        "status_codes": [404],
        "body_match": ["Couldn't find the requested release"],
        "severity": "CRITICAL",
        "type": "Dead jsDelivr CDN Resource (Supply Chain Risk)"
    },
    "unpkg": {
        "url_pattern": r"unpkg\.com/([\w\-@/\.]+)",
        "status_codes": [404],
        "body_match": ["Cannot find package"],
        "severity": "CRITICAL",
        "type": "Dead unpkg CDN Resource (Supply Chain Risk)"
    },
    "cdnjs": {
        "url_pattern": r"cdnjs\.cloudflare\.com/ajax/libs/([\w\-\.]+)",
        "status_codes": [404],
        "severity": "HIGH",
        "type": "Dead CDNJS Resource"
    },

    # ── Other Hosting ──
    "netlify": {
        "url_pattern": r"([\w\-]+)\.netlify\.app",
        "body_match": ["Not Found - Request ID"],
        "severity": "HIGH",
        "type": "Unclaimed Netlify Site"
    },
    "vercel": {
        "url_pattern": r"([\w\-]+)\.vercel\.app",
        "body_match": ["The deployment could not be found"],
        "severity": "HIGH",
        "type": "Unclaimed Vercel Deployment"
    },
    "surge": {
        "url_pattern": r"([\w\-]+)\.surge\.sh",
        "body_match": ["project not found"],
        "severity": "MEDIUM",
        "type": "Unclaimed Surge.sh Site"
    },
    "fly_io": {
        "url_pattern": r"([\w\-]+)\.fly\.dev",
        "status_codes": [404],
        "body_match": ["Could not resolve"],
        "severity": "MEDIUM",
        "type": "Unclaimed Fly.io App"
    },
    "render": {
        "url_pattern": r"([\w\-]+)\.onrender\.com",
        "body_match": ["Not Found"],
        "severity": "MEDIUM",
        "type": "Unclaimed Render App"
    },

    # ── Zendesk / Freshdesk / Helpdesks ──
    "zendesk": {
        "url_pattern": r"([\w\-]+)\.zendesk\.com",
        "body_match": ["Help Center Closed", "Oops, this help center"],
        "severity": "MEDIUM",
        "type": "Unclaimed Zendesk Help Center"
    },
    "freshdesk": {
        "url_pattern": r"([\w\-]+)\.freshdesk\.com",
        "body_match": ["There is no helpdesk here", "Company not found"],
        "severity": "MEDIUM",
        "type": "Unclaimed Freshdesk Portal"
    },

    # ── Domain Expired ──
    "expired_domain": {
        "url_pattern": r".*",  # catch-all — checked last
        "body_match": [
            "This domain is for sale",
            "buy this domain",
            "domain has expired",
            "is parked free",
            "sedoparking",
            "hugedomains.com",
            "This webpage is parked",
            "godaddy.com/domain",
            "namecheap.com",
            "domainmarket.com",
            "afternic.com",
            "This site can't be reached",
            "domain is available for purchase"
        ],
        "dns_check": True,
        "severity": "CRITICAL",
        "type": "Expired / Parked Domain (Registerable)"
    }
}

# Tags to extract links from
LINK_ATTRIBUTES = {
    "a": "href",
    "link": "href",
    "script": "src",
    "img": "src",
    "iframe": "src",
    "video": "src",
    "audio": "src",
    "source": "src",
    "embed": "src",
    "object": "data",
    "form": "action",
    "area": "href",
}

# File extensions to skip during crawling
SKIP_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico",
    ".bmp", ".tiff", ".mp4", ".mp3", ".avi", ".mov", ".wmv",
    ".flv", ".webm", ".ogg", ".wav", ".flac", ".aac",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".rar", ".tar", ".gz", ".7z", ".bz2",
    ".exe", ".msi", ".dmg", ".bin", ".iso",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".css",  # skip CSS files during crawl (we extract from pages)
}

BANNER = r"""
[bold cyan]
 ____  _     _   _
| __ )| |   | | | |
|  _ \| |   | |_| |
| |_) | |___|  _  |
|____/|_____|_| |_|  v{version}

[bold white]Broken Link Hijacker[/bold white]
[dim]Automated Broken Link Takeover Scanner[/dim]
[dim]Author: {author} | github.com/Vishal-HaCkEr1910[/dim]
""".format(version=VERSION, author=AUTHOR)


# ═══════════════════════════════════════════════════════════════
# SECTION 3 — DATA CLASSES
# ═══════════════════════════════════════════════════════════════

@dataclass
class ExtractedLink:
    """Represents a link found during crawling."""
    url: str
    source_page: str
    tag: str
    attribute: str
    anchor_text: str = ""
    is_external: bool = False

@dataclass
class LinkCheckResult:
    """Result of checking whether a link is alive or dead."""
    url: str
    status_code: int = 0
    is_dead: bool = False
    is_timeout: bool = False
    error: str = ""
    response_body: str = ""
    redirect_url: str = ""
    redirect_chain: list = field(default_factory=list)
    response_time_ms: float = 0
    content_type: str = ""
    source_pages: list = field(default_factory=list)
    tags_found_in: list = field(default_factory=list)

@dataclass
class HijackCandidate:
    """A dead link that is potentially claimable."""
    url: str
    service: str
    service_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    claimable: bool = False
    claim_target: str = ""  # What to claim (domain, repo name, bucket, etc.)
    evidence: str = ""
    source_pages: list = field(default_factory=list)
    tags_found_in: list = field(default_factory=list)
    status_code: int = 0
    dns_resolved: bool = True
    cname_record: str = ""

@dataclass
class ScanStats:
    """Live scan statistics."""
    pages_crawled: int = 0
    pages_queued: int = 0
    internal_links: int = 0
    external_links: int = 0
    unique_external: int = 0
    links_checked: int = 0
    dead_links: int = 0
    hijackable: int = 0
    errors: int = 0
    start_time: float = 0
    phase: str = "Initializing"

    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time if self.start_time else 0

    @property
    def rate(self) -> float:
        e = self.elapsed
        return (self.pages_crawled + self.links_checked) / e if e > 0 else 0


# ═══════════════════════════════════════════════════════════════
# SECTION 4 — UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════

def normalize_url(url: str) -> str:
    """Normalize a URL for deduplication."""
    parsed = urlparse(url)
    # Remove fragment, normalize scheme
    normalized = urlunparse((
        parsed.scheme.lower(),
        parsed.netloc.lower().rstrip("."),
        parsed.path.rstrip("/") if parsed.path != "/" else "/",
        parsed.params,
        parsed.query,
        ""  # remove fragment
    ))
    return normalized


def is_same_domain(url1: str, url2: str) -> bool:
    """Check if two URLs belong to the same registered domain."""
    ext1 = tldextract.extract(url1)
    ext2 = tldextract.extract(url2)
    return (ext1.domain == ext2.domain and ext1.suffix == ext2.suffix)


def get_domain(url: str) -> str:
    """Extract registered domain from URL."""
    ext = tldextract.extract(url)
    if ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return ext.domain


def should_skip_url(url: str) -> bool:
    """Check if URL should be skipped (mailto, tel, javascript, data, etc.)."""
    skip_schemes = ("mailto:", "tel:", "javascript:", "data:", "blob:", "ftp:", "file:", "#")
    lower = url.lower().strip()
    return any(lower.startswith(s) for s in skip_schemes)


def get_file_extension(url: str) -> str:
    """Extract file extension from URL path."""
    path = urlparse(url).path.lower()
    for ext in SKIP_EXTENSIONS:
        if path.endswith(ext):
            return ext
    return ""


def severity_color(severity: str) -> str:
    """Return Rich color for severity level."""
    return {
        "CRITICAL": "bold red",
        "HIGH": "bold yellow",
        "MEDIUM": "bold blue",
        "LOW": "dim white",
        "INFO": "dim cyan"
    }.get(severity, "white")


def severity_emoji(severity: str) -> str:
    """Return emoji for severity."""
    return {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "⚪",
    }.get(severity, "⚫")


def timestamp_str() -> str:
    """Current timestamp string for filenames."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def sha256_hash(data: str) -> str:
    """SHA-256 hash of a string."""
    return hashlib.sha256(data.encode()).hexdigest()


def is_false_positive_domain(url: str) -> bool:
    """Check if URL belongs to a known false-positive domain (anti-bot blockers)."""
    hostname = urlparse(url).netloc.lower().split(":")[0]
    # Direct match
    if hostname in FALSE_POSITIVE_DOMAINS:
        return True
    # Subdomain match (e.g., o1243174.ingest.us.sentry.io)
    for fp_domain in FALSE_POSITIVE_DOMAINS:
        if hostname.endswith(f".{fp_domain}"):
            return True
    # Pattern match
    for pattern in FALSE_POSITIVE_URL_PATTERNS:
        if re.match(pattern, url, re.IGNORECASE):
            return True
    return False


def build_user_agent() -> str:
    """Generate a realistic browser User-Agent."""
    try:
        ua = UserAgent()
        return ua.random
    except Exception:
        return (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        )


# ═══════════════════════════════════════════════════════════════
# SECTION 5 — ASYNC CRAWLER ENGINE
# ═══════════════════════════════════════════════════════════════

class Crawler:
    """
    Async web crawler that discovers all pages on a target domain
    and extracts every internal + external link.
    """

    def __init__(
        self,
        target_url: str,
        max_depth: int = DEFAULT_CRAWL_DEPTH,
        max_pages: int = MAX_PAGES_DEFAULT,
        concurrency: int = DEFAULT_CRAWL_CONCURRENCY,
        timeout: int = DEFAULT_TIMEOUT,
        stats: ScanStats | None = None,
        respect_robots: bool = True,
    ):
        self.target_url = normalize_url(target_url)
        parsed = urlparse(self.target_url)
        self.target_scheme = parsed.scheme
        self.target_netloc = parsed.netloc
        self.target_domain = get_domain(self.target_url)
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.concurrency = concurrency
        self.timeout = aiohttp.ClientTimeout(total=timeout, connect=10, sock_read=timeout)
        self.stats = stats or ScanStats()

        # SSL context — use system certs (needed for Cloudflare/WAF sites)
        self.ssl_ctx = ssl.create_default_context(cafile=certifi.where())

        # State
        self.visited: set[str] = set()
        self.external_links: list[ExtractedLink] = []
        self.internal_links_set: set[str] = set()
        self.external_urls_set: set[str] = set()
        self.semaphore = asyncio.Semaphore(concurrency)
        self.user_agent = build_user_agent()

        # Robots.txt disallowed paths
        self.disallowed_paths: set[str] = set()
        self.respect_robots = respect_robots

    async def _fetch_robots_txt(self, session: aiohttp.ClientSession):
        """Parse robots.txt for disallowed paths."""
        robots_url = f"{self.target_scheme}://{self.target_netloc}/robots.txt"
        try:
            async with session.get(robots_url, timeout=self.timeout) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    applies = False
                    for line in text.splitlines():
                        line = line.strip()
                        if line.lower().startswith("user-agent:"):
                            agent = line.split(":", 1)[1].strip().lower()
                            applies = agent == "*" or "bot" in agent
                        elif line.lower().startswith("disallow:") and applies:
                            path = line.split(":", 1)[1].strip()
                            if path:
                                self.disallowed_paths.add(path)
        except Exception:
            pass

    def _is_allowed(self, url: str) -> bool:
        """Check if URL is allowed by robots.txt."""
        if not self.respect_robots or not self.disallowed_paths:
            return True
        path = urlparse(url).path
        for disallowed in self.disallowed_paths:
            if path.startswith(disallowed):
                return False
        return True

    def _is_internal(self, url: str) -> bool:
        """Check if URL belongs to the target domain."""
        return is_same_domain(url, self.target_url)

    def _extract_links(self, html: str, page_url: str) -> list[ExtractedLink]:
        """Extract all links from an HTML page."""
        links = []
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            try:
                soup = BeautifulSoup(html, "html.parser")
            except Exception:
                return links

        for tag_name, attr in LINK_ATTRIBUTES.items():
            for tag in soup.find_all(tag_name):
                raw = tag.get(attr, "")
                if not raw or should_skip_url(raw):
                    continue

                # Resolve relative URLs
                full_url = urljoin(page_url, raw.strip())
                full_url = normalize_url(full_url)

                # Must be HTTP(S)
                if not full_url.startswith(("http://", "https://")):
                    continue

                is_ext = not self._is_internal(full_url)
                anchor_text = ""
                if tag_name == "a":
                    anchor_text = tag.get_text(strip=True)[:200]

                links.append(ExtractedLink(
                    url=full_url,
                    source_page=page_url,
                    tag=tag_name,
                    attribute=attr,
                    anchor_text=anchor_text,
                    is_external=is_ext,
                ))

        # Also extract links from inline CSS (background-image, etc.)
        for style_tag in soup.find_all("style"):
            css_text = style_tag.string or ""
            for match in re.finditer(r'url\(["\']?(https?://[^"\')\s]+)["\']?\)', css_text):
                css_url = normalize_url(match.group(1))
                if not self._is_internal(css_url):
                    links.append(ExtractedLink(
                        url=css_url,
                        source_page=page_url,
                        tag="style",
                        attribute="url()",
                        is_external=True,
                    ))

        # Extract from srcset attributes
        for tag in soup.find_all(["img", "source"], srcset=True):
            srcset = tag.get("srcset", "")
            for part in srcset.split(","):
                src = part.strip().split()[0] if part.strip() else ""
                if src and not should_skip_url(src):
                    full = urljoin(page_url, src.strip())
                    full = normalize_url(full)
                    if full.startswith(("http://", "https://")) and not self._is_internal(full):
                        links.append(ExtractedLink(
                            url=full,
                            source_page=page_url,
                            tag=tag.name,
                            attribute="srcset",
                            is_external=True,
                        ))

        return links

    async def _crawl_page(
        self,
        session: aiohttp.ClientSession,
        url: str,
        depth: int,
        queue: asyncio.Queue
    ):
        """Crawl a single page and extract links."""
        if url in self.visited:
            return
        if len(self.visited) >= self.max_pages:
            return
        if not self._is_allowed(url):
            return

        self.visited.add(url)

        async with self.semaphore:
            try:
                headers = {
                    "User-Agent": self.user_agent,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Connection": "keep-alive",
                    "Upgrade-Insecure-Requests": "1",
                    "Sec-Fetch-Dest": "document",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-Site": "none",
                    "Sec-Fetch-User": "?1",
                }
                # Try with SSL first, fall back to no-SSL, then HTTP
                fetch_url = url
                resp = None
                ssl_options = [self.ssl_ctx, False]
                for ssl_opt in ssl_options:
                    try:
                        resp = await session.get(
                            fetch_url, timeout=self.timeout, headers=headers,
                            allow_redirects=True, ssl=ssl_opt,
                            max_redirects=5,
                        )
                        break
                    except (aiohttp.ClientConnectorSSLError, aiohttp.ClientConnectorCertificateError):
                        continue
                    except (aiohttp.ClientConnectorError, asyncio.TimeoutError):
                        if fetch_url.startswith("https://"):
                            fetch_url = fetch_url.replace("https://", "http://", 1)
                            try:
                                resp = await session.get(
                                    fetch_url, timeout=self.timeout, headers=headers,
                                    allow_redirects=True, ssl=False,
                                    max_redirects=5,
                                )
                                break
                            except Exception:
                                raise
                        else:
                            raise

                if resp is None:
                    return

                async with resp:
                    ct = resp.headers.get("Content-Type", "")
                    if "text/html" not in ct and "application/xhtml" not in ct:
                        return

                    html = await resp.text(errors="replace")
                    self.stats.pages_crawled += 1

            except Exception:
                self.stats.errors += 1
                return

        # Extract links
        found_links = self._extract_links(html, url)

        for link in found_links:
            if link.is_external:
                if link.url not in self.external_urls_set:
                    self.external_urls_set.add(link.url)
                    self.external_links.append(link)
                    self.stats.external_links += 1
                    self.stats.unique_external = len(self.external_urls_set)
                else:
                    # Update source_pages for existing link
                    for existing in self.external_links:
                        if existing.url == link.url:
                            break
            else:
                # Internal — queue for further crawling
                normalized = normalize_url(link.url)
                ext = get_file_extension(normalized)
                if (
                    normalized not in self.visited
                    and normalized not in self.internal_links_set
                    and depth + 1 <= self.max_depth
                    and not ext
                ):
                    self.internal_links_set.add(normalized)
                    self.stats.internal_links += 1
                    await queue.put((normalized, depth + 1))

    async def crawl(self) -> list[ExtractedLink]:
        """Main crawl loop. Returns list of external links found."""
        self.stats.phase = "Crawling"
        connector = aiohttp.TCPConnector(
            limit=self.concurrency,
            limit_per_host=10,
            ttl_dns_cache=300,
            ssl=self.ssl_ctx,
        )
        async with aiohttp.ClientSession(connector=connector) as session:
            # Fetch robots.txt first
            if self.respect_robots:
                await self._fetch_robots_txt(session)

            queue: asyncio.Queue = asyncio.Queue()
            await queue.put((self.target_url, 0))
            self.stats.pages_queued = 1

            active_tasks: set[asyncio.Task] = set()

            while not queue.empty() or active_tasks:
                # Drain queue into tasks
                while not queue.empty() and len(active_tasks) < self.concurrency:
                    url, depth = await queue.get()
                    task = asyncio.create_task(
                        self._crawl_page(session, url, depth, queue)
                    )
                    active_tasks.add(task)
                    task.add_done_callback(active_tasks.discard)

                if active_tasks:
                    # Wait for at least one task to complete
                    done, _ = await asyncio.wait(
                        active_tasks, return_when=asyncio.FIRST_COMPLETED
                    )
                    for t in done:
                        if t.exception():
                            self.stats.errors += 1

                self.stats.pages_queued = queue.qsize()

            # Deduplicate external links and consolidate source pages
            url_to_link: dict[str, ExtractedLink] = {}
            url_to_sources: dict[str, list[str]] = defaultdict(list)
            url_to_tags: dict[str, set[str]] = defaultdict(set)

            for link in self.external_links:
                if link.url not in url_to_link:
                    url_to_link[link.url] = link
                url_to_sources[link.url].append(link.source_page)
                url_to_tags[link.url].add(f"<{link.tag} {link.attribute}>")

            self.external_links = list(url_to_link.values())
            self._source_map = url_to_sources
            self._tag_map = url_to_tags
            self.stats.unique_external = len(self.external_links)

            return self.external_links


# ═══════════════════════════════════════════════════════════════
# SECTION 6 — ASYNC LINK CHECKER
# ═══════════════════════════════════════════════════════════════

class LinkChecker:
    """
    Checks external links concurrently to determine if they are dead.
    Uses smart retry logic and status code analysis.
    """

    def __init__(
        self,
        concurrency: int = DEFAULT_CHECK_CONCURRENCY,
        timeout: int = DEFAULT_TIMEOUT,
        stats: ScanStats | None = None,
        retries: int = 2,
    ):
        self.concurrency = concurrency
        self.timeout = aiohttp.ClientTimeout(total=timeout, connect=8)
        self.stats = stats or ScanStats()
        self.retries = retries
        self.semaphore = asyncio.Semaphore(concurrency)
        self.results: list[LinkCheckResult] = []
        self.user_agent = build_user_agent()
        self.ssl_ctx = ssl.create_default_context(cafile=certifi.where())

    async def _check_single(
        self,
        session: aiohttp.ClientSession,
        link: ExtractedLink,
        source_map: dict,
        tag_map: dict,
    ) -> LinkCheckResult:
        """Check a single link with retries."""
        result = LinkCheckResult(
            url=link.url,
            source_pages=list(set(source_map.get(link.url, [link.source_page]))),
            tags_found_in=list(tag_map.get(link.url, {f"<{link.tag} {link.attribute}>"})),
        )

        for attempt in range(self.retries + 1):
            try:
                async with self.semaphore:
                    start = time.time()
                    headers = {
                        "User-Agent": self.user_agent,
                        "Accept": "*/*",
                        "Accept-Language": "en-US,en;q=0.9",
                    }
                    # Try proper SSL first, fall back to unverified
                    ssl_opt = self.ssl_ctx if link.url.startswith("https") else False
                    try:
                        resp_ctx = session.get(
                            link.url, timeout=self.timeout, headers=headers,
                            allow_redirects=True, ssl=ssl_opt,
                            max_redirects=10,
                        )
                        resp = await resp_ctx.__aenter__()
                    except (aiohttp.ClientConnectorSSLError, aiohttp.ClientConnectorCertificateError):
                        resp_ctx = session.get(
                            link.url, timeout=self.timeout, headers=headers,
                            allow_redirects=True, ssl=False,
                            max_redirects=10,
                        )
                        resp = await resp_ctx.__aenter__()

                    try:
                        elapsed = (time.time() - start) * 1000
                        result.status_code = resp.status
                        result.response_time_ms = round(elapsed, 1)
                        result.content_type = resp.headers.get("Content-Type", "")

                        # Track redirect chain
                        if resp.history:
                            result.redirect_chain = [
                                str(r.url) for r in resp.history
                            ]
                            result.redirect_url = str(resp.url)

                        # Read body for fingerprint matching (limit to 50KB)
                        try:
                            body = await resp.text(errors="replace")
                            result.response_body = body[:50000]
                        except Exception:
                            result.response_body = ""

                        # Determine if dead
                        # Filter false positives: major sites that block bots
                        is_fp = is_false_positive_domain(link.url)

                        if resp.status in DEAD_CODES:
                            # Even 404 on known FP domains is likely anti-bot
                            result.is_dead = not is_fp
                        elif resp.status in ERROR_CODES and attempt == self.retries:
                            result.is_dead = not is_fp
                        elif resp.status >= 400:
                            result.is_dead = not is_fp

                        if not result.is_dead:
                            break  # Success — no need to retry

                        # Retry on server errors
                        if resp.status in ERROR_CODES and attempt < self.retries:
                            await asyncio.sleep(1.5 * (attempt + 1))
                            continue
                        break
                    finally:
                        resp.release()

            except asyncio.TimeoutError:
                result.is_timeout = True
                result.error = "Connection timed out"
                if attempt < self.retries:
                    await asyncio.sleep(2)
                    continue
                # Timeouts on known FP domains are anti-bot, not dead
                result.is_dead = not is_false_positive_domain(link.url)

            except aiohttp.ClientConnectorError as e:
                result.error = f"Connection failed: {str(e)[:100]}"
                # DNS failures are real dead links (not FP)
                dns_fail = "Name or service not known" in str(e) or "nodename nor servname" in str(e)
                if dns_fail:
                    result.is_dead = True
                    break
                result.is_dead = not is_false_positive_domain(link.url)
                if attempt < self.retries:
                    await asyncio.sleep(2)
                    continue
                break

            except Exception as e:
                result.error = str(e)[:150]
                if attempt == self.retries:
                    result.is_dead = not is_false_positive_domain(link.url)
                else:
                    await asyncio.sleep(1)

        self.stats.links_checked += 1
        if result.is_dead:
            self.stats.dead_links += 1

        return result

    async def check_all(
        self,
        links: list[ExtractedLink],
        source_map: dict,
        tag_map: dict,
    ) -> list[LinkCheckResult]:
        """Check all links concurrently."""
        self.stats.phase = "Checking Links"
        connector = aiohttp.TCPConnector(
            limit=self.concurrency,
            limit_per_host=5,
            ttl_dns_cache=300,
            ssl=self.ssl_ctx,
        )
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [
                self._check_single(session, link, source_map, tag_map)
                for link in links
            ]
            self.results = await asyncio.gather(*tasks, return_exceptions=False)

        return [r for r in self.results if isinstance(r, LinkCheckResult)]


# ═══════════════════════════════════════════════════════════════
# SECTION 7 — HIJACK ANALYZER
# ═══════════════════════════════════════════════════════════════

class HijackAnalyzer:
    """
    Analyzes dead links to determine if they are CLAIMABLE.
    Checks against known service fingerprints, DNS records, and
    domain registration status.
    """

    def __init__(self, stats: ScanStats | None = None):
        self.stats = stats or ScanStats()
        self.candidates: list[HijackCandidate] = []

    def _check_dns(self, hostname: str) -> tuple[bool, str]:
        """Check if hostname resolves and get CNAME if any."""
        resolved = False
        cname = ""
        try:
            socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
            resolved = True
        except socket.gaierror:
            resolved = False

        # Check CNAME
        try:
            import subprocess
            result = subprocess.run(
                ["dig", "+short", "CNAME", hostname],
                capture_output=True, text=True, timeout=5
            )
            cname = result.stdout.strip().rstrip(".")
        except Exception:
            pass

        return resolved, cname

    def _match_fingerprint(
        self,
        result: LinkCheckResult,
        service_name: str,
        fingerprint: dict,
    ) -> HijackCandidate | None:
        """Check if a dead link matches a claimable service fingerprint."""
        url = result.url
        body = result.response_body.lower() if result.response_body else ""

        # Check URL pattern
        pattern = fingerprint.get("url_pattern", "")
        if pattern == ".*":
            # Catch-all (expired domain) — only check if DNS fails or body matches
            pass
        else:
            match = re.search(pattern, url, re.IGNORECASE)
            if not match:
                return None

        # Check status codes if specified
        expected_codes = fingerprint.get("status_codes", [])
        if expected_codes and result.status_code not in expected_codes:
            # Some services return 200 with error body, so also check body
            if not fingerprint.get("body_match"):
                return None

        # Check response body fingerprint
        body_matches = fingerprint.get("body_match", [])
        body_matched = False
        matched_text = ""
        if body_matches:
            for bm in body_matches:
                if bm.lower() in body:
                    body_matched = True
                    matched_text = bm
                    break

        # For services with status codes AND body_match, need at least one
        if expected_codes and body_matches:
            if result.status_code not in expected_codes and not body_matched:
                return None
        elif body_matches and not body_matched:
            return None

        # DNS check for expired domains
        if fingerprint.get("dns_check"):
            hostname = urlparse(url).netloc
            resolved, cname = self._check_dns(hostname)
            if resolved and not body_matched:
                return None  # Domain resolves and no parked fingerprint

            # Extract what to claim
            domain = get_domain(url)
            return HijackCandidate(
                url=url,
                service=service_name,
                service_type=fingerprint["type"],
                severity=fingerprint["severity"],
                claimable=not resolved,
                claim_target=domain,
                evidence=f"DNS {'unresolved' if not resolved else 'resolved'}"
                         + (f", body matched: '{matched_text}'" if body_matched else "")
                         + (f", CNAME: {cname}" if cname else ""),
                source_pages=result.source_pages,
                tags_found_in=result.tags_found_in,
                status_code=result.status_code,
                dns_resolved=resolved,
                cname_record=cname,
            )

        # For all other services — extract claim target
        match = re.search(pattern, url, re.IGNORECASE)
        claim_target = match.group(1) if match and match.lastindex else urlparse(url).netloc

        return HijackCandidate(
            url=url,
            service=service_name,
            service_type=fingerprint["type"],
            severity=fingerprint["severity"],
            claimable=True,
            claim_target=claim_target,
            evidence=f"Status: {result.status_code}"
                     + (f", body matched: '{matched_text}'" if body_matched else "")
                     + (f", error: {result.error}" if result.error else ""),
            source_pages=result.source_pages,
            tags_found_in=result.tags_found_in,
            status_code=result.status_code,
        )

    def analyze(self, dead_links: list[LinkCheckResult]) -> list[HijackCandidate]:
        """Analyze all dead links for hijack potential."""
        self.stats.phase = "Analyzing Hijack Potential"

        for result in dead_links:
            matched = False
            # Check against all fingerprints (specific ones first, catch-all last)
            for service_name, fp in CLAIMABLE_FINGERPRINTS.items():
                if service_name == "expired_domain":
                    continue  # Check last
                candidate = self._match_fingerprint(result, service_name, fp)
                if candidate:
                    self.candidates.append(candidate)
                    self.stats.hijackable += 1
                    matched = True
                    break

            # If no specific service matched, check expired domain
            if not matched:
                candidate = self._match_fingerprint(
                    result, "expired_domain",
                    CLAIMABLE_FINGERPRINTS["expired_domain"]
                )
                if candidate and candidate.claimable:
                    self.candidates.append(candidate)
                    self.stats.hijackable += 1

        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.candidates.sort(key=lambda c: severity_order.get(c.severity, 4))

        return self.candidates


# ═══════════════════════════════════════════════════════════════
# SECTION 8 — REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════

class ReportGenerator:
    """Generates JSON, HTML, and terminal reports."""

    def __init__(
        self,
        target_url: str,
        stats: ScanStats,
        dead_links: list[LinkCheckResult],
        candidates: list[HijackCandidate],
        all_external: list[ExtractedLink],
        output_dir: str = "output",
        output_name: str = "",
    ):
        self.target_url = target_url
        self.stats = stats
        self.dead_links = dead_links
        self.candidates = candidates
        self.all_external = all_external
        self.ts = timestamp_str()
        self.domain = get_domain(target_url)

        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        prefix = output_name if output_name else f"blh_{self.domain}_{self.ts}"
        self.json_path = self.output_dir / f"{prefix}.json"
        self.html_path = self.output_dir / f"{prefix}.html"

    def _build_json_data(self) -> dict:
        """Build the full JSON report."""
        return {
            "tool": "Broken Link Hijacker (BLH)",
            "version": VERSION,
            "scan_date": datetime.now(timezone.utc).isoformat(),
            "target": self.target_url,
            "target_domain": self.domain,
            "statistics": {
                "pages_crawled": self.stats.pages_crawled,
                "internal_links_found": self.stats.internal_links,
                "external_links_found": self.stats.unique_external,
                "dead_links": self.stats.dead_links,
                "hijackable_links": self.stats.hijackable,
                "scan_duration_seconds": round(self.stats.elapsed, 1),
                "errors": self.stats.errors,
            },
            "hijackable_links": [
                {
                    "url": c.url,
                    "service": c.service,
                    "type": c.service_type,
                    "severity": c.severity,
                    "claimable": c.claimable,
                    "claim_target": c.claim_target,
                    "evidence": c.evidence,
                    "status_code": c.status_code,
                    "dns_resolved": c.dns_resolved,
                    "cname_record": c.cname_record,
                    "found_on_pages": c.source_pages[:10],
                    "html_tags": c.tags_found_in,
                }
                for c in self.candidates
            ],
            "dead_links": [
                {
                    "url": r.url,
                    "status_code": r.status_code,
                    "error": r.error,
                    "response_time_ms": r.response_time_ms,
                    "found_on_pages": r.source_pages[:5],
                }
                for r in self.dead_links
            ],
            "report_hash": "",  # filled below
        }

    def generate_json(self) -> str:
        """Generate JSON report and return path."""
        data = self._build_json_data()
        content = json.dumps(data, indent=2, default=str)
        data["report_hash"] = sha256_hash(content)
        content = json.dumps(data, indent=2, default=str)

        self.json_path.write_text(content)
        return str(self.json_path)

    def generate_html(self) -> str:
        """Generate professional HTML report."""
        severity_counts = defaultdict(int)
        for c in self.candidates:
            severity_counts[c.severity] += 1

        rows_hijack = ""
        for i, c in enumerate(self.candidates, 1):
            sev_cls = c.severity.lower()
            pages = "<br>".join(f"<a href='{p}' target='_blank'>{p[:80]}...</a>" for p in c.source_pages[:3])
            rows_hijack += f"""
            <tr class="{sev_cls}">
                <td>{i}</td>
                <td class="sev-{sev_cls}">{severity_emoji(c.severity)} {c.severity}</td>
                <td><a href="{c.url}" target="_blank">{c.url[:90]}</a></td>
                <td>{c.service_type}</td>
                <td><code>{c.claim_target}</code></td>
                <td>{c.status_code}</td>
                <td>{c.evidence[:120]}</td>
                <td class="small">{pages}</td>
            </tr>"""

        rows_dead = ""
        for i, d in enumerate(self.dead_links[:100], 1):
            pages = "<br>".join(p[:80] for p in d.source_pages[:2])
            rows_dead += f"""
            <tr>
                <td>{i}</td>
                <td><a href="{d.url}" target="_blank">{d.url[:90]}</a></td>
                <td>{d.status_code}</td>
                <td>{d.error[:80] if d.error else '-'}</td>
                <td>{d.response_time_ms}ms</td>
                <td class="small">{pages}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BLH Report — {self.domain}</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ font-family:'Segoe UI',system-ui,-apple-system,sans-serif; background:#0a0a0f; color:#e0e0e0; line-height:1.6; }}
        .container {{ max-width:1400px; margin:0 auto; padding:20px; }}
        .header {{ background:linear-gradient(135deg,#1a1a2e 0%,#16213e 50%,#0f3460 100%); padding:40px; border-radius:16px; margin-bottom:30px; text-align:center; border:1px solid #1e3a5f; }}
        .header h1 {{ font-size:2.2em; color:#00d4ff; margin-bottom:8px; }}
        .header .subtitle {{ color:#7f8c9b; font-size:1.1em; }}
        .header .target {{ color:#ffd700; font-size:1.3em; margin-top:12px; font-family:monospace; }}

        .stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:15px; margin-bottom:30px; }}
        .stat-card {{ background:#12121a; border:1px solid #2a2a3a; border-radius:12px; padding:20px; text-align:center; }}
        .stat-card .number {{ font-size:2.5em; font-weight:700; }}
        .stat-card .label {{ color:#7f8c9b; font-size:0.9em; margin-top:4px; }}
        .stat-card.critical .number {{ color:#ff4444; }}
        .stat-card.high .number {{ color:#ff8c00; }}
        .stat-card.medium .number {{ color:#ffd700; }}
        .stat-card.crawled .number {{ color:#00d4ff; }}
        .stat-card.dead .number {{ color:#ff6b6b; }}
        .stat-card.hijack .number {{ color:#ff1744; text-shadow:0 0 20px rgba(255,23,68,0.5); }}

        .section {{ background:#12121a; border:1px solid #2a2a3a; border-radius:12px; padding:25px; margin-bottom:25px; }}
        .section h2 {{ color:#00d4ff; font-size:1.5em; margin-bottom:15px; padding-bottom:10px; border-bottom:1px solid #2a2a3a; }}

        table {{ width:100%; border-collapse:collapse; font-size:0.85em; }}
        th {{ background:#1a1a2e; color:#00d4ff; padding:12px 8px; text-align:left; position:sticky; top:0; }}
        td {{ padding:10px 8px; border-bottom:1px solid #1a1a2a; vertical-align:top; }}
        tr:hover {{ background:#1a1a25; }}
        a {{ color:#4dabf7; text-decoration:none; }}
        a:hover {{ text-decoration:underline; }}
        code {{ background:#1a1a2e; padding:2px 6px; border-radius:4px; color:#ffd700; font-size:0.9em; }}
        .small {{ font-size:0.8em; color:#6b7b8d; }}

        .sev-critical {{ color:#ff4444; font-weight:700; }}
        .sev-high {{ color:#ff8c00; font-weight:700; }}
        .sev-medium {{ color:#ffd700; font-weight:600; }}
        .sev-low {{ color:#aaa; }}

        tr.critical {{ border-left:3px solid #ff4444; }}
        tr.high {{ border-left:3px solid #ff8c00; }}
        tr.medium {{ border-left:3px solid #ffd700; }}
        tr.low {{ border-left:3px solid #666; }}

        .footer {{ text-align:center; color:#4a5568; margin-top:30px; padding:20px; font-size:0.85em; }}
        .no-results {{ text-align:center; padding:40px; color:#4a5568; font-size:1.1em; }}

        @media(max-width:768px) {{
            .stats {{ grid-template-columns:repeat(2,1fr); }}
            table {{ font-size:0.75em; }}
        }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🔗 Broken Link Hijacker — Report</h1>
        <div class="subtitle">Automated Broken Link Takeover Scanner v{VERSION}</div>
        <div class="target">{self.target_url}</div>
        <div class="subtitle" style="margin-top:8px;">{datetime.now().strftime('%d %B %Y, %H:%M:%S')}</div>
    </div>

    <div class="stats">
        <div class="stat-card crawled"><div class="number">{self.stats.pages_crawled}</div><div class="label">Pages Crawled</div></div>
        <div class="stat-card"><div class="number" style="color:#4dabf7">{self.stats.unique_external}</div><div class="label">External Links</div></div>
        <div class="stat-card dead"><div class="number">{self.stats.dead_links}</div><div class="label">Dead Links</div></div>
        <div class="stat-card hijack"><div class="number">{self.stats.hijackable}</div><div class="label">Hijackable</div></div>
        <div class="stat-card critical"><div class="number">{severity_counts.get('CRITICAL',0)}</div><div class="label">Critical</div></div>
        <div class="stat-card high"><div class="number">{severity_counts.get('HIGH',0)}</div><div class="label">High</div></div>
        <div class="stat-card medium"><div class="number">{severity_counts.get('MEDIUM',0)}</div><div class="label">Medium</div></div>
        <div class="stat-card"><div class="number" style="color:#aaa">{severity_counts.get('LOW',0)}</div><div class="label">Low</div></div>
    </div>

    <div class="section">
        <h2>🎯 Hijackable Links ({len(self.candidates)})</h2>
        {"<table><thead><tr><th>#</th><th>Severity</th><th>Dead URL</th><th>Type</th><th>Claim Target</th><th>Status</th><th>Evidence</th><th>Found On</th></tr></thead><tbody>" + rows_hijack + "</tbody></table>" if self.candidates else '<div class="no-results">✅ No hijackable links found — target appears secure.</div>'}
    </div>

    <div class="section">
        <h2>💀 All Dead Links ({len(self.dead_links)})</h2>
        {"<table><thead><tr><th>#</th><th>URL</th><th>Status</th><th>Error</th><th>Response Time</th><th>Found On</th></tr></thead><tbody>" + rows_dead + "</tbody></table>" if self.dead_links else '<div class="no-results">✅ No dead links found.</div>'}
        {"<p class='small' style='margin-top:10px;'>Showing first 100 of " + str(len(self.dead_links)) + " dead links.</p>" if len(self.dead_links) > 100 else ""}
    </div>

    <div class="footer">
        Broken Link Hijacker v{VERSION} — by {AUTHOR} (@Vishal-HaCkEr1910)<br>
        For authorized security testing only. Report hash: <code>{sha256_hash(json.dumps(self._build_json_data(), default=str))[:16]}...</code>
    </div>
</div>
</body>
</html>"""

        self.html_path.write_text(html)
        return str(self.html_path)

    def print_terminal_summary(self):
        """Print rich summary to terminal."""
        console.print()

        # Stats panel
        stats_table = Table(show_header=False, box=None, padding=(0, 2))
        stats_table.add_column(style="bold cyan")
        stats_table.add_column(style="bold white")
        stats_table.add_row("Pages Crawled", str(self.stats.pages_crawled))
        stats_table.add_row("External Links Found", str(self.stats.unique_external))
        stats_table.add_row("Dead Links", f"[bold red]{self.stats.dead_links}[/]")
        stats_table.add_row("Hijackable Links", f"[bold {'red' if self.stats.hijackable else 'green'}]{self.stats.hijackable}[/]")
        stats_table.add_row("Scan Duration", f"{self.stats.elapsed:.1f}s")
        stats_table.add_row("Errors", str(self.stats.errors))

        console.print(Panel(
            stats_table,
            title=f"[bold cyan]Scan Results — {self.domain}[/]",
            border_style="cyan",
        ))

        # Hijackable links table
        if self.candidates:
            console.print()
            table = Table(
                title=f"🎯 Hijackable Links ({len(self.candidates)})",
                border_style="red",
                show_lines=True,
            )
            table.add_column("#", style="dim", width=4)
            table.add_column("Severity", width=10)
            table.add_column("URL", max_width=55)
            table.add_column("Type", max_width=30)
            table.add_column("Claim Target", max_width=25, style="yellow")
            table.add_column("Status", width=7)
            table.add_column("Found On", max_width=40, style="dim")

            for i, c in enumerate(self.candidates, 1):
                sev_style = severity_color(c.severity)
                page_preview = c.source_pages[0][:40] + "..." if c.source_pages else "-"
                table.add_row(
                    str(i),
                    f"[{sev_style}]{severity_emoji(c.severity)} {c.severity}[/]",
                    c.url[:55],
                    c.service_type,
                    c.claim_target,
                    str(c.status_code) if c.status_code else "DNS",
                    page_preview,
                )

            console.print(table)
        else:
            console.print(
                Panel(
                    "[bold green]✅ No hijackable links found — target appears secure.[/]",
                    border_style="green",
                )
            )

        # Dead links summary
        if self.dead_links:
            console.print()
            dead_table = Table(
                title=f"💀 Dead Links ({len(self.dead_links)})",
                border_style="yellow",
                show_lines=True,
            )
            dead_table.add_column("#", style="dim", width=4)
            dead_table.add_column("Dead URL", max_width=60)
            dead_table.add_column("Status", width=7)
            dead_table.add_column("Error", max_width=25, style="dim")
            dead_table.add_column("Found On (Source Page)", max_width=50, style="cyan")

            for i, d in enumerate(self.dead_links[:40], 1):
                # Show source pages where this dead link was found
                sources = ""
                if d.source_pages:
                    for sp in d.source_pages[:3]:
                        # Show path part for readability
                        parsed = urlparse(sp)
                        path = parsed.path if parsed.path and parsed.path != "/" else parsed.netloc
                        sources += f"{path[:48]}\n"
                    if len(d.source_pages) > 3:
                        sources += f"(+{len(d.source_pages) - 3} more)"
                    sources = sources.strip()
                else:
                    sources = "-"

                dead_table.add_row(
                    str(i),
                    d.url[:60],
                    str(d.status_code) if d.status_code else "-",
                    d.error[:25] if d.error else "-",
                    sources,
                )

            console.print(dead_table)
            if len(self.dead_links) > 40:
                console.print(f"  [dim]... and {len(self.dead_links) - 40} more (see full report)[/dim]")


# ═══════════════════════════════════════════════════════════════
# SECTION 9 — LIVE DASHBOARD
# ═══════════════════════════════════════════════════════════════

def build_dashboard(stats: ScanStats) -> Table:
    """Build a Rich table showing live scan progress."""
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column(style="bold cyan", width=22)
    table.add_column(style="bold white", width=15)
    table.add_column(style="bold cyan", width=22)
    table.add_column(style="bold white", width=15)

    table.add_row(
        "Phase:", f"[yellow]{stats.phase}[/]",
        "Elapsed:", f"{stats.elapsed:.0f}s",
    )
    table.add_row(
        "Pages Crawled:", str(stats.pages_crawled),
        "Queue:", str(stats.pages_queued),
    )
    table.add_row(
        "External Links:", str(stats.unique_external),
        "Links Checked:", f"{stats.links_checked}/{stats.unique_external}",
    )
    table.add_row(
        "Dead Links:", f"[red]{stats.dead_links}[/]",
        "Hijackable:", f"[bold red]{stats.hijackable}[/]" if stats.hijackable else "0",
    )
    table.add_row(
        "Rate:", f"{stats.rate:.0f}/s",
        "Errors:", str(stats.errors),
    )

    return Panel(
        table,
        title="[bold cyan]🔗 Broken Link Hijacker — Live[/]",
        border_style="cyan",
    )


# ═══════════════════════════════════════════════════════════════
# SECTION 10 — MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════

async def run_scan(args: argparse.Namespace):
    """Main scan orchestrator."""
    target_url = args.url.rstrip("/")
    if not target_url.startswith(("http://", "https://")):
        # Try HTTPS first, fall back to HTTP
        target_url = f"https://{target_url}"
        try:
            async with aiohttp.ClientSession() as _s:
                async with _s.get(target_url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as _r:
                    pass  # HTTPS works
        except Exception:
            target_url = target_url.replace("https://", "http://", 1)

    stats = ScanStats(start_time=time.time())

    console.print(BANNER)
    console.print(f"[bold cyan]Target:[/] [bold white]{target_url}[/]")
    console.print(f"[bold cyan]Depth:[/]  {args.depth}  [bold cyan]Threads:[/] {args.threads}  [bold cyan]Timeout:[/] {args.timeout}s")
    console.print(f"[bold cyan]Max Pages:[/] {args.max_pages}")
    console.print()

    # ── Phase 1: Crawl ──
    crawler = Crawler(
        target_url=target_url,
        max_depth=args.depth,
        max_pages=args.max_pages,
        concurrency=args.threads,
        timeout=args.timeout,
        stats=stats,
        respect_robots=not args.ignore_robots,
    )

    with Live(build_dashboard(stats), console=console, refresh_per_second=4) as live:

        async def update_dashboard():
            while True:
                live.update(build_dashboard(stats))
                await asyncio.sleep(0.25)

        dashboard_task = asyncio.create_task(update_dashboard())

        try:
            # Phase 1: Crawl
            external_links = await crawler.crawl()
            console.print(f"\n[green]✓[/] Crawling complete — [bold]{stats.pages_crawled}[/] pages, [bold]{stats.unique_external}[/] external links")

            if not external_links:
                console.print("[yellow]⚠ No external links found. Try increasing --depth.[/]")
                dashboard_task.cancel()
                return

            # Phase 2: Check links
            checker = LinkChecker(
                concurrency=min(args.threads * 2, 100),
                timeout=args.timeout,
                stats=stats,
                retries=2,
            )

            all_results = await checker.check_all(
                external_links,
                source_map=crawler._source_map,
                tag_map=crawler._tag_map,
            )
            dead_links = [r for r in all_results if r.is_dead]
            console.print(f"[green]✓[/] Link checking complete — [bold red]{len(dead_links)}[/] dead links found")

            # Phase 3: Analyze hijack potential
            analyzer = HijackAnalyzer(stats=stats)
            candidates = analyzer.analyze(dead_links)
            console.print(f"[green]✓[/] Analysis complete — [bold red]{len(candidates)}[/] hijackable links")

        finally:
            dashboard_task.cancel()
            try:
                await dashboard_task
            except asyncio.CancelledError:
                pass

    # Phase 4: Generate reports
    stats.phase = "Generating Reports"
    output_name = args.output if args.output else ""
    report = ReportGenerator(
        target_url=target_url,
        stats=stats,
        dead_links=dead_links,
        candidates=candidates,
        all_external=external_links,
        output_dir=args.output_dir,
        output_name=output_name,
    )

    json_path = report.generate_json()
    html_path = report.generate_html()
    report.print_terminal_summary()

    console.print()
    console.print(Panel(
        f"[bold green]JSON:[/] {json_path}\n[bold green]HTML:[/] {html_path}",
        title="[bold green]📄 Reports Saved[/]",
        border_style="green",
    ))


# ═══════════════════════════════════════════════════════════════
# SECTION 11 — CLI ARGUMENT PARSER
# ═══════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blh",
        description=(
            "🔗 Broken Link Hijacker (BLH) — "
            "Automated Broken Link Takeover Scanner"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python blh.py -u https://example.com
  python blh.py -u https://flipkart.com --depth 3 --threads 50
  python blh.py -u https://meta.com --depth 2 --output meta_report
  python blh.py -u example.com --max-pages 10000 --timeout 20

Detects hijackable resources:
  • Expired/parked domains        • Unclaimed GitHub Pages/repos
  • AWS S3 / Azure / GCP buckets  • Dead CDN resources (jsDelivr, unpkg)
  • Heroku / Netlify / Vercel      • Dead social profiles
  • Unclaimed NPM/PyPI packages   • Dangling CNAME records
        """,
    )

    parser.add_argument(
        "-u", "--url", required=True,
        help="Target URL to scan (e.g., https://example.com)"
    )
    parser.add_argument(
        "-d", "--depth", type=int, default=DEFAULT_CRAWL_DEPTH,
        help=f"Crawl depth (default: {DEFAULT_CRAWL_DEPTH})"
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=DEFAULT_CRAWL_CONCURRENCY,
        help=f"Concurrency level (default: {DEFAULT_CRAWL_CONCURRENCY})"
    )
    parser.add_argument(
        "--timeout", type=int, default=DEFAULT_TIMEOUT,
        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})"
    )
    parser.add_argument(
        "--max-pages", type=int, default=MAX_PAGES_DEFAULT,
        help=f"Max pages to crawl (default: {MAX_PAGES_DEFAULT})"
    )
    parser.add_argument(
        "-o", "--output", default="",
        help="Output filename prefix (without extension)"
    )
    parser.add_argument(
        "--output-dir", default="output",
        help="Output directory (default: output/)"
    )
    parser.add_argument(
        "--ignore-robots", action="store_true",
        help="Ignore robots.txt restrictions"
    )
    parser.add_argument(
        "-v", "--version", action="version",
        version=f"Broken Link Hijacker (BLH) v{VERSION}"
    )

    return parser


# ═══════════════════════════════════════════════════════════════
# SECTION 12 — ENTRY POINT
# ═══════════════════════════════════════════════════════════════

def main():
    parser = build_parser()
    args = parser.parse_args()

    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        console.print("\n[yellow]⚠ Scan interrupted by user. Exiting...[/]")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    try:
        asyncio.run(run_scan(args))
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Scan interrupted.[/]")
        sys.exit(0)


if __name__ == "__main__":
    main()
