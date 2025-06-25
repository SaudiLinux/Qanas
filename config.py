#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Qanas Configuration File
Developed by Saudi Linux (SaudiLinux1@gmail.com)

This file contains configuration settings for the Qanas tool.
"""

import os
import sys
import platform

# Tool Information
VERSION = "1.0.0"
AUTHOR = "Saudi Linux"
EMAIL = "SaudiLinux1@gmail.com"
TOOL_NAME = "Qanas"
DESCRIPTION = "Advanced Penetration Testing and Attack Surface Management Tool"

# Determine the base directory
if getattr(sys, 'frozen', False):
    # Running as compiled executable
    BASE_DIR = os.path.dirname(sys.executable)
else:
    # Running as script
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Directory Paths
MODULES_DIR = os.path.join(BASE_DIR, "modules")
LOOT_DIR = os.path.join(BASE_DIR, "loot")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
PLUGINS_DIR = os.path.join(BASE_DIR, "plugins")
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
WORDLISTS_DIR = os.path.join(BASE_DIR, "wordlists")

# Create directories if they don't exist
for directory in [MODULES_DIR, LOOT_DIR, TEMPLATES_DIR, PLUGINS_DIR, ASSETS_DIR, WORDLISTS_DIR]:
    if not os.path.exists(directory):
        os.makedirs(directory)

# Default wordlists
DEFAULT_WORDLIST = os.path.join(WORDLISTS_DIR, "default.txt")
SUBDOMAIN_WORDLIST = os.path.join(WORDLISTS_DIR, "subdomains.txt")
DIRBUSTER_WORDLIST = os.path.join(WORDLISTS_DIR, "dirbuster.txt")

# API Keys (replace with your own keys)
SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"
CENSYS_API_ID = "YOUR_CENSYS_API_ID"
CENSYS_API_SECRET = "YOUR_CENSYS_API_SECRET"
WPSCAN_API_TOKEN = "YOUR_WPSCAN_API_TOKEN"

# Scan Modes
SCAN_MODES = {
    "normal": {
        "description": "Standard scan with basic enumeration",
        "intensity": "low",
        "stealth": "medium"
    },
    "airstrike": {
        "description": "More aggressive scan with additional enumeration",
        "intensity": "medium",
        "stealth": "low"
    },
    "nuke": {
        "description": "Full scan with all available tools and techniques",
        "intensity": "high",
        "stealth": "very low"
    }
}

# Default scan options
DEFAULT_SCAN_OPTIONS = {
    # Port scanning options
    "port_scan": True,
    "quick_scan": True,
    "full_scan": False,
    "udp_scan": False,
    "port_timeout": 2,
    
    # Web scanning options
    "web_scan": True,
    "web_screenshots": True,
    "web_crawl": True,
    "web_fuzz": False,
    
    # DNS options
    "dns_enum": True,
    "zone_transfer": True,
    "subdomain_enum": True,
    "subdomain_takeover": False,
    
    # Vulnerability scanning options
    "vuln_scan": True,
    "nmap_vuln": True,
    "web_vuln": True,
    "ssl_scan": True,
    "nuclei": True,
    "wpscan": True,
    "sqlmap": False,
    "xss": False,
    
    # Reconnaissance options
    "whois": True,
    "shodan": False,
    "censys": False,
    "harvester": True,
    "google_dorks": True,
    "github_dorks": True,
    "waybackurls": True,
    "pastebin": True,
    "social_media": True,
    "ssl_info": True,
    
    # Reporting options
    "report_format": "html",  # html, json, txt
    "save_evidence": True,
    "screenshots": True
}

# Mode-specific scan options
MODE_SCAN_OPTIONS = {
    "normal": DEFAULT_SCAN_OPTIONS,
    
    "airstrike": {
        **DEFAULT_SCAN_OPTIONS,
        "full_scan": True,
        "udp_scan": True,
        "web_fuzz": True,
        "subdomain_takeover": True,
        "sqlmap": True,
        "shodan": True,
        "censys": True
    },
    
    "nuke": {
        **DEFAULT_SCAN_OPTIONS,
        "full_scan": True,
        "udp_scan": True,
        "web_fuzz": True,
        "subdomain_takeover": True,
        "sqlmap": True,
        "xss": True,
        "shodan": True,
        "censys": True
    }
}

# User-Agent strings
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59"
]

# Default User-Agent
DEFAULT_USER_AGENT = USER_AGENTS[0]

# HTTP request timeout (in seconds)
HTTP_TIMEOUT = 10

# Maximum number of threads for parallel operations
MAX_THREADS = 10

# Default output format
DEFAULT_OUTPUT_FORMAT = "html"

# Colors for terminal output
COLORS = {
    'red': '\033[91m',
    'green': '\033[92m',
    'yellow': '\033[93m',
    'blue': '\033[94m',
    'purple': '\033[95m',
    'cyan': '\033[96m',
    'white': '\033[97m',
    'end': '\033[0m'
}

# Check if running on Windows and disable colors if necessary
if platform.system() == "Windows":
    # Check if running in a terminal that supports ANSI colors
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except:
        # Disable colors if ANSI is not supported
        for key in COLORS:
            COLORS[key] = ''

# Banner text
BANNER = f"""
{COLORS['red']}  ██████╗  █████╗ ███╗   ██╗ █████╗ ███████╗{COLORS['end']}
{COLORS['red']} ██╔═══██╗██╔══██╗████╗  ██║██╔══██╗██╔════╝{COLORS['end']}
{COLORS['red']} ██║   ██║███████║██╔██╗ ██║███████║███████╗{COLORS['end']}
{COLORS['red']} ██║▄▄ ██║██╔══██║██║╚██╗██║██╔══██║╚════██║{COLORS['end']}
{COLORS['red']} ╚██████╔╝██║  ██║██║ ╚████║██║  ██║███████║{COLORS['end']}
{COLORS['red']}  ╚══▀▀═╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝{COLORS['end']}
{COLORS['cyan']}                                قناص{COLORS['end']}
{COLORS['yellow']}       Advanced Penetration Testing Tool{COLORS['end']}
{COLORS['blue']}             Version: {VERSION}{COLORS['end']}
{COLORS['green']}       Developed by: {AUTHOR}{COLORS['end']}
"""

# Help message
HELP_MESSAGE = f"""
{COLORS['cyan']}Usage:{COLORS['end']} python qanas.py [options] <target>

{COLORS['cyan']}Options:{COLORS['end']}
  -h, --help              Show this help message and exit
  -v, --version           Show version information and exit
  -m, --mode MODE         Scan mode: normal, airstrike, nuke (default: normal)
  -o, --output DIR        Output directory for scan results
  -p, --ports PORTS       Ports to scan (e.g., 80,443,8080 or 1-1000)
  -t, --threads NUM       Number of threads (default: 10)
  -f, --file FILE         Scan multiple targets from a file
  -l, --loot              Display all previous scan results
  --no-web                Skip web scanning
  --no-dns                Skip DNS enumeration
  --no-vuln               Skip vulnerability scanning
  --no-recon              Skip reconnaissance
  --update                Update the tool to the latest version

{COLORS['cyan']}Examples:{COLORS['end']}
  python qanas.py example.com
  python qanas.py -m airstrike example.com
  python qanas.py -p 80,443,8080 example.com
  python qanas.py -f targets.txt
  python qanas.py -l
"""

# Version message
VERSION_MESSAGE = f"""
{COLORS['cyan']}{TOOL_NAME} v{VERSION}{COLORS['end']}
{COLORS['green']}Developed by: {AUTHOR} ({EMAIL}){COLORS['end']}
{COLORS['yellow']}{DESCRIPTION}{COLORS['end']}
"""