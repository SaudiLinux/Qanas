#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Qanas - أداة اختبار اختراق متقدمة
Developed by Saudi Linux (SaudiLinux1@gmail.com)

Qanas is an advanced penetration testing tool and attack surface management platform
designed to automate information gathering and vulnerability discovery.
"""

import os
import sys
import argparse
import subprocess
import socket
import datetime
import json
import re
import time
import random
import threading
import ipaddress
from urllib.parse import urlparse

# Define colors for terminal output
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

# Version information
VERSION = "1.0.0"
AUTHOR = "Saudi Linux"
EMAIL = "SaudiLinux1@gmail.com"

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODULES_DIR = os.path.join(BASE_DIR, "modules")
LOOT_DIR = os.path.join(BASE_DIR, "loot")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
PLUGINS_DIR = os.path.join(BASE_DIR, "plugins")

# Create directories if they don't exist
for directory in [MODULES_DIR, LOOT_DIR, TEMPLATES_DIR, PLUGINS_DIR]:
    if not os.path.exists(directory):
        os.makedirs(directory)

# Banner function
def display_banner():
    """
    Display the Qanas banner
    """
    banner = f"""
{COLORS['red']}
  ██████╗  █████╗ ███╗   ██╗ █████╗ ███████╗
 ██╔═══██╗██╔══██╗████╗  ██║██╔══██╗██╔════╝
 ██║   ██║███████║██╔██╗ ██║███████║███████╗
 ██║▄▄ ██║██╔══██║██║╚██╗██║██╔══██║╚════██║
 ╚██████╔╝██║  ██║██║ ╚████║██║  ██║███████║
  ╚══▀▀═╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝
{COLORS['yellow']}                                قناص{COLORS['end']}

{COLORS['blue']}       Developed by {AUTHOR}{COLORS['end']}
{COLORS['blue']}       Email: {EMAIL}{COLORS['end']}
{COLORS['purple']}       Version: {VERSION}{COLORS['end']}

{COLORS['cyan']}[*] Advanced Penetration Testing Tool & Attack Surface Management Platform{COLORS['end']}
"""
    print(banner)

# Helper functions
def print_status(message):
    """
    Print status message
    """
    print(f"{COLORS['blue']}[*] {message}{COLORS['end']}")

def print_success(message):
    """
    Print success message
    """
    print(f"{COLORS['green']}[+] {message}{COLORS['end']}")

def print_error(message):
    """
    Print error message
    """
    print(f"{COLORS['red']}[-] {message}{COLORS['end']}")

def print_warning(message):
    """
    Print warning message
    """
    print(f"{COLORS['yellow']}[!] {message}{COLORS['end']}")

def print_info(message):
    """
    Print info message
    """
    print(f"{COLORS['cyan']}[i] {message}{COLORS['end']}")

def is_valid_ip(ip):
    """
    Check if the given string is a valid IP address
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_domain(domain):
    """
    Check if the given string is a valid domain name
    """
    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
        r'[a-zA-Z]{2,}$'
    )
    return bool(domain_regex.match(domain))

def is_valid_url(url):
    """
    Check if the given string is a valid URL
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def validate_target(target):
    """
    Validate the target (IP, domain, or URL)
    """
    if is_valid_ip(target):
        return {'type': 'ip', 'value': target}
    elif is_valid_domain(target):
        return {'type': 'domain', 'value': target}
    elif is_valid_url(target):
        return {'type': 'url', 'value': target}
    else:
        return None

def check_command_exists(command):
    """
    Check if a command exists in the system
    """
    if sys.platform == 'win32':
        # On Windows, use where command
        try:
            subprocess.run(['where', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            return True
        except subprocess.CalledProcessError:
            return False
    else:
        # On Unix-like systems, use which command
        try:
            subprocess.run(['which', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            return True
        except subprocess.CalledProcessError:
            return False

def run_command(command, shell=False):
    """
    Run a shell command and return the output
    """
    try:
        # Check if the command exists
        if not shell and isinstance(command, list) and not check_command_exists(command[0]):
            return {
                'returncode': 1,
                'stdout': '',
                'stderr': f"Command not found: {command[0]}"
            }
            
        if shell:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        stdout, stderr = process.communicate()
        return {
            'returncode': process.returncode,
            'stdout': stdout.decode('utf-8', errors='ignore'),
            'stderr': stderr.decode('utf-8', errors='ignore')
        }
    except Exception as e:
        return {
            'returncode': 1,
            'stdout': '',
            'stderr': str(e)
        }

def create_report_directory(target):
    """
    Create a directory for the target's scan results
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    target_dir = os.path.join(LOOT_DIR, f"{target}_{timestamp}")
    
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
    
    return target_dir

# Scan functions
def perform_nmap_scan(target, output_dir, quick=False):
    """
    Perform an Nmap scan on the target
    """
    print_status(f"Starting Nmap scan on {target}")
    
    # Check if nmap is installed
    if not check_command_exists("nmap"):
        print_error("Nmap is not installed or not in PATH. Please install Nmap to use this feature.")
        with open(os.path.join(output_dir, "nmap_scan_error.txt"), 'w') as f:
            f.write("Nmap is not installed or not in PATH. Please install Nmap to use this feature.")
        return False
    
    output_file = os.path.join(output_dir, "nmap_scan.xml")
    
    if quick:
        # Quick scan - top ports only
        command = ["nmap", "-sV", "-sC", "--top-ports", "100", "-oX", output_file, target]
    else:
        # Full scan
        command = ["nmap", "-sV", "-sC", "-p-", "-oX", output_file, target]
    
    result = run_command(command)
    
    if result['returncode'] == 0:
        print_success(f"Nmap scan completed. Results saved to {output_file}")
        return True
    else:
        print_error(f"Nmap scan failed: {result['stderr']}")
        with open(os.path.join(output_dir, "nmap_scan_error.txt"), 'w') as f:
            f.write(f"Nmap scan failed: {result['stderr']}")
        return False

def perform_whois_lookup(target, output_dir):
    """
    Perform a WHOIS lookup on the target
    """
    print_status(f"Performing WHOIS lookup on {target}")
    
    # Check if whois is installed
    if not check_command_exists("whois"):
        print_error("WHOIS is not installed or not in PATH. Please install WHOIS to use this feature.")
        with open(os.path.join(output_dir, "whois_error.txt"), 'w') as f:
            f.write("WHOIS is not installed or not in PATH. Please install WHOIS to use this feature.")
        return False
    
    output_file = os.path.join(output_dir, "whois.txt")
    command = ["whois", target]
    
    result = run_command(command)
    
    if result['returncode'] == 0:
        with open(output_file, 'w') as f:
            f.write(result['stdout'])
        print_success(f"WHOIS lookup completed. Results saved to {output_file}")
        return True
    else:
        print_error(f"WHOIS lookup failed: {result['stderr']}")
        with open(os.path.join(output_dir, "whois_error.txt"), 'w') as f:
            f.write(f"WHOIS lookup failed: {result['stderr']}")
        return False

def perform_dns_enumeration(target, output_dir):
    """
    Perform DNS enumeration on the target
    """
    print_status(f"Performing DNS enumeration on {target}")
    
    # Check if host command is installed
    if not check_command_exists("host"):
        print_error("Host command is not installed or not in PATH. Please install host to use this feature.")
        with open(os.path.join(output_dir, "dns_enum_error.txt"), 'w') as f:
            f.write("Host command is not installed or not in PATH. Please install host to use this feature.")
        return False
    
    output_file = os.path.join(output_dir, "dns_enum.txt")
    command = ["host", "-a", target]
    
    result = run_command(command)
    
    if result['returncode'] == 0:
        with open(output_file, 'w') as f:
            f.write(result['stdout'])
        print_success(f"DNS enumeration completed. Results saved to {output_file}")
        return True
    else:
        print_error(f"DNS enumeration failed: {result['stderr']}")
        with open(os.path.join(output_dir, "dns_enum_error.txt"), 'w') as f:
            f.write(f"DNS enumeration failed: {result['stderr']}")
        return False

def perform_web_scan(target, output_dir):
    """
    Perform web scanning on the target
    """
    print_status(f"Performing web scan on {target}")
    
    # Ensure target has http:// or https:// prefix
    if not target.startswith('http'):
        target = f"http://{target}"
    
    # Nikto scan
    print_status("Running Nikto scan...")
    nikto_output = os.path.join(output_dir, "nikto.txt")
    nikto_command = ["nikto", "-h", target, "-o", nikto_output]
    run_command(nikto_command)
    
    # Whatweb scan
    print_status("Running WhatWeb scan...")
    whatweb_output = os.path.join(output_dir, "whatweb.txt")
    whatweb_command = ["whatweb", "-v", target, "--log-file", whatweb_output]
    run_command(whatweb_command)
    
    # Check for WordPress
    if check_wordpress(target):
        print_status("WordPress detected, running WPScan...")
        wpscan_output = os.path.join(output_dir, "wpscan.txt")
        wpscan_command = ["wpscan", "--url", target, "--output", wpscan_output, "--format", "cli"]
        run_command(wpscan_command)
    
    print_success(f"Web scanning completed. Results saved to {output_dir}")
    return True

def check_wordpress(url):
    """
    Check if the target is running WordPress
    """
    wp_login = f"{url}/wp-login.php"
    wp_admin = f"{url}/wp-admin"
    
    try:
        import requests
        response1 = requests.get(wp_login, timeout=5)
        response2 = requests.get(wp_admin, timeout=5)
        
        return (response1.status_code == 200 and "WordPress" in response1.text) or \
               (response2.status_code == 200 or response2.status_code == 302)
    except:
        return False

def perform_vulnerability_scan(target, output_dir):
    """
    Perform vulnerability scanning on the target
    """
    print_status(f"Performing vulnerability scan on {target}")
    
    # Run SQLMap if target is a URL
    if target.startswith('http'):
        print_status("Running SQLMap scan...")
        sqlmap_output = os.path.join(output_dir, "sqlmap.txt")
        sqlmap_command = ["sqlmap", "-u", target, "--batch", "--level", "1", "--risk", "1", "-o", "--output-dir", output_dir]
        run_command(sqlmap_command)
    
    print_success(f"Vulnerability scanning completed. Results saved to {output_dir}")
    return True

# Main scan function
def scan_target(target, mode="normal"):
    """
    Perform a comprehensive scan on the target
    """
    target_info = validate_target(target)
    
    if not target_info:
        print_error(f"Invalid target: {target}")
        return False
    
    print_status(f"Starting {mode} scan on {target}")
    output_dir = create_report_directory(target)
    
    # Save target information
    with open(os.path.join(output_dir, "target_info.json"), 'w') as f:
        json.dump({
            'target': target,
            'type': target_info['type'],
            'scan_mode': mode,
            'timestamp': datetime.datetime.now().isoformat()
        }, f, indent=4)
    
    # Perform scans based on mode
    if mode == "normal" or mode == "nuke":
        perform_nmap_scan(target, output_dir, quick=(mode=="normal"))
        
        if target_info['type'] in ['domain', 'url']:
            perform_whois_lookup(target, output_dir)
            perform_dns_enumeration(target, output_dir)
        
        if target_info['type'] == 'url' or (target_info['type'] == 'domain' and mode == "nuke"):
            perform_web_scan(target, output_dir)
        
        if mode == "nuke":
            perform_vulnerability_scan(target, output_dir)
    
    elif mode == "airstrike":
        # Quick scan for multiple targets
        perform_nmap_scan(target, output_dir, quick=True)
    
    print_success(f"Scan completed for {target}. Results saved to {output_dir}")
    return output_dir

# Process targets from a file
def process_targets_file(file_path, mode):
    """
    Process multiple targets from a file
    """
    if not os.path.isfile(file_path):
        print_error(f"File not found: {file_path}")
        return False
    
    with open(file_path, 'r') as f:
        targets = [line.strip() for line in f if line.strip()]
    
    if not targets:
        print_error("No targets found in the file")
        return False
    
    print_status(f"Found {len(targets)} targets in {file_path}")
    
    results = []
    for target in targets:
        print_status(f"Processing target: {target}")
        result = scan_target(target, mode)
        results.append({
            'target': target,
            'result': result
        })
    
    return results

# Display loot function
def display_loot():
    """
    Display the loot directory in a browser
    """
    if not os.path.exists(LOOT_DIR):
        print_error(f"Loot directory not found: {LOOT_DIR}")
        return False
    
    # Count scan results
    scan_dirs = [d for d in os.listdir(LOOT_DIR) if os.path.isdir(os.path.join(LOOT_DIR, d))]
    
    if not scan_dirs:
        print_warning("No scan results found in the loot directory")
        return False
    
    print_success(f"Found {len(scan_dirs)} scan results in the loot directory")
    
    # Create an HTML index file
    index_file = os.path.join(LOOT_DIR, "index.html")
    
    with open(index_file, 'w') as f:
        f.write(f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Qanas - Scan Results</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
                h1 {{ color: #e94560; }}
                .container {{ max-width: 1200px; margin: 0 auto; }}
                .scan-list {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; }}
                .scan-card {{ background-color: white; border-radius: 8px; padding: 15px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
                .scan-card h3 {{ margin-top: 0; color: #0f3460; }}
                .scan-card p {{ margin: 5px 0; }}
                .scan-card a {{ display: inline-block; margin-top: 10px; padding: 8px 15px; background-color: #0f3460; color: white; text-decoration: none; border-radius: 4px; }}
                .scan-card a:hover {{ background-color: #e94560; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Qanas - Scan Results</h1>
                <p>Total scans: {len(scan_dirs)}</p>
                <div class="scan-list">
        """)
        
        for scan_dir in scan_dirs:
            dir_path = os.path.join(LOOT_DIR, scan_dir)
            target_info_file = os.path.join(dir_path, "target_info.json")
            
            if os.path.exists(target_info_file):
                try:
                    with open(target_info_file, 'r') as info_file:
                        info = json.load(info_file)
                    
                    target = info.get('target', 'Unknown')
                    scan_type = info.get('type', 'Unknown')
                    scan_mode = info.get('scan_mode', 'Unknown')
                    timestamp = info.get('timestamp', 'Unknown')
                    
                    # Format timestamp
                    if timestamp != 'Unknown':
                        try:
                            dt = datetime.datetime.fromisoformat(timestamp)
                            timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
                        except:
                            pass
                    
                    f.write(f"""
                    <div class="scan-card">
                        <h3>{target}</h3>
                        <p><strong>Type:</strong> {scan_type}</p>
                        <p><strong>Mode:</strong> {scan_mode}</p>
                        <p><strong>Date:</strong> {timestamp}</p>
                        <a href="file://{dir_path}">View Results</a>
                    </div>
                    """)
                except:
                    f.write(f"""
                    <div class="scan-card">
                        <h3>{scan_dir}</h3>
                        <p><strong>Info:</strong> No details available</p>
                        <a href="file://{dir_path}">View Results</a>
                    </div>
                    """)
            else:
                f.write(f"""
                <div class="scan-card">
                    <h3>{scan_dir}</h3>
                    <p><strong>Info:</strong> No details available</p>
                    <a href="file://{dir_path}">View Results</a>
                </div>
                """)
        
        f.write(f"""
                </div>
            </div>
        </body>
        </html>
        """)
    
    # Open the index file in the default browser
    try:
        import webbrowser
        webbrowser.open(f"file://{index_file}")
        print_success(f"Opened loot directory in browser: {index_file}")
        return True
    except:
        print_warning(f"Could not open browser. Loot index is at: {index_file}")
        return False

# Main function
def main():
    """
    Main function
    """
    parser = argparse.ArgumentParser(description="Qanas - Advanced Penetration Testing Tool")
    parser.add_argument("target", nargs="?", help="Target to scan (IP, domain, URL, or file path)")
    parser.add_argument("mode", nargs="?", default="normal", 
                        choices=["normal", "airstrike", "nuke", "loot"],
                        help="Scan mode: normal, airstrike, nuke, or loot")
    parser.add_argument("-v", "--version", action="store_true", help="Show version information")
    
    args = parser.parse_args()
    
    # Display banner
    display_banner()
    
    # Show version and exit
    if args.version:
        print(f"Qanas v{VERSION}")
        return 0
    
    # Display loot
    if args.mode == "loot" or (args.target and args.target.lower() == "loot"):
        display_loot()
        return 0
    
    # Check if target is provided
    if not args.target:
        parser.print_help()
        return 1
    
    # Process target
    if os.path.isfile(args.target):
        # Target is a file containing multiple targets
        process_targets_file(args.target, args.mode)
    else:
        # Single target
        scan_target(args.target, args.mode)
    
    return 0

# Entry point
if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n" + COLORS['red'] + "[!] Scan interrupted by user" + COLORS['end'])
        sys.exit(1)
    except Exception as e:
        print("\n" + COLORS['red'] + f"[!] An error occurred: {str(e)}" + COLORS['end'])
        sys.exit(1)