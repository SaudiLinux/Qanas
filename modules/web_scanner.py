#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web Scanner Module for Qanas
Developed by Saudi Linux (SaudiLinux1@gmail.com)

This module handles web scanning functionality using various tools.
"""

import os
import sys
import subprocess
import json
import re
import time
import threading
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

def run_command(command, shell=False):
    """
    Run a shell command and return the output
    """
    try:
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

# URL validation and normalization
def normalize_url(url):
    """
    Normalize URL by adding http:// if missing
    
    Args:
        url (str): URL to normalize
        
    Returns:
        str: Normalized URL
    """
    if not url.startswith('http://') and not url.startswith('https://'):
        url = f"http://{url}"
    return url

def is_valid_url(url):
    """
    Check if the given string is a valid URL
    
    Args:
        url (str): URL to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

# Web scanning functions
def whatweb_scan(url, output_dir):
    """
    Perform a WhatWeb scan on the target
    
    Args:
        url (str): The target URL
        output_dir (str): Directory to save scan results
        
    Returns:
        dict: Scan results
    """
    url = normalize_url(url)
    print_status(f"Starting WhatWeb scan on {url}")
    
    # Create output files
    json_output = os.path.join(output_dir, "whatweb.json")
    txt_output = os.path.join(output_dir, "whatweb.txt")
    
    # Build command for JSON output
    json_command = ["whatweb", "-v", url, "--log-json", json_output]
    
    # Build command for text output
    txt_command = ["whatweb", "-v", url, "--log-brief", txt_output]
    
    # Run JSON scan
    json_result = run_command(json_command)
    
    # Run text scan
    txt_result = run_command(txt_command)
    
    if json_result['returncode'] == 0 and txt_result['returncode'] == 0:
        print_success(f"WhatWeb scan completed")
        
        # Parse JSON results
        try:
            with open(json_output, 'r') as f:
                scan_results = json.load(f)
            print_success(f"Results saved to {json_output} and {txt_output}")
            return scan_results
        except Exception as e:
            print_error(f"Error parsing WhatWeb results: {str(e)}")
            return None
    else:
        print_error(f"WhatWeb scan failed: {json_result['stderr']}")
        return None

def nikto_scan(url, output_dir):
    """
    Perform a Nikto scan on the target
    
    Args:
        url (str): The target URL
        output_dir (str): Directory to save scan results
        
    Returns:
        dict: Scan results
    """
    url = normalize_url(url)
    print_status(f"Starting Nikto scan on {url}")
    
    # Create output files
    txt_output = os.path.join(output_dir, "nikto.txt")
    xml_output = os.path.join(output_dir, "nikto.xml")
    
    # Build command
    command = ["nikto", "-h", url, "-o", txt_output, "-Format", "txt", "-Output", xml_output, "-Format", "xml"]
    
    # Run scan
    start_time = time.time()
    result = run_command(command)
    end_time = time.time()
    
    scan_time = end_time - start_time
    
    if result['returncode'] == 0:
        print_success(f"Nikto scan completed in {scan_time:.2f} seconds")
        print_success(f"Results saved to {txt_output} and {xml_output}")
        
        # Parse results
        scan_results = {
            'scan_time': scan_time,
            'output_files': {
                'txt': txt_output,
                'xml': xml_output
            },
            'findings': parse_nikto_output(txt_output)
        }
        
        return scan_results
    else:
        print_error(f"Nikto scan failed: {result['stderr']}")
        return None

def parse_nikto_output(output_file):
    """
    Parse Nikto output file
    
    Args:
        output_file (str): Path to Nikto output file
        
    Returns:
        list: Parsed findings
    """
    if not os.path.exists(output_file):
        print_error(f"Output file not found: {output_file}")
        return []
    
    findings = []
    
    try:
        with open(output_file, 'r') as f:
            content = f.read()
        
        # Extract findings
        pattern = r"\+ (.+)"
        matches = re.findall(pattern, content)
        
        for match in matches:
            findings.append(match.strip())
        
        return findings
    except Exception as e:
        print_error(f"Error parsing Nikto output: {str(e)}")
        return []

def dirb_scan(url, output_dir, wordlist=None):
    """
    Perform a directory brute force scan using dirb
    
    Args:
        url (str): The target URL
        output_dir (str): Directory to save scan results
        wordlist (str): Path to wordlist file
        
    Returns:
        dict: Scan results
    """
    url = normalize_url(url)
    print_status(f"Starting dirb scan on {url}")
    
    # Default wordlist
    if wordlist is None:
        wordlist = "/usr/share/dirb/wordlists/common.txt"
    
    # Create output file
    output_file = os.path.join(output_dir, "dirb.txt")
    
    # Build command
    command = ["dirb", url, wordlist, "-o", output_file]
    
    # Run scan
    start_time = time.time()
    result = run_command(command)
    end_time = time.time()
    
    scan_time = end_time - start_time
    
    if result['returncode'] == 0:
        print_success(f"dirb scan completed in {scan_time:.2f} seconds")
        print_success(f"Results saved to {output_file}")
        
        # Parse results
        scan_results = {
            'scan_time': scan_time,
            'output_file': output_file,
            'findings': parse_dirb_output(output_file)
        }
        
        return scan_results
    else:
        print_error(f"dirb scan failed: {result['stderr']}")
        return None

def parse_dirb_output(output_file):
    """
    Parse dirb output file
    
    Args:
        output_file (str): Path to dirb output file
        
    Returns:
        list: Parsed findings
    """
    if not os.path.exists(output_file):
        print_error(f"Output file not found: {output_file}")
        return []
    
    findings = []
    
    try:
        with open(output_file, 'r') as f:
            content = f.read()
        
        # Extract findings
        pattern = r"==> DIRECTORY: (.+)"
        dir_matches = re.findall(pattern, content)
        
        pattern = r"\+ (.+) \("
        file_matches = re.findall(pattern, content)
        
        # Add directories
        for match in dir_matches:
            findings.append({
                'type': 'directory',
                'url': match.strip()
            })
        
        # Add files
        for match in file_matches:
            findings.append({
                'type': 'file',
                'url': match.strip()
            })
        
        return findings
    except Exception as e:
        print_error(f"Error parsing dirb output: {str(e)}")
        return []

def gobuster_scan(url, output_dir, wordlist=None):
    """
    Perform a directory brute force scan using gobuster
    
    Args:
        url (str): The target URL
        output_dir (str): Directory to save scan results
        wordlist (str): Path to wordlist file
        
    Returns:
        dict: Scan results
    """
    url = normalize_url(url)
    print_status(f"Starting gobuster scan on {url}")
    
    # Default wordlist
    if wordlist is None:
        wordlist = "/usr/share/wordlists/dirb/common.txt"
    
    # Create output file
    output_file = os.path.join(output_dir, "gobuster.txt")
    
    # Build command
    command = ["gobuster", "dir", "-u", url, "-w", wordlist, "-o", output_file]
    
    # Run scan
    start_time = time.time()
    result = run_command(command)
    end_time = time.time()
    
    scan_time = end_time - start_time
    
    if result['returncode'] == 0:
        print_success(f"gobuster scan completed in {scan_time:.2f} seconds")
        print_success(f"Results saved to {output_file}")
        
        # Parse results
        scan_results = {
            'scan_time': scan_time,
            'output_file': output_file,
            'findings': parse_gobuster_output(output_file)
        }
        
        return scan_results
    else:
        print_error(f"gobuster scan failed: {result['stderr']}")
        return None

def parse_gobuster_output(output_file):
    """
    Parse gobuster output file
    
    Args:
        output_file (str): Path to gobuster output file
        
    Returns:
        list: Parsed findings
    """
    if not os.path.exists(output_file):
        print_error(f"Output file not found: {output_file}")
        return []
    
    findings = []
    
    try:
        with open(output_file, 'r') as f:
            content = f.readlines()
        
        for line in content:
            if line.startswith("/"):
                parts = line.strip().split()
                if len(parts) >= 2:
                    path = parts[0]
                    status = parts[1].strip("[]")
                    
                    findings.append({
                        'path': path,
                        'status': status
                    })
        
        return findings
    except Exception as e:
        print_error(f"Error parsing gobuster output: {str(e)}")
        return []

def wpscan(url, output_dir, api_token=None):
    """
    Perform a WordPress scan using WPScan
    
    Args:
        url (str): The target URL
        output_dir (str): Directory to save scan results
        api_token (str): WPVulnDB API token
        
    Returns:
        dict: Scan results
    """
    url = normalize_url(url)
    print_status(f"Starting WPScan on {url}")
    
    # Create output files
    json_output = os.path.join(output_dir, "wpscan.json")
    txt_output = os.path.join(output_dir, "wpscan.txt")
    
    # Build command
    command = ["wpscan", "--url", url, "--format", "json", "--output", json_output]
    
    # Add API token if provided
    if api_token:
        command.extend(["--api-token", api_token])
    
    # Run scan
    start_time = time.time()
    result = run_command(command)
    end_time = time.time()
    
    scan_time = end_time - start_time
    
    if result['returncode'] == 0:
        print_success(f"WPScan completed in {scan_time:.2f} seconds")
        
        # Also save text output
        command = ["wpscan", "--url", url, "--format", "cli", "--output", txt_output]
        if api_token:
            command.extend(["--api-token", api_token])
        run_command(command)
        
        print_success(f"Results saved to {json_output} and {txt_output}")
        
        # Parse JSON results
        try:
            with open(json_output, 'r') as f:
                scan_results = json.load(f)
            return scan_results
        except Exception as e:
            print_error(f"Error parsing WPScan results: {str(e)}")
            return None
    else:
        print_error(f"WPScan failed: {result['stderr']}")
        return None

def wafw00f_scan(url, output_dir):
    """
    Detect WAF using wafw00f
    
    Args:
        url (str): The target URL
        output_dir (str): Directory to save scan results
        
    Returns:
        dict: Scan results
    """
    url = normalize_url(url)
    print_status(f"Starting WAF detection on {url}")
    
    # Create output file
    output_file = os.path.join(output_dir, "wafw00f.txt")
    
    # Build command
    command = ["wafw00f", url]
    
    # Run scan
    result = run_command(command)
    
    if result['returncode'] == 0:
        # Save output
        with open(output_file, 'w') as f:
            f.write(result['stdout'])
        
        print_success(f"WAF detection completed. Results saved to {output_file}")
        
        # Parse results
        waf_detected = "No WAF detected" not in result['stdout']
        waf_name = None
        
        if waf_detected:
            # Try to extract WAF name
            pattern = r"The site .+ is behind a (.+)"
            match = re.search(pattern, result['stdout'])
            if match:
                waf_name = match.group(1).strip()
        
        scan_results = {
            'waf_detected': waf_detected,
            'waf_name': waf_name,
            'output_file': output_file,
            'raw_output': result['stdout']
        }
        
        return scan_results
    else:
        print_error(f"WAF detection failed: {result['stderr']}")
        return None

def detect_cms(url):
    """
    Detect CMS used by the target
    
    Args:
        url (str): The target URL
        
    Returns:
        dict: Detection results
    """
    url = normalize_url(url)
    print_status(f"Detecting CMS on {url}")
    
    cms_signatures = {
        'wordpress': [
            '/wp-login.php',
            '/wp-admin/',
            '/wp-content/'
        ],
        'joomla': [
            '/administrator/',
            '/components/',
            '/templates/'
        ],
        'drupal': [
            '/sites/default/',
            '/modules/',
            '/themes/'
        ],
        'magento': [
            '/app/etc/',
            '/skin/',
            '/magento_version'
        ]
    }
    
    detected_cms = None
    confidence = 0
    
    try:
        import requests
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Check for CMS-specific paths
        for cms, paths in cms_signatures.items():
            cms_confidence = 0
            
            for path in paths:
                try:
                    response = requests.get(f"{url}{path}", headers=headers, timeout=5, verify=False)
                    if response.status_code == 200 or response.status_code == 403:
                        cms_confidence += 1
                except:
                    pass
            
            # Calculate confidence percentage
            cms_confidence_percent = (cms_confidence / len(paths)) * 100
            
            if cms_confidence_percent > confidence:
                confidence = cms_confidence_percent
                detected_cms = cms
        
        # Check HTML source for additional clues
        try:
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            html = response.text.lower()
            
            # WordPress clues
            if 'wp-content' in html or 'wordpress' in html:
                if detected_cms == 'wordpress':
                    confidence += 20
                else:
                    detected_cms = 'wordpress'
                    confidence = 60
            
            # Joomla clues
            elif 'joomla' in html:
                if detected_cms == 'joomla':
                    confidence += 20
                else:
                    detected_cms = 'joomla'
                    confidence = 60
            
            # Drupal clues
            elif 'drupal' in html:
                if detected_cms == 'drupal':
                    confidence += 20
                else:
                    detected_cms = 'drupal'
                    confidence = 60
            
            # Magento clues
            elif 'magento' in html:
                if detected_cms == 'magento':
                    confidence += 20
                else:
                    detected_cms = 'magento'
                    confidence = 60
        except:
            pass
        
        # Cap confidence at 100%
        confidence = min(confidence, 100)
        
        result = {
            'cms': detected_cms,
            'confidence': confidence
        }
        
        if detected_cms:
            print_success(f"Detected CMS: {detected_cms} (Confidence: {confidence}%)")
        else:
            print_warning("Could not detect CMS")
        
        return result
    except Exception as e:
        print_error(f"Error detecting CMS: {str(e)}")
        return {
            'cms': None,
            'confidence': 0,
            'error': str(e)
        }

# Comprehensive web scan
def comprehensive_web_scan(url, output_dir, options=None):
    """
    Perform a comprehensive web scan on the target
    
    Args:
        url (str): The target URL
        output_dir (str): Directory to save scan results
        options (dict): Scan options
        
    Returns:
        dict: Scan results
    """
    url = normalize_url(url)
    print_status(f"Starting comprehensive web scan on {url}")
    
    if options is None:
        options = {
            'whatweb': True,
            'nikto': True,
            'dirb': True,
            'waf': True,
            'cms_detect': True,
            'wpscan': False,  # Only run if WordPress is detected
            'wordlist': None  # Default wordlist
        }
    
    results = {
        'target': url,
        'scan_time': datetime.datetime.now().isoformat(),
        'scans': {}
    }
    
    # Detect WAF
    if options.get('waf', True):
        waf_results = wafw00f_scan(url, output_dir)
        results['scans']['waf'] = waf_results
    
    # Detect CMS
    if options.get('cms_detect', True):
        cms_results = detect_cms(url)
        results['scans']['cms'] = cms_results
        
        # Run WPScan if WordPress is detected
        if options.get('wpscan', False) or (cms_results.get('cms') == 'wordpress' and cms_results.get('confidence', 0) > 50):
            wpscan_results = wpscan(url, output_dir, api_token=options.get('wpscan_api_token'))
            results['scans']['wpscan'] = wpscan_results
    
    # Run WhatWeb
    if options.get('whatweb', True):
        whatweb_results = whatweb_scan(url, output_dir)
        results['scans']['whatweb'] = whatweb_results
    
    # Run Nikto
    if options.get('nikto', True):
        nikto_results = nikto_scan(url, output_dir)
        results['scans']['nikto'] = nikto_results
    
    # Run directory brute force
    if options.get('dirb', True):
        # Use gobuster if available, fall back to dirb
        try:
            gobuster_results = gobuster_scan(url, output_dir, wordlist=options.get('wordlist'))
            results['scans']['directory_scan'] = gobuster_results
        except:
            dirb_results = dirb_scan(url, output_dir, wordlist=options.get('wordlist'))
            results['scans']['directory_scan'] = dirb_results
    
    # Save summary
    summary_file = os.path.join(output_dir, "web_scan_summary.json")
    with open(summary_file, 'w') as f:
        json.dump(results, f, indent=4)
    
    print_success(f"Comprehensive web scan completed. Summary saved to {summary_file}")
    return results

# Main function for testing
def main():
    """
    Main function for testing the module
    """
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <url>")
        return 1
    
    url = sys.argv[1]
    output_dir = "./output"
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Perform comprehensive web scan
    comprehensive_web_scan(url, output_dir)
    
    return 0

# Entry point
if __name__ == "__main__":
    sys.exit(main())