#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Vulnerability Scanner Module for Qanas
Developed by Saudi Linux (SaudiLinux1@gmail.com)

This module handles vulnerability scanning functionality.
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

# Vulnerability scanning functions
def sqlmap_scan(url, output_dir, options=None):
    """
    Perform SQL injection scanning using SQLMap
    
    Args:
        url (str): The target URL
        output_dir (str): Directory to save scan results
        options (dict): SQLMap options
        
    Returns:
        dict: Scan results
    """
    url = normalize_url(url)
    print_status(f"Starting SQLMap scan on {url}")
    
    # Create output directory
    sqlmap_output_dir = os.path.join(output_dir, "sqlmap")
    if not os.path.exists(sqlmap_output_dir):
        os.makedirs(sqlmap_output_dir)
    
    # Default options
    if options is None:
        options = {
            'level': 1,
            'risk': 1,
            'batch': True,
            'forms': True,
            'crawl': 1
        }
    
    # Build command
    command = ["sqlmap", "-u", url]
    
    if options.get('batch', True):
        command.append("--batch")
    
    if options.get('forms', True):
        command.append("--forms")
    
    if 'level' in options:
        command.extend(["--level", str(options['level'])])
    
    if 'risk' in options:
        command.extend(["--risk", str(options['risk'])])
    
    if 'crawl' in options:
        command.extend(["--crawl", str(options['crawl'])])
    
    command.extend(["--output-dir", sqlmap_output_dir])
    
    # Run scan
    start_time = time.time()
    result = run_command(command)
    end_time = time.time()
    
    scan_time = end_time - start_time
    
    if result['returncode'] == 0:
        print_success(f"SQLMap scan completed in {scan_time:.2f} seconds")
        print_success(f"Results saved to {sqlmap_output_dir}")
        
        # Save output to file
        output_file = os.path.join(output_dir, "sqlmap_output.txt")
        with open(output_file, 'w') as f:
            f.write(result['stdout'])
        
        # Parse results
        vulnerabilities = []
        if "is vulnerable" in result['stdout']:
            # Extract vulnerable parameters
            pattern = r"Parameter '([^']+)' is vulnerable"
            matches = re.findall(pattern, result['stdout'])
            
            for match in matches:
                vulnerabilities.append({
                    'parameter': match,
                    'type': 'SQL Injection'
                })
        
        scan_results = {
            'scan_time': scan_time,
            'output_dir': sqlmap_output_dir,
            'output_file': output_file,
            'vulnerable': len(vulnerabilities) > 0,
            'vulnerabilities': vulnerabilities
        }
        
        return scan_results
    else:
        print_error(f"SQLMap scan failed: {result['stderr']}")
        return None

def xss_scan(url, output_dir):
    """
    Perform XSS scanning using XSStrike
    
    Args:
        url (str): The target URL
        output_dir (str): Directory to save scan results
        
    Returns:
        dict: Scan results
    """
    url = normalize_url(url)
    print_status(f"Starting XSS scan on {url}")
    
    # Create output file
    output_file = os.path.join(output_dir, "xsstrike_output.txt")
    
    # Build command
    command = ["xsstrike", "-u", url, "--crawl", "--forms"]
    
    # Run scan
    start_time = time.time()
    result = run_command(command)
    end_time = time.time()
    
    scan_time = end_time - start_time
    
    # Save output to file
    with open(output_file, 'w') as f:
        f.write(result['stdout'])
    
    if result['returncode'] == 0:
        print_success(f"XSS scan completed in {scan_time:.2f} seconds")
        print_success(f"Results saved to {output_file}")
        
        # Parse results
        vulnerabilities = []
        if "Vulnerable" in result['stdout']:
            # Extract vulnerable parameters
            pattern = r"Vulnerable parameter: ([^\s]+)"
            matches = re.findall(pattern, result['stdout'])
            
            for match in matches:
                vulnerabilities.append({
                    'parameter': match,
                    'type': 'Cross-Site Scripting (XSS)'
                })
        
        scan_results = {
            'scan_time': scan_time,
            'output_file': output_file,
            'vulnerable': len(vulnerabilities) > 0,
            'vulnerabilities': vulnerabilities
        }
        
        return scan_results
    else:
        print_error(f"XSS scan failed: {result['stderr']}")
        return None

def sslyze_scan(url, output_dir):
    """
    Perform SSL/TLS scanning using SSLyze
    
    Args:
        url (str): The target URL
        output_dir (str): Directory to save scan results
        
    Returns:
        dict: Scan results
    """
    url = normalize_url(url)
    print_status(f"Starting SSL/TLS scan on {url}")
    
    # Parse URL to get hostname and port
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc
    
    # Remove port if present
    if ':' in hostname:
        hostname = hostname.split(':')[0]
    
    # Create output files
    json_output = os.path.join(output_dir, "sslyze.json")
    txt_output = os.path.join(output_dir, "sslyze.txt")
    
    # Build command
    command = ["sslyze", hostname, "--json_out", json_output]
    
    # Run scan
    start_time = time.time()
    result = run_command(command)
    end_time = time.time()
    
    scan_time = end_time - start_time
    
    # Save text output
    with open(txt_output, 'w') as f:
        f.write(result['stdout'])
    
    if result['returncode'] == 0:
        print_success(f"SSL/TLS scan completed in {scan_time:.2f} seconds")
        print_success(f"Results saved to {json_output} and {txt_output}")
        
        # Parse results
        try:
            with open(json_output, 'r') as f:
                scan_results = json.load(f)
            
            return {
                'scan_time': scan_time,
                'output_files': {
                    'json': json_output,
                    'txt': txt_output
                },
                'results': scan_results
            }
        except Exception as e:
            print_error(f"Error parsing SSLyze results: {str(e)}")
            return {
                'scan_time': scan_time,
                'output_files': {
                    'json': json_output,
                    'txt': txt_output
                },
                'error': str(e)
            }
    else:
        print_error(f"SSL/TLS scan failed: {result['stderr']}")
        return None

def nmap_vuln_scan(target, output_dir):
    """
    Perform vulnerability scanning using Nmap scripts
    
    Args:
        target (str): The target (IP or domain)
        output_dir (str): Directory to save scan results
        
    Returns:
        dict: Scan results
    """
    print_status(f"Starting Nmap vulnerability scan on {target}")
    
    # Create output files
    xml_output = os.path.join(output_dir, "nmap_vuln.xml")
    txt_output = os.path.join(output_dir, "nmap_vuln.txt")
    
    # Build command
    command = [
        "nmap", "-sV", "--script", "vuln",
        "-oX", xml_output, "-oN", txt_output,
        target
    ]
    
    # Run scan
    start_time = time.time()
    result = run_command(command)
    end_time = time.time()
    
    scan_time = end_time - start_time
    
    if result['returncode'] == 0:
        print_success(f"Nmap vulnerability scan completed in {scan_time:.2f} seconds")
        print_success(f"Results saved to {xml_output} and {txt_output}")
        
        # Parse results
        vulnerabilities = []
        
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(xml_output)
            root = tree.getroot()
            
            # Extract vulnerabilities from script output
            for host in root.findall('.//host'):
                for port in host.findall('.//port'):
                    port_id = port.attrib.get('portid')
                    protocol = port.attrib.get('protocol')
                    
                    for script in port.findall('.//script'):
                        script_id = script.attrib.get('id')
                        output = script.attrib.get('output')
                        
                        if 'VULNERABLE' in output:
                            vulnerabilities.append({
                                'port': port_id,
                                'protocol': protocol,
                                'script': script_id,
                                'output': output
                            })
        except Exception as e:
            print_error(f"Error parsing Nmap XML: {str(e)}")
        
        scan_results = {
            'scan_time': scan_time,
            'output_files': {
                'xml': xml_output,
                'txt': txt_output
            },
            'vulnerable': len(vulnerabilities) > 0,
            'vulnerabilities': vulnerabilities
        }
        
        return scan_results
    else:
        print_error(f"Nmap vulnerability scan failed: {result['stderr']}")
        return None

def wpscan_vuln(url, output_dir, api_token=None):
    """
    Perform WordPress vulnerability scanning using WPScan
    
    Args:
        url (str): The target URL
        output_dir (str): Directory to save scan results
        api_token (str): WPVulnDB API token
        
    Returns:
        dict: Scan results
    """
    url = normalize_url(url)
    print_status(f"Starting WordPress vulnerability scan on {url}")
    
    # Create output files
    json_output = os.path.join(output_dir, "wpscan_vuln.json")
    txt_output = os.path.join(output_dir, "wpscan_vuln.txt")
    
    # Build command
    command = [
        "wpscan", "--url", url,
        "--enumerate", "vp,vt,tt,cb,dbe,u,m",
        "--format", "json", "--output", json_output
    ]
    
    # Add API token if provided
    if api_token:
        command.extend(["--api-token", api_token])
    
    # Run scan
    start_time = time.time()
    result = run_command(command)
    end_time = time.time()
    
    scan_time = end_time - start_time
    
    if result['returncode'] == 0:
        print_success(f"WordPress vulnerability scan completed in {scan_time:.2f} seconds")
        
        # Also save text output
        command = [
            "wpscan", "--url", url,
            "--enumerate", "vp,vt,tt,cb,dbe,u,m",
            "--format", "cli", "--output", txt_output
        ]
        if api_token:
            command.extend(["--api-token", api_token])
        run_command(command)
        
        print_success(f"Results saved to {json_output} and {txt_output}")
        
        # Parse JSON results
        try:
            with open(json_output, 'r') as f:
                scan_results = json.load(f)
            
            # Extract vulnerabilities
            vulnerabilities = []
            
            # Check main WordPress
            if 'version' in scan_results and 'vulnerabilities' in scan_results['version']:
                for vuln in scan_results['version']['vulnerabilities']:
                    vulnerabilities.append({
                        'component': 'WordPress Core',
                        'version': scan_results['version'].get('number', 'unknown'),
                        'title': vuln.get('title', 'Unknown'),
                        'fixed_in': vuln.get('fixed_in', 'Unknown'),
                        'references': vuln.get('references', {})
                    })
            
            # Check plugins
            if 'plugins' in scan_results:
                for plugin_name, plugin_data in scan_results['plugins'].items():
                    if 'vulnerabilities' in plugin_data:
                        for vuln in plugin_data['vulnerabilities']:
                            vulnerabilities.append({
                                'component': f"Plugin: {plugin_name}",
                                'version': plugin_data.get('version', {}).get('number', 'unknown'),
                                'title': vuln.get('title', 'Unknown'),
                                'fixed_in': vuln.get('fixed_in', 'Unknown'),
                                'references': vuln.get('references', {})
                            })
            
            # Check themes
            if 'themes' in scan_results:
                for theme_name, theme_data in scan_results['themes'].items():
                    if 'vulnerabilities' in theme_data:
                        for vuln in theme_data['vulnerabilities']:
                            vulnerabilities.append({
                                'component': f"Theme: {theme_name}",
                                'version': theme_data.get('version', {}).get('number', 'unknown'),
                                'title': vuln.get('title', 'Unknown'),
                                'fixed_in': vuln.get('fixed_in', 'Unknown'),
                                'references': vuln.get('references', {})
                            })
            
            return {
                'scan_time': scan_time,
                'output_files': {
                    'json': json_output,
                    'txt': txt_output
                },
                'vulnerable': len(vulnerabilities) > 0,
                'vulnerabilities': vulnerabilities
            }
        except Exception as e:
            print_error(f"Error parsing WPScan results: {str(e)}")
            return {
                'scan_time': scan_time,
                'output_files': {
                    'json': json_output,
                    'txt': txt_output
                },
                'error': str(e)
            }
    else:
        print_error(f"WordPress vulnerability scan failed: {result['stderr']}")
        return None

def nuclei_scan(target, output_dir, templates=None):
    """
    Perform vulnerability scanning using Nuclei
    
    Args:
        target (str): The target (URL, IP, or domain)
        output_dir (str): Directory to save scan results
        templates (str): Templates to use (e.g., 'cves,vulnerabilities')
        
    Returns:
        dict: Scan results
    """
    print_status(f"Starting Nuclei scan on {target}")
    
    # Create output files
    json_output = os.path.join(output_dir, "nuclei.json")
    txt_output = os.path.join(output_dir, "nuclei.txt")
    
    # Build command
    command = ["nuclei", "-target", target, "-json", "-o", json_output]
    
    # Add templates if specified
    if templates:
        command.extend(["-t", templates])
    
    # Run scan
    start_time = time.time()
    result = run_command(command)
    end_time = time.time()
    
    scan_time = end_time - start_time
    
    # Also save text output
    txt_command = ["nuclei", "-target", target, "-o", txt_output]
    if templates:
        txt_command.extend(["-t", templates])
    run_command(txt_command)
    
    if result['returncode'] == 0:
        print_success(f"Nuclei scan completed in {scan_time:.2f} seconds")
        print_success(f"Results saved to {json_output} and {txt_output}")
        
        # Parse results
        vulnerabilities = []
        
        try:
            # Nuclei outputs one JSON object per line
            with open(json_output, 'r') as f:
                for line in f:
                    try:
                        finding = json.loads(line.strip())
                        vulnerabilities.append({
                            'template': finding.get('template', 'Unknown'),
                            'template-id': finding.get('template-id', 'Unknown'),
                            'severity': finding.get('info', {}).get('severity', 'Unknown'),
                            'name': finding.get('info', {}).get('name', 'Unknown'),
                            'description': finding.get('info', {}).get('description', 'Unknown'),
                            'matched-at': finding.get('matched-at', 'Unknown')
                        })
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            print_error(f"Error parsing Nuclei results: {str(e)}")
        
        scan_results = {
            'scan_time': scan_time,
            'output_files': {
                'json': json_output,
                'txt': txt_output
            },
            'vulnerable': len(vulnerabilities) > 0,
            'vulnerabilities': vulnerabilities
        }
        
        return scan_results
    else:
        print_error(f"Nuclei scan failed: {result['stderr']}")
        return None

# Comprehensive vulnerability scan
def comprehensive_vuln_scan(target, output_dir, options=None):
    """
    Perform a comprehensive vulnerability scan on the target
    
    Args:
        target (str): The target (URL, IP, or domain)
        output_dir (str): Directory to save scan results
        options (dict): Scan options
        
    Returns:
        dict: Scan results
    """
    print_status(f"Starting comprehensive vulnerability scan on {target}")
    
    if options is None:
        options = {
            'nmap_vuln': True,
            'web_scan': True,
            'ssl_scan': True,
            'nuclei': True,
            'wpscan': False,  # Only if WordPress is detected
            'sqlmap': False,  # Can be slow and intrusive
            'xss': False,     # Can be slow and intrusive
            'wpscan_api_token': None
        }
    
    results = {
        'target': target,
        'scan_time': time.strftime("%Y-%m-%d %H:%M:%S"),
        'scans': {}
    }
    
    # Determine if target is a URL
    is_url = target.startswith('http://') or target.startswith('https://')
    
    # Run Nmap vulnerability scan
    if options.get('nmap_vuln', True):
        if is_url:
            # Extract hostname from URL
            parsed_url = urlparse(target)
            hostname = parsed_url.netloc
            if ':' in hostname:
                hostname = hostname.split(':')[0]
            nmap_target = hostname
        else:
            nmap_target = target
        
        nmap_results = nmap_vuln_scan(nmap_target, output_dir)
        results['scans']['nmap_vuln'] = nmap_results
    
    # Run web vulnerability scans if target is a URL
    if is_url:
        # Run SSL/TLS scan
        if options.get('ssl_scan', True) and target.startswith('https://'):
            ssl_results = sslyze_scan(target, output_dir)
            results['scans']['ssl_scan'] = ssl_results
        
        # Check if target is WordPress
        is_wordpress = False
        if options.get('wpscan', False):
            # Simple check for WordPress
            try:
                import requests
                wp_login = f"{target}/wp-login.php"
                response = requests.get(wp_login, timeout=5, verify=False)
                is_wordpress = response.status_code == 200 and "WordPress" in response.text
            except:
                pass
        
        # Run WPScan if WordPress is detected
        if is_wordpress or options.get('wpscan', False):
            wpscan_results = wpscan_vuln(target, output_dir, api_token=options.get('wpscan_api_token'))
            results['scans']['wpscan'] = wpscan_results
        
        # Run SQLMap
        if options.get('sqlmap', False):
            sqlmap_results = sqlmap_scan(target, output_dir)
            results['scans']['sqlmap'] = sqlmap_results
        
        # Run XSS scan
        if options.get('xss', False):
            xss_results = xss_scan(target, output_dir)
            results['scans']['xss'] = xss_results
    
    # Run Nuclei scan
    if options.get('nuclei', True):
        nuclei_results = nuclei_scan(target, output_dir)
        results['scans']['nuclei'] = nuclei_results
    
    # Save summary
    summary_file = os.path.join(output_dir, "vuln_scan_summary.json")
    with open(summary_file, 'w') as f:
        json.dump(results, f, indent=4)
    
    print_success(f"Comprehensive vulnerability scan completed. Summary saved to {summary_file}")
    return results

# Main function for testing
def main():
    """
    Main function for testing the module
    """
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target>")
        return 1
    
    target = sys.argv[1]
    output_dir = "./output"
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Perform comprehensive vulnerability scan
    comprehensive_vuln_scan(target, output_dir)
    
    return 0

# Entry point
if __name__ == "__main__":
    sys.exit(main())