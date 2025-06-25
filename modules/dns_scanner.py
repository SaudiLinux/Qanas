#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS Scanner Module for Qanas
Developed by Saudi Linux (SaudiLinux1@gmail.com)

This module handles DNS enumeration and subdomain discovery.
"""

import os
import sys
import subprocess
import json
import re
import time
import threading
import socket
import dns.resolver
import dns.zone
import dns.query

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

# DNS functions
def get_dns_records(domain, record_types=None):
    """
    Get DNS records for a domain
    
    Args:
        domain (str): The domain to query
        record_types (list): List of record types to query
        
    Returns:
        dict: DNS records
    """
    if record_types is None:
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
    
    print_status(f"Getting DNS records for {domain}")
    
    records = {}
    resolver = dns.resolver.Resolver()
    
    for record_type in record_types:
        try:
            answers = resolver.resolve(domain, record_type)
            records[record_type] = [str(answer) for answer in answers]
            print_success(f"Found {len(records[record_type])} {record_type} records")
        except dns.resolver.NoAnswer:
            records[record_type] = []
            print_warning(f"No {record_type} records found")
        except dns.resolver.NXDOMAIN:
            print_error(f"Domain {domain} does not exist")
            return None
        except Exception as e:
            print_error(f"Error getting {record_type} records: {str(e)}")
            records[record_type] = []
    
    return records

def zone_transfer(domain, output_dir):
    """
    Attempt a zone transfer
    
    Args:
        domain (str): The domain to query
        output_dir (str): Directory to save results
        
    Returns:
        dict: Zone transfer results
    """
    print_status(f"Attempting zone transfer for {domain}")
    
    # Get name servers
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        nameservers = [str(ns) for ns in ns_records]
    except Exception as e:
        print_error(f"Error getting nameservers: {str(e)}")
        return None
    
    if not nameservers:
        print_error("No nameservers found")
        return None
    
    print_success(f"Found {len(nameservers)} nameservers: {', '.join(nameservers)}")
    
    # Try zone transfer with each nameserver
    results = {
        'successful': False,
        'nameservers': nameservers,
        'transfers': []
    }
    
    for ns in nameservers:
        try:
            print_status(f"Attempting zone transfer from {ns}")
            zone = dns.zone.from_xfr(dns.query.xfr(ns, domain))
            
            # Zone transfer successful
            results['successful'] = True
            
            # Extract records
            records = []
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        records.append({
                            'name': str(name),
                            'type': dns.rdatatype.to_text(rdataset.rdtype),
                            'data': str(rdata)
                        })
            
            results['transfers'].append({
                'nameserver': ns,
                'successful': True,
                'records': records
            })
            
            print_success(f"Zone transfer successful from {ns}")
            
            # Save records to file
            output_file = os.path.join(output_dir, f"zone_transfer_{domain}_{ns}.json")
            with open(output_file, 'w') as f:
                json.dump(records, f, indent=4)
            
            print_success(f"Zone transfer records saved to {output_file}")
        except Exception as e:
            print_warning(f"Zone transfer failed from {ns}: {str(e)}")
            results['transfers'].append({
                'nameserver': ns,
                'successful': False,
                'error': str(e)
            })
    
    return results

def dnsenum(domain, output_dir):
    """
    Run dnsenum on the domain
    
    Args:
        domain (str): The domain to enumerate
        output_dir (str): Directory to save results
        
    Returns:
        dict: Enumeration results
    """
    print_status(f"Running dnsenum on {domain}")
    
    # Create output file
    xml_output = os.path.join(output_dir, f"dnsenum_{domain}.xml")
    
    # Build command
    command = ["dnsenum", "--enum", "--noreverse", "-o", xml_output, domain]
    
    # Run command
    start_time = time.time()
    result = run_command(command)
    end_time = time.time()
    
    scan_time = end_time - start_time
    
    if result['returncode'] == 0:
        print_success(f"dnsenum completed in {scan_time:.2f} seconds")
        print_success(f"Results saved to {xml_output}")
        
        # Save stdout to text file
        txt_output = os.path.join(output_dir, f"dnsenum_{domain}.txt")
        with open(txt_output, 'w') as f:
            f.write(result['stdout'])
        
        return {
            'scan_time': scan_time,
            'output_files': {
                'xml': xml_output,
                'txt': txt_output
            },
            'stdout': result['stdout']
        }
    else:
        print_error(f"dnsenum failed: {result['stderr']}")
        return None

def sublist3r(domain, output_dir, threads=None):
    """
    Run Sublist3r for subdomain enumeration
    
    Args:
        domain (str): The domain to enumerate
        output_dir (str): Directory to save results
        threads (int): Number of threads to use
        
    Returns:
        dict: Enumeration results
    """
    print_status(f"Running Sublist3r on {domain}")
    
    # Create output file
    output_file = os.path.join(output_dir, f"sublist3r_{domain}.txt")
    
    # Build command
    command = ["sublist3r", "-d", domain, "-o", output_file]
    
    if threads:
        command.extend(["-t", str(threads)])
    
    # Run command
    start_time = time.time()
    result = run_command(command)
    end_time = time.time()
    
    scan_time = end_time - start_time
    
    if result['returncode'] == 0:
        print_success(f"Sublist3r completed in {scan_time:.2f} seconds")
        print_success(f"Results saved to {output_file}")
        
        # Parse results
        subdomains = []
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
        
        return {
            'scan_time': scan_time,
            'output_file': output_file,
            'subdomains': subdomains,
            'count': len(subdomains)
        }
    else:
        print_error(f"Sublist3r failed: {result['stderr']}")
        return None

def amass(domain, output_dir, passive=True):
    """
    Run Amass for subdomain enumeration
    
    Args:
        domain (str): The domain to enumerate
        output_dir (str): Directory to save results
        passive (bool): Whether to use passive mode
        
    Returns:
        dict: Enumeration results
    """
    print_status(f"Running Amass on {domain}")
    
    # Create output file
    output_file = os.path.join(output_dir, f"amass_{domain}.txt")
    
    # Build command
    if passive:
        command = ["amass", "enum", "-passive", "-d", domain, "-o", output_file]
    else:
        command = ["amass", "enum", "-d", domain, "-o", output_file]
    
    # Run command
    start_time = time.time()
    result = run_command(command)
    end_time = time.time()
    
    scan_time = end_time - start_time
    
    if result['returncode'] == 0:
        print_success(f"Amass completed in {scan_time:.2f} seconds")
        print_success(f"Results saved to {output_file}")
        
        # Parse results
        subdomains = []
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
        
        return {
            'scan_time': scan_time,
            'output_file': output_file,
            'subdomains': subdomains,
            'count': len(subdomains)
        }
    else:
        print_error(f"Amass failed: {result['stderr']}")
        return None

def check_wildcard_dns(domain):
    """
    Check if domain has wildcard DNS enabled
    
    Args:
        domain (str): The domain to check
        
    Returns:
        bool: True if wildcard DNS is enabled
    """
    print_status(f"Checking for wildcard DNS on {domain}")
    
    # Generate random subdomains
    import random
    import string
    
    random_subdomains = [
        ''.join(random.choice(string.ascii_lowercase) for _ in range(10)) + '.' + domain
        for _ in range(3)
    ]
    
    # Check if random subdomains resolve
    wildcard_enabled = False
    resolved_ips = set()
    
    for subdomain in random_subdomains:
        try:
            answers = dns.resolver.resolve(subdomain, 'A')
            for answer in answers:
                resolved_ips.add(str(answer))
            wildcard_enabled = True
        except:
            pass
    
    if wildcard_enabled:
        print_warning(f"Wildcard DNS detected for {domain}. Resolved IPs: {', '.join(resolved_ips)}")
    else:
        print_success(f"No wildcard DNS detected for {domain}")
    
    return {
        'wildcard_enabled': wildcard_enabled,
        'resolved_ips': list(resolved_ips)
    }

def reverse_dns(ip):
    """
    Perform reverse DNS lookup
    
    Args:
        ip (str): The IP address to lookup
        
    Returns:
        str: Hostname or None
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except:
        return None

def brute_force_subdomains(domain, output_dir, wordlist=None):
    """
    Brute force subdomains using a wordlist
    
    Args:
        domain (str): The domain to brute force
        output_dir (str): Directory to save results
        wordlist (str): Path to wordlist file
        
    Returns:
        dict: Brute force results
    """
    print_status(f"Brute forcing subdomains for {domain}")
    
    # Default wordlist
    if wordlist is None:
        wordlist = "/usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt"
    
    if not os.path.exists(wordlist):
        print_error(f"Wordlist not found: {wordlist}")
        return None
    
    # Load wordlist
    try:
        with open(wordlist, 'r') as f:
            words = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print_error(f"Error loading wordlist: {str(e)}")
        return None
    
    print_status(f"Loaded {len(words)} words from wordlist")
    
    # Check for wildcard DNS
    wildcard_check = check_wildcard_dns(domain)
    
    # Brute force subdomains
    found_subdomains = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    resolver.lifetime = 1
    
    # Use threading for faster brute forcing
    lock = threading.Lock()
    threads = []
    
    def check_subdomain(word):
        subdomain = f"{word}.{domain}"
        try:
            answers = resolver.resolve(subdomain, 'A')
            ips = [str(answer) for answer in answers]
            
            # If wildcard DNS is enabled, check if resolved IPs are different
            if wildcard_check['wildcard_enabled'] and all(ip in wildcard_check['resolved_ips'] for ip in ips):
                return
            
            with lock:
                found_subdomains.append({
                    'subdomain': subdomain,
                    'ips': ips
                })
                print_success(f"Found subdomain: {subdomain} ({', '.join(ips)})")
        except:
            pass
    
    # Create and start threads
    for word in words:
        thread = threading.Thread(target=check_subdomain, args=(word,))
        threads.append(thread)
        thread.start()
        
        # Limit number of concurrent threads
        if len(threads) >= 50:
            for t in threads:
                t.join()
            threads = []
    
    # Wait for remaining threads
    for thread in threads:
        thread.join()
    
    # Save results
    output_file = os.path.join(output_dir, f"brute_subdomains_{domain}.json")
    with open(output_file, 'w') as f:
        json.dump(found_subdomains, f, indent=4)
    
    print_success(f"Found {len(found_subdomains)} subdomains. Results saved to {output_file}")
    
    return {
        'count': len(found_subdomains),
        'subdomains': found_subdomains,
        'output_file': output_file
    }

# Comprehensive DNS scan
def comprehensive_dns_scan(domain, output_dir, options=None):
    """
    Perform a comprehensive DNS scan on the domain
    
    Args:
        domain (str): The domain to scan
        output_dir (str): Directory to save results
        options (dict): Scan options
        
    Returns:
        dict: Scan results
    """
    print_status(f"Starting comprehensive DNS scan on {domain}")
    
    if options is None:
        options = {
            'dns_records': True,
            'zone_transfer': True,
            'dnsenum': True,
            'sublist3r': True,
            'amass': False,  # Can be slow
            'brute_force': False,  # Can be slow
            'wordlist': None
        }
    
    results = {
        'domain': domain,
        'scan_time': time.strftime("%Y-%m-%d %H:%M:%S"),
        'scans': {}
    }
    
    # Get DNS records
    if options.get('dns_records', True):
        dns_records = get_dns_records(domain)
        results['scans']['dns_records'] = dns_records
    
    # Try zone transfer
    if options.get('zone_transfer', True):
        zone_results = zone_transfer(domain, output_dir)
        results['scans']['zone_transfer'] = zone_results
    
    # Run dnsenum
    if options.get('dnsenum', True):
        dnsenum_results = dnsenum(domain, output_dir)
        results['scans']['dnsenum'] = dnsenum_results
    
    # Run Sublist3r
    if options.get('sublist3r', True):
        sublist3r_results = sublist3r(domain, output_dir)
        results['scans']['sublist3r'] = sublist3r_results
    
    # Run Amass
    if options.get('amass', False):
        amass_results = amass(domain, output_dir)
        results['scans']['amass'] = amass_results
    
    # Brute force subdomains
    if options.get('brute_force', False):
        brute_force_results = brute_force_subdomains(domain, output_dir, wordlist=options.get('wordlist'))
        results['scans']['brute_force'] = brute_force_results
    
    # Save summary
    summary_file = os.path.join(output_dir, f"dns_scan_summary_{domain}.json")
    with open(summary_file, 'w') as f:
        json.dump(results, f, indent=4)
    
    print_success(f"Comprehensive DNS scan completed. Summary saved to {summary_file}")
    return results

# Main function for testing
def main():
    """
    Main function for testing the module
    """
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <domain>")
        return 1
    
    domain = sys.argv[1]
    output_dir = "./output"
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Perform comprehensive DNS scan
    comprehensive_dns_scan(domain, output_dir)
    
    return 0

# Entry point
if __name__ == "__main__":
    sys.exit(main())