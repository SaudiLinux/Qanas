#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Reconnaissance Scanner Module for Qanas
Developed by Saudi Linux (SaudiLinux1@gmail.com)

This module handles reconnaissance and information gathering functionality.
"""

import os
import sys
import json
import subprocess
import re
import time
import socket
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

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

def is_valid_ip(ip):
    """
    Check if the given string is a valid IP address
    
    Args:
        ip (str): IP address to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

# Reconnaissance functions
def whois_lookup(target, output_dir):
    """
    Perform WHOIS lookup on the target
    
    Args:
        target (str): The target domain or IP
        output_dir (str): Directory to save results
        
    Returns:
        dict: WHOIS information
    """
    print_status(f"Performing WHOIS lookup on {target}")
    
    # Create output file
    output_file = os.path.join(output_dir, "whois.txt")
    
    # Build command
    command = ["whois", target]
    
    # Run command
    result = run_command(command)
    
    if result['returncode'] == 0:
        # Save output to file
        with open(output_file, 'w') as f:
            f.write(result['stdout'])
        
        print_success(f"WHOIS lookup completed. Results saved to {output_file}")
        
        # Parse basic information
        whois_info = {
            'raw': result['stdout'],
            'output_file': output_file
        }
        
        # Extract registrar
        registrar_match = re.search(r"Registrar:\s*(.+)", result['stdout'])
        if registrar_match:
            whois_info['registrar'] = registrar_match.group(1).strip()
        
        # Extract creation date
        creation_match = re.search(r"Creation Date:\s*(.+)", result['stdout'])
        if creation_match:
            whois_info['creation_date'] = creation_match.group(1).strip()
        
        # Extract expiration date
        expiration_match = re.search(r"Registry Expiry Date:\s*(.+)", result['stdout'])
        if expiration_match:
            whois_info['expiration_date'] = expiration_match.group(1).strip()
        
        # Extract name servers
        nameservers = re.findall(r"Name Server:\s*(.+)", result['stdout'])
        if nameservers:
            whois_info['nameservers'] = [ns.strip() for ns in nameservers]
        
        return whois_info
    else:
        print_error(f"WHOIS lookup failed: {result['stderr']}")
        return None

def shodan_lookup(target, api_key, output_dir):
    """
    Perform Shodan lookup on the target
    
    Args:
        target (str): The target domain or IP
        api_key (str): Shodan API key
        output_dir (str): Directory to save results
        
    Returns:
        dict: Shodan information
    """
    if not api_key:
        print_error("Shodan API key not provided. Skipping Shodan lookup.")
        return None
    
    print_status(f"Performing Shodan lookup on {target}")
    
    # Create output file
    output_file = os.path.join(output_dir, "shodan.json")
    
    try:
        # Resolve domain to IP if needed
        if not is_valid_ip(target):
            try:
                target_ip = socket.gethostbyname(target)
            except socket.gaierror:
                print_error(f"Could not resolve {target} to an IP address")
                return None
        else:
            target_ip = target
        
        # Query Shodan API
        url = f"https://api.shodan.io/shodan/host/{target_ip}?key={api_key}"
        response = requests.get(url)
        
        if response.status_code == 200:
            shodan_data = response.json()
            
            # Save output to file
            with open(output_file, 'w') as f:
                json.dump(shodan_data, f, indent=4)
            
            print_success(f"Shodan lookup completed. Results saved to {output_file}")
            
            # Extract useful information
            shodan_info = {
                'ip': shodan_data.get('ip_str'),
                'hostnames': shodan_data.get('hostnames', []),
                'country': shodan_data.get('country_name'),
                'org': shodan_data.get('org'),
                'isp': shodan_data.get('isp'),
                'last_update': shodan_data.get('last_update'),
                'ports': shodan_data.get('ports', []),
                'vulns': shodan_data.get('vulns', []),
                'output_file': output_file
            }
            
            return shodan_info
        else:
            print_error(f"Shodan lookup failed: {response.text}")
            return None
    except Exception as e:
        print_error(f"Error during Shodan lookup: {str(e)}")
        return None

def censys_lookup(target, api_id, api_secret, output_dir):
    """
    Perform Censys lookup on the target
    
    Args:
        target (str): The target domain or IP
        api_id (str): Censys API ID
        api_secret (str): Censys API Secret
        output_dir (str): Directory to save results
        
    Returns:
        dict: Censys information
    """
    if not api_id or not api_secret:
        print_error("Censys API credentials not provided. Skipping Censys lookup.")
        return None
    
    print_status(f"Performing Censys lookup on {target}")
    
    # Create output file
    output_file = os.path.join(output_dir, "censys.json")
    
    try:
        # Resolve domain to IP if needed
        if not is_valid_ip(target):
            try:
                target_ip = socket.gethostbyname(target)
            except socket.gaierror:
                print_error(f"Could not resolve {target} to an IP address")
                return None
        else:
            target_ip = target
        
        # Query Censys API
        url = f"https://search.censys.io/api/v1/view/ipv4/{target_ip}"
        response = requests.get(url, auth=(api_id, api_secret))
        
        if response.status_code == 200:
            censys_data = response.json()
            
            # Save output to file
            with open(output_file, 'w') as f:
                json.dump(censys_data, f, indent=4)
            
            print_success(f"Censys lookup completed. Results saved to {output_file}")
            
            # Extract useful information
            censys_info = {
                'ip': target_ip,
                'protocols': [],
                'output_file': output_file
            }
            
            # Extract protocols
            if 'protocols' in censys_data:
                censys_info['protocols'] = censys_data['protocols']
            
            # Extract location information
            if 'location' in censys_data:
                censys_info['location'] = censys_data['location']
            
            # Extract autonomous system information
            if 'autonomous_system' in censys_data:
                censys_info['as'] = {
                    'name': censys_data['autonomous_system'].get('name'),
                    'asn': censys_data['autonomous_system'].get('asn')
                }
            
            return censys_info
        else:
            print_error(f"Censys lookup failed: {response.text}")
            return None
    except Exception as e:
        print_error(f"Error during Censys lookup: {str(e)}")
        return None

def theHarvester_scan(target, output_dir):
    """
    Perform email and subdomain harvesting using theHarvester
    
    Args:
        target (str): The target domain
        output_dir (str): Directory to save results
        
    Returns:
        dict: Harvested information
    """
    print_status(f"Harvesting information for {target} using theHarvester")
    
    # Create output files
    xml_output = os.path.join(output_dir, "theharvester.xml")
    html_output = os.path.join(output_dir, "theharvester.html")
    
    # Build command
    # Use common data sources: google, bing, linkedin, twitter, duckduckgo, yahoo
    command = [
        "theHarvester", "-d", target, "-b", "all",
        "-f", xml_output, "-v"
    ]
    
    # Run command
    result = run_command(command)
    
    if result['returncode'] == 0:
        print_success(f"Information harvesting completed. Results saved to {xml_output}")
        
        # Parse results
        harvested_info = {
            'emails': [],
            'hosts': [],
            'output_file': xml_output
        }
        
        # Extract emails and hosts from output
        emails = re.findall(r"\[\*\] Email: (.+)", result['stdout'])
        if emails:
            harvested_info['emails'] = emails
        
        hosts = re.findall(r"\[\*\] Host: (.+)", result['stdout'])
        if hosts:
            harvested_info['hosts'] = hosts
        
        # Save raw output
        with open(os.path.join(output_dir, "theharvester_raw.txt"), 'w') as f:
            f.write(result['stdout'])
        
        return harvested_info
    else:
        print_error(f"Information harvesting failed: {result['stderr']}")
        return None

def google_dorks(target, output_dir):
    """
    Generate Google dork queries for the target
    
    Args:
        target (str): The target domain
        output_dir (str): Directory to save results
        
    Returns:
        dict: Google dork information
    """
    print_status(f"Generating Google dork queries for {target}")
    
    # Create output file
    output_file = os.path.join(output_dir, "google_dorks.txt")
    
    # Define common Google dorks
    dorks = [
        f"site:{target} inurl:login | inurl:signin | intitle:Login | intitle:\"sign in\" | inurl:auth",
        f"site:{target} intext:\"sql syntax near\" | intext:\"syntax error has occurred\" | intext:\"incorrect syntax near\" | intext:\"unexpected end of SQL command\" | intext:\"Warning: mysql_connect()\" | intext:\"Warning: mysql_query()\" | intext:\"Warning: pg_connect()\"",
        f"site:{target} ext:log | ext:txt | ext:conf | ext:cnf | ext:ini | ext:env | ext:sh | ext:bak | ext:backup | ext:swp | ext:old | ext:~ | ext:git | ext:svn | ext:htpasswd | ext:htaccess",
        f"site:{target} inurl:wp-content | inurl:wp-includes",
        f"site:{target} intitle:index.of | ext:log | ext:php | intitle:\"apache:directory listing\" | intitle:\"index of /\" | inurl:shell | inurl:backdoor | inurl:wso | inurl:cmd | shadow | passwd | boot.ini | inurl:backdoor",
        f"site:{target} inurl:readme | inurl:license | inurl:install | inurl:setup | inurl:config",
        f"site:{target} inurl:redir | inurl:url | inurl:redirect | inurl:return | inurl:src=http | inurl:r=http",
        f"site:{target} ext:action | ext:struts | ext:do",
        f"site:{target} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini",
        f"site:{target} ext:sql | ext:dbf | ext:mdb",
        f"site:{target} ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup",
        f"site:{target} inurl:login | inurl:admin",
        f"site:{target} intext:\"powered by\" | intext:\"built with\" | intext:\"maintained by\" | intext:\"created by\"",
        f"site:{target} inurl:upload | inurl:file | inurl:download",
        f"site:{target} inurl:wp-admin | inurl:phpMyAdmin | inurl:cpanel | inurl:webmail"
    ]
    
    # Save dorks to file
    with open(output_file, 'w') as f:
        for dork in dorks:
            f.write(f"{dork}\n\n")
    
    print_success(f"Google dork queries generated. Results saved to {output_file}")
    
    return {
        'dorks': dorks,
        'output_file': output_file
    }

def waybackurls_scan(target, output_dir):
    """
    Retrieve URLs from Wayback Machine for the target
    
    Args:
        target (str): The target domain
        output_dir (str): Directory to save results
        
    Returns:
        dict: Wayback URLs information
    """
    print_status(f"Retrieving URLs from Wayback Machine for {target}")
    
    # Create output file
    output_file = os.path.join(output_dir, "waybackurls.txt")
    
    # Build command
    command = ["waybackurls", target]
    
    # Run command
    result = run_command(command)
    
    if result['returncode'] == 0:
        # Save output to file
        with open(output_file, 'w') as f:
            f.write(result['stdout'])
        
        # Count URLs
        urls = result['stdout'].strip().split('\n')
        url_count = len(urls) if urls and urls[0] else 0
        
        print_success(f"Retrieved {url_count} URLs from Wayback Machine. Results saved to {output_file}")
        
        return {
            'url_count': url_count,
            'output_file': output_file
        }
    else:
        print_error(f"Wayback URL retrieval failed: {result['stderr']}")
        
        # Try alternative method using curl and Wayback Machine API
        print_status("Trying alternative method...")
        
        command = [
            "curl", "-s",
            f"http://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=text&fl=original&collapse=urlkey"
        ]
        
        result = run_command(command)
        
        if result['returncode'] == 0:
            # Save output to file
            with open(output_file, 'w') as f:
                f.write(result['stdout'])
            
            # Count URLs
            urls = result['stdout'].strip().split('\n')
            url_count = len(urls) if urls and urls[0] else 0
            
            print_success(f"Retrieved {url_count} URLs from Wayback Machine. Results saved to {output_file}")
            
            return {
                'url_count': url_count,
                'output_file': output_file
            }
        else:
            print_error(f"Alternative Wayback URL retrieval failed: {result['stderr']}")
            return None

def github_dorks(target, output_dir):
    """
    Generate GitHub dork queries for the target
    
    Args:
        target (str): The target domain
        output_dir (str): Directory to save results
        
    Returns:
        dict: GitHub dork information
    """
    print_status(f"Generating GitHub dork queries for {target}")
    
    # Create output file
    output_file = os.path.join(output_dir, "github_dorks.txt")
    
    # Define common GitHub dorks
    dorks = [
        f"\"{target}\" password",
        f"\"{target}\" api_key",
        f"\"{target}\" apikey",
        f"\"{target}\" secret",
        f"\"{target}\" token",
        f"\"{target}\" config",
        f"\"{target}\" credential",
        f"\"{target}\" key",
        f"\"{target}\" pass",
        f"\"{target}\" login",
        f"\"{target}\" pwd",
        f"\"{target}\" ftp",
        f"\"{target}\" ssh",
        f"filename:.env \"{target}\"",
        f"filename:.npmrc _auth \"{target}\"",
        f"filename:.dockercfg auth \"{target}\"",
        f"filename:wp-config.php \"{target}\"",
        f"filename:.htpasswd \"{target}\"",
        f"filename:.git-credentials \"{target}\"",
        f"filename:.bashrc password \"{target}\"",
        f"filename:.bash_profile password \"{target}\"",
        f"filename:.bash_history password \"{target}\"",
        f"filename:id_rsa \"{target}\"",
        f"filename:id_dsa \"{target}\"",
        f"filename:.s3cfg \"{target}\"",
        f"filename:sftp-config.json \"{target}\"",
        f"filename:WebServers.xml \"{target}\""
    ]
    
    # Save dorks to file
    with open(output_file, 'w') as f:
        for dork in dorks:
            f.write(f"{dork}\n\n")
    
    print_success(f"GitHub dork queries generated. Results saved to {output_file}")
    
    return {
        'dorks': dorks,
        'output_file': output_file
    }

def pastebin_search(target, output_dir):
    """
    Search for the target on Pastebin-like sites
    
    Args:
        target (str): The target domain
        output_dir (str): Directory to save results
        
    Returns:
        dict: Pastebin search information
    """
    print_status(f"Searching for {target} on Pastebin-like sites")
    
    # Create output file
    output_file = os.path.join(output_dir, "pastebin_search.txt")
    
    # Define search URLs
    search_urls = [
        f"https://www.google.com/search?q=site:pastebin.com+\"{target}\"",
        f"https://www.google.com/search?q=site:paste.ee+\"{target}\"",
        f"https://www.google.com/search?q=site:ghostbin.com+\"{target}\"",
        f"https://www.google.com/search?q=site:github.com+\"{target}\"",
        f"https://www.google.com/search?q=site:gitlab.com+\"{target}\"",
        f"https://www.google.com/search?q=site:bitbucket.org+\"{target}\""
    ]
    
    # Save search URLs to file
    with open(output_file, 'w') as f:
        f.write("Pastebin-like Site Search URLs:\n\n")
        for url in search_urls:
            f.write(f"{url}\n\n")
    
    print_success(f"Pastebin search URLs generated. Results saved to {output_file}")
    
    return {
        'search_urls': search_urls,
        'output_file': output_file
    }

def social_media_search(target, output_dir):
    """
    Generate social media search queries for the target
    
    Args:
        target (str): The target domain or company name
        output_dir (str): Directory to save results
        
    Returns:
        dict: Social media search information
    """
    print_status(f"Generating social media search queries for {target}")
    
    # Create output file
    output_file = os.path.join(output_dir, "social_media_search.txt")
    
    # Define search queries
    search_queries = [
        f"site:linkedin.com \"{target}\"",
        f"site:twitter.com \"{target}\"",
        f"site:facebook.com \"{target}\"",
        f"site:instagram.com \"{target}\"",
        f"site:youtube.com \"{target}\"",
        f"site:glassdoor.com \"{target}\"",
        f"site:indeed.com \"{target}\"",
        f"site:slideshare.net \"{target}\"",
        f"site:medium.com \"{target}\"",
        f"site:reddit.com \"{target}\""
    ]
    
    # Save search queries to file
    with open(output_file, 'w') as f:
        f.write("Social Media Search Queries:\n\n")
        for query in search_queries:
            f.write(f"{query}\n\n")
    
    print_success(f"Social media search queries generated. Results saved to {output_file}")
    
    return {
        'search_queries': search_queries,
        'output_file': output_file
    }

def ssl_certificate_info(target, output_dir):
    """
    Retrieve SSL certificate information for the target
    
    Args:
        target (str): The target domain
        output_dir (str): Directory to save results
        
    Returns:
        dict: SSL certificate information
    """
    print_status(f"Retrieving SSL certificate information for {target}")
    
    # Create output file
    output_file = os.path.join(output_dir, "ssl_certificate.txt")
    
    # Normalize target
    if target.startswith('http://') or target.startswith('https://'):
        parsed_url = urlparse(target)
        target = parsed_url.netloc
    
    # Remove port if present
    if ':' in target:
        target = target.split(':')[0]
    
    # Build command
    command = ["openssl", "s_client", "-showcerts", "-connect", f"{target}:443", "-servername", target]
    
    # Run command
    result = run_command(command)
    
    if result['returncode'] == 0:
        # Save output to file
        with open(output_file, 'w') as f:
            f.write(result['stdout'])
        
        print_success(f"SSL certificate information retrieved. Results saved to {output_file}")
        
        # Extract certificate information
        cert_info = {}
        
        # Extract subject
        subject_match = re.search(r"subject=([^\n]+)", result['stdout'])
        if subject_match:
            cert_info['subject'] = subject_match.group(1).strip()
        
        # Extract issuer
        issuer_match = re.search(r"issuer=([^\n]+)", result['stdout'])
        if issuer_match:
            cert_info['issuer'] = issuer_match.group(1).strip()
        
        # Extract validity
        not_before_match = re.search(r"notBefore=([^\n]+)", result['stdout'])
        if not_before_match:
            cert_info['not_before'] = not_before_match.group(1).strip()
        
        not_after_match = re.search(r"notAfter=([^\n]+)", result['stdout'])
        if not_after_match:
            cert_info['not_after'] = not_after_match.group(1).strip()
        
        # Extract alternative names
        alt_names_match = re.search(r"X509v3 Subject Alternative Name:[\s\n]+(DNS:[^\n]+)", result['stdout'])
        if alt_names_match:
            alt_names = alt_names_match.group(1).strip().split(', ')
            cert_info['alternative_names'] = [name.replace('DNS:', '') for name in alt_names]
        
        return {
            'certificate': cert_info,
            'output_file': output_file
        }
    else:
        print_error(f"SSL certificate retrieval failed: {result['stderr']}")
        return None

# Comprehensive reconnaissance scan
def comprehensive_recon(target, output_dir, options=None):
    """
    Perform a comprehensive reconnaissance scan on the target
    
    Args:
        target (str): The target domain, IP, or URL
        output_dir (str): Directory to save results
        options (dict): Scan options
        
    Returns:
        dict: Scan results
    """
    print_status(f"Starting comprehensive reconnaissance on {target}")
    
    if options is None:
        options = {
            'whois': True,
            'shodan': False,
            'censys': False,
            'harvester': True,
            'google_dorks': True,
            'github_dorks': True,
            'waybackurls': True,
            'pastebin': True,
            'social_media': True,
            'ssl_info': True,
            'shodan_api_key': None,
            'censys_api_id': None,
            'censys_api_secret': None
        }
    
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    results = {
        'target': target,
        'scan_time': time.strftime("%Y-%m-%d %H:%M:%S"),
        'scans': {}
    }
    
    # Normalize target if it's a URL
    normalized_target = target
    if target.startswith('http://') or target.startswith('https://'):
        parsed_url = urlparse(target)
        normalized_target = parsed_url.netloc
    
    # Remove port if present
    if ':' in normalized_target:
        normalized_target = normalized_target.split(':')[0]
    
    # Run scans in parallel
    with ThreadPoolExecutor(max_workers=5) as executor:
        # Submit tasks
        future_to_scan = {}
        
        if options.get('whois', True):
            future_to_scan[executor.submit(whois_lookup, normalized_target, output_dir)] = 'whois'
        
        if options.get('shodan', False) and options.get('shodan_api_key'):
            future_to_scan[executor.submit(shodan_lookup, normalized_target, options.get('shodan_api_key'), output_dir)] = 'shodan'
        
        if options.get('censys', False) and options.get('censys_api_id') and options.get('censys_api_secret'):
            future_to_scan[executor.submit(censys_lookup, normalized_target, options.get('censys_api_id'), options.get('censys_api_secret'), output_dir)] = 'censys'
        
        if options.get('harvester', True):
            future_to_scan[executor.submit(theHarvester_scan, normalized_target, output_dir)] = 'harvester'
        
        if options.get('google_dorks', True):
            future_to_scan[executor.submit(google_dorks, normalized_target, output_dir)] = 'google_dorks'
        
        if options.get('github_dorks', True):
            future_to_scan[executor.submit(github_dorks, normalized_target, output_dir)] = 'github_dorks'
        
        if options.get('waybackurls', True):
            future_to_scan[executor.submit(waybackurls_scan, normalized_target, output_dir)] = 'waybackurls'
        
        if options.get('pastebin', True):
            future_to_scan[executor.submit(pastebin_search, normalized_target, output_dir)] = 'pastebin'
        
        if options.get('social_media', True):
            future_to_scan[executor.submit(social_media_search, normalized_target, output_dir)] = 'social_media'
        
        if options.get('ssl_info', True):
            future_to_scan[executor.submit(ssl_certificate_info, normalized_target, output_dir)] = 'ssl_info'
        
        # Collect results
        for future in future_to_scan:
            scan_type = future_to_scan[future]
            try:
                scan_result = future.result()
                if scan_result:
                    results['scans'][scan_type] = scan_result
            except Exception as e:
                print_error(f"Error in {scan_type} scan: {str(e)}")
    
    # Save summary
    summary_file = os.path.join(output_dir, "recon_summary.json")
    with open(summary_file, 'w') as f:
        json.dump(results, f, indent=4)
    
    print_success(f"Comprehensive reconnaissance completed. Summary saved to {summary_file}")
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
    
    # Perform comprehensive reconnaissance
    comprehensive_recon(target, output_dir)
    
    return 0

# Entry point
if __name__ == "__main__":
    sys.exit(main())