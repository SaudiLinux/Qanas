#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Port Scanner Module for Qanas
Developed by Saudi Linux (SaudiLinux1@gmail.com)

This module handles port scanning functionality using Nmap and other tools.
"""

import os
import sys
import subprocess
import json
import xml.etree.ElementTree as ET
import ipaddress
import socket
import time
import threading
from datetime import datetime

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

# Port scanning functions
def nmap_scan(target, output_dir, options=None, quick=False):
    """
    Perform an Nmap scan on the target
    
    Args:
        target (str): The target to scan (IP or domain)
        output_dir (str): Directory to save scan results
        options (list): Additional Nmap options
        quick (bool): Whether to perform a quick scan
        
    Returns:
        dict: Scan results
    """
    print_status(f"Starting Nmap scan on {target}")
    
    # Create output files
    xml_output = os.path.join(output_dir, "nmap_scan.xml")
    txt_output = os.path.join(output_dir, "nmap_scan.txt")
    
    # Build command
    command = ["nmap", "-sV", "-sC"]
    
    if quick:
        command.extend(["--top-ports", "100"])
    else:
        command.append("-p-")
    
    if options:
        command.extend(options)
    
    command.extend(["-oX", xml_output, "-oN", txt_output, target])
    
    # Run scan
    start_time = time.time()
    result = run_command(command)
    end_time = time.time()
    
    scan_time = end_time - start_time
    
    if result['returncode'] == 0:
        print_success(f"Nmap scan completed in {scan_time:.2f} seconds")
        
        # Parse XML output
        try:
            scan_results = parse_nmap_xml(xml_output)
            
            # Save parsed results as JSON
            json_output = os.path.join(output_dir, "nmap_scan.json")
            with open(json_output, 'w') as f:
                json.dump(scan_results, f, indent=4)
            
            print_success(f"Scan results saved to {output_dir}")
            return scan_results
        except Exception as e:
            print_error(f"Error parsing Nmap results: {str(e)}")
            return None
    else:
        print_error(f"Nmap scan failed: {result['stderr']}")
        return None

def parse_nmap_xml(xml_file):
    """
    Parse Nmap XML output file
    
    Args:
        xml_file (str): Path to Nmap XML output file
        
    Returns:
        dict: Parsed scan results
    """
    if not os.path.exists(xml_file):
        print_error(f"XML file not found: {xml_file}")
        return None
    
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        # Extract scan information
        scan_info = {
            'scanner': root.attrib.get('scanner', 'unknown'),
            'args': root.attrib.get('args', ''),
            'start': root.attrib.get('start', ''),
            'startstr': root.attrib.get('startstr', ''),
            'version': root.attrib.get('version', ''),
            'hosts': []
        }
        
        # Process each host
        for host in root.findall('.//host'):
            host_info = {
                'status': host.find('.//status').attrib.get('state', 'unknown') if host.find('.//status') is not None else 'unknown',
                'addresses': [],
                'hostnames': [],
                'ports': []
            }
            
            # Get addresses
            for addr in host.findall('.//address'):
                host_info['addresses'].append({
                    'addr': addr.attrib.get('addr', ''),
                    'addrtype': addr.attrib.get('addrtype', ''),
                    'vendor': addr.attrib.get('vendor', '')
                })
            
            # Get hostnames
            hostnames_elem = host.find('.//hostnames')
            if hostnames_elem is not None:
                for hostname in hostnames_elem.findall('.//hostname'):
                    host_info['hostnames'].append({
                        'name': hostname.attrib.get('name', ''),
                        'type': hostname.attrib.get('type', '')
                    })
            
            # Get ports
            ports_elem = host.find('.//ports')
            if ports_elem is not None:
                for port in ports_elem.findall('.//port'):
                    port_info = {
                        'protocol': port.attrib.get('protocol', ''),
                        'portid': port.attrib.get('portid', ''),
                        'state': {},
                        'service': {}
                    }
                    
                    # Get state
                    state_elem = port.find('.//state')
                    if state_elem is not None:
                        port_info['state'] = {
                            'state': state_elem.attrib.get('state', ''),
                            'reason': state_elem.attrib.get('reason', ''),
                            'reason_ttl': state_elem.attrib.get('reason_ttl', '')
                        }
                    
                    # Get service
                    service_elem = port.find('.//service')
                    if service_elem is not None:
                        service_info = {
                            'name': service_elem.attrib.get('name', ''),
                            'product': service_elem.attrib.get('product', ''),
                            'version': service_elem.attrib.get('version', ''),
                            'extrainfo': service_elem.attrib.get('extrainfo', ''),
                            'method': service_elem.attrib.get('method', ''),
                            'conf': service_elem.attrib.get('conf', '')
                        }
                        port_info['service'] = service_info
                    
                    # Get scripts
                    scripts = []
                    for script in port.findall('.//script'):
                        script_info = {
                            'id': script.attrib.get('id', ''),
                            'output': script.attrib.get('output', '')
                        }
                        scripts.append(script_info)
                    
                    if scripts:
                        port_info['scripts'] = scripts
                    
                    host_info['ports'].append(port_info)
            
            scan_info['hosts'].append(host_info)
        
        return scan_info
    except Exception as e:
        print_error(f"Error parsing XML: {str(e)}")
        return None

def quick_port_scan(target, ports=None):
    """
    Perform a quick port scan using socket
    
    Args:
        target (str): The target to scan (IP or domain)
        ports (list): List of ports to scan
        
    Returns:
        list: Open ports
    """
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    
    print_status(f"Starting quick port scan on {target}")
    
    open_ports = []
    threads = []
    lock = threading.Lock()
    
    def scan_port(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            with lock:
                open_ports.append(port)
                print_success(f"Port {port} is open")
        sock.close()
    
    for port in ports:
        thread = threading.Thread(target=scan_port, args=(port,))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    return sorted(open_ports)

def masscan(target, output_dir, rate="1000", ports="1-65535"):
    """
    Perform a Masscan scan on the target
    
    Args:
        target (str): The target to scan (IP or domain)
        output_dir (str): Directory to save scan results
        rate (str): Packet rate
        ports (str): Port range to scan
        
    Returns:
        dict: Scan results
    """
    print_status(f"Starting Masscan on {target} (rate: {rate}, ports: {ports})")
    
    # Create output file
    output_file = os.path.join(output_dir, "masscan.json")
    
    # Build command
    command = ["masscan", target, "--rate", rate, "-p", ports, "-oJ", output_file]
    
    # Run scan
    start_time = time.time()
    result = run_command(command)
    end_time = time.time()
    
    scan_time = end_time - start_time
    
    if result['returncode'] == 0:
        print_success(f"Masscan completed in {scan_time:.2f} seconds")
        print_success(f"Results saved to {output_file}")
        
        # Parse results
        try:
            with open(output_file, 'r') as f:
                scan_results = json.load(f)
            return scan_results
        except Exception as e:
            print_error(f"Error parsing Masscan results: {str(e)}")
            return None
    else:
        print_error(f"Masscan failed: {result['stderr']}")
        return None

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
    
    # Perform quick port scan
    open_ports = quick_port_scan(target)
    print(f"Open ports: {open_ports}")
    
    # Perform Nmap scan
    nmap_scan(target, output_dir, quick=True)
    
    return 0

# Entry point
if __name__ == "__main__":
    sys.exit(main())