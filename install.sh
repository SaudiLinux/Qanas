#!/bin/bash

# Qanas Installation Script
# Developed by Saudi Linux (SaudiLinux1@gmail.com)

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logo display function
display_logo() {
    echo -e "${RED}"
    echo "  ██████╗  █████╗ ███╗   ██╗ █████╗ ███████╗"
    echo " ██╔═══██╗██╔══██╗████╗  ██║██╔══██╗██╔════╝"
    echo " ██║   ██║███████║██╔██╗ ██║███████║███████╗"
    echo " ██║▄▄ ██║██╔══██║██║╚██╗██║██╔══██║╚════██║"
    echo " ╚██████╔╝██║  ██║██║ ╚████║██║  ██║███████║"
    echo "  ╚══▀▀═╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝"
    echo -e "${YELLOW}                                قناص${NC}"
    echo -e "${BLUE}       Developed by Saudi Linux${NC}"
    echo -e "${BLUE}       Email: SaudiLinux1@gmail.com${NC}"
    echo ""
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[!] This script must be run as root${NC}"
        echo -e "${YELLOW}[i] Try: sudo $0${NC}"
        exit 1
    fi
}

# Check OS compatibility
check_os() {
    echo -e "${BLUE}[*] Checking operating system compatibility...${NC}"
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
        
        if [[ $OS == *"Kali"* ]] || [[ $OS == *"Ubuntu"* ]] || [[ $OS == *"Debian"* ]]; then
            echo -e "${GREEN}[✓] $OS $VER is compatible${NC}"
        else
            echo -e "${YELLOW}[!] $OS $VER might not be fully compatible${NC}"
            echo -e "${YELLOW}[i] Qanas is designed for Kali/Ubuntu/Debian systems${NC}"
            read -p "Do you want to continue anyway? (y/n): " choice
            if [[ $choice != "y" && $choice != "Y" ]]; then
                echo -e "${RED}[!] Installation aborted${NC}"
                exit 1
            fi
        fi
    else
        echo -e "${RED}[!] Unable to determine OS${NC}"
        read -p "Do you want to continue anyway? (y/n): " choice
        if [[ $choice != "y" && $choice != "Y" ]]; then
            echo -e "${RED}[!] Installation aborted${NC}"
            exit 1
        fi
    fi
}

# Create necessary directories
create_directories() {
    echo -e "${BLUE}[*] Creating necessary directories...${NC}"
    
    mkdir -p /usr/share/qanas
    mkdir -p /usr/share/qanas/loot
    mkdir -p /usr/share/qanas/modules
    mkdir -p /usr/share/qanas/templates
    mkdir -p /usr/share/qanas/plugins
    
    echo -e "${GREEN}[✓] Directories created${NC}"
}

# Install dependencies
install_dependencies() {
    echo -e "${BLUE}[*] Updating package lists...${NC}"
    apt-get update
    
    echo -e "${BLUE}[*] Installing dependencies...${NC}"
    apt-get install -y python3 python3-pip nmap whois nikto dirb sqlmap hydra metasploit-framework wpscan gobuster nbtscan enum4linux sslscan masscan theharvester whatweb wafw00f
    
    echo -e "${BLUE}[*] Installing Python dependencies...${NC}"
    pip3 install requests beautifulsoup4 colorama dnspython python-nmap paramiko shodan censys
    
    echo -e "${GREEN}[✓] Dependencies installed${NC}"
}

# Copy files to installation directory
copy_files() {
    echo -e "${BLUE}[*] Copying files to installation directory...${NC}"
    
    # Copy main script
    cp qanas.py /usr/share/qanas/
    cp -r modules/* /usr/share/qanas/modules/
    cp -r templates/* /usr/share/qanas/templates/
    cp -r plugins/* /usr/share/qanas/plugins/
    
    # Create symlink
    ln -sf /usr/share/qanas/qanas.py /usr/bin/qanas
    chmod +x /usr/bin/qanas
    
    echo -e "${GREEN}[✓] Files copied${NC}"
}

# Configure settings
configure_settings() {
    echo -e "${BLUE}[*] Configuring settings...${NC}"
    
    # Create config file
    cat > /usr/share/qanas/config.py << EOF
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Qanas Configuration File
# Developed by Saudi Linux (SaudiLinux1@gmail.com)

# General Settings
VERSION = "1.0.0"
AUTHOR = "Saudi Linux"
EMAIL = "SaudiLinux1@gmail.com"

# Paths
LOOT_DIR = "/usr/share/qanas/loot"
MODULES_DIR = "/usr/share/qanas/modules"
TEMPLATES_DIR = "/usr/share/qanas/templates"
PLUGINS_DIR = "/usr/share/qanas/plugins"

# API Keys (set these to your own keys)
SHODAN_API_KEY = ""
CENSYS_API_ID = ""
CENSYS_API_SECRET = ""

# Scan Settings
DEFAULT_THREADS = 10
DEFAULT_TIMEOUT = 60
DEFAULT_USER_AGENT = "Qanas/1.0"
EOF
    
    echo -e "${GREEN}[✓] Settings configured${NC}"
}

# Finalize installation
finalize_installation() {
    echo -e "${BLUE}[*] Finalizing installation...${NC}"
    
    echo -e "${GREEN}[✓] Qanas has been successfully installed!${NC}"
    echo -e "${YELLOW}[i] You can now run 'qanas' from anywhere in your terminal${NC}"
    echo -e "${YELLOW}[i] For usage instructions, run 'qanas --help'${NC}"
    echo -e "${PURPLE}[i] Consider setting up your API keys in /usr/share/qanas/config.py for full functionality${NC}"
}

# Main installation process
main() {
    clear
    display_logo
    check_root
    check_os
    create_directories
    install_dependencies
    copy_files
    configure_settings
    finalize_installation
}

# Run the main function
main