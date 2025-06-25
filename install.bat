@echo off
REM Qanas Installation Script for Windows
REM Developed by Saudi Linux (SaudiLinux1@gmail.com)

echo.
echo   ██████╗  █████╗ ███╗   ██╗ █████╗ ███████╗
echo  ██╔═══██╗██╔══██╗████╗  ██║██╔══██╗██╔════╝
echo  ██║   ██║███████║██╔██╗ ██║███████║███████╗
echo  ██║▄▄ ██║██╔══██║██║╚██╗██║██╔══██║╚════██║
echo  ╚██████╔╝██║  ██║██║ ╚████║██║  ██║███████║
echo   ╚══▀▀═╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝
echo                                 قناص
echo.
echo        Developed by Saudi Linux
echo        Email: SaudiLinux1@gmail.com
echo.

REM Check for Python installation
echo [*] Checking for Python installation...
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] Python is not installed or not in PATH.
    echo [i] Please install Python 3.8+ from https://www.python.org/downloads/
    exit /b 1
) else (
    for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
    echo [+] Found Python %PYTHON_VERSION%
)

REM Create necessary directories
echo [*] Creating necessary directories...
if not exist loot mkdir loot
if not exist modules mkdir modules
if not exist templates mkdir templates
if not exist plugins mkdir plugins
if not exist assets mkdir assets
if not exist wordlists mkdir wordlists
echo [+] Directories created

REM Install Python dependencies
echo [*] Installing Python dependencies...
pip install -r requirements.txt
if %ERRORLEVEL% NEQ 0 (
    echo [!] Failed to install Python dependencies.
    exit /b 1
) else (
    echo [+] Python dependencies installed
)

REM Check for external tools
echo [*] Checking for external tools...

where nmap >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] Nmap is not installed or not in PATH.
    echo [i] Consider installing Nmap using Chocolatey: choco install nmap
    echo [i] Or download from https://nmap.org/download.html
) else (
    echo [+] Nmap is installed
)

where whois >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] Whois is not installed or not in PATH.
    echo [i] Consider installing Whois using Chocolatey: choco install whois
) else (
    echo [+] Whois is installed
)

where host >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] Host command is not installed or not in PATH.
    echo [i] Consider installing BIND tools using Chocolatey: choco install bind-toolsonly
) else (
    echo [+] Host command is installed
)

echo.
echo [+] Qanas has been successfully installed!
echo [i] You can now run 'python qanas.py --help' to see available options
echo [i] For full functionality, please install the missing external tools mentioned above
echo.

pause