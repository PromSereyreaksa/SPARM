#!/bin/bash

# SPARM Enhanced Installation Script
# Automatically installs dependencies and security tools for SPARM toolkit

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                    SPARM Enhanced Installer                      ║"
echo "║              Security Penetration & Research Multitool          ║"
echo "║                        Educational Use Only                      ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}[!] Please don't run this script as root${NC}"
   echo -e "${YELLOW}[!] Some tools work better when installed as regular user${NC}"
   read -p "Continue anyway? (y/N): " -n 1 -r
   echo
   if [[ ! $REPLY =~ ^[Yy]$ ]]; then
       exit 1
   fi
fi

# Function to print status
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Update system packages
update_system() {
    print_status "Updating system packages..."
    
    if command_exists apt; then
        sudo apt update && sudo apt upgrade -y
    elif command_exists yum; then
        sudo yum update -y
    elif command_exists dnf; then
        sudo dnf update -y
    elif command_exists pacman; then
        sudo pacman -Syu --noconfirm
    else
        print_warning "Unknown package manager. Please update manually."
    fi
}

# Install Python dependencies
install_python_deps() {
    print_status "Installing Python dependencies..."
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        print_success "Created virtual environment"
    fi
    
    # Activate virtual environment and install requirements
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
    
    print_success "Python dependencies installed"
}

# Install system tools
install_system_tools() {
    print_status "Installing system penetration testing tools..."
    
    if command_exists apt; then
        # Debian/Ubuntu
        sudo apt install -y \
            nmap \
            masscan \
            gobuster \
            dirb \
            nikto \
            sqlmap \
            hydra \
            john \
            hashcat \
            aircrack-ng \
            reaver \
            wifite \
            enum4linux \
            smbclient \
            curl \
            wget \
            git \
            python3-pip \
            python3-venv \
            build-essential \
            dnsutils \
            whois \
            netcat \
            socat \
            ncat
            
    elif command_exists yum || command_exists dnf; then
        # RHEL/CentOS/Fedora
        PKG_MANAGER="yum"
        if command_exists dnf; then
            PKG_MANAGER="dnf"
        fi
        
        sudo $PKG_MANAGER install -y \
            nmap \
            gobuster \
            dirb \
            nikto \
            sqlmap \
            hydra \
            john \
            hashcat \
            aircrack-ng \
            curl \
            wget \
            git \
            python3-pip \
            python3-venv \
            gcc \
            make \
            bind-utils \
            whois \
            nc \
            socat
            
    elif command_exists pacman; then
        # Arch Linux
        sudo pacman -S --noconfirm \
            nmap \
            masscan \
            gobuster \
            dirb \
            nikto \
            sqlmap \
            hydra \
            john \
            hashcat \
            aircrack-ng \
            reaver \
            curl \
            wget \
            git \
            python-pip \
            base-devel \
            bind-tools \
            whois \
            gnu-netcat \
            socat
    fi
    
    print_success "System tools installation completed"
}

# Install GitHub tools
install_github_tools() {
    print_status "Installing additional tools from GitHub..."
    
    # Create tools directory
    mkdir -p ~/sparm-tools
    cd ~/sparm-tools
    
    # LinPEAS/WinPEAS
    if [ ! -d "PEASS-ng" ]; then
        print_status "Installing PEASS-ng (LinPEAS/WinPEAS)..."
        git clone https://github.com/carlospolop/PEASS-ng.git
        print_success "PEASS-ng installed"
    fi
    
    # Linux Exploit Suggester
    if [ ! -d "linux-exploit-suggester" ]; then
        print_status "Installing Linux Exploit Suggester..."
        git clone https://github.com/mzet-/linux-exploit-suggester.git
        chmod +x linux-exploit-suggester/linux-exploit-suggester.sh
        print_success "Linux Exploit Suggester installed"
    fi
    
    # TheHarvester
    if [ ! -d "theHarvester" ]; then
        print_status "Installing theHarvester..."
        git clone https://github.com/laramies/theHarvester.git
        cd theHarvester
        python3 -m pip install -r requirements/base.txt
        cd ..
        print_success "theHarvester installed"
    fi
    
    # Sherlock
    if [ ! -d "sherlock" ]; then
        print_status "Installing Sherlock..."
        git clone https://github.com/sherlock-project/sherlock.git
        cd sherlock
        python3 -m pip install -r requirements.txt
        cd ..
        print_success "Sherlock installed"
    fi
    
    # SecLists (wordlists)
    if [ ! -d "SecLists" ]; then
        print_status "Installing SecLists wordlists..."
        git clone https://github.com/danielmiessler/SecLists.git
        print_success "SecLists installed"
    fi
    
    # Impacket
    if [ ! -d "impacket" ]; then
        print_status "Installing Impacket..."
        git clone https://github.com/SecureAuthCorp/impacket.git
        cd impacket
        python3 -m pip install .
        cd ..
        print_success "Impacket installed"
    fi
    
    # Return to SPARM directory
    cd - > /dev/null
}

# Install Metasploit (if not already installed)
install_metasploit() {
    if ! command_exists msfconsole; then
        print_status "Installing Metasploit Framework..."
        
        # Download and run Metasploit installer
        curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
        chmod 755 msfinstall
        ./msfinstall
        rm msfinstall
        
        print_success "Metasploit Framework installed"
    else
        print_success "Metasploit Framework already installed"
    fi
}

# Setup wordlists
setup_wordlists() {
    print_status "Setting up wordlists..."
    
    # Create wordlists directory if it doesn't exist
    sudo mkdir -p /usr/share/wordlists
    
    # Download rockyou.txt if not present
    if [ ! -f "/usr/share/wordlists/rockyou.txt" ]; then
        print_status "Downloading rockyou.txt wordlist..."
        sudo wget -O /usr/share/wordlists/rockyou.txt.gz \
            https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
        sudo gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
        print_success "rockyou.txt wordlist installed"
    fi
    
    # Link SecLists if installed
    if [ -d "~/sparm-tools/SecLists" ]; then
        sudo ln -sf ~/sparm-tools/SecLists /usr/share/wordlists/seclists 2>/dev/null || true
    fi
}

# Install Go tools
install_go_tools() {
    if command_exists go; then
        print_status "Installing Go-based security tools..."
        
        # Gobuster (if not installed via package manager)
        if ! command_exists gobuster; then
            go install github.com/OJ/gobuster/v3@latest
        fi
        
        # Subfinder
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        
        # httpx
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
        
        print_success "Go tools installed"
    else
        print_warning "Go not installed, skipping Go tools"
    fi
}

# Create desktop shortcut
create_desktop_shortcut() {
    print_status "Creating desktop shortcut..."
    
    DESKTOP_DIR="$HOME/Desktop"
    if [ ! -d "$DESKTOP_DIR" ]; then
        DESKTOP_DIR="$HOME"
    fi
    
    cat > "$DESKTOP_DIR/SPARM.desktop" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=SPARM Toolkit
Comment=Security Penetration & Research Multitool
Exec=gnome-terminal -- bash -c 'cd $(pwd) && python3 sparm.py; exec bash'
Icon=utilities-terminal
Terminal=false
Categories=Security;Development;
EOF
    
    chmod +x "$DESKTOP_DIR/SPARM.desktop"
    print_success "Desktop shortcut created"
}

# Main installation process
main() {
    echo -e "${CYAN}[INFO] Starting SPARM installation...${NC}"
    echo -e "${YELLOW}[WARNING] This script will install various security tools${NC}"
    echo -e "${YELLOW}[WARNING] Ensure you have permission to install these tools${NC}"
    echo
    
    read -p "Continue with installation? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Installation cancelled."
        exit 0
    fi
    
    echo
    print_status "Starting installation process..."
    
    # Run installation steps
    update_system
    install_python_deps
    install_system_tools
    install_github_tools
    setup_wordlists
    install_go_tools
    
    # Optional Metasploit installation
    echo
    read -p "Install Metasploit Framework? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_metasploit
    fi
    
    create_desktop_shortcut
    
    echo
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    Installation Complete!                       ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${CYAN}[INFO] SPARM has been successfully installed!${NC}"
    echo -e "${CYAN}[INFO] Run with: python3 sparm.py${NC}"
    echo -e "${CYAN}[INFO] Additional tools installed in: ~/sparm-tools/${NC}"
    echo -e "${CYAN}[INFO] Wordlists available in: /usr/share/wordlists/${NC}"
    echo
    echo -e "${YELLOW}[REMINDER] This toolkit is for educational and authorized testing only!${NC}"
    echo -e "${YELLOW}[REMINDER] Always ensure you have permission before testing any system.${NC}"
    echo
    
    # Offer to run SPARM immediately
    read -p "Would you like to run SPARM now? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        python3 sparm.py
    fi
}

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi