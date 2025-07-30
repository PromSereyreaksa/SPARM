#!/bin/bash

# SPARM Installation Script for Linux (Kali Linux/Ubuntu/Debian)
# Security Penetration & Research Multitool Setup

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Print functions
print_banner() {
    echo -e "${CYAN}"
    echo "┌─────────────────────────────────────────────────────────┐"
    echo "│  ███████╗██████╗  █████╗ ██████╗ ███╗   ███╗             │"
    echo "│  ██╔════╝██╔══██╗██╔══██╗██╔══██╗████╗ ████║             │"
    echo "│  ███████╗██████╔╝███████║██████╔╝██╔████╔██║             │"
    echo "│  ╚════██║██╔═══╝ ██╔══██║██╔══██╗██║╚██╔╝██║             │"
    echo "│  ███████║██║     ██║  ██║██║  ██║██║ ╚═╝ ██║             │"
    echo "│  ╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝             │"
    echo "│                                                         │"
    echo "│          Installation Script v2.0                      │"
    echo "│     Educational Cybersecurity Toolkit Setup            │"
    echo "└─────────────────────────────────────────────────────────┘"
    echo -e "${NC}"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "This script should not be run as root. Please run as a regular user."
        exit 1
    fi
}

# Detect Linux distribution
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    else
        print_error "Cannot detect Linux distribution"
        exit 1
    fi
    
    print_info "Detected: $PRETTY_NAME"
}

# Update package lists
update_packages() {
    print_info "Updating package lists..."
    case $DISTRO in
        kali|debian|ubuntu)
            sudo apt update -qq
            ;;
        fedora|centos|rhel)
            sudo dnf check-update -q || true
            ;;
        arch|manjaro)
            sudo pacman -Sy --noconfirm
            ;;
        *)
            print_warning "Unsupported distribution: $DISTRO"
            ;;
    esac
    print_success "Package lists updated"
}

# Install Python dependencies
install_python_deps() {
    print_info "Setting up Python environment..."
    
    # Check if Python 3 is installed
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed. Please install Python 3.8+ first."
        exit 1
    fi
    
    # Create virtual environment
    if [ ! -d "venv" ]; then
        print_info "Creating Python virtual environment..."
        python3 -m venv venv
        print_success "Virtual environment created"
    else
        print_info "Virtual environment already exists"
    fi
    
    # Activate virtual environment and install requirements
    print_info "Installing Python packages..."
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
    print_success "Python dependencies installed"
}

# Install cybersecurity tools
install_security_tools() {
    print_info "Installing cybersecurity tools..."
    
    case $DISTRO in
        kali)
            # Kali Linux has most tools pre-installed
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
                theharvester \
                amass \
                sherlock \
                metasploit-framework \
                tor \
                proxychains4 \
                aircrack-ng \
                burpsuite \
                wireshark \
                netcat-traditional \
                socat \
                ncat \
                curl \
                wget \
                git
            ;;
        ubuntu|debian)
            # Install available tools
            sudo apt install -y \
                nmap \
                gobuster \
                dirb \
                nikto \
                sqlmap \
                hydra \
                john \
                hashcat \
                tor \
                proxychains4 \
                aircrack-ng \
                wireshark \
                netcat-openbsd \
                socat \
                curl \
                wget \
                git \
                python3-pip \
                python3-venv
                
            # Install additional tools from source/pip
            install_additional_tools
            ;;
        *)
            print_warning "Installing basic tools for $DISTRO..."
            install_basic_tools
            ;;
    esac
    
    print_success "Security tools installation completed"
}

# Install additional tools not in standard repos
install_additional_tools() {
    print_info "Installing additional tools..."
    
    # Create tools directory
    mkdir -p ~/.local/bin
    
    # Install theHarvester if not available
    if ! command -v theHarvester &> /dev/null; then
        print_info "Installing theHarvester..."
        cd /tmp
        git clone https://github.com/laramies/theHarvester.git
        cd theHarvester
        pip3 install --user -r requirements.txt
        sudo ln -sf "$(pwd)/theHarvester.py" /usr/local/bin/theHarvester
        cd - > /dev/null
    fi
    
    # Install Amass if not available
    if ! command -v amass &> /dev/null; then
        print_info "Installing Amass..."
        cd /tmp
        wget -q https://github.com/OWASP/Amass/releases/download/v3.23.3/amass_linux_amd64.zip
        unzip -q amass_linux_amd64.zip
        sudo mv amass_linux_amd64/amass /usr/local/bin/
        rm -rf amass_linux_amd64*
        cd - > /dev/null
    fi
    
    # Install Sherlock if not available
    if ! command -v sherlock &> /dev/null; then
        print_info "Installing Sherlock..."
        pip3 install --user sherlock-project
    fi
}

# Install basic tools for unsupported distributions
install_basic_tools() {
    case $DISTRO in
        fedora|centos|rhel)
            sudo dnf install -y nmap curl wget git python3-pip
            ;;
        arch|manjaro)
            sudo pacman -S --noconfirm nmap curl wget git python-pip
            ;;
    esac
}

# Setup wordlists
setup_wordlists() {
    print_info "Setting up wordlists..."
    
    WORDLIST_DIR="$HOME/.sparm/wordlists"
    mkdir -p "$WORDLIST_DIR"
    
    # Download common wordlists if they don't exist
    if [ ! -f "$WORDLIST_DIR/common.txt" ]; then
        print_info "Downloading common wordlists..."
        cd "$WORDLIST_DIR"
        
        # SecLists (if not already available)
        if [ ! -d "/usr/share/seclists" ] && [ ! -d "$WORDLIST_DIR/SecLists" ]; then
            git clone https://github.com/danielmiessler/SecLists.git
        fi
        
        # Create symlinks to common wordlists
        if [ -d "/usr/share/wordlists" ]; then
            ln -sf /usr/share/wordlists/* . 2>/dev/null || true
        fi
        
        cd - > /dev/null
    fi
    
    print_success "Wordlists setup completed"
}

# Set proper permissions
set_permissions() {
    print_info "Setting file permissions..."
    chmod +x sparm.py
    chmod +x sparm_main.py
    if [ -f "serve_docs.py" ]; then
        chmod +x serve_docs.py
    fi
    print_success "Permissions set"
}

# Create desktop entry (optional)
create_desktop_entry() {
    if command -v desktop-file-install &> /dev/null; then
        print_info "Creating desktop entry..."
        cat > sparm.desktop << EOF
[Desktop Entry]
Name=SPARM
Comment=Security Penetration & Research Multitool
Exec=$(pwd)/sparm.py
Icon=security-high
Terminal=true
Type=Application
Categories=Network;Security;
EOF
        desktop-file-install --dir="$HOME/.local/share/applications" sparm.desktop
        rm sparm.desktop
        print_success "Desktop entry created"
    fi
}

# Verify installation
verify_installation() {
    print_info "Verifying installation..."
    
    # Check Python environment
    if [ -d "venv" ] && [ -f "venv/bin/python" ]; then
        print_success "Python virtual environment: OK"
    else
        print_error "Python virtual environment: FAILED"
        return 1
    fi
    
    # Check main script
    if [ -f "sparm.py" ] && [ -x "sparm.py" ]; then
        print_success "Main script: OK"
    else
        print_error "Main script: FAILED"
        return 1
    fi
    
    # Check some core tools
    local tools=("nmap" "curl" "wget" "python3")
    for tool in "${tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            print_success "$tool: OK"
        else
            print_warning "$tool: Not found"
        fi
    done
    
    print_success "Installation verification completed"
}

# Main installation function
main() {
    print_banner
    
    echo -e "${YELLOW}SPARM Installation Script${NC}"
    echo "This script will install SPARM and its dependencies on your Linux system."
    echo
    
    read -p "Do you want to continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Installation cancelled."
        exit 0
    fi
    
    echo
    print_info "Starting SPARM installation..."
    
    check_root
    detect_distro
    update_packages
    install_python_deps
    install_security_tools
    setup_wordlists
    set_permissions
    create_desktop_entry
    verify_installation
    
    echo
    print_success "SPARM installation completed!"
    echo
    echo -e "${CYAN}Usage:${NC}"
    echo "  ./sparm.py                 # Run SPARM"
    echo "  python3 sparm.py           # Alternative way to run"
    echo "  source venv/bin/activate   # Activate Python environment manually"
    echo
    echo -e "${YELLOW}Note:${NC} Use SPARM responsibly and only in authorized environments."
    echo -e "${YELLOW}Educational and research purposes only.${NC}"
}

# Run main function
main "$@"