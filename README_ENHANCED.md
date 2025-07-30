# SPARM Enhanced v2.1

╔═══════════════════════════════════════════════════════════════╗
║  ███████╗██████╗  █████╗ ██████╗ ███╗   ███╗                  ║
║  ██╔════╝██╔══██╗██╔══██╗██╔══██╗████╗ ████║                  ║
║  ███████╗██████╔╝███████║██████╔╝██╔████╔██║                  ║
║  ╚════██║██╔═══╝ ██╔══██║██╔══██╗██║╚██╔╝██║                  ║
║  ███████║██║     ██║  ██║██║  ██║██║ ╚═╝ ██║                  ║
║  ╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝                  ║
║                                                               ║
║       Security Penetration & Attack Research Multitool       ║
║                      Enhanced Version 2.1                    ║
║                   Educational Use Only                        ║
╚═══════════════════════════════════════════════════════════════╝

A comprehensive, enhanced cybersecurity toolkit with intuitive UI, category-based organization, and extensive tool integration.

## 🆕 What's New in v2.1

### 🎨 Redesigned User Interface
- **Three-Column Layout**: Clean, organized display of tool categories
- **Name-Based Selection**: No more numbered menus - simply type tool or category names
- **Flexible Input**: Intelligent matching for partial names and common terms
- **Rich Visual Display**: Enhanced colors, emojis, and formatting

### 🏗️ Reorganized Tool Categories
- **🔍 Information Gathering** - OSINT, domain enumeration, reconnaissance
- **🌐 Scanning & Enumeration** - Port scanning, service discovery, enumeration
- **💥 Exploitation** - Exploit frameworks and vulnerability exploitation
- **⚡ Post-Exploitation** - Privilege escalation and persistence
- **👥 Social Engineering** - Social engineering toolkit and phishing
- **📡 Wi-Fi Attacks** - Wireless network testing and attacks
- **🌍 Web App Attacks** - Web application security testing
- **🛠️ Misc Tools** - Additional penetration testing utilities
- **🎯 Cyber Kill Chain** - Systematic attack methodology framework
- **💬 Discord Security Analysis** - Educational Discord security tools

### 🎯 Cyber Kill Chain Integration
Complete 7-phase attack methodology:
1. **Reconnaissance** - Intelligence gathering
2. **Weaponization** - Payload creation
3. **Delivery** - Attack transmission
4. **Exploitation** - Code execution
5. **Installation** - Malware installation
6. **Command & Control** - Remote access
7. **Actions on Objective** - Goal achievement

### 💬 Discord Security Analysis (Educational Only)
- **Token Structure Analyzer** - Understand Discord token format
- **Token Format Validator** - Educational token validation
- **Phishing Pattern Detector** - Identify common Discord scams
- **Security Scanner** - Discord server security assessment
- **Bot Permission Analyzer** - Analyze bot permission risks

## 🚀 Enhanced Installation

### Automatic Installation Script
```bash
# Run the enhanced installer
chmod +x install_enhanced.sh
./install_enhanced.sh
```

The installer automatically:
- Updates system packages
- Installs Python dependencies in virtual environment
- Installs penetration testing tools via package manager
- Downloads additional tools from GitHub
- Sets up wordlists and resources
- Creates desktop shortcuts
- Offers optional Metasploit installation

### Manual Installation
```bash
# Clone SPARM
git clone [repository-url] SPARM
cd SPARM

# Run enhanced installer
./install_enhanced.sh

# Or manual setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
chmod +x sparm.py
```

## 🎮 Enhanced Usage

### Launching SPARM
```bash
# Using the launcher (recommended)
python3 sparm.py

# Or with virtual environment
source venv/bin/activate
python3 sparm_main.py
```

### New User Experience
1. **Disclaimer** - Educational use agreement
2. **Three-Column Category Display** - Visual tool organization
3. **Natural Language Selection** - Type category or tool names
4. **Flexible Navigation** - Easy browsing and tool launching

### Example Interactions
```
SPARM > information gathering
# Opens Information Gathering category

SPARM > web app attacks  
# Opens Web Application Attacks category

SPARM > nmap
# Directly launches Nmap from any category

SPARM > cyber kill chain
# Shows complete attack methodology

SPARM > discord security
# Opens Discord security analysis tools
```

## 📊 Tool Categories Overview

### 🔍 Information Gathering
- **nmap** - Network discovery and security auditing
- **masscan** - High-speed port scanner
- **theharvester** - Email and subdomain harvester
- **sherlock** - Social media account hunter
- **maltego** - Link analysis and data mining
- **recon-ng** - Web reconnaissance framework

### 🌐 Scanning & Enumeration
- **gobuster** - Directory/file & DNS busting
- **dirb** - Web content scanner
- **nikto** - Web server scanner
- **enum4linux** - SMB enumeration tool
- **smbclient** - SMB/CIFS client

### 💥 Exploitation
- **metasploit** - Penetration testing framework
- **msfvenom** - Payload generator
- **searchsploit** - Exploit database search
- **commix** - Command injection testing
- **xsser** - XSS testing framework

### ⚡ Post-Exploitation
- **linpeas** - Linux privilege escalation scanner
- **winpeas** - Windows privilege escalation scanner
- **linux_exploit_suggester** - Kernel exploit suggestions
- **gtfobins** - Unix binary exploitation guide
- **pspy** - Process monitoring without root

### 👥 Social Engineering
- **setoolkit** - Social Engineering Toolkit
- **gophish** - Phishing framework
- **king_phisher** - Phishing campaign toolkit
- **evilginx** - Advanced phishing framework

### 📡 Wi-Fi Attacks
- **aircrack_suite** - Wireless network auditing
- **wifite** - Automated wireless attack tool
- **reaver** - WPS attack tool
- **bully** - WPS brute force attack

### 🌍 Web App Attacks
- **sqlmap** - Automated SQL injection tool
- **burpsuite** - Web application security testing
- **owasp_zap** - Web application security scanner
- **wpscan** - WordPress security scanner

### 🛠️ Misc Tools
- **hydra** - Network logon cracker
- **john** - Password cracker
- **hashcat** - Advanced password recovery
- **crunch** - Wordlist generator

## 🔧 Enhanced Features

### Intelligent Tool Matching
- **Partial Name Matching** - Type "info" for Information Gathering
- **Alias Support** - Common term recognition (scan → Scanning & Enumeration)
- **Flexible Input** - Case-insensitive, space-tolerant matching

### Rich Documentation Integration
- **Local Documentation Server** - Serve docs locally
- **Browser Integration** - Open documentation in web browser
- **Comprehensive Guides** - Detailed tool usage and methodologies

### Experience Level Adaptation
- **Beginner Mode** - Guided workflows with explanations
- **Intermediate Mode** - Balanced automation and guidance
- **Advanced Mode** - Minimal guidance, maximum control

## 📁 Enhanced Project Structure
```
SPARM/
├── sparm.py                    # Main launcher
├── sparm_main.py               # Enhanced interface
├── sparm_main_backup.py        # Original backup
├── install_enhanced.sh         # Automatic installer
├── requirements.txt            # Python dependencies
├── core/
│   ├── utils.py               # Enhanced UI utilities
│   └── config.py              # Configuration constants
├── modules/
│   ├── osint_toolkit.py       # OSINT tools
│   ├── reconnaissance.py      # Network reconnaissance
│   ├── web_vulnerability.py   # Web security testing
│   ├── sql_injection.py       # SQL injection testing
│   ├── credential_access.py   # Credential tools
│   ├── advanced_offensive.py  # Advanced exploitation
│   └── privacy_protection.py  # VPN/Tor integration
├── docs/
│   ├── sparm_documentation.html
│   └── enhanced_documentation.html
└── venv/                      # Virtual environment
```

## 🛡️ Security & Ethics

### Educational Purpose
- **Authorized Testing Only** - Use only on systems you own or have permission to test
- **Learning Focus** - Designed for cybersecurity education and defensive skills
- **Ethical Guidelines** - Built-in reminders about responsible use

### Discord Security Tools
All Discord-related tools are:
- **Educational Only** - For understanding security threats
- **Defensive Focused** - Designed to improve security awareness
- **Lab Environment** - Use only in controlled, authorized environments
- **No Malicious Intent** - Not designed for abuse or harm

## 🚀 Advanced Workflows

### Complete Penetration Test
1. **Information Gathering** → Use TheHarvester, Sherlock, Recon-ng
2. **Scanning & Enumeration** → Nmap, Gobuster, Nikto discovery
3. **Exploitation** → Metasploit, SQLMap, custom exploits
4. **Post-Exploitation** → LinPEAS, privilege escalation
5. **Documentation** → Report generation and findings

### Cyber Kill Chain Execution
1. **Reconnaissance** → OSINT gathering and target profiling
2. **Weaponization** → Payload creation with MSFVenom
3. **Delivery** → Social engineering and phishing campaigns
4. **Exploitation** → Vulnerability exploitation and code execution
5. **Installation** → Persistence and backdoor installation
6. **C2** → Command and control establishment
7. **Actions** → Objective completion and data exfiltration

## 🤝 Contributing

### Enhancement Guidelines
- Maintain educational focus and ethical standards
- Follow the three-column UI design pattern
- Add comprehensive tool descriptions
- Include beginner-friendly explanations
- Test all functionality thoroughly

### Tool Addition Process
1. Add tool to appropriate category in `sparm_main.py`
2. Implement tool launcher in relevant module
3. Update documentation and help text
4. Test with all experience levels

## 📄 License & Disclaimer

**Educational Use Only** - This toolkit is designed for:
- Cybersecurity education and training
- Authorized penetration testing
- Security research in controlled environments
- Defensive security skill development

**Not Intended For:**
- Unauthorized system access
- Malicious activities
- Production system testing without permission
- Any illegal or unethical use

## ⚡ Quick Start Commands

```bash
# Complete setup in one command
git clone [repo] SPARM && cd SPARM && ./install_enhanced.sh

# Launch SPARM
python3 sparm.py

# Example usage
SPARM > information gathering
SPARM > nmap
SPARM > web app attacks  
SPARM > sqlmap
SPARM > cyber kill chain
SPARM > settings
```

## 🔗 Resources

### Tool Documentation
- **Nmap** - https://nmap.org/book/
- **SQLMap** - https://sqlmap.org/
- **Metasploit** - https://www.metasploit.com/
- **TheHarvester** - https://github.com/laramies/theHarvester

### Learning Resources
- **OWASP Testing Guide** - https://owasp.org/www-project-web-security-testing-guide/
- **NIST Cybersecurity Framework** - https://www.nist.gov/cyberframework
- **SANS Penetration Testing** - https://www.sans.org/cyber-security-courses/

---

**Remember: Use responsibly, test ethically, learn continuously! 🛡️**

*SPARM Enhanced v2.1 - Empowering ethical hackers and cybersecurity professionals with organized, intuitive, and comprehensive security testing tools.*