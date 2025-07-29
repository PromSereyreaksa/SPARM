# SPARM

╔═══════════════════════════════════════════════════════════════╗
║  ███████╗██████╗  █████╗ ██████╗ ███╗   ███╗                  ║
║  ██╔════╝██╔══██╗██╔══██╗██╔══██╗████╗ ████║                  ║
║  ███████╗██████╔╝███████║██████╔╝██╔████╔██║                  ║
║  ╚════██║██╔═══╝ ██╔══██║██╔══██╗██║╚██╔╝██║                  ║
║  ███████║██║     ██║  ██║██║  ██║██║ ╚═╝ ██║                  ║
║  ╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝                  ║
║                                                               ║
║        TVER EY KOR BAN OY TA COPPSARY                         ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

A comprehensive cybersecurity toolkit designed for Kali Linux.

## 🚀 Features

### Kill Chain Categories
- 🔍 **OSINT & Information Gathering** - TheHarvester, Amass, Sherlock
- 🌐 **Network Reconnaissance** - Nmap, Gobuster, Nikto
- 🛡️ **Web Vulnerability Assessment** - Custom scanner, XSSer, WPScan
- 💉 **SQL Injection Testing** - SQLMap integration with guided interface
- 🔑 **Credential Access** - Hydra, John the Ripper, Hashcat
- ⬆️ **Privilege Escalation** - LinPEAS, Linux Exploit Suggester, GTFOBins

### User Experience Features
- **Experience Levels**: Beginner, Intermediate, Advanced modes
- **Rich Terminal UI**: Beautiful interface with colors and formatting
- **Interactive Guidance**: Step-by-step instructions and next-step suggestions
- **Dynamic Command Building**: Interactive parameter selection for tools
- **Educational Context**: Explanations and best practices for beginners

## 🛠️ Installation

### Prerequisites
- Kali Linux (recommended)
- Python 3.8+
- Common pentesting tools (nmap, sqlmap, hydra, etc.)

### Setup
```bash
# Clone or download SPARM
cd /path/to/sparm

# Create virtual environment
python3 -m venv venv

# Activate virtual environment and install dependencies
source venv/bin/activate
pip install -r requirements.txt

# Make launcher executable
chmod +x sparm.py
```

## 🎯 Usage

### Launch SPARM
```bash
# Using the launcher (recommended)
./sparm.py

# Or directly with virtual environment
source venv/bin/activate
python multitools.py
```

### First Run
1. Accept the educational use disclaimer
2. Select your experience level (Beginner/Intermediate/Advanced)
3. Choose from the available tool categories
4. Follow the interactive prompts for each tool

### 📚 Enhanced Documentation
SPARM now includes comprehensive documentation with detailed methodologies:

- **Basic Documentation**: `docs/sparm_documentation.html` - Core tool usage and basic workflows
- **Enhanced Documentation**: `docs/enhanced_documentation.html` - Advanced techniques, combos, and complete methodologies

#### Documentation Features:
- **Complete Penetration Testing Methodology**: 6-phase approach from reconnaissance to reporting
- **Advanced Exploitation Combos**: Multi-step attack chains for web apps, networks, and databases
- **Gaining Complete Control**: Comprehensive guide to system domination techniques
- **Stealth and Evasion**: Advanced techniques for avoiding detection
- **Professional Reporting**: Templates and structures for pentest reports

### Example Workflow - Basic
1. **OSINT Phase**: Use TheHarvester to gather emails and subdomains
2. **Reconnaissance**: Scan with Nmap to discover open ports and services
3. **Web Assessment**: Check for web vulnerabilities with the custom scanner
4. **SQL Injection**: Test for database vulnerabilities with SQLMap
5. **Credential Access**: Attempt to crack passwords with Hydra or John
6. **Privilege Escalation**: Use LinPEAS to find escalation vectors

### Example Workflow - Advanced Complete Control
1. **Intelligence Gathering**: Multi-source OSINT with theHarvester, Amass, Sherlock
2. **Active Reconnaissance**: Network mapping with Nmap, service enumeration
3. **Vulnerability Assessment**: Automated scanning + manual testing
4. **Initial Exploitation**: SQL injection → web shell → reverse shell
5. **Privilege Escalation**: LinPEAS → kernel exploits → root access
6. **Persistence**: Multiple backdoors, rootkits, scheduled tasks
7. **Lateral Movement**: Network-wide compromise via credential reuse
8. **Data Exfiltration**: Sensitive data collection and secure transfer
9. **Complete Control**: Domain admin access, network-wide backdoors

## 📁 Project Structure
```
sparm/
├── sparm.py              # Main launcher script
├── multitools.py         # Main CLI interface
├── requirements.txt      # Python dependencies
├── core/
│   ├── __init__.py
│   ├── utils.py         # Utility functions and UI helpers
│   └── config.py        # Configuration and constants
└── modules/
    ├── __init__.py
    ├── osint_toolkit.py      # OSINT tools
    ├── reconnaissance.py     # Network reconnaissance
    ├── web_vulnerability.py  # Web security testing
    ├── sql_injection.py      # SQL injection testing
    └── credential_access.py  # Password and credential tools
```

## 🔧 Adding New Tools

To add a new tool to SPARM:

1. **Add to configuration** (`core/config.py`):
```python
CATEGORIES["new_category"] = {
    "name": "New Category Name",
    "description": "Description of the category",
    "next_steps": ["Step 1", "Step 2", "Step 3"]
}
```

2. **Create module** (`modules/new_module.py`):
```python
from core.utils import *
from core.config import *

class NewToolkit:
    def __init__(self):
        self.tools = {"tool_name": "description"}
    
    def run_tool(self):
        # Tool implementation
        pass
    
    def display_menu(self):
        # Menu implementation
        pass

def run():
    toolkit = NewToolkit()
    toolkit.display_menu()
```

3. **Add to main menu** (`multitools.py`):
```python
# Add menu item and routing logic
```


## 🤝 Contributing

Contributions are welcome! Please ensure:
- All tools are for educational/defensive purposes only
- Code follows the existing structure and style
- New features include proper documentation
- Security best practices are followed

## 📄 License

This project is for educational purposes only. Use responsibly and ethically.

## ⚡ Quick Commands

```bash
# Install all at once
python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt && chmod +x sparm.py

# Launch SPARM
./sparm.py

# View Enhanced Documentation
firefox docs/enhanced_documentation.html
# or
python3 serve_docs.py  # then visit http://localhost:8080/enhanced_documentation.html

# Clean installation
rm -rf venv && python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt
```

## 🔥 Advanced Features

### Complete Penetration Testing Combos
- **Web App to Shell**: SQL injection → file upload → reverse shell → privilege escalation
- **Network Domination**: SMB exploitation → credential harvesting → lateral movement → domain compromise
- **Stealth Operations**: Decoy scanning → obfuscated payloads → anti-forensics → persistent backdoors

### Professional Methodologies
- **OWASP Testing Guide** compliance
- **NIST Cybersecurity Framework** alignment  
- **PTES (Penetration Testing Execution Standard)** methodology
- **OSSTMM (Open Source Security Testing Methodology Manual)** practices

---

**Remember**: tver ey kor ban oy ta coppsary