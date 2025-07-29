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

### Example Workflow
1. **OSINT Phase**: Use TheHarvester to gather emails and subdomains
2. **Reconnaissance**: Scan with Nmap to discover open ports and services
3. **Web Assessment**: Check for web vulnerabilities with the custom scanner
4. **SQL Injection**: Test for database vulnerabilities with SQLMap
5. **Credential Access**: Attempt to crack passwords with Hydra or John
6. **Privilege Escalation**: Use LinPEAS to find escalation vectors

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

# Clean installation
rm -rf venv && python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt
```

---

**Remember**: tver ey kor ban oy ta coppsary