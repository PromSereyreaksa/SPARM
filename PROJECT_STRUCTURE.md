# SPARM - Security Penetration & Research Multitool

## 📁 Project Structure (Cleaned & Organized)

```
SPARM/
├── 🚀 MAIN LAUNCHER
│   ├── sparm.py              # Main launcher (uses venv)
│   └── sparm_main.py         # Core application
│
├── 📚 CORE MODULES
│   └── core/
│       ├── __init__.py
│       ├── config.py         # Configuration & wordlists
│       └── utils.py          # Utilities & logging
│
├── 🛠️ SECURITY MODULES  
│   └── modules/
│       ├── __init__.py
│       ├── credential_access.py    # Hydra, John, Hashcat
│       ├── reconnaissance.py       # Nmap, scanning tools
│       ├── web_vulnerability.py    # Nikto, web scanners
│       ├── sql_injection.py        # SQLMap tools
│       ├── osint_toolkit.py        # OSINT gathering
│       ├── privacy_protection.py   # Privacy tools
│       └── advanced_offensive.py   # Advanced tools
│
├── 🧪 TESTING SUITE
│   └── tests/
│       ├── __init__.py
│       ├── test_sparm_tools.py     # Comprehensive tests
│       ├── quick_test.py           # Quick validation
│       └── dvwa_tool_tests.py      # DVWA specific tests
│
├── 📊 LOGS & OUTPUTS
│   └── logs/                       # Session logs & test results
│       ├── tool_test_*.txt         # Tool test results
│       ├── comprehensive_test_*.txt # Full test logs
│       └── [tool]_*.log           # Individual tool sessions
│
├── 📖 DOCUMENTATION
│   └── docs/
│       └── enhanced_documentation.html
│
├── 🗂️ WORDLISTS (SecLists)
│   └── SecLists-master/            # Complete SecLists collection
│       ├── Passwords/              # Password wordlists
│       ├── Usernames/              # Username wordlists
│       ├── Discovery/              # Discovery wordlists
│       └── [...]                   # Other categories
│
├── ⚙️ CONFIGURATION
│   ├── requirements.txt            # Python dependencies
│   ├── install.sh                  # Installation script
│   └── README.md                   # Project documentation
│
└── 🐍 VIRTUAL ENVIRONMENT
    └── venv/                       # Python virtual environment
```

## 🎯 Key Features Implemented

### ✅ Enhanced Hydra Tool
- **SecList Integration**: Choose from categorized wordlists
- **Custom Wordlist Support**: Specify your own wordlist paths
- **Real-time Output**: Live streaming output like the actual tool
- **Session Logging**: Complete session logs with timestamps

### ✅ Comprehensive Testing
- **DVWA Integration**: All tools tested against localhost:8080
- **Tool Verification**: Validates all security tools are working
- **Module Testing**: Tests Python modules and utilities
- **Automated Logging**: All test results logged to txt files

### ✅ Output Preservation
- **No Screen Clearing**: Output remains visible when exiting tools
- **Session Persistence**: All tool outputs logged to files
- **Documentation Ready**: Perfect for penetration testing reports

### ✅ Clean Architecture
- **Modular Design**: Each security category in separate modules
- **Consistent Interface**: Unified user experience across tools
- **Proper Logging**: Structured logging for all operations
- **Error Handling**: Robust error handling and recovery

## 🚀 Quick Start

```bash
# Launch SPARM
python3 sparm.py

# Run tests
python3 tests/quick_test.py
python3 tests/dvwa_tool_tests.py

# Check logs
ls -la logs/
```

## 📊 Test Results Summary

All major tools verified against DVWA localhost:8080:
- ✅ **Nmap**: Port scanning and service detection
- ✅ **Nikto**: Web vulnerability scanning  
- ✅ **SQLMap**: SQL injection testing
- ✅ **Gobuster**: Directory enumeration
- ✅ **Hydra**: Authentication brute forcing
- ✅ **Core Modules**: All Python modules working
- ✅ **SecLists**: Wordlist integration functional
- ✅ **Logging**: Session logging operational

## 🔒 Security Notice

This tool is designed for:
- ✅ Authorized penetration testing
- ✅ Cybersecurity education and research  
- ✅ CTF competitions and practice
- ✅ Personal lab environments (like DVWA)

**⚠️ DO NOT use on systems without explicit permission ⚠️**