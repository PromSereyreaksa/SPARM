#!/usr/bin/env python3

import os
from pathlib import Path

# Application Configuration
APP_NAME = "SPARM"
APP_VERSION = "2.0.0"
APP_DESCRIPTION = "Security Penetration & Research Multitool"

# HTTP Headers for web requests
headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}

# Tool Categories and their descriptions
CATEGORIES = {
    "osint": {
        "name": "OSINT & Information Gathering",
        "description": "Open Source Intelligence tools for reconnaissance",
        "next_steps": [
            "Perform network reconnaissance with Nmap",
            "Check for web vulnerabilities",
            "Gather email addresses and subdomains"
        ]
    },
    "recon": {
        "name": "Network Reconnaissance", 
        "description": "Network scanning and enumeration tools",
        "next_steps": [
            "Perform directory bruteforcing",
            "Check for common vulnerabilities",
            "Enumerate services and versions"
        ]
    },
    "web_vuln": {
        "name": "Web Vulnerability Assessment",
        "description": "Web application security testing tools",
        "next_steps": [
            "Test for SQL injection vulnerabilities",
            "Check for XSS vulnerabilities", 
            "Perform directory traversal tests"
        ]
    },
    "sql_injection": {
        "name": "SQL Injection Testing",
        "description": "Database injection and exploitation tools",
        "next_steps": [
            "Dump database contents",
            "Escalate privileges",
            "Extract sensitive data"
        ]
    },
    "credential_access": {
        "name": "Credential Access",
        "description": "Password cracking and credential harvesting",
        "next_steps": [
            "Crack password hashes",
            "Perform credential stuffing",
            "Check for default credentials"
        ]
    },
    "privilege_escalation": {
        "name": "Privilege Escalation",
        "description": "Local and remote privilege escalation",
        "next_steps": [
            "Run automated enumeration scripts",
            "Check for kernel exploits",
            "Look for misconfigurations"
        ]
    }
}

# Experience levels
EXPERIENCE_LEVELS = {
    "beginner": {
        "name": "🎓 Beginner",
        "description": "Guided mode with explanations and recommendations"
    },
    "intermediate": {
        "name": "⚡ Intermediate", 
        "description": "Balanced mode with some automation"
    },
    "advanced": {
        "name": "🔥 Advanced",
        "description": "Expert mode with minimal guidance"
    }
}

# Common wordlists and paths (Kali Linux)
WORDLISTS = {
    "directories": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "subdomains": "/usr/share/wordlists/amass/subdomains-top1mil-5000.txt",
    "passwords": "/usr/share/wordlists/rockyou.txt",
    "usernames": "/usr/share/wordlists/metasploit/unix_users.txt"
}

# Tool paths (common Kali Linux locations)
TOOL_PATHS = {
    "nmap": "/usr/bin/nmap",
    "sqlmap": "/usr/bin/sqlmap", 
    "hydra": "/usr/bin/hydra",
    "gobuster": "/usr/bin/gobuster",
    "nikto": "/usr/bin/nikto",
    "john": "/usr/bin/john",
    "hashcat": "/usr/bin/hashcat",
    "theharvester": "/usr/bin/theHarvester",
    "amass": "/usr/bin/amass",
    "recon-ng": "/usr/bin/recon-ng"
}

# Educational disclaimer
DISCLAIMER = """
⚠️  EDUCATIONAL USE ONLY ⚠️

This tool is designed for:
• Authorized penetration testing
• Cybersecurity education and research  
• CTF competitions and practice
• Personal lab environments

DO NOT use this tool on systems you do not own or have explicit permission to test.
Unauthorized access to computer systems is illegal and unethical.

By using this tool, you agree to use it responsibly and within legal boundaries.
"""