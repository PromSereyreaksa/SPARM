#!/usr/bin/env python3
"""
Quick SPARM Testing Script
"""

import subprocess
import sys
import os
from datetime import datetime

def log_test(message, log_file):
    """Log test message"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}")
    with open(log_file, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

def main():
    """Run quick tests"""
    # Ensure logs directory exists
    os.makedirs("/home/s001kaliv1/Desktop/SPARM/logs", exist_ok=True)
    
    log_file = f"/home/s001kaliv1/Desktop/SPARM/logs/quick_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    log_test("=== SPARM QUICK TESTING STARTED ===", log_file)
    
    # Test 1: DVWA Connectivity
    log_test("Testing DVWA connectivity...", log_file)
    try:
        result = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "http://localhost:8080"], 
                              capture_output=True, text=True, timeout=10)
        if result.stdout.strip() in ["200", "302", "301"]:
            log_test("✅ DVWA connectivity successful", log_file)
        else:
            log_test(f"❌ DVWA connectivity failed - HTTP code: {result.stdout.strip()}", log_file)
    except Exception as e:
        log_test(f"❌ DVWA connectivity error: {e}", log_file)
    
    # Test 2: Nmap scan
    log_test("Testing Nmap scan...", log_file)
    try:
        result = subprocess.run(["nmap", "-p", "8080", "localhost"], 
                              capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            log_test("✅ Nmap scan successful", log_file)
            log_test(f"Nmap output: {result.stdout[:200]}...", log_file)
        else:
            log_test(f"❌ Nmap scan failed: {result.stderr}", log_file)
    except Exception as e:
        log_test(f"❌ Nmap test error: {e}", log_file)
    
    # Test 3: Check tool availability
    tools_to_check = ["nmap", "nikto", "sqlmap", "hydra", "gobuster", "dirb"]
    log_test("Checking tool availability...", log_file)
    
    for tool in tools_to_check:
        try:
            result = subprocess.run(["which", tool], capture_output=True, text=True)
            if result.returncode == 0:
                log_test(f"✅ {tool} found at {result.stdout.strip()}", log_file)
            else:
                log_test(f"❌ {tool} not found", log_file)
        except Exception as e:
            log_test(f"❌ Error checking {tool}: {e}", log_file)
    
    # Test 4: SecLists availability
    log_test("Checking SecLists availability...", log_file)
    seclist_dir = "/home/s001kaliv1/Desktop/SPARM/SecLists-master"
    if os.path.exists(seclist_dir):
        log_test("✅ SecLists directory found", log_file)
        
        # Check specific wordlists
        wordlists = [
            "Passwords/Common-Credentials/best1050.txt",
            "Usernames/top-usernames-shortlist.txt"
        ]
        
        for wl in wordlists:
            path = os.path.join(seclist_dir, wl)
            if os.path.exists(path):
                log_test(f"✅ Found wordlist: {wl}", log_file)
            else:
                log_test(f"❌ Missing wordlist: {wl}", log_file)
    else:
        log_test("❌ SecLists directory not found", log_file)
    
    # Test 5: Python modules import
    log_test("Testing Python module imports...", log_file)
    try:
        sys.path.insert(0, "/home/s001kaliv1/Desktop/SPARM")
        from core.utils import validate_ip, validate_domain
        from core.config import WORDLISTS, TOOL_PATHS
        
        if validate_ip("127.0.0.1") and validate_domain("localhost"):
            log_test("✅ Core utilities working", log_file)
        else:
            log_test("❌ Core utilities failed", log_file)
            
        log_test(f"✅ Configuration loaded - {len(WORDLISTS)} wordlist categories", log_file)
        log_test(f"✅ Configuration loaded - {len(TOOL_PATHS)} tool paths", log_file)
        
    except Exception as e:
        log_test(f"❌ Module import error: {e}", log_file)
    
    log_test("=== SPARM QUICK TESTING COMPLETED ===", log_file)
    print(f"\n📊 Test results logged to: {log_file}")
    
    return log_file

if __name__ == "__main__":
    main()