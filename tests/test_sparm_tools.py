#!/usr/bin/env python3
"""
SPARM Tools Testing Suite
Tests all tools against localhost:8080 DVWA lab
"""

import unittest
import sys
import os
import subprocess
import time
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.utils import *
from core.config import *
from modules.credential_access import CredentialAccessToolkit
from modules.reconnaissance import *
from modules.web_vulnerability import *
from modules.sql_injection import *

class TestSPARMTools(unittest.TestCase):
    """Test SPARM tools against DVWA localhost:8080"""
    
    def setUp(self):
        """Set up test environment"""
        self.target = "localhost:8080"
        self.test_log_file = f"/home/s001kaliv1/Desktop/SPARM/logs/test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        self.log_message("=== SPARM TOOL TESTING STARTED ===")
        
        # Ensure logs directory exists
        os.makedirs(os.path.dirname(self.test_log_file), exist_ok=True)
        
    def log_message(self, message):
        """Log message to test results file"""
        with open(self.test_log_file, "a", encoding="utf-8") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {message}\n")
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
    
    def test_dvwa_connectivity(self):
        """Test connectivity to DVWA lab"""
        self.log_message("Testing connectivity to DVWA localhost:8080...")
        
        try:
            # Test HTTP connectivity
            result = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", f"http://{self.target}"],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0 and result.stdout.strip() in ["200", "302", "301"]:
                self.log_message("✅ DVWA connectivity successful")
                return True
            else:
                self.log_message(f"❌ DVWA connectivity failed - HTTP code: {result.stdout.strip()}")
                return False
                
        except Exception as e:
            self.log_message(f"❌ DVWA connectivity error: {e}")
            return False
    
    def test_nmap_scan(self):
        """Test Nmap scanning functionality"""
        self.log_message("Testing Nmap scan against localhost:8080...")
        
        try:
            command = f"nmap -sV -p 8080 localhost"
            result = subprocess.run(
                command.split(), 
                capture_output=True, 
                text=True, 
                timeout=60
            )
            
            self.log_message(f"Nmap command: {command}")
            self.log_message(f"Nmap output:\n{result.stdout}")
            
            if result.returncode == 0:
                self.log_message("✅ Nmap scan completed successfully")
                return True
            else:
                self.log_message(f"❌ Nmap scan failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.log_message(f"❌ Nmap test error: {e}")
            return False
    
    def test_dirb_scan(self):
        """Test directory brute force scanning"""
        self.log_message("Testing directory brute force against DVWA...")
        
        try:
            # Use a small wordlist for testing
            command = f"dirb http://{self.target}/ /usr/share/wordlists/dirb/small.txt -r"
            result = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                timeout=120
            )
            
            self.log_message(f"Dirb command: {command}")
            self.log_message(f"Dirb output:\n{result.stdout}")
            
            if result.returncode == 0:
                self.log_message("✅ Directory brute force completed successfully")
                return True
            else:
                self.log_message(f"❌ Directory brute force failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.log_message(f"❌ Dirb test error: {e}")
            return False
    
    def test_nikto_scan(self):
        """Test Nikto web vulnerability scanner"""
        self.log_message("Testing Nikto scan against DVWA...")
        
        try:
            command = f"nikto -h {self.target} -maxtime 60"
            result = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                timeout=90
            )
            
            self.log_message(f"Nikto command: {command}")
            self.log_message(f"Nikto output:\n{result.stdout}")
            
            if result.returncode == 0:
                self.log_message("✅ Nikto scan completed successfully")
                return True
            else:
                self.log_message(f"❌ Nikto scan failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.log_message(f"❌ Nikto test error: {e}")
            return False
    
    def test_sqlmap_basic(self):
        """Test SQLMap basic functionality against DVWA"""
        self.log_message("Testing SQLMap against DVWA SQL injection page...")
        
        try:
            # DVWA SQL injection vulnerable page
            target_url = f"http://{self.target}/vulnerabilities/sqli/?id=1&Submit=Submit#"
            command = f"sqlmap -u \"{target_url}\" --batch --level=1 --risk=1 --time-sec=5"
            
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=180
            )
            
            self.log_message(f"SQLMap command: {command}")
            self.log_message(f"SQLMap output:\n{result.stdout}")
            
            if result.returncode == 0:
                self.log_message("✅ SQLMap scan completed successfully")
                return True
            else:
                self.log_message(f"❌ SQLMap scan failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.log_message(f"❌ SQLMap test error: {e}")
            return False
    
    def test_hydra_http_form(self):
        """Test Hydra HTTP form brute force against DVWA login"""
        self.log_message("Testing Hydra HTTP form brute force against DVWA login...")
        
        try:
            # Create small test wordlists
            test_users = ["admin", "user", "test"]
            test_passwords = ["password", "admin", "123456"]
            
            user_file = "/tmp/test_users.txt"
            pass_file = "/tmp/test_passwords.txt"
            
            with open(user_file, "w") as f:
                f.write("\n".join(test_users))
            
            with open(pass_file, "w") as f:
                f.write("\n".join(test_passwords))
            
            # DVWA login form parameters
            form_data = "username=^USER^&password=^PASS^&Login=Login"
            failure_string = "Username and/or password incorrect"
            
            command = f"hydra -L {user_file} -P {pass_file} -s 8080 -t 4 localhost http-post-form \"/login.php:{form_data}:{failure_string}\""
            
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            self.log_message(f"Hydra command: {command}")
            self.log_message(f"Hydra output:\n{result.stdout}")
            
            # Clean up test files
            os.remove(user_file)
            os.remove(pass_file)
            
            if result.returncode == 0:
                self.log_message("✅ Hydra HTTP form brute force completed successfully")
                return True
            else:
                self.log_message(f"❌ Hydra HTTP form brute force failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.log_message(f"❌ Hydra test error: {e}")
            return False
    
    def test_gobuster_scan(self):
        """Test Gobuster directory enumeration"""
        self.log_message("Testing Gobuster directory enumeration against DVWA...")
        
        try:
            command = f"gobuster dir -u http://{self.target}/ -w /usr/share/wordlists/dirb/common.txt -t 10 --timeout 10s"
            result = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                timeout=120
            )
            
            self.log_message(f"Gobuster command: {command}")
            self.log_message(f"Gobuster output:\n{result.stdout}")
            
            if result.returncode == 0:
                self.log_message("✅ Gobuster directory enumeration completed successfully")
                return True
            else:
                self.log_message(f"❌ Gobuster directory enumeration failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.log_message(f"❌ Gobuster test error: {e}")
            return False
    
    def test_utility_functions(self):
        """Test SPARM utility functions"""
        self.log_message("Testing SPARM utility functions...")
        
        try:
            # Test IP validation
            if validate_ip("127.0.0.1"):
                self.log_message("✅ IP validation function working")
            else:
                self.log_message("❌ IP validation function failed")
                return False
            
            # Test domain validation
            if validate_domain("localhost"):
                self.log_message("✅ Domain validation function working")
            else:
                self.log_message("❌ Domain validation function failed")
                return False
            
            # Test wordlist functions
            available_wordlists = get_available_wordlists("passwords")
            if available_wordlists:
                self.log_message(f"✅ Found {len(available_wordlists)} password wordlists")
            else:
                self.log_message("⚠️ No password wordlists found")
            
            # Test logging functions
            test_log = setup_session_logging("test")
            log_command_start(test_log, "test", "test command")
            log_output_line(test_log, "test output")
            log_command_end(test_log, "test", 0)
            
            if os.path.exists(test_log):
                self.log_message("✅ Logging functions working")
                os.remove(test_log)  # Clean up
            else:
                self.log_message("❌ Logging functions failed")
                return False
            
            return True
            
        except Exception as e:
            self.log_message(f"❌ Utility functions test error: {e}")
            return False
    
    def test_seclist_integration(self):
        """Test SecList wordlist integration"""
        self.log_message("Testing SecList wordlist integration...")
        
        try:
            # Check if SecLists directory exists
            current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            seclist_base = os.path.join(current_dir, "SecLists-master")
            
            if os.path.exists(seclist_base):
                self.log_message("✅ SecLists directory found")
                
                # Check for common wordlists
                password_files = [
                    "Passwords/Common-Credentials/best1050.txt",
                    "Passwords/Common-Credentials/darkweb2017-top1000.txt"
                ]
                
                found_files = 0
                for pf in password_files:
                    full_path = os.path.join(seclist_base, pf)
                    if os.path.exists(full_path):
                        found_files += 1
                        self.log_message(f"✅ Found wordlist: {pf}")
                    else:
                        self.log_message(f"⚠️ Missing wordlist: {pf}")
                
                if found_files > 0:
                    self.log_message(f"✅ SecList integration working - {found_files} wordlists available")
                    return True
                else:
                    self.log_message("❌ No SecList wordlists found")
                    return False
            else:
                self.log_message("❌ SecLists directory not found")
                return False
                
        except Exception as e:
            self.log_message(f"❌ SecList integration test error: {e}")
            return False
    
    def run_all_tests(self):
        """Run all tests and generate comprehensive report"""
        self.log_message("=== STARTING COMPREHENSIVE SPARM TESTING ===")
        
        test_results = {}
        
        # List of all tests to run
        tests = [
            ("DVWA Connectivity", self.test_dvwa_connectivity),
            ("Nmap Scanning", self.test_nmap_scan),
            ("Directory Brute Force (Dirb)", self.test_dirb_scan),
            ("Web Vulnerability Scanner (Nikto)", self.test_nikto_scan),
            ("SQL Injection (SQLMap)", self.test_sqlmap_basic),
            ("HTTP Form Brute Force (Hydra)", self.test_hydra_http_form),
            ("Directory Enumeration (Gobuster)", self.test_gobuster_scan),
            ("Utility Functions", self.test_utility_functions),
            ("SecList Integration", self.test_seclist_integration)
        ]
        
        for test_name, test_func in tests:
            self.log_message(f"\n--- Running Test: {test_name} ---")
            try:
                result = test_func()
                test_results[test_name] = "PASSED" if result else "FAILED"
            except Exception as e:
                self.log_message(f"❌ Test {test_name} crashed: {e}")
                test_results[test_name] = "CRASHED"
        
        # Generate final report
        self.log_message("\n=== FINAL TEST REPORT ===")
        passed = 0
        failed = 0
        crashed = 0
        
        for test_name, result in test_results.items():
            status_icon = "✅" if result == "PASSED" else "❌" if result == "FAILED" else "💥"
            self.log_message(f"{status_icon} {test_name}: {result}")
            
            if result == "PASSED":
                passed += 1
            elif result == "FAILED":
                failed += 1
            else:
                crashed += 1
        
        self.log_message(f"\nSUMMARY: {passed} PASSED, {failed} FAILED, {crashed} CRASHED")
        self.log_message(f"Test Results Logged to: {self.test_log_file}")
        self.log_message("=== SPARM TOOL TESTING COMPLETED ===")
        
        return test_results

def main():
    """Main test runner"""
    tester = TestSPARMTools()
    tester.setUp()
    results = tester.run_all_tests()
    
    # Print summary to console
    print(f"\n🎯 Test Results Summary:")
    print(f"📊 Results logged to: {tester.test_log_file}")
    
    return results

if __name__ == "__main__":
    main()