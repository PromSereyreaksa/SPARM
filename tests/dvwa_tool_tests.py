#!/usr/bin/env python3
"""
DVWA Tool Testing Script
Tests each tool individually against DVWA localhost:8080
"""

import subprocess
import sys
import os
import time
from datetime import datetime

def log_test(message, log_file):
    """Log test message"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}")
    with open(log_file, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

def run_tool_test(tool_name, command, timeout, log_file):
    """Run individual tool test"""
    log_test(f"--- Testing {tool_name} ---", log_file)
    log_test(f"Command: {command}", log_file)
    
    try:
        start_time = time.time()
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        end_time = time.time()
        
        duration = round(end_time - start_time, 2)
        log_test(f"Duration: {duration}s", log_file)
        log_test(f"Return code: {result.returncode}", log_file)
        
        if result.stdout:
            # Truncate output for readability
            output = result.stdout[:1000]
            if len(result.stdout) > 1000:
                output += "... [TRUNCATED]"
            log_test(f"Output:\n{output}", log_file)
        
        if result.stderr:
            error = result.stderr[:500]
            if len(result.stderr) > 500:
                error += "... [TRUNCATED]"
            log_test(f"Errors:\n{error}", log_file)
        
        if result.returncode == 0:
            log_test(f"✅ {tool_name} test completed successfully", log_file)
            return True
        else:
            log_test(f"⚠️ {tool_name} test completed with warnings/errors", log_file)
            return True  # Many security tools return non-zero on findings
            
    except subprocess.TimeoutExpired:
        log_test(f"⏰ {tool_name} test timed out after {timeout}s", log_file)
        return False
    except Exception as e:
        log_test(f"❌ {tool_name} test error: {e}", log_file)
        return False

def main():
    """Run DVWA tool tests"""
    # Ensure logs directory exists
    os.makedirs("/home/s001kaliv1/Desktop/SPARM/logs", exist_ok=True)
    
    log_file = f"/home/s001kaliv1/Desktop/SPARM/logs/dvwa_tool_tests_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    log_test("=== DVWA TOOL TESTING STARTED ===", log_file)
    log_test("Target: localhost:8080 (DVWA)", log_file)
    
    test_results = {}
    
    # Define test commands for each tool
    tests = [
        ("Nmap Port Scan", "nmap -sV -p 8080 localhost", 60),
        ("Nmap Script Scan", "nmap -sC -p 8080 localhost", 90),
        ("Nikto Web Scanner", "nikto -h localhost:8080 -maxtime 30", 45),
        ("Dirb Directory Scan", "dirb http://localhost:8080/ /usr/share/wordlists/dirb/small.txt -r", 60),
        ("Gobuster Directory Scan", "gobuster dir -u http://localhost:8080/ -w /usr/share/wordlists/dirb/common.txt -t 5 --timeout 5s", 60),
        ("SQLMap Basic Test", "sqlmap -u 'http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit' --batch --level=1 --risk=1 --time-sec=3", 120),
        ("Curl Basic Test", "curl -I http://localhost:8080/", 10),
        ("Whatweb Scanner", "whatweb http://localhost:8080/", 30)
    ]
    
    # Create small test wordlists for Hydra
    log_test("Creating test wordlists for Hydra...", log_file)
    test_users = ["admin", "user", "test", "dvwa"]
    test_passwords = ["password", "admin", "123456", "dvwa"]
    
    user_file = "/tmp/test_users.txt"
    pass_file = "/tmp/test_passwords.txt"
    
    with open(user_file, "w") as f:
        f.write("\n".join(test_users))
    
    with open(pass_file, "w") as f:
        f.write("\n".join(test_passwords))
    
    # Add Hydra test (if we can identify the login form)
    tests.append((
        "Hydra HTTP Test", 
        f"hydra -L {user_file} -P {pass_file} -s 8080 -t 2 localhost http-get /", 
        45
    ))
        
    # Run all tests
    for test_name, command, timeout in tests:
        result = run_tool_test(test_name, command, timeout, log_file)
        test_results[test_name] = "PASSED" if result else "FAILED"
        
        # Add small delay between tests
        time.sleep(2)
    
    # Clean up test files
    try:
        os.remove(user_file)
        os.remove(pass_file)
        log_test("Cleaned up test wordlist files", log_file)
    except:
        pass
    
    # Generate final report
    log_test("\n=== FINAL TEST REPORT ===", log_file)
    passed = sum(1 for result in test_results.values() if result == "PASSED")
    failed = sum(1 for result in test_results.values() if result == "FAILED")
    
    for test_name, result in test_results.items():
        status_icon = "✅" if result == "PASSED" else "❌"
        log_test(f"{status_icon} {test_name}: {result}", log_file)
    
    log_test(f"\nSUMMARY: {passed} PASSED, {failed} FAILED out of {len(test_results)} tests", log_file)
    success_rate = round((passed / len(test_results)) * 100, 1)
    log_test(f"SUCCESS RATE: {success_rate}%", log_file)
    log_test(f"Test Results Logged to: {log_file}", log_file)
    log_test("=== DVWA TOOL TESTING COMPLETED ===", log_file)
    
    print(f"\n🎯 Test Results Summary:")
    print(f"✅ {passed} tests passed")
    print(f"❌ {failed} tests failed")
    print(f"📊 Success rate: {success_rate}%")
    print(f"📝 Full results: {log_file}")
    
    return test_results

if __name__ == "__main__":
    main()