#!/usr/bin/env python3

import subprocess
import sys
import os
from core.utils import *
from core.config import *

class ReconnaissanceToolkit:
    def __init__(self):
        self.tools = {
            "nmap": "Network discovery and security auditing",
            "masscan": "High-speed port scanner", 
            "gobuster": "Directory/file & DNS busting tool",
            "dirb": "Web content scanner",
            "nikto": "Web server scanner",
            "enum4linux": "SMB enumeration tool"
        }
    
    def run_nmap(self):
        """Nmap - Network scanning"""
        banner("Nmap - Network Discovery & Security Auditing")
        
        target = get_user_input("Enter target IP/domain (e.g., 192.168.1.1 or example.com)")
        
        console.print("\n[bold cyan]Scan types:[/bold cyan]")
        scan_types = {
            "1": ("-sS", "SYN Stealth Scan"),
            "2": ("-sT", "TCP Connect Scan"),
            "3": ("-sU", "UDP Scan"),
            "4": ("-sV", "Version Detection"),
            "5": ("-O", "OS Detection"),
            "6": ("-A", "Aggressive Scan (OS, version, script, traceroute)"),
            "7": ("-Pn", "Skip host discovery")
        }
        
        for key, (flag, desc) in scan_types.items():
            console.print(f"  {key}. {desc}")
        
        scan_choice = get_user_input("Choose scan type (1-7)", choices=[str(i) for i in range(1, 8)])
        scan_flag = scan_types[scan_choice][0]
        
        # Port specification
        ports = get_user_input("Enter ports (e.g., 22,80,443 or 1-1000) [default: top 1000]") or ""
        port_flag = f"-p {ports}" if ports else ""
        
        # Timing template
        timing = get_user_input("Timing template (0-5) [default: 3]", choices=["0","1","2","3","4","5"]) or "3"
        
        command = f"nmap {scan_flag} -T{timing} {port_flag} {target}".strip()
        
        console.print(f"\n[bold yellow]Command:[/bold yellow] {command}")
        
        console.print(f"\n[bold green]Executing: {command}[/bold green]")
        try:
            result = subprocess.run(command.split(), capture_output=True, text=True, timeout=600)
            if result.stdout:
                console.print("\n[bold green]Results:[/bold green]")
                console.print(result.stdout)
            if result.stderr:
                Warning(f"Errors: {result.stderr}")
        except subprocess.TimeoutExpired:
            Warning("Command timed out after 10 minutes")
        except Exception as e:
            Warning(f"Error executing command: {e}")
        
        show_next_steps("Reconnaissance", CATEGORIES["recon"]["next_steps"])
    
    def run_gobuster(self):
        """Gobuster - Directory/file bruteforcing"""
        banner("Gobuster - Directory & File Discovery")
        
        target = get_user_input("Enter target URL (e.g., https://example.com)")
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        console.print("\n[bold cyan]Gobuster modes:[/bold cyan]")
        modes = {
            "1": ("dir", "Directory/file bruteforcing"),
            "2": ("dns", "DNS subdomain bruteforcing"),
            "3": ("vhost", "Virtual host bruteforcing")
        }
        
        for key, (mode, desc) in modes.items():
            console.print(f"  {key}. {mode} - {desc}")
        
        mode_choice = get_user_input("Choose mode (1-3)", choices=["1", "2", "3"])
        selected_mode = modes[mode_choice][0]
        
        # Wordlist selection
        if selected_mode == "dir":
            wordlist = WORDLISTS.get("directories", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
            extensions = get_user_input("File extensions (e.g., php,html,txt) [optional]") or ""
            ext_flag = f"-x {extensions}" if extensions else ""
            command = f"gobuster dir -u {target} -w {wordlist} {ext_flag}".strip()
        elif selected_mode == "dns":
            wordlist = WORDLISTS.get("subdomains", "/usr/share/wordlists/amass/subdomains-top1mil-5000.txt")
            domain = target.replace('https://', '').replace('http://', '').split('/')[0]
            command = f"gobuster dns -d {domain} -w {wordlist}"
        else:  # vhost
            wordlist = WORDLISTS.get("subdomains", "/usr/share/wordlists/amass/subdomains-top1mil-5000.txt")
            command = f"gobuster vhost -u {target} -w {wordlist}"
        
        # Additional options
        threads = get_user_input("Number of threads [default: 10]") or "10"
        command += f" -t {threads}"
        
        console.print(f"\n[bold yellow]Command:[/bold yellow] {command}")
        
        console.print(f"\n[bold green]Executing: {command}[/bold green]")
        try:
            result = subprocess.run(command.split(), capture_output=True, text=True, timeout=600)
            if result.stdout:
                console.print("\n[bold green]Results:[/bold green]")
                console.print(result.stdout)
            if result.stderr:
                Warning(f"Errors: {result.stderr}")
        except subprocess.TimeoutExpired:
            Warning("Command timed out after 10 minutes")
        except Exception as e:
            Warning(f"Error executing command: {e}")
        
        show_next_steps("Reconnaissance", CATEGORIES["recon"]["next_steps"])
    
    def run_nikto(self):
        """Nikto - Web server scanner"""
        banner("Nikto - Web Server Scanner")
        
        target = get_user_input("Enter target URL (e.g., https://example.com)")
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        console.print("\n[bold cyan]Scan options:[/bold cyan]")
        console.print("  1. Basic scan")
        console.print("  2. SSL scan")
        console.print("  3. Comprehensive scan")
        
        scan_choice = get_user_input("Choose scan type (1-3)", choices=["1", "2", "3"])
        
        if scan_choice == "1":
            command = f"nikto -h {target}"
        elif scan_choice == "2":
            command = f"nikto -h {target} -ssl"
        else:  # comprehensive
            command = f"nikto -h {target} -Tuning 123456789a"
        
        console.print(f"\n[bold yellow]Command:[/bold yellow] {command}")
        
        console.print(f"\n[bold green]Executing: {command}[/bold green]")
        try:
            result = subprocess.run(command.split(), capture_output=True, text=True, timeout=600)
            if result.stdout:
                console.print("\n[bold green]Results:[/bold green]")
                console.print(result.stdout)
            if result.stderr:
                Warning(f"Errors: {result.stderr}")
        except subprocess.TimeoutExpired:
            Warning("Command timed out after 10 minutes")
        except Exception as e:
            Warning(f"Error executing command: {e}")
        
        show_next_steps("Reconnaissance", CATEGORIES["recon"]["next_steps"])
    
    def display_menu(self):
        """Display reconnaissance toolkit menu"""
        clear()
        Title("Network Reconnaissance Toolkit")
        
        console.print(DISCLAIMER)
        Continue()
        
        display_tools_table("Reconnaissance", self.tools)
        
        console.print("\n[bold cyan]Available Tools:[/bold cyan]")
        console.print("  1. Nmap - Network discovery & security auditing")
        console.print("  2. Gobuster - Directory/file & DNS busting")
        console.print("  3. Nikto - Web server scanner")
        console.print("  4. Back to main menu")
        
        choice = get_user_input("Select tool (1-4)", choices=["1", "2", "3", "4"])
        
        if choice == "1":
            self.run_nmap()
        elif choice == "2":
            self.run_gobuster()
        elif choice == "3":
            self.run_nikto()
        elif choice == "4":
            return
        
        Continue()

def run():
    """Entry point for reconnaissance toolkit"""
    toolkit = ReconnaissanceToolkit()
    toolkit.display_menu()