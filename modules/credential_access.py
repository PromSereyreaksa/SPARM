#!/usr/bin/env python3

import subprocess
import sys
import os
from core.utils import *
from core.config import *

class CredentialAccessToolkit:
    def __init__(self):
        self.tools = {
            "hydra": "Network logon cracker supporting many services",
            "john": "John the Ripper password cracker",
            "hashcat": "Advanced password recovery utility",
            "medusa": "Speedy, parallel, modular login brute-forcer",
            "ncrack": "High-speed network authentication cracking tool",
            "patator": "Multi-purpose brute-forcer"
        }
    
    def run_hydra(self):
        """Hydra - Network login brute forcer"""
        banner("Hydra - Network Login Brute Forcer")
        
        # Target specification
        target = get_user_input("Enter target IP/domain (e.g., 192.168.1.1)")
        
        # Service selection
        console.print("\n[bold cyan]Available services:[/bold cyan]")
        services = {
            "1": "ssh", "2": "ftp", "3": "telnet", "4": "http-get", 
            "5": "http-post-form", "6": "smb", "7": "rdp", "8": "mysql",
            "9": "postgres", "10": "vnc"
        }
        
        for key, service in services.items():
            console.print(f"  {key}. {service}")
        
        service_choice = get_user_input("Choose service (1-10)", choices=[str(i) for i in range(1, 11)])
        selected_service = services[service_choice]
        
        # Port specification
        if service_choice in ["1"]: # SSH
            default_port = "22"
        elif service_choice in ["2"]: # FTP
            default_port = "21"
        elif service_choice in ["3"]: # Telnet
            default_port = "23"
        elif service_choice in ["4", "5"]: # HTTP
            default_port = "80"
        elif service_choice in ["6"]: # SMB
            default_port = "445"
        elif service_choice in ["7"]: # RDP
            default_port = "3389"
        elif service_choice in ["8"]: # MySQL
            default_port = "3306"
        elif service_choice in ["9"]: # PostgreSQL
            default_port = "5432"
        else: # VNC
            default_port = "5900"
        
        port = get_user_input(f"Enter port [default: {default_port}]") or default_port
        
        # Username/password lists
        console.print("\n[bold cyan]Authentication method:[/bold cyan]")
        console.print("  1. Username list + Password list")
        console.print("  2. Single username + Password list")
        console.print("  3. Username list + Single password")
        console.print("  4. Single username + Single password")
        
        auth_method = get_user_input("Choose method (1-4)", choices=["1", "2", "3", "4"])
        
        if auth_method in ["1", "2"]:
            user_input = get_user_input("Username (single) or username list file path")
            if os.path.isfile(user_input):
                user_param = f"-L {user_input}"
            else:
                user_param = f"-l {user_input}"
        else:
            username = get_user_input("Enter username")
            user_param = f"-l {username}"
        
        if auth_method in ["1", "3"]:
            pass_input = get_user_input("Password (single) or password list file path")
            if os.path.isfile(pass_input):
                pass_param = f"-P {pass_input}"
            else:
                pass_param = f"-p {pass_input}"
        else:
            if auth_method == "2":
                pass_file = get_user_input("Password list file path") or WORDLISTS.get("passwords", "/usr/share/wordlists/rockyou.txt")
                pass_param = f"-P {pass_file}"
            else:
                password = get_user_input("Enter password")
                pass_param = f"-p {password}"
        
        # Additional options
        threads = get_user_input("Number of threads [default: 16]") or "16"
        
        # Special handling for HTTP POST forms
        if selected_service == "http-post-form":
            login_path = get_user_input("Login path (e.g., /login.php)")
            form_params = get_user_input("Form parameters (e.g., username=^USER^&password=^PASS^)")
            failure_string = get_user_input("Failure string (e.g., 'Invalid credentials')")
            service_param = f'"{login_path}:{form_params}:{failure_string}"'
        else:
            service_param = selected_service
        
        # Build command
        command = f"hydra -s {port} {user_param} {pass_param} -t {threads} {target} {service_param}"
        
        console.print(f"\n[bold yellow]Command:[/bold yellow] {command}")
        
        console.print(f"\n[bold green]Executing: {command}[/bold green]")
            try:
                result = subprocess.run(command.split(), capture_output=True, text=True, timeout=1800)
                if result.stdout:
                    console.print("\n[bold green]Results:[/bold green]")
                    console.print(result.stdout)
                if result.stderr:
                    Warning(f"Errors: {result.stderr}")
            except subprocess.TimeoutExpired:
                Warning("Command timed out after 30 minutes")
            except Exception as e:
                Warning(f"Error executing command: {e}")
        
        show_next_steps("Credential Access", CATEGORIES["credential_access"]["next_steps"])
    
    def run_john(self):
        """John the Ripper - Password cracker"""
        banner("John the Ripper - Password Cracker")
        
        # Hash file
        hash_file = get_user_input("Enter path to hash file (e.g., /tmp/hashes.txt)")
        
        if not os.path.isfile(hash_file):
            Warning(f"Hash file not found: {hash_file}")
            return
        
        # Attack mode
        console.print("\n[bold cyan]Attack modes:[/bold cyan]")
        console.print("  1. Dictionary attack")
        console.print("  2. Brute force attack")
        console.print("  3. Incremental attack")
        console.print("  4. Show cracked passwords")
        
        attack_choice = get_user_input("Choose attack mode (1-4)", choices=["1", "2", "3", "4"])
        
        if attack_choice == "1":
            # Dictionary attack
            wordlist = get_user_input("Wordlist path [default: rockyou.txt]") or WORDLISTS.get("passwords", "/usr/share/wordlists/rockyou.txt")
            command = f"john --wordlist={wordlist} {hash_file}"
            
        elif attack_choice == "2":
            # Brute force
            min_len = get_user_input("Minimum password length [default: 1]") or "1"
            max_len = get_user_input("Maximum password length [default: 8]") or "8"
            charset = get_user_input("Character set (a=lower, A=upper, 0=digits) [default: a0A]") or "a0A"
            command = f"john --incremental={charset} {hash_file}"
            
        elif attack_choice == "3":
            # Incremental
            command = f"john --incremental {hash_file}"
            
        else:
            # Show results
            command = f"john --show {hash_file}"
        
        # Hash format
        if attack_choice != "4":
            console.print("\n[bold cyan]Common hash formats:[/bold cyan]")
            formats = {
                "1": "auto-detect",
                "2": "md5crypt", 
                "3": "sha512crypt",
                "4": "bcrypt",
                "5": "NT (NTLM)",
                "6": "raw-md5"
            }
            
            for key, fmt in formats.items():
                console.print(f"  {key}. {fmt}")
            
            format_choice = get_user_input("Choose hash format (1-6)", choices=["1", "2", "3", "4", "5", "6"])
            
            if format_choice != "1":
                format_name = {
                    "2": "md5crypt", "3": "sha512crypt", "4": "bcrypt", 
                    "5": "nt", "6": "raw-md5"
                }[format_choice]
                command += f" --format={format_name}"
        
        console.print(f"\n[bold yellow]Command:[/bold yellow] {command}")
        
        console.print(f"\n[bold green]Executing: {command}[/bold green]")
            try:
                result = subprocess.run(command.split(), capture_output=True, text=True, timeout=3600)
                if result.stdout:
                    console.print("\n[bold green]Results:[/bold green]")
                    console.print(result.stdout)
                if result.stderr:
                    Warning(f"Errors: {result.stderr}")
            except subprocess.TimeoutExpired:
                Warning("Command timed out after 1 hour")
            except Exception as e:
                Warning(f"Error executing command: {e}")
        
        show_next_steps("Credential Access", CATEGORIES["credential_access"]["next_steps"])
    
    def run_hashcat(self):
        """Hashcat - Advanced password recovery"""
        banner("Hashcat - Advanced Password Recovery")
        
        # Hash file
        hash_file = get_user_input("Enter path to hash file (e.g., /tmp/hashes.txt)")
        
        if not os.path.isfile(hash_file):
            Warning(f"Hash file not found: {hash_file}")
            return
        
        # Hash type
        console.print("\n[bold cyan]Common hash types:[/bold cyan]")
        hash_types = {
            "1": ("0", "MD5"),
            "2": ("100", "SHA1"),
            "3": ("1000", "NTLM"),
            "4": ("1400", "SHA256"),
            "5": ("1700", "SHA512"),
            "6": ("1800", "sha512crypt"),
            "7": ("3200", "bcrypt")
        }
        
        for key, (code, name) in hash_types.items():
            console.print(f"  {key}. {name} ({code})")
        
        hash_choice = get_user_input("Choose hash type (1-7)", choices=["1", "2", "3", "4", "5", "6", "7"])
        hash_mode = hash_types[hash_choice][0]
        
        # Attack mode
        console.print("\n[bold cyan]Attack modes:[/bold cyan]")
        console.print("  1. Dictionary attack (0)")
        console.print("  2. Combinator attack (1)")
        console.print("  3. Brute-force attack (3)")
        console.print("  4. Hybrid dict + mask (6)")
        
        attack_choice = get_user_input("Choose attack mode (1-4)", choices=["1", "2", "3", "4"])
        
        attack_modes = {"1": "0", "2": "1", "3": "3", "4": "6"}
        attack_mode = attack_modes[attack_choice]
        
        if attack_choice == "1":  # Dictionary
            wordlist = get_user_input("Wordlist path [default: rockyou.txt]") or WORDLISTS.get("passwords", "/usr/share/wordlists/rockyou.txt")
            command = f"hashcat -m {hash_mode} -a {attack_mode} {hash_file} {wordlist}"
            
        elif attack_choice == "2":  # Combinator
            wordlist1 = get_user_input("First wordlist path")
            wordlist2 = get_user_input("Second wordlist path")
            command = f"hashcat -m {hash_mode} -a {attack_mode} {hash_file} {wordlist1} {wordlist2}"
            
        elif attack_choice == "3":  # Brute-force
            mask = get_user_input("Mask (e.g., ?a?a?a?a?a?a for 6 chars) [default: ?a?a?a?a?a?a]") or "?a?a?a?a?a?a"
            command = f"hashcat -m {hash_mode} -a {attack_mode} {hash_file} {mask}"
            
        else:  # Hybrid
            wordlist = get_user_input("Wordlist path")
            mask = get_user_input("Mask to append (e.g., ?d?d?d)")
            command = f"hashcat -m {hash_mode} -a {attack_mode} {hash_file} {wordlist} {mask}"
        
        console.print(f"\n[bold yellow]Command:[/bold yellow] {command}")
        
        console.print(f"\n[bold green]Executing: {command}[/bold green]")
            try:
                result = subprocess.run(command.split(), capture_output=True, text=True, timeout=3600)
                if result.stdout:
                    console.print("\n[bold green]Results:[/bold green]")
                    console.print(result.stdout)
                if result.stderr:
                    Warning(f"Errors: {result.stderr}")
            except subprocess.TimeoutExpired:
                Warning("Command timed out after 1 hour")
            except Exception as e:
                Warning(f"Error executing command: {e}")
        
        show_next_steps("Credential Access", CATEGORIES["credential_access"]["next_steps"])
    
    def display_menu(self):
        """Display credential access toolkit menu"""
        clear()
        Title("Credential Access Toolkit")
        
        console.print(DISCLAIMER)
        Continue()
        
        display_tools_table("Credential Access", self.tools)
        
        console.print("\n[bold cyan]Available Tools:[/bold cyan]")
        console.print("  1. Hydra - Network login brute forcer")
        console.print("  2. John the Ripper - Password cracker")
        console.print("  3. Hashcat - Advanced password recovery")
        console.print("  4. Back to main menu")
        
        choice = get_user_input("Select tool (1-4)", choices=["1", "2", "3", "4"])
        
        if choice == "1":
            self.run_hydra()
        elif choice == "2":
            self.run_john()
        elif choice == "3":
            self.run_hashcat()
        elif choice == "4":
            return
        
        Continue()

def run():
    """Entry point for credential access toolkit"""
    toolkit = CredentialAccessToolkit()
    toolkit.display_menu()