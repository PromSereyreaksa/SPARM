#!/usr/bin/env python3

import subprocess
import sys
import os
from core.utils import *
from core.config import *

class OSINTToolkit:
    def __init__(self):
        self.tools = {
            "theHarvester": "Email harvesting and OSINT reconnaissance",
            "amass": "In-depth attack surface mapping and asset discovery", 
            "recon-ng": "Full-featured reconnaissance framework",
            "sherlock": "Hunt down social media accounts by username",
            "spiderfoot": "Automated OSINT collection",
            "maltego": "Link analysis and data mining platform"
        }
    
    def run_theharvester(self):
        """TheHarvester - Email and subdomain harvesting"""
        banner("TheHarvester - Email & Subdomain Harvesting")
        
        domain = get_user_input("Enter target domain (e.g., example.com)")
        limit = get_user_input("Enter email limit", choices=["100", "200", "500"]) or "100"
        
        sources = ["google", "bing", "yahoo", "duckduckgo", "linkedin", "twitter"]
        console.print("\n[bold cyan]Available sources:[/bold cyan]")
        for i, source in enumerate(sources, 1):
            console.print(f"  {i}. {source}")
        
        source_choice = get_user_input("Choose source (1-6)", choices=[str(i) for i in range(1, 7)])
        selected_source = sources[int(source_choice) - 1]
        
        info(f"Running TheHarvester on {domain} using {selected_source}")
        
        command = f"theHarvester -d {domain} -l {limit} -b {selected_source}"
        
        console.print(f"\n[bold yellow]Command:[/bold yellow] {command}")
        
        console.print(f"\n[bold green]Executing: {command}[/bold green]")
        try:
                result = subprocess.run(command.split(), capture_output=True, text=True, timeout=300)
                if result.stdout:
                    console.print("\n[bold green]Results:[/bold green]")
                    console.print(result.stdout)
                if result.stderr:
                    Warning(f"Errors: {result.stderr}")
        except subprocess.TimeoutExpired:
                Warning("Command timed out after 5 minutes")
        except Exception as e:
                Warning(f"Error executing command: {e}")
        
        show_next_steps("OSINT", CATEGORIES["osint"]["next_steps"])
    
    def run_amass(self):
        """Amass - Subdomain enumeration"""
        banner("Amass - Attack Surface Mapping")
        
        domain = get_user_input("Enter target domain (e.g., example.com)")
        
        console.print("\n[bold cyan]Amass scan types:[/bold cyan]")
        scan_types = {
            "1": ("enum", "Basic subdomain enumeration"),
            "2": ("intel", "Intelligence gathering"),
            "3": ("viz", "Visualization of results")
        }
        
        for key, (cmd, desc) in scan_types.items():
            console.print(f"  {key}. {cmd} - {desc}")
        
        scan_choice = get_user_input("Choose scan type (1-3)", choices=["1", "2", "3"])
        scan_type = scan_types[scan_choice][0]
        
        if scan_type == "enum":
            command = f"amass enum -d {domain}"
        elif scan_type == "intel":
            command = f"amass intel -d {domain}"
        else:
            command = f"amass viz -d3 -d {domain}"
        
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
        
        show_next_steps("OSINT", CATEGORIES["osint"]["next_steps"])
    
    def run_sherlock(self):
        """Sherlock - Social media username hunting"""
        banner("Sherlock - Social Media Account Hunter")
        
        username = get_user_input("Enter username to search for")
        
        info(f"Searching for username '{username}' across social media platforms")
        
        command = f"sherlock {username}"
        
        console.print(f"\n[bold yellow]Command:[/bold yellow] {command}")
        
        console.print(f"\n[bold green]Executing: {command}[/bold green]")
        try:
            result = subprocess.run(command.split(), capture_output=True, text=True, timeout=300)
            if result.stdout:
                console.print("\n[bold green]Results:[/bold green]")
                console.print(result.stdout)
            if result.stderr:
                Warning(f"Errors: {result.stderr}")
        except subprocess.TimeoutExpired:
            Warning("Command timed out after 5 minutes")
        except Exception as e:
            Warning(f"Error executing command: {e}")
        
        show_next_steps("OSINT", CATEGORIES["osint"]["next_steps"])
    
    def display_menu(self):
        """Display OSINT toolkit menu"""
        clear()
        Title("OSINT & Information Gathering Toolkit")
        
        console.print(DISCLAIMER)
        Continue()
        
        display_tools_table("OSINT", self.tools)
        
        console.print("\n[bold cyan]Available Tools:[/bold cyan]")
        console.print("  1. TheHarvester - Email & subdomain harvesting")
        console.print("  2. Amass - Attack surface mapping")
        console.print("  3. Sherlock - Social media username search")
        console.print("  4. Back to main menu")
        
        choice = get_user_input("Select tool (1-4)", choices=["1", "2", "3", "4"])
        
        if choice == "1":
            self.run_theharvester()
        elif choice == "2":
            self.run_amass()
        elif choice == "3":
            self.run_sherlock()
        elif choice == "4":
            return
        
        Continue()

def run():
    """Entry point for OSINT toolkit"""
    toolkit = OSINTToolkit()
    toolkit.display_menu()