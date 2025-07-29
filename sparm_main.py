#!/usr/bin/env python3
"""
SPARM - Security Penetration & Research Multitool
A comprehensive cybersecurity education toolkit for Kali Linux

Educational Use Only - Authorized Testing Environment Required
"""

import sys
import os
from core.utils import *
from core.config import *

class SPARMInterface:
    def __init__(self):
        self.user_level = "beginner"
        self.session_data = {}
    
    def show_disclaimer(self):
        """Display educational disclaimer"""
        clear()
        console.print(Panel(DISCLAIMER, title="⚠️  IMPORTANT DISCLAIMER ⚠️", style="bold red"))
        console.print("\n[bold green]Proceeding to SPARM interface...[/bold green]")
        import time
        time.sleep(2)
    
    def initialize_user_profile(self):
        """Initialize user profile with intermediate settings"""
        self.user_level = "intermediate"  # Default to intermediate level
        clear()
        console.print("[bold cyan]SPARM initialized with guided assistance mode[/bold cyan]\n")
    
    def display_main_menu(self):
        """Display the main menu interface"""
        clear()
        ascii_art("SPARM")
        
        console.print(f"[bold cyan]Experience Level:[/bold cyan] {EXPERIENCE_LEVELS[self.user_level]['name']}")
        console.print(f"[bold green]Status:[/bold green] Ready for security testing\n")
        
        # Kill chain phases
        console.print("[bold yellow]🎯 Cyber Kill Chain Phases[/bold yellow]\n")
        
        menu_items = [
            ("1", "🔍 OSINT & Information Gathering", "osint", "Reconnaissance phase - Gather intelligence about targets"),
            ("2", "🌐 Network Reconnaissance", "recon", "Discovery phase - Map network topology and services"),
            ("3", "🛡️  Web Vulnerability Assessment", "web_vuln", "Exploitation phase - Test web applications for vulnerabilities"),
            ("4", "💉 SQL Injection Testing", "sql_injection", "Exploitation phase - Database injection attacks"),
            ("5", "🔑 Credential Access", "credential_access", "Credential access - Password attacks and harvesting"),
            ("6", "⬆️  Privilege Escalation", "privilege_escalation", "Post-exploitation - Escalate system privileges"),
            ("7", "🚀 Advanced Offensive Tools", "advanced_offensive", "Advanced payloads, C2, persistence, and evasion"),
            ("8", "ℹ️  Tool Information", "info", "Learn about cybersecurity tools and techniques"),
            ("9", "⚙️  Settings", "settings", "Configure SPARM settings"),
            ("0", "🚪 Exit", "exit", "Exit SPARM")
        ]
        
        for choice, name, category, description in menu_items:
            console.print(f"[bold cyan]▸[/bold cyan] {name}")
            console.print(f"  [dim cyan]{description}[/dim cyan]")
            console.print(f"  [bold white]Select: {choice}[/bold white]\n")
        
        console.print()
        return get_user_input("Select an option", choices=[item[0] for item in menu_items])
    
    def route_selection(self, choice):
        """Route user selection to appropriate module"""
        if choice == "1":
            from modules.osint_toolkit import run as osint_run
            osint_run()
        elif choice == "2":
            from modules.reconnaissance import run as recon_run
            recon_run()
        elif choice == "3":
            from modules.web_vulnerability import run as web_vuln_run
            web_vuln_run()
        elif choice == "4":
            from modules.sql_injection import run as sql_run
            sql_run()
        elif choice == "5":
            from modules.credential_access import run as cred_run
            cred_run()
        elif choice == "6":
            self.privilege_escalation_menu()
        elif choice == "7":
            from modules.advanced_offensive import run as advanced_run
            advanced_run()
        elif choice == "8":
            self.show_tool_information()
        elif choice == "9":
            self.settings_menu()
        elif choice == "0":
            self.exit_application()
    
    def privilege_escalation_menu(self):
        """Privilege escalation tools and techniques"""
        clear()
        Title("Privilege Escalation Toolkit")
        
        console.print(DISCLAIMER)
        Continue()
        
        console.print("\n[bold cyan]Privilege Escalation Tools:[/bold cyan]")
        console.print("  1. LinPEAS - Linux privilege escalation scanner")
        console.print("  2. WinPEAS - Windows privilege escalation scanner") 
        console.print("  3. Linux Exploit Suggester")
        console.print("  4. GTFOBins lookup")
        console.print("  5. Back to main menu")
        
        choice = get_user_input("Select tool (1-5)", choices=["1", "2", "3", "4", "5"])
        
        if choice == "1":
            self.run_linpeas()
        elif choice == "2":
            info("WinPEAS - Use on Windows targets for privilege escalation enumeration")
        elif choice == "3":
            self.run_linux_exploit_suggester()
        elif choice == "4":
            self.gtfobins_lookup()
        elif choice == "5":
            return
        
        Continue()
    
    def run_linpeas(self):
        """LinPEAS privilege escalation scanner"""
        banner("LinPEAS - Linux Privilege Escalation Scanner")
        
        console.print("LinPEAS helps identify potential privilege escalation vectors on Linux systems.\n")
        
        if self.user_level == "beginner":
            console.print("[bold cyan]💡 Beginner Tip:[/bold cyan]")
            console.print("LinPEAS should be run on the target system after gaining initial access.")
            console.print("It will scan for misconfigurations, vulnerable software, and escalation paths.\n")
        
        console.print("Download and run LinPEAS on target:")
        console.print("curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh")
        
        show_next_steps("Privilege Escalation", [
            "Analyze LinPEAS output for high-priority findings",
            "Check for SUID binaries and capabilities",
            "Look for writable service files or cron jobs",
            "Search for credentials in config files"
        ])
    
    def run_linux_exploit_suggester(self):
        """Linux Exploit Suggester"""
        banner("Linux Exploit Suggester")
        
        console.print("Suggests kernel exploits based on system information.\n")
        
        console.print("Usage on target system:")
        console.print("1. Upload linux-exploit-suggester.sh to target")
        console.print("2. Run: ./linux-exploit-suggester.sh")
        console.print("3. Review suggested exploits carefully")
        
        if self.user_level == "beginner":
            Warning("Kernel exploits can crash systems. Use with extreme caution!")
    
    def gtfobins_lookup(self):
        """GTFOBins information"""
        banner("GTFOBins - Unix Binary Exploitation")
        
        console.print("GTFOBins is a curated list of Unix binaries that can be exploited for privilege escalation.\n")
        
        binary = get_user_input("Enter binary name to look up (e.g., vim, find, awk)")
        
        console.print(f"\n[bold cyan]GTFOBins lookup for '{binary}':[/bold cyan]")
        console.print(f"Visit: https://gtfobins.github.io/gtfobins/{binary}/")
        console.print("\nCommon privilege escalation techniques:")
        console.print("• SUID exploitation")
        console.print("• Sudo abuse")  
        console.print("• File read/write capabilities")
        console.print("• Shell escape sequences")
    
    def show_tool_information(self):
        """Display information about cybersecurity tools"""
        clear()
        Title("Cybersecurity Tool Information")
        
        console.print("Learn about the tools included in SPARM:\n")
        
        for category, info in CATEGORIES.items():
            console.print(f"[bold cyan]{info['name']}[/bold cyan]")
            console.print(f"  {info['description']}\n")
        
        Continue()
    
    def settings_menu(self):
        """Settings and configuration menu"""
        clear()
        Title("SPARM Settings")
        
        console.print(f"Current experience level: {EXPERIENCE_LEVELS[self.user_level]['name']}\n")
        
        console.print("Settings options:")
        console.print("  1. Change experience level")
        console.print("  2. View tool paths")
        console.print("  3. View wordlist locations")
        console.print("  4. Back to main menu")
        
        choice = get_user_input("Select option (1-4)", choices=["1", "2", "3", "4"])
        
        if choice == "1":
            self.select_experience_level()
        elif choice == "2":
            self.show_tool_paths()
        elif choice == "3":
            self.show_wordlists()
        elif choice == "4":
            return
    
    def show_tool_paths(self):
        """Display configured tool paths"""
        Title("Tool Paths Configuration")
        
        for tool, path in TOOL_PATHS.items():
            if os.path.exists(path):
                console.print(f"[green]✓[/green] {tool}: {path}")
            else:
                console.print(f"[red]✗[/red] {tool}: {path} (not found)")
        
        Continue()
    
    def show_wordlists(self):
        """Display available wordlists"""
        Title("Wordlist Locations")
        
        for list_type, path in WORDLISTS.items():
            if os.path.exists(path):
                console.print(f"[green]✓[/green] {list_type}: {path}")
            else:
                console.print(f"[red]✗[/red] {list_type}: {path} (not found)")
        
        Continue()
    
    def exit_application(self):
        """Exit the application"""
        clear()
        console.print("[bold cyan]Thank you for using SPARM![/bold cyan]")
        console.print("Remember to use these tools responsibly and ethically.")
        console.print("\n[dim]Stay curious, stay ethical! 🛡️[/dim]")
        sys.exit(0)
    
    def run(self):
        """Main application loop"""
        try:
            self.show_disclaimer()
            self.initialize_user_profile()
            
            while True:
                choice = self.display_main_menu()
                self.route_selection(choice)
                
        except KeyboardInterrupt:
            console.print("\n\n[bold yellow]Interrupted by user. Exiting...[/bold yellow]")
            sys.exit(0)
        except Exception as e:
            console.print(f"\n[bold red]Unexpected error: {e}[/bold red]")
            if self.user_level == "advanced":
                import traceback
                console.print(traceback.format_exc())
            sys.exit(1)

def main():
    """Entry point for SPARM"""
    sparm = SPARMInterface()
    sparm.run()

if __name__ == "__main__":
    main()