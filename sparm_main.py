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
        console.print("[bold red]" + "─" * 60 + "[/bold red]")
        console.print("[bold red]⚠️  EDUCATIONAL USE ONLY - AUTHORIZED TESTING REQUIRED ⚠️[/bold red]")
        console.print("[bold red]" + "─" * 60 + "[/bold red]")
        console.print(DISCLAIMER)
        console.print("[bold red]" + "─" * 60 + "[/bold red]")
        console.print("\n[bold green]✓[/bold green] Initializing SPARM interface...")
        import time
        time.sleep(1.5)
    
    def initialize_user_profile(self):
        """Initialize user profile with experience level selection"""
        self.user_level = "intermediate"  # Default to intermediate level
        clear()
        console.print("[bold green]✓[/bold green] SPARM initialized successfully")
        console.print("[dim]Ready for security testing operations[/dim]\n")
    
    def display_main_menu(self):
        """Display the compact main menu interface"""
        clear()
        ascii_art("SPARM")
        
        compact_menu_header()
        status_line(self.user_level, "Ready for security testing")
        separator()
        
        console.print("[bold yellow]🎯 Cyber Kill Chain Phases[/bold yellow]")
        separator()
        
        menu_items = [
            ("1", "🔍", "OSINT & Information Gathering", "Reconnaissance phase", "cyan"),
            ("2", "🌐", "Network Reconnaissance", "Discovery & enumeration", "blue"),
            ("3", "🛡️", "Web Vulnerability Assessment", "Web application testing", "magenta"),
            ("4", "💉", "SQL Injection Testing", "Database injection attacks", "red"),
            ("5", "🔑", "Credential Access", "Password attacks & harvesting", "yellow"),
            ("6", "⬆️", "Privilege Escalation", "System privilege escalation", "green"),
            ("7", "🚀", "Advanced Offensive Tools", "Payloads, C2 & persistence", "red"),
            ("8", "🔒", "Privacy Protection", "VPN, Tor & lab security", "magenta"),
            ("9", "📚", "Documentation Server", "Host SPARM documentation", "blue"),
            ("10", "ℹ️", "Tool Information", "Learn tools & techniques", "white"),
            ("11", "⚙️", "Settings", "Configure SPARM settings", "cyan"),
            ("0", "🚪", "Exit", "Exit SPARM safely", "dim")
        ]
        
        display_three_row_menu(menu_items)
        
        separator()
        return get_user_input("[bold cyan]SPARM[/bold cyan] > Select option", choices=[item[0] for item in menu_items])
    
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
            from modules.privacy_protection import run as privacy_run
            privacy_run()
        elif choice == "9":
            self.documentation_server()
        elif choice == "10":
            self.show_tool_information()
        elif choice == "11":
            self.settings_menu()
        elif choice == "0":
            self.exit_application()
    
    def privilege_escalation_menu(self):
        """Privilege escalation tools and techniques"""
        clear()
        console.print("[bold green]⬆️  Privilege Escalation Toolkit[/bold green]")
        separator()
        
        tools = [
            ("1", "🐧", "LinPEAS", "Linux privilege escalation scanner", "green"),
            ("2", "🪟", "WinPEAS", "Windows privilege escalation scanner", "blue"),
            ("3", "🔍", "Linux Exploit Suggester", "Kernel exploit suggestions", "yellow"),
            ("4", "📚", "GTFOBins Lookup", "Unix binary exploitation guide", "cyan"),
            ("5", "🔙", "Back to Main Menu", "Return to main interface", "dim")
        ]
        
        for choice, icon, name, description, color in tools:
            display_compact_menu_item(int(choice), icon, name, description, color)
        
        separator()
        choice = get_user_input("[bold green]PRIVESC[/bold green] > Select tool", choices=["1", "2", "3", "4", "5"])
        
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
        console.print("[bold cyan]⚙️  SPARM Configuration[/bold cyan]")
        separator()
        
        console.print(f"[bold white]Current Level:[/bold white] {EXPERIENCE_LEVELS[self.user_level]['name']}")
        separator()
        
        settings = [
            ("1", "🎓", "Change Experience Level", "Adjust guidance and automation", "yellow"),
            ("2", "🛠️", "View Tool Paths", "Check installed tool locations", "green"),
            ("3", "📝", "View Wordlist Locations", "Show available wordlists", "blue"),
            ("4", "🔙", "Back to Main Menu", "Return to main interface", "dim")
        ]
        
        for choice, icon, name, description, color in settings:
            display_compact_menu_item(int(choice), icon, name, description, color)
        
        separator()
        choice = get_user_input("[bold cyan]SETTINGS[/bold cyan] > Select option", choices=["1", "2", "3", "4"])
        
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
    
    def select_experience_level(self):
        """Allow user to select experience level"""
        clear()
        console.print("[bold yellow]🎓 Select Experience Level[/bold yellow]")
        separator()
        
        levels = [
            ("1", "🎓", "Beginner", "Guided mode with explanations", "green"),
            ("2", "⚡", "Intermediate", "Balanced mode with some automation", "yellow"),
            ("3", "🔥", "Advanced", "Expert mode with minimal guidance", "red"),
            ("4", "🔙", "Back", "Return to settings menu", "dim")
        ]
        
        for choice, icon, name, description, color in levels:
            display_compact_menu_item(int(choice), icon, name, description, color)
        
        separator()
        choice = get_user_input("[bold yellow]LEVEL[/bold yellow] > Select experience level", choices=["1", "2", "3", "4"])
        
        if choice == "1":
            self.user_level = "beginner"
            Success("Experience level set to Beginner")
        elif choice == "2":
            self.user_level = "intermediate"
            Success("Experience level set to Intermediate")
        elif choice == "3":
            self.user_level = "advanced"
            Success("Experience level set to Advanced")
        elif choice == "4":
            return
        
        Continue()
    
    def documentation_server(self):
        """Start documentation server with localxpose option"""
        clear()
        console.print("[bold blue]📚 SPARM Documentation Server[/bold blue]")
        separator()
        
        console.print("Host your SPARM documentation locally or publicly")
        separator()
        
        options = [
            ("1", "🌐", "Start Local Server", "Host docs at http://localhost:8080", "green"),
            ("2", "🚀", "Setup Public Access", "Configure localxpose for public hosting", "yellow"),
            ("3", "📖", "Open Documentation", "View docs in browser", "blue"),
            ("4", "ℹ️", "Server Information", "View hosting details and URLs", "white"),
            ("5", "🔙", "Back to Main Menu", "Return to SPARM main menu", "dim")
        ]
        
        for choice, icon, name, description, color in options:
            display_compact_menu_item(int(choice), icon, name, description, color)
        
        separator()
        choice = get_user_input("[bold blue]DOCS[/bold blue] > Select option", choices=["1", "2", "3", "4", "5"])
        
        if choice == "1":
            self.start_local_server()
        elif choice == "2":
            self.setup_public_access()
        elif choice == "3":
            self.open_documentation()
        elif choice == "4":
            self.show_server_info()
        elif choice == "5":
            return
            
        Continue()
    
    def start_local_server(self):
        """Start local documentation server"""
        console.print("[bold green]🌐 Starting Local Documentation Server[/bold green]")
        separator()
        
        console.print("Starting server on http://localhost:8080...")
        console.print("\n[bold yellow]To start server:[/bold yellow]")
        console.print("python3 serve_docs.py")
        
        console.print("\n[bold cyan]Server will be accessible at:[/bold cyan]")
        console.print("• Local: http://localhost:8080/sparm_documentation.html")
        console.print("• Network: http://0.0.0.0:8080/sparm_documentation.html")
        
        if Confirm.ask("\nStart server now?"):
            import subprocess
            import threading
            
            def run_server():
                subprocess.run(['python3', 'serve_docs.py'])
            
            thread = threading.Thread(target=run_server, daemon=True)
            thread.start()
            
            Success("Documentation server started in background!")
            console.print("Press Ctrl+C in the terminal to stop the server")
    
    def setup_public_access(self):
        """Setup public access with localxpose"""
        console.print("[bold yellow]🚀 Public Access Setup[/bold yellow]")
        separator()
        
        console.print("Setting up public access using localxpose...")
        console.print("\n[bold cyan]Steps to enable public access:[/bold cyan]")
        console.print("1. Run the setup script: ./setup_public_docs.sh")
        console.print("2. Start combined server: ./start_public_docs.sh")
        
        console.print("\n[bold cyan]Your localxpose token:[/bold cyan]")
        console.print("EuuH7kG0tZTCgB3rioKeR5a24e1iWc6oFEaolvca")
        
        console.print("\n[bold green]Manual setup commands:[/bold green]")
        console.print("loclx account login --token EuuH7kG0tZTCgB3rioKeR5a24e1iWc6oFEaolvca")
        console.print("loclx tunnel http --to localhost:8080")
        
        if Confirm.ask("\nRun setup script now?"):
            import subprocess
            subprocess.run(['./setup_public_docs.sh'])
    
    def open_documentation(self):
        """Open documentation in browser"""
        console.print("[bold blue]📖 Opening Documentation[/bold blue]")
        separator()
        
        import webbrowser
        import os
        
        doc_path = os.path.join(os.getcwd(), "docs", "sparm_documentation.html")
        
        if os.path.exists(doc_path):
            try:
                webbrowser.open(f'file://{doc_path}')
                Success("Documentation opened in browser!")
            except Exception as e:
                Warning(f"Could not open browser: {e}")
                console.print(f"[bold cyan]Manual path:[/bold cyan] file://{doc_path}")
        else:
            Warning("Documentation file not found!")
            console.print("Please ensure docs/sparm_documentation.html exists")
    
    def show_server_info(self):
        """Show server information and URLs"""
        console.print("[bold white]ℹ️  Server Information[/bold white]")
        separator()
        
        console.print("[bold cyan]Local Access:[/bold cyan]")
        console.print("• URL: http://localhost:8080/sparm_documentation.html")
        console.print("• Start: python3 serve_docs.py")
        
        console.print("\n[bold cyan]Public Access (localxpose):[/bold cyan]")
        console.print("• Setup: ./setup_public_docs.sh")
        console.print("• Start: ./start_public_docs.sh")
        console.print("• Token: EuuH7kG0tZTCgB3rioKeR5a24e1iWc6oFEaolvca")
        
        console.print("\n[bold cyan]Documentation Features:[/bold cyan]")
        console.print("• Comprehensive tool guides")
        console.print("• Step-by-step methodologies")
        console.print("• Advanced red team techniques")
        console.print("• Privacy protection guidance")
        console.print("• Ethical hacking best practices")
        
        console.print("\n[bold yellow]Security Notes:[/bold yellow]")
        console.print("• Only share public URLs with trusted individuals")
        console.print("• Documentation contains educational cybersecurity content")
        console.print("• Intended for authorized lab testing environments only")
    
    def exit_application(self):
        """Exit the application"""
        clear()
        console.print("[bold red]" + "─" * 50 + "[/bold red]")
        console.print("[bold cyan]      Thank you for using SPARM! 🛡️[/bold cyan]")
        console.print("[bold red]" + "─" * 50 + "[/bold red]")
        console.print("[bold white]Remember:[/bold white]")
        console.print("  • Use tools responsibly and ethically")
        console.print("  • Only test systems you own or have permission for")
        console.print("  • Keep learning and stay curious!")
        console.print("[bold red]" + "─" * 50 + "[/bold red]")
        console.print("[dim]Stay safe, stay ethical! 🔒[/dim]")
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