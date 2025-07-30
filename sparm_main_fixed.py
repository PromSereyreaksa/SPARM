#!/usr/bin/env python3
"""
SPARM - Security Penetration & Research Multitool
Enhanced Version with 3x3 Matrix Layout and Numbered Menu System

Educational Use Only - Authorized Testing Environment Required
"""

import sys
import os
import webbrowser
import subprocess
import threading
from core.utils import *
from core.config import *

class SPARMInterface:
    def __init__(self):
        self.user_level = "intermediate"
        self.session_data = {}
    
    def show_disclaimer(self):
        """Display educational disclaimer"""
        clear()
        console.print("[bold red]" + "─" * 70 + "[/bold red]")
        console.print("[bold red]⚠️  EDUCATIONAL USE ONLY - AUTHORIZED TESTING REQUIRED ⚠️[/bold red]")
        console.print("[bold red]" + "─" * 70 + "[/bold red]")
        console.print(DISCLAIMER)
        console.print("[bold red]" + "─" * 70 + "[/bold red]")
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
        """Display the main menu with 3x3 matrix layout"""
        clear()
        ascii_art("SPARM")
        
        compact_menu_header()
        status_line(self.user_level, "Ready for security testing")
        separator()
        
        # 3x3 Matrix Layout with Category Headers
        console.print("[bold yellow]🛡️ Security Testing Categories[/bold yellow]")
        separator()
        
        # Row 1: Information Gathering & Reconnaissance
        console.print("[bold cyan]🔍 Information Gathering    🌐 Network Reconnaissance    🛡️ Web Vulnerability[/bold cyan]")
        console.print("┌────────────────────────┬────────────────────────┬────────────────────────┐")
        console.print("│[bold green] 1.[/bold green] 🔍 OSINT Toolkit      │[bold blue] 2.[/bold blue] 🌐 Network Recon       │[bold magenta] 3.[/bold magenta] 🛡️ Web Vuln Assessment │")
        console.print("│   Information gathering │   Discovery & enum     │   Web application test │")
        console.print("├────────────────────────┼────────────────────────┼────────────────────────┤")
        
        # Row 2: Exploitation & Post-Exploitation  
        console.print("│[bold red] 4.[/bold red] 💉 SQL Injection      │[bold yellow] 5.[/bold yellow] 🔑 Credential Access   │[bold green] 6.[/bold green] ⬆️ Privilege Escalation │")
        console.print("│   Database attacks     │   Password & harvesting│   System privilege esc │")
        console.print("├────────────────────────┼────────────────────────┼────────────────────────┤")
        
        # Row 3: Advanced & Utilities
        console.print("│[bold red] 7.[/bold red] 🚀 Advanced Offensive  │[bold magenta] 8.[/bold magenta] 🔒 Privacy Protection  │[bold blue] 9.[/bold blue] 📚 Documentation      │")
        console.print("│   Payloads, C2 & persist│   VPN, Tor & lab security│   Host SPARM docs    │")
        console.print("└────────────────────────┴────────────────────────┴────────────────────────┘")
        
        separator()
        
        # Additional Options Row
        console.print("[bold white]Additional Options:[/bold white]")
        console.print("┌─────────────────────┬─────────────────────┬─────────────────────┐")
        console.print("│[bold yellow]10.[/bold yellow] 🎯 Cyber Kill Chain │[bold cyan]11.[/bold cyan] 💬 Discord Security  │[bold white]12.[/bold white] ⚙️ Settings          │")
        console.print("│    Attack methodology│    Educational analysis│    Configure SPARM   │")
        console.print("└─────────────────────┴─────────────────────┴─────────────────────┘")
        
        console.print("\n[bold red]0.[/bold red] 🚪 Exit SPARM")
        
        separator()
        return get_user_input("[bold cyan]SPARM[/bold cyan] > Select option (0-12)", 
                            choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"])
    
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
            self.cyber_kill_chain_menu()
        elif choice == "11":
            self.discord_security_menu()
        elif choice == "12":
            self.settings_menu()
        elif choice == "0":
            self.exit_application()
    
    def cyber_kill_chain_menu(self):
        """Cyber Kill Chain methodology menu"""
        clear()
        console.print("[bold yellow]🎯 Cyber Kill Chain Methodology[/bold yellow]")
        separator()
        
        console.print("[bold white]The 7-Phase Cyber Kill Chain Framework:[/bold white]\n")
        
        # Display kill chain phases in a structured format
        phases = [
            ("1", "🔍", "Reconnaissance", "Gather intelligence on target", "green"),
            ("2", "⚔️", "Weaponization", "Create deliverable payload", "yellow"), 
            ("3", "📤", "Delivery", "Transmit weapon to target", "blue"),
            ("4", "💥", "Exploitation", "Execute code on victim's system", "red"),
            ("5", "💿", "Installation", "Install malware on target", "magenta"),
            ("6", "🎮", "Command & Control", "Establish remote control channel", "cyan"),
            ("7", "🎯", "Actions on Objective", "Achieve intended goals", "white")
        ]
        
        for choice, icon, name, description, color in phases:
            display_compact_menu_item(int(choice), icon, name, description, color)
        
        console.print("\n[bold cyan]Kill Chain Tools by Phase:[/bold cyan]")
        console.print("• Phase 1: TheHarvester, Maltego, Recon-ng, Nmap")
        console.print("• Phase 2: MSFVenom, SET, Custom payloads")
        console.print("• Phase 3: Phishing, Social engineering, Physical delivery")
        console.print("• Phase 4: Metasploit, Custom exploits, Web shells")
        console.print("• Phase 5: Persistence scripts, Backdoors, Rootkits")
        console.print("• Phase 6: C2 frameworks, Remote access tools")
        console.print("• Phase 7: Data exfiltration, Lateral movement")
        
        separator()
        choice = get_user_input("[bold yellow]KILL-CHAIN[/bold yellow] > Select phase to explore (1-7) or 0 to return", 
                              choices=["0", "1", "2", "3", "4", "5", "6", "7"])
        
        if choice == "0":
            return
        elif choice == "1":
            info("Phase 1: Reconnaissance - Use OSINT Toolkit (Option 1) and Network Recon (Option 2)")
        elif choice == "2":
            info("Phase 2: Weaponization - Use Advanced Offensive Tools (Option 7)")
        elif choice == "3":
            info("Phase 3: Delivery - Use Social Engineering and phishing techniques")
        elif choice == "4":
            info("Phase 4: Exploitation - Use Web Vulnerability and SQL Injection tools")
        elif choice == "5":
            info("Phase 5: Installation - Use Privilege Escalation tools (Option 6)")
        elif choice == "6":
            info("Phase 6: C2 - Use Advanced Offensive framework tools")
        elif choice == "7":
            info("Phase 7: Actions - Use all post-exploitation and data gathering tools")
        
        Continue()
    
    def discord_security_menu(self):
        """Discord Security Analysis menu (Educational Only)"""
        clear()
        console.print("[bold magenta]💬 Discord Security Analysis[/bold magenta]")
        console.print("[bold red]⚠️ EDUCATIONAL PURPOSE ONLY ⚠️[/bold red]")
        separator()
        
        console.print("[dim]These tools are designed for understanding Discord security threats")
        console.print("and improving defensive security awareness. Use only in authorized")
        console.print("lab environments for educational purposes.[/dim]\n")
        
        tools = [
            ("1", "🔍", "Token Structure Analyzer", "Analyze Discord token format (educational)", "cyan"),
            ("2", "✅", "Token Format Validator", "Validate Discord token structure", "green"),
            ("3", "🎣", "Phishing Pattern Detector", "Identify common Discord scams", "yellow"),
            ("4", "🛡️", "Security Scanner", "Discord server security assessment", "blue"),
            ("5", "🤖", "Bot Permission Analyzer", "Analyze bot permission risks", "magenta"),
            ("6", "📚", "Security Education", "Learn about Discord security threats", "white"),
            ("0", "🔙", "Back to Main Menu", "Return to main interface", "dim")
        ]
        
        for choice, icon, name, description, color in tools:
            if choice == "0":
                console.print(f"\n[bold {color}][{choice}][/bold {color}] {icon} [bold white]{name}[/bold white] - [dim]{description}[/dim]")
            else:
                display_compact_menu_item(int(choice), icon, name, description, color)
        
        separator()
        choice = get_user_input("[bold magenta]DISCORD-SEC[/bold magenta] > Select option", 
                               choices=["0", "1", "2", "3", "4", "5", "6"])
        
        if choice == "0":
            return
        elif choice == "1":
            self.discord_token_analyzer()
        elif choice == "2":
            self.discord_token_validator()
        elif choice == "3":
            self.discord_phishing_detector() 
        elif choice == "4":
            self.discord_security_scanner()
        elif choice == "5":
            self.discord_bot_analyzer()
        elif choice == "6":
            self.discord_security_education()
        
        Continue()
    
    def discord_token_analyzer(self):
        """Educational Discord token structure analyzer"""
        banner("Discord Token Structure Analyzer")
        console.print("[bold red]EDUCATIONAL PURPOSE ONLY[/bold red]\n")
        
        console.print("[bold cyan]Discord Token Structure:[/bold cyan]")
        console.print("• Part 1: User ID (Base64 encoded)")
        console.print("• Part 2: Timestamp") 
        console.print("• Part 3: HMAC signature")
        console.print("• Format: XXXXXXXX.XXXXXX.XXXXXXXXXXXXXXXXXXXXXXXXXXX")
        
        console.print("\n[bold yellow]Security Notes:[/bold yellow]")
        console.print("• Tokens provide full account access")
        console.print("• Never share or expose tokens")
        console.print("• Use 2FA for additional security")
        console.print("• Regenerate if compromised")
        
        console.print("\n[bold red]⚠️ WARNING:[/bold red]")
        console.print("• Token grabbers are malware that steal Discord tokens")
        console.print("• Always scan downloads with antivirus")
        console.print("• Be suspicious of 'free Nitro' offers")
        console.print("• Only download Discord from official sources")
    
    def discord_token_validator(self):
        """Educational Discord token format validator"""
        banner("Discord Token Format Validator")
        console.print("[bold red]EDUCATIONAL PURPOSE ONLY[/bold red]\n")
        
        console.print("[bold yellow]This tool validates token FORMAT only - never use real tokens![/bold yellow]\n")
        
        token = get_user_input("Enter example token to analyze format (example: MTk4NjIyNDgzNDcxOTI1MjQ4.Cl2FMQ.ZnCjm1XVW7vRze4b7Cq4se7kKWs)")
        
        if not token or len(token) < 50:
            Warning("Invalid token format - too short")
            return
        
        parts = token.split('.')
        if len(parts) != 3:
            Warning("Invalid token format - should have 3 parts separated by dots")
            return
        
        console.print(f"[bold green]✓[/bold green] Token format appears valid")
        console.print(f"• Part 1 length: {len(parts[0])} (User ID)")
        console.print(f"• Part 2 length: {len(parts[1])} (Timestamp)")
        console.print(f"• Part 3 length: {len(parts[2])} (HMAC)")
        
        Warning("This tool only validates format - never test with real tokens!")
    
    def discord_phishing_detector(self):
        """Educational Discord phishing pattern detector"""
        banner("Discord Phishing Pattern Detector")
        console.print("[bold red]EDUCATIONAL PURPOSE ONLY[/bold red]\n")
        
        console.print("[bold cyan]Common Discord Phishing Patterns:[/bold cyan]")
        console.print("• Fake Nitro giveaways")
        console.print("• Suspicious login pages")
        console.print("• Malicious bot invitations")
        console.print("• Token grabber executables")
        console.print("• QR code scams")
        console.print("• Fake Discord updates")
        
        console.print("\n[bold yellow]Detection Indicators:[/bold yellow]")
        console.print("• Non-discord.com domains")
        console.print("• Urgent language and time limits")
        console.print("• Requests for tokens or passwords")
        console.print("• Suspicious file downloads")
        console.print("• Unusual permission requests")
        console.print("• Grammar/spelling errors")
        
        console.print("\n[bold green]Protection Tips:[/bold green]")
        console.print("• Always verify URLs before clicking")
        console.print("• Enable 2FA on your Discord account")
        console.print("• Never share your token with anyone")
        console.print("• Be skeptical of 'too good to be true' offers")
        console.print("• Keep Discord client updated")
    
    def discord_security_scanner(self):
        """Discord server security assessment"""
        banner("Discord Server Security Scanner")
        console.print("[bold red]EDUCATIONAL PURPOSE ONLY[/bold red]\n")
        
        console.print("[bold cyan]Server Security Checklist:[/bold cyan]")
        console.print("✓ Proper role permissions configured")
        console.print("✓ Verification levels set appropriately") 
        console.print("✓ Bot permissions limited to necessary functions")
        console.print("✓ Audit log monitoring enabled")
        console.print("✓ Suspicious user activity monitoring")
        console.print("✓ Regular permission audits")
        
        console.print("\n[bold yellow]Common Security Issues:[/bold yellow]")
        console.print("• Overprivileged bots")
        console.print("• Weak verification requirements")
        console.print("• Unmoderated channels")
        console.print("• Excessive admin permissions")
        console.print("• No audit log review")
        
        info("Use this checklist to assess Discord server security in authorized environments")
    
    def discord_bot_analyzer(self):
        """Discord bot permission analyzer"""
        banner("Discord Bot Permission Analyzer")
        console.print("[bold red]EDUCATIONAL PURPOSE ONLY[/bold red]\n")
        
        console.print("[bold cyan]High-Risk Bot Permissions:[/bold cyan]")
        console.print("🔴 Administrator - Full server control")
        console.print("🔴 Manage Server - Server settings access")
        console.print("🔴 Manage Roles - Role permission changes")
        console.print("🔴 Manage Channels - Channel modification")
        console.print("🔴 Ban Members - User banning capability")
        console.print("🔴 Kick Members - User removal capability")
        
        console.print("\n[bold yellow]Medium-Risk Permissions:[/bold yellow]")
        console.print("🟡 Manage Messages - Message deletion")
        console.print("🟡 Mention Everyone - Mass notifications")
        console.print("🟡 Use External Emojis - Resource usage")
        
        console.print("\n[bold green]Safe Permissions:[/bold green]")
        console.print("🟢 Send Messages - Basic communication")
        console.print("🟢 Read Message History - Message access")
        console.print("🟢 Add Reactions - Emoji reactions")
        
        info("Only grant bots the minimum permissions required for their function")
    
    def discord_security_education(self):
        """Discord security education module"""
        banner("Discord Security Education")
        
        console.print("[bold cyan]Learning Objectives:[/bold cyan]")
        console.print("• Understand Discord security threats")
        console.print("• Recognize phishing attempts")
        console.print("• Implement proper security practices")
        console.print("• Protect personal and server data")
        
        console.print("\n[bold yellow]Key Security Concepts:[/bold yellow]")
        console.print("• Authentication vs Authorization")
        console.print("• Principle of Least Privilege")
        console.print("• Social Engineering Tactics")
        console.print("• Malware Detection and Prevention")
        
        console.print("\n[bold white]Recommended Security Practices:[/bold white]")
        console.print("1. Enable Two-Factor Authentication")
        console.print("2. Regularly review server permissions")
        console.print("3. Monitor audit logs for suspicious activity")
        console.print("4. Educate server members about phishing")
        console.print("5. Keep bots and integrations updated")
        console.print("6. Use strong, unique passwords")
        
        info("These practices help maintain a secure Discord environment")
    
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