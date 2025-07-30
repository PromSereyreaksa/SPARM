#!/usr/bin/env python3
"""
SPARM - Security Penetration & Research Multitool
Enhanced Version with Category-Based Organization and Improved UI

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
        self.tool_categories = {
            "information_gathering": {
                "name": "🔍 Information Gathering",
                "description": "OSINT, domain enumeration, and reconnaissance",
                "tools": {
                    "nmap": "Network discovery and security auditing",
                    "masscan": "High-speed port scanner",
                    "dnsrecon": "DNS reconnaissance tool",
                    "fierce": "Domain scanner",
                    "theharvester": "Email and subdomain harvester",
                    "maltego": "Link analysis and data mining",
                    "recon-ng": "Full-featured web reconnaissance framework",
                    "sherlock": "Hunt social media accounts by username"
                }
            },
            "scanning_enumeration": {
                "name": "🌐 Scanning & Enumeration", 
                "description": "Port scanning, service enumeration, and discovery",
                "tools": {
                    "gobuster": "Directory/file & DNS busting",
                    "dirb": "Web content scanner",
                    "nikto": "Web server scanner",
                    "enum4linux": "SMB enumeration tool",
                    "smbclient": "SMB/CIFS client",
                    "snmpwalk": "SNMP enumeration",
                    "ldapsearch": "LDAP enumeration",
                    "rpcinfo": "RPC enumeration"
                }
            },
            "exploitation": {
                "name": "💥 Exploitation",
                "description": "Exploit frameworks and vulnerability exploitation",
                "tools": {
                    "metasploit": "Penetration testing framework",
                    "msfvenom": "Payload generator",
                    "searchsploit": "Exploit database search",
                    "commix": "Command injection testing",
                    "xsser": "XSS testing framework",
                    "beef": "Browser exploitation framework"
                }
            },
            "post_exploitation": {
                "name": "⚡ Post-Exploitation",
                "description": "Privilege escalation and persistence",
                "tools": {
                    "linpeas": "Linux privilege escalation scanner",
                    "winpeas": "Windows privilege escalation scanner",
                    "linux_exploit_suggester": "Kernel exploit suggestions",
                    "gtfobins": "Unix binary exploitation guide",
                    "pspy": "Process monitoring without root",
                    "powerup": "Windows privilege escalation"
                }
            },
            "social_engineering": {
                "name": "👥 Social Engineering",
                "description": "Social engineering toolkit and phishing",
                "tools": {
                    "setoolkit": "Social Engineering Toolkit",
                    "gophish": "Phishing framework",
                    "king_phisher": "Phishing campaign toolkit",
                    "evilginx": "Advanced phishing framework",
                    "shellphish": "Phishing tool collection"
                }
            },
            "wifi_attacks": {
                "name": "📡 Wi-Fi Attacks",
                "description": "Wireless network testing and attacks",
                "tools": {
                    "aircrack_suite": "Wireless network auditing",
                    "wifite": "Automated wireless attack tool",
                    "reaver": "WPS attack tool",
                    "bully": "WPS brute force attack",
                    "pixiewps": "WPS Pixie Dust attack",
                    "fern": "Wireless security auditing"
                }
            },
            "web_app_attacks": {
                "name": "🌍 Web App Attacks",
                "description": "Web application security testing",
                "tools": {
                    "sqlmap": "Automated SQL injection tool",
                    "burpsuite": "Web application security testing",
                    "owasp_zap": "Web application security scanner",
                    "wpscan": "WordPress security scanner",
                    "droopescan": "Drupal/SilverStripe scanner",
                    "joomscan": "Joomla vulnerability scanner"
                }
            },
            "misc_tools": {
                "name": "🛠️ Misc Tools",
                "description": "Additional penetration testing utilities",
                "tools": {
                    "hydra": "Network logon cracker",
                    "john": "Password cracker",
                    "hashcat": "Advanced password recovery",
                    "crunch": "Wordlist generator",
                    "cewl": "Custom wordlist generator",
                    "steghide": "Steganography tool"
                }
            },
            "cyber_kill_chain": {
                "name": "🎯 Cyber Kill Chain",
                "description": "Systematic attack methodology framework",
                "phases": [
                    {
                        "name": "1. Reconnaissance",
                        "description": "Gather intelligence on target",
                        "tools": ["theharvester", "maltego", "recon-ng", "nmap"]
                    },
                    {
                        "name": "2. Weaponization", 
                        "description": "Create deliverable payload",
                        "tools": ["msfvenom", "setoolkit", "beef"]
                    },
                    {
                        "name": "3. Delivery",
                        "description": "Transmit weapon to target",
                        "tools": ["gophish", "setoolkit", "king_phisher"]
                    },
                    {
                        "name": "4. Exploitation",
                        "description": "Execute code on victim's system",
                        "tools": ["metasploit", "searchsploit", "commix"]
                    },
                    {
                        "name": "5. Installation",
                        "description": "Install malware on target",
                        "tools": ["meterpreter", "powerup", "persistence_tools"]
                    },
                    {
                        "name": "6. Command & Control",
                        "description": "Establish remote control channel",
                        "tools": ["metasploit", "empire", "covenant"]
                    },
                    {
                        "name": "7. Actions on Objective",
                        "description": "Achieve intended goals",
                        "tools": ["linpeas", "winpeas", "data_exfiltration"]
                    }
                ]
            },
            "discord_security": {
                "name": "💬 Discord Security Analysis",
                "description": "Educational Discord security analysis tools",
                "tools": {
                    "token_analyzer": "Analyze Discord token structure (educational)",
                    "token_validator": "Validate Discord token format",
                    "phishing_detector": "Detect Discord phishing patterns",
                    "stealer_behavior": "Analyze token stealer behavior (sandbox)",
                    "security_scanner": "Discord server security assessment",
                    "bot_permissions": "Analyze bot permission risks"
                }
            }
        }
    
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
    
    def display_main_menu(self):
        """Display the main menu with three-column layout"""
        clear()
        ascii_art("SPARM")
        
        console.print("[bold cyan]" + "─" * 70 + "[/bold cyan]")
        console.print("[bold white]Security Penetration & Attack Research Multitool v2.1[/bold white]")
        console.print(f"[bold green]Level: {self.user_level.title()}[/bold green] | [bold yellow]Status: Ready[/bold yellow]")
        console.print("[bold cyan]" + "─" * 70 + "[/bold cyan]")
        
        # Display categories in three columns
        categories = list(self.tool_categories.keys())
        
        # Split into three columns
        col1 = categories[0:4]
        col2 = categories[4:8]  
        col3 = categories[8:]
        
        console.print("\n[bold yellow]🛡️ Security Tool Categories[/bold yellow]")
        console.print("[bold cyan]" + "─" * 70 + "[/bold cyan]")
        
        # Display three columns side by side
        max_rows = max(len(col1), len(col2), len(col3))
        
        for i in range(max_rows):
            row_text = ""
            
            # Column 1
            if i < len(col1):
                cat_key = col1[i]
                cat_info = self.tool_categories[cat_key]
                row_text += f"[bold green]{cat_info['name']}[/bold green]"
                row_text += " " * (25 - len(cat_info['name']))
            else:
                row_text += " " * 25
            
            # Column 2
            if i < len(col2):
                cat_key = col2[i]
                cat_info = self.tool_categories[cat_key]
                row_text += f"[bold blue]{cat_info['name']}[/bold blue]"
                row_text += " " * (25 - len(cat_info['name']))
            else:
                row_text += " " * 25
                
            # Column 3
            if i < len(col3):
                cat_key = col3[i]
                cat_info = self.tool_categories[cat_key]
                row_text += f"[bold magenta]{cat_info['name']}[/bold magenta]"
            
            console.print(row_text)
        
        console.print("\n[bold cyan]" + "─" * 70 + "[/bold cyan]")
        console.print("[bold white]Additional Options:[/bold white]")
        console.print("[bold yellow]📚 Documentation[/bold yellow]  [bold cyan]⚙️ Settings[/bold cyan]  [bold red]🚪 Exit[/bold red]")
        console.print("[bold cyan]" + "─" * 70 + "[/bold cyan]")
        
        return self.get_category_selection()
    
    def get_category_selection(self):
        """Get user's category selection by name"""
        console.print("\n[bold cyan]Enter category name or option:[/bold cyan]")
        console.print("[dim]Examples: 'information gathering', 'web app attacks', 'cyber kill chain'[/dim]")
        console.print("[dim]Or: 'documentation', 'settings', 'exit'[/dim]")
        
        choice = get_user_input("SPARM > ").lower().strip()
        
        # Handle special commands
        if choice in ['exit', 'quit', 'q']:
            return 'exit'
        elif choice in ['settings', 'config']:
            return 'settings'
        elif choice in ['documentation', 'docs', 'help']:
            return 'documentation'
        
        # Match category names (flexible matching)
        for key, category in self.tool_categories.items():
            cat_name = category['name'].lower()
            # Remove emojis and normalize
            clean_name = ''.join(c for c in cat_name if c.isalnum() or c.isspace()).strip()
            
            if choice in clean_name or clean_name.startswith(choice):
                return key
        
        # Partial matching for common terms
        if 'info' in choice or 'recon' in choice:
            return 'information_gathering'
        elif 'scan' in choice or 'enum' in choice:
            return 'scanning_enumeration'
        elif 'exploit' in choice and 'post' not in choice:
            return 'exploitation'
        elif 'post' in choice or 'priv' in choice:
            return 'post_exploitation'
        elif 'social' in choice:
            return 'social_engineering'
        elif 'wifi' in choice or 'wireless' in choice:
            return 'wifi_attacks'
        elif 'web' in choice:
            return 'web_app_attacks'
        elif 'misc' in choice or 'tool' in choice:
            return 'misc_tools'
        elif 'kill' in choice or 'chain' in choice:
            return 'cyber_kill_chain'
        elif 'discord' in choice:
            return 'discord_security'
        
        Warning(f"Category '{choice}' not found. Please try again.")
        return self.get_category_selection()
    
    def display_category_tools(self, category_key):
        """Display tools in a selected category"""
        category = self.tool_categories[category_key]
        clear()
        
        console.print(f"[bold green]{category['name']}[/bold green]")
        console.print("[bold cyan]" + "─" * 60 + "[/bold cyan]")
        console.print(f"[dim]{category['description']}[/dim]\n")
        
        if category_key == "cyber_kill_chain":
            self.display_kill_chain()
        elif category_key == "discord_security":
            self.display_discord_security()
        else:
            # Display tools in three columns
            tools = list(category['tools'].items())
            
            # Split into three columns
            tools_per_col = (len(tools) + 2) // 3
            col1 = tools[0:tools_per_col]
            col2 = tools[tools_per_col:tools_per_col*2]
            col3 = tools[tools_per_col*2:]
            
            max_rows = max(len(col1), len(col2), len(col3))
            
            for i in range(max_rows):
                row_text = ""
                
                # Column 1
                if i < len(col1):
                    tool_name, desc = col1[i]
                    row_text += f"[bold cyan]{tool_name}[/bold cyan]"
                    row_text += " " * (20 - len(tool_name))
                else:
                    row_text += " " * 20
                
                # Column 2  
                if i < len(col2):
                    tool_name, desc = col2[i]
                    row_text += f"[bold yellow]{tool_name}[/bold yellow]"
                    row_text += " " * (20 - len(tool_name))
                else:
                    row_text += " " * 20
                    
                # Column 3
                if i < len(col3):
                    tool_name, desc = col3[i]
                    row_text += f"[bold green]{tool_name}[/bold green]"
                
                console.print(row_text)
        
        console.print(f"\n[bold cyan]" + "─" * 60 + "[/bold cyan]")
        
        tool_choice = get_user_input("Enter tool name to launch, or 'back' to return")
        
        if tool_choice.lower() == 'back':
            return
        
        self.launch_tool(category_key, tool_choice.lower())
    
    def display_kill_chain(self):
        """Display Cyber Kill Chain methodology"""
        kill_chain = self.tool_categories["cyber_kill_chain"]
        
        console.print("[bold yellow]🎯 Cyber Kill Chain Methodology[/bold yellow]\n")
        
        for phase in kill_chain["phases"]:
            console.print(f"[bold green]{phase['name']}[/bold green]")
            console.print(f"  {phase['description']}")
            console.print(f"  [bold cyan]Tools:[/bold cyan] {', '.join(phase['tools'])}")
            console.print()
    
    def display_discord_security(self):
        """Display Discord security analysis tools"""
        console.print("[bold red]⚠️ EDUCATIONAL ANALYSIS ONLY ⚠️[/bold red]")
        console.print("[dim]These tools are for understanding Discord security threats[/dim]")
        console.print("[dim]Use only in authorized lab environments[/dim]\n")
        
        tools = self.tool_categories["discord_security"]["tools"]
        
        for tool_name, description in tools.items():
            console.print(f"[bold cyan]{tool_name}[/bold cyan]")
            console.print(f"  [dim]{description}[/dim]\n")
    
    def launch_tool(self, category_key, tool_name):
        """Launch the selected tool"""
        category = self.tool_categories[category_key]
        
        if tool_name not in category.get('tools', {}):
            Warning(f"Tool '{tool_name}' not found in {category['name']}")
            Continue()
            return
        
        clear()
        banner(f"Launching {tool_name.title()}")
        
        # Route to appropriate module based on category
        if category_key == "information_gathering":
            self.launch_info_gathering_tool(tool_name)
        elif category_key == "scanning_enumeration":
            self.launch_scanning_tool(tool_name)
        elif category_key == "exploitation":
            self.launch_exploitation_tool(tool_name)
        elif category_key == "post_exploitation":
            self.launch_post_exploitation_tool(tool_name)
        elif category_key == "web_app_attacks":
            self.launch_web_tool(tool_name)
        elif category_key == "discord_security":
            self.launch_discord_tool(tool_name)
        else:
            info(f"Tool '{tool_name}' implementation coming soon!")
        
        Continue()
    
    def launch_info_gathering_tool(self, tool_name):
        """Launch information gathering tools"""
        if tool_name == "nmap":
            from modules.reconnaissance import ReconnaissanceToolkit
            toolkit = ReconnaissanceToolkit()
            toolkit.run_nmap()
        elif tool_name == "theharvester":
            from modules.osint_toolkit import OSINTToolkit
            toolkit = OSINTToolkit()
            toolkit.run_theharvester()
        else:
            info(f"Running {tool_name}...")
            console.print(f"Command: {tool_name} --help")
    
    def launch_scanning_tool(self, tool_name):
        """Launch scanning and enumeration tools"""
        if tool_name == "gobuster":
            from modules.reconnaissance import ReconnaissanceToolkit
            toolkit = ReconnaissanceToolkit()
            toolkit.run_gobuster()
        elif tool_name == "nikto":
            info("Running Nikto web server scanner...")
            target = get_user_input("Enter target URL")
            console.print(f"Command: nikto -h {target}")
        else:
            info(f"Running {tool_name}...")
    
    def launch_exploitation_tool(self, tool_name):
        """Launch exploitation tools"""
        if tool_name == "msfvenom":
            from modules.advanced_offensive import AdvancedOffensiveToolkit
            toolkit = AdvancedOffensiveToolkit()
            toolkit.generate_windows_payload()
        else:
            info(f"Running {tool_name}...")
    
    def launch_post_exploitation_tool(self, tool_name):
        """Launch post-exploitation tools"""
        if tool_name == "linpeas":
            info("LinPEAS - Linux Privilege Escalation Scanner")
            console.print("Download and run on target:")
            console.print("curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh")
        else:
            info(f"Running {tool_name}...")
    
    def launch_web_tool(self, tool_name):
        """Launch web application testing tools"""
        if tool_name == "sqlmap":
            from modules.sql_injection import SQLInjectionToolkit
            toolkit = SQLInjectionToolkit()
            toolkit.run_sqlmap()
        else:
            info(f"Running {tool_name}...")
    
    def launch_discord_tool(self, tool_name):
        """Launch Discord security analysis tools (educational only)"""
        Warning("Educational analysis tool - Use only in authorized environments")
        
        if tool_name == "token_analyzer":
            self.discord_token_analyzer()
        elif tool_name == "token_validator":
            self.discord_token_validator()
        elif tool_name == "phishing_detector":
            self.discord_phishing_detector()
        else:
            info(f"Discord tool '{tool_name}' - Educational implementation")
    
    def discord_token_analyzer(self):
        """Educational Discord token structure analyzer"""
        console.print("[bold yellow]Discord Token Structure Analyzer[/bold yellow]")
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
    
    def discord_token_validator(self):
        """Educational Discord token format validator"""
        console.print("[bold yellow]Discord Token Format Validator[/bold yellow]")
        console.print("[bold red]EDUCATIONAL PURPOSE ONLY[/bold red]\n")
        
        token = get_user_input("Enter token to analyze format (will not be stored)")
        
        if not token or len(token) < 50:
            Warning("Invalid token format - too short")
            return
        
        parts = token.split('.')
        if len(parts) != 3:
            Warning("Invalid token format - should have 3 parts separated by dots")
            return
        
        console.print(f"[bold green]✓[/bold green] Token format appears valid")
        console.print(f"• Part 1 length: {len(parts[0])}")
        console.print(f"• Part 2 length: {len(parts[1])}")
        console.print(f"• Part 3 length: {len(parts[2])}")
        
        Warning("This tool only validates format - never test with real tokens!")
    
    def discord_phishing_detector(self):
        """Educational Discord phishing pattern detector"""
        console.print("[bold yellow]Discord Phishing Pattern Detector[/bold yellow]")
        console.print("[bold red]EDUCATIONAL PURPOSE ONLY[/bold red]\n")
        
        console.print("[bold cyan]Common Discord Phishing Patterns:[/bold cyan]")
        console.print("• Fake Nitro giveaways")
        console.print("• Suspicious login pages")
        console.print("• Malicious bot invitations")
        console.print("• Token grabber executables")
        console.print("• QR code scams")
        
        console.print("\n[bold yellow]Detection Indicators:[/bold yellow]")
        console.print("• Non-discord.com domains")
        console.print("• Urgent language and time limits")
        console.print("• Requests for tokens or passwords")
        console.print("• Suspicious file downloads")
        console.print("• Unusual permission requests")
    
    def settings_menu(self):
        """Settings and configuration menu"""
        clear()
        console.print("[bold cyan]⚙️ SPARM Settings[/bold cyan]")
        console.print("[bold cyan]" + "─" * 50 + "[/bold cyan]")
        
        console.print(f"[bold white]Experience Level:[/bold white] {self.user_level.title()}")
        console.print("[bold cyan]" + "─" * 50 + "[/bold cyan]")
        
        console.print("\n[bold yellow]Available Settings:[/bold yellow]")
        console.print("• change_level - Change experience level")
        console.print("• tool_paths - View tool installation paths")
        console.print("• wordlists - View wordlist locations")
        console.print("• back - Return to main menu")
        
        choice = get_user_input("Settings > ").lower()
        
        if choice == "change_level":
            self.select_experience_level()
        elif choice == "tool_paths":
            self.show_tool_paths()
        elif choice == "wordlists":
            self.show_wordlists()
        elif choice == "back":
            return
        else:
            Warning("Invalid option")
            self.settings_menu()
    
    def select_experience_level(self):
        """Allow user to select experience level"""
        console.print("\n[bold yellow]Select Experience Level:[/bold yellow]")
        console.print("• beginner - Guided mode with explanations")
        console.print("• intermediate - Balanced mode with some automation")
        console.print("• advanced - Expert mode with minimal guidance")
        
        level = get_user_input("Enter level", choices=["beginner", "intermediate", "advanced"])
        self.user_level = level
        Success(f"Experience level set to {level.title()}")
    
    def show_tool_paths(self):
        """Display tool installation paths"""
        console.print("[bold cyan]Tool Installation Paths:[/bold cyan]")
        
        common_tools = [
            "nmap", "gobuster", "sqlmap", "nikto", "dirb", 
            "hydra", "john", "hashcat", "metasploit"
        ]
        
        for tool in common_tools:
            import shutil
            path = shutil.which(tool)
            if path:
                console.print(f"[green]✓[/green] {tool}: {path}")
            else:
                console.print(f"[red]✗[/red] {tool}: Not found")
    
    def show_wordlists(self):
        """Display wordlist locations"""
        console.print("[bold cyan]Common Wordlist Locations:[/bold cyan]")
        
        wordlist_paths = [
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/seclists"
        ]
        
        for path in wordlist_paths:
            if os.path.exists(path):
                console.print(f"[green]✓[/green] {path}")
            else:
                console.print(f"[red]✗[/red] {path}")
    
    def documentation_server(self):
        """Start documentation server"""
        clear()
        console.print("[bold blue]📚 SPARM Documentation[/bold blue]")
        console.print("[bold cyan]" + "─" * 50 + "[/bold cyan]")
        
        console.print("Documentation options:")
        console.print("• start_server - Start local documentation server")
        console.print("• open_docs - Open documentation in browser")
        console.print("• back - Return to main menu")
        
        choice = get_user_input("Documentation > ").lower()
        
        if choice == "start_server":
            self.start_local_server()
        elif choice == "open_docs":
            self.open_documentation()
        elif choice == "back":
            return
        else:
            self.documentation_server()
    
    def start_local_server(self):
        """Start local documentation server"""
        console.print("[bold green]Starting Documentation Server...[/bold green]")
        console.print("Server will be available at: http://localhost:8080")
        console.print("Command: python3 serve_docs.py")
        
        if Confirm.ask("Start server now?"):
            def run_server():
                subprocess.run(['python3', 'serve_docs.py'])
            
            thread = threading.Thread(target=run_server, daemon=True)
            thread.start()
            Success("Documentation server started!")
    
    def open_documentation(self):
        """Open documentation in browser"""
        doc_path = os.path.join(os.getcwd(), "docs", "sparm_documentation.html")
        
        if os.path.exists(doc_path):
            try:
                webbrowser.open(f'file://{doc_path}')
                Success("Documentation opened in browser!")
            except:
                console.print(f"Manual path: file://{doc_path}")
        else:
            Warning("Documentation file not found!")
    
    def exit_application(self):
        """Exit the application"""
        clear()
        console.print("[bold cyan]" + "─" * 60 + "[/bold cyan]")
        console.print("[bold green]      Thank you for using SPARM! 🛡️[/bold green]")
        console.print("[bold cyan]" + "─" * 60 + "[/bold cyan]")
        console.print("[bold white]Remember:[/bold white]")
        console.print("  • Use tools responsibly and ethically")
        console.print("  • Only test systems you own or have permission for")
        console.print("  • Keep learning and stay curious!")
        console.print("[bold cyan]" + "─" * 60 + "[/bold cyan]")
        console.print("[dim]Stay safe, stay ethical! 🔒[/dim]")
        sys.exit(0)
    
    def run(self):
        """Main application loop"""
        try:
            self.show_disclaimer()
            
            while True:
                choice = self.display_main_menu()
                
                if choice == 'exit':
                    self.exit_application()
                elif choice == 'settings':
                    self.settings_menu()
                elif choice == 'documentation':
                    self.documentation_server()
                else:
                    self.display_category_tools(choice)
                    
        except KeyboardInterrupt:
            console.print("\n\n[bold yellow]Interrupted by user. Exiting...[/bold yellow]")
            sys.exit(0)
        except Exception as e:
            console.print(f"\n[bold red]Unexpected error: {e}[/bold red]")
            sys.exit(1)

def main():
    """Entry point for SPARM"""
    sparm = SPARMInterface()
    sparm.run()

if __name__ == "__main__":
    main()