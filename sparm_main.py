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
        
        console.print("[bold yellow]🛡️ SPARM TOOLS[/bold yellow]")
        separator()
        
        console.print("[bold cyan]🔍 Information Gathering[/bold cyan]")
        console.print("├── [bold green]1.[/bold green]  🌾 TheHarvester - Email & subdomain harvesting") 
        console.print("├── [bold green]2.[/bold green]  🕵️ Sherlock - Social media username hunter")
        console.print("├── [bold green]3.[/bold green]  📡 Amass - Subdomain enumeration")
        console.print("└── [bold green]4.[/bold green]  🔬 Recon-ng - Reconnaissance framework")
        console.print()
        
        console.print("[bold cyan]🌐 Network Reconnaissance[/bold cyan]")
        console.print("├── [bold blue]5.[/bold blue]  🎯 Nmap - Network discovery & port scanning")
        console.print("├── [bold blue]6.[/bold blue]  ⚡ Masscan - High-speed port scanner") 
        console.print("├── [bold blue]7.[/bold blue]  💥 Gobuster - Directory & DNS brute-forcing")
        console.print("└── [bold blue]8.[/bold blue]  🔍 Nikto - Web server scanner")
        console.print()
        
        console.print("[bold cyan]🌍 Web Application Testing[/bold cyan]")
        console.print("├── [bold magenta]9.[/bold magenta]  🛡️ Custom Web Scanner - Built-in vulnerability scanner")
        console.print("├── [bold magenta]10.[/bold magenta] 💉 SQLMap - Automated SQL injection testing")
        console.print("└── [bold magenta]11.[/bold magenta] ⚠️ XSS Scanner - Cross-site scripting detection")
        console.print()
        
        console.print("[bold cyan]🔐 Password & Credential Attacks[/bold cyan]")
        console.print("├── [bold yellow]12.[/bold yellow] 🔨 Hydra - Network login brute-forcer")
        console.print("├── [bold yellow]13.[/bold yellow] 🏴‍☠️ John the Ripper - Password cracker")
        console.print("└── [bold yellow]14.[/bold yellow] ⚔️ Hashcat - Advanced password recovery")
        console.print()
        
        console.print("[bold cyan]⬆️ Privilege Escalation[/bold cyan]")
        console.print("├── [bold green]15.[/bold green] 🐧 LinPEAS - Linux privilege escalation scanner")
        console.print("├── [bold green]16.[/bold green] 🪟 WinPEAS - Windows privilege escalation scanner")
        console.print("└── [bold green]17.[/bold green] 📚 GTFOBins Lookup - Binary exploitation guide")
        console.print()
        
        console.print("[bold cyan]🚀 Advanced Offensive[/bold cyan]")
        console.print("├── [bold red]18.[/bold red] 🎭 MSFVenom - Payload generator")
        console.print("└── [bold red]19.[/bold red] 🔥 Metasploit Console - Exploitation framework")
        console.print()
        
        console.print("[bold cyan]🛠️ Additional Tools[/bold cyan]")
        console.print("├── [bold white]20.[/bold white] 🎯 Cyber Kill Chain - Attack methodology")
        console.print("├── [bold cyan]21.[/bold cyan] 💬 Discord Security - Educational analysis")
        console.print("├── [bold blue]22.[/bold blue] 📚 Documentation - Local docs server")
        console.print("└── [bold white]23.[/bold white] ⚙️ Settings - Configure SPARM")
        
        console.print("\n[bold red]0.[/bold red] 🚪 Exit SPARM")
        
        separator()
        choice = get_user_input("[bold cyan]SPARM[/bold cyan] > ")
        
        # Validate the choice
        valid_choices = [str(i) for i in range(0, 24)]  # 0-23
        while choice not in valid_choices:
            Warning("Invalid option. Please select 0-23.")
            choice = get_user_input("[bold cyan]SPARM[/bold cyan] > ")
        
        return choice
    
    def route_selection(self, choice):
        """Route user selection to appropriate tool"""
        try:
            # Information Gathering Tools
            if choice == "1":
                self.run_theharvester()
            elif choice == "2":
                self.run_sherlock()
            elif choice == "3":
                self.run_amass()
            elif choice == "4":
                self.run_recon_ng()
            
            # Network Reconnaissance Tools
            elif choice == "5":
                self.run_nmap()
            elif choice == "6":
                self.run_masscan()
            elif choice == "7":
                self.run_gobuster()
            elif choice == "8":
                self.run_nikto()
            
            # Web Application Testing
            elif choice == "9":
                self.run_custom_web_scanner()
            elif choice == "10":
                self.run_sqlmap()
            elif choice == "11":
                self.run_xss_scanner()
            
            # Password & Credential Attacks
            elif choice == "12":
                self.run_hydra()
            elif choice == "13":
                self.run_john()
            elif choice == "14":
                self.run_hashcat()
            
            # Privilege Escalation
            elif choice == "15":
                self.run_linpeas()
            elif choice == "16":
                self.run_winpeas()
            elif choice == "17":
                self.gtfobins_lookup()
            
            # Advanced Offensive
            elif choice == "18":
                self.run_msfvenom()
            elif choice == "19":
                self.run_metasploit()
            
            # Additional Tools
            elif choice == "20":
                self.cyber_kill_chain_menu()
            elif choice == "21":
                self.discord_security_menu()
            elif choice == "22":
                self.documentation_server()
            elif choice == "23":
                self.settings_menu()
            elif choice == "0":
                self.exit_application()
            
            # Wait for user input before returning to main menu
            Continue()
            
        except Exception as e:
            console.print(f"[bold red]Error running tool: {e}[/bold red]")
            Continue()
    
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
        
        console.print("[dim]These tools are designed for understanding Discord security threats[/dim]")
        console.print("[dim]and improving defensive security awareness. Use only in authorized[/dim]")  
        console.print("[dim]lab environments for educational purposes.[/dim]")
        console.print()
        
        tools = [
            ("1", "🔍", "Token Structure Analyzer", "Learn Discord token anatomy (educational)", "cyan"),
            ("2", "🎣", "Phishing URL Detector", "Analyze suspicious Discord links", "yellow"),
            ("3", "🛡️", "Server Security Audit", "Discord server security checklist", "blue"),
            ("4", "🤖", "Bot Permission Analyzer", "Analyze bot permission risks", "magenta"),
            ("5", "📱", "Social Engineering Awareness", "Common Discord attack scenarios", "red"),
            ("6", "🔗", "Webhook Security Guide", "Safe webhook implementation practices", "green"),
            ("7", "📚", "Security Best Practices", "Complete Discord security guide", "white"),
            ("0", "🔙", "Back to Main Menu", "Return to main interface", "dim")
        ]
        
        for choice, icon, name, description, color in tools:
            if choice == "0":
                console.print(f"\n[bold {color}][{choice}][/bold {color}] {icon} [bold white]{name}[/bold white] - [dim]{description}[/dim]")
            else:
                display_compact_menu_item(int(choice), icon, name, description, color)
        
        separator()
        choice = get_user_input("[bold magenta]DISCORD-SEC[/bold magenta] > ")
        
        # Validate the choice
        valid_choices = ["0", "1", "2", "3", "4", "5", "6", "7"]
        while choice not in valid_choices:
            Warning("Invalid option. Please select 0-7.")
            choice = get_user_input("[bold magenta]DISCORD-SEC[/bold magenta] > ")
        
        if choice == "0":
            return
        elif choice == "1":
            self.discord_token_analyzer()
        elif choice == "2":
            self.discord_phishing_url_detector()
        elif choice == "3":
            self.discord_server_security_audit() 
        elif choice == "4":
            self.discord_bot_analyzer()
        elif choice == "5":
            self.discord_social_engineering_awareness()
        elif choice == "6":
            self.discord_webhook_security_guide()
        elif choice == "7":
            self.discord_security_best_practices()
        
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
    
    def discord_phishing_url_detector(self):
        """Educational Discord phishing URL analysis tool"""
        banner("Discord Phishing URL Detector")
        console.print("[bold red]EDUCATIONAL PURPOSE ONLY[/bold red]\n")
        
        console.print("[bold cyan]This tool analyzes URLs for common Discord phishing patterns[/bold cyan]\n")
        
        url = get_user_input("Enter URL to analyze (example: https://dlscord-nitro.com/free)")
        
        # Educational analysis of URL patterns
        console.print(f"\n[bold yellow]Analyzing URL:[/bold yellow] {url}")
        
        # Check common phishing indicators
        phishing_indicators = []
        
        if "discord" in url.lower() and "discord.com" not in url.lower():
            phishing_indicators.append("❌ Suspicious domain - not official discord.com")
        
        suspicious_domains = ["dlscord", "discrod", "discord-nitro", "free-nitro", "nitro-gen"]
        for domain in suspicious_domains:
            if domain in url.lower():
                phishing_indicators.append(f"❌ Known phishing domain pattern: {domain}")
        
        if "free" in url.lower() and "nitro" in url.lower():
            phishing_indicators.append("❌ Suspicious keywords: 'free nitro' (common scam)")
        
        if len(url) > 100:
            phishing_indicators.append("❌ Unusually long URL (possible obfuscation)")
        
        # Display results
        console.print(f"\n[bold cyan]Analysis Results:[/bold cyan]")
        if phishing_indicators:
            console.print("[bold red]⚠️ POTENTIAL PHISHING DETECTED[/bold red]\n")
            for indicator in phishing_indicators:
                console.print(f"  {indicator}")
        else:
            console.print("[bold green]✓ No obvious phishing patterns detected[/bold green]")
        
        console.print(f"\n[bold yellow]Educational Notes:[/bold yellow]")
        console.print("• Always verify URLs before clicking")
        console.print("• Official Discord links use discord.com domain")  
        console.print("• Be suspicious of 'free Nitro' offers")
        console.print("• Check for typos in domain names")
        console.print("• When in doubt, navigate to Discord directly")
    
    def discord_server_security_audit(self):
        """Discord server security assessment tool"""
        banner("Discord Server Security Audit")
        console.print("[bold red]EDUCATIONAL PURPOSE ONLY[/bold red]\n")
        
        console.print("[bold cyan]Server Security Checklist:[/bold cyan]\n")
        
        security_items = [
            ("Verification Level", "Set appropriate verification requirements"),
            ("Role Permissions", "Review and limit role permissions"),
            ("Channel Permissions", "Secure sensitive channels"),
            ("Bot Permissions", "Audit bot access and permissions"),
            ("Audit Log Review", "Regularly check audit logs"),
            ("Member Screening", "Enable member screening rules"),
            ("Two-Factor Auth", "Require 2FA for moderators"),
            ("Vanity URL", "Secure custom invite links")
        ]
        
        console.print("[bold yellow]Interactive Security Assessment:[/bold yellow]")
        console.print("Rate each area from 1-5 (1=Poor, 5=Excellent):\n")
        
        total_score = 0
        max_score = len(security_items) * 5
        
        for item, description in security_items:
            console.print(f"[bold white]{item}:[/bold white] {description}")
            while True:
                try:
                    score = int(get_user_input(f"Rate {item} (1-5)"))
                    if 1 <= score <= 5:
                        total_score += score
                        if score <= 2:
                            console.print(f"  [red]⚠️ Needs improvement[/red]")
                        elif score <= 3:
                            console.print(f"  [yellow]⚠️ Could be better[/yellow]")
                        else:
                            console.print(f"  [green]✓ Good security[/green]")
                        break
                    else:
                        Warning("Please enter a number between 1-5")
                except ValueError:
                    Warning("Please enter a valid number")
            console.print()
        
        # Calculate and display results
        percentage = (total_score / max_score) * 100
        console.print(f"[bold cyan]Security Assessment Results:[/bold cyan]")
        console.print(f"Total Score: {total_score}/{max_score} ({percentage:.1f}%)")
        
        if percentage >= 80:
            console.print("[bold green]🛡️ Excellent security posture![/bold green]")
        elif percentage >= 60:
            console.print("[bold yellow]⚠️ Good security, room for improvement[/bold yellow]")
        else:
            console.print("[bold red]🚨 Security needs significant improvement[/bold red]")
        
        console.print(f"\n[bold yellow]Recommendations:[/bold yellow]")
        console.print("• Focus on areas rated 3 or below")
        console.print("• Review Discord's safety documentation")
        console.print("• Consider additional moderation bots")
        console.print("• Regular security audits recommended")
    
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
    
    def discord_social_engineering_awareness(self):
        """Social engineering awareness training for Discord"""
        banner("Discord Social Engineering Awareness")
        console.print("[bold red]EDUCATIONAL PURPOSE ONLY[/bold red]\n")
        
        console.print("[bold cyan]Common Social Engineering Scenarios:[/bold cyan]\n")
        
        scenarios = [
            {
                "title": "Fake Nitro Giveaway",
                "description": "Someone offers free Discord Nitro through suspicious links",
                "red_flags": ["Too good to be true", "Urgent time limits", "Suspicious domains"],
                "response": "Verify through official Discord channels, never click suspicious links"
            },
            {
                "title": "Impersonation Attack", 
                "description": "Scammer pretends to be Discord staff or friends",
                "red_flags": ["Requests for passwords/tokens", "Claims of account issues", "Unofficial contact"],
                "response": "Discord staff never ask for passwords. Verify identity through known channels"
            },
            {
                "title": "Malicious Bot Invite",
                "description": "Bot requests excessive permissions or seems suspicious",
                "red_flags": ["Administrator permissions", "Unusual permission requests", "Sketchy bot description"],
                "response": "Only grant minimum necessary permissions, research bot reputation"
            },
            {
                "title": "Token Grabber",
                "description": "Malware disguised as game cheats, Discord themes, or tools",
                "red_flags": ["Unofficial software", "Requests for Discord files", "Suspicious downloads"],
                "response": "Only download from official sources, use antivirus, never share token files"
            }
        ]
        
        for i, scenario in enumerate(scenarios, 1):
            console.print(f"[bold yellow]Scenario {i}: {scenario['title']}[/bold yellow]")
            console.print(f"[dim]{scenario['description']}[/dim]\n")
            
            console.print("[red]🚩 Red Flags:[/red]")
            for flag in scenario['red_flags']:
                console.print(f"  • {flag}")
            
            console.print(f"\n[green]✅ Proper Response:[/green]")
            console.print(f"  {scenario['response']}\n")
            console.print("─" * 50)
        
        console.print(f"\n[bold cyan]Interactive Quiz:[/bold cyan]")
        console.print("Someone DMs you: 'Hey! Free Discord Nitro here: https://dlscord-nitro.com/claim'")
        console.print("\nWhat should you do?")
        console.print("1. Click the link immediately")
        console.print("2. Ask them for more details first") 
        console.print("3. Ignore and report as suspicious")
        
        answer = get_user_input("Your choice (1-3)")
        
        if answer == "3":
            console.print("[bold green]✅ Correct! Always be suspicious of unsolicited 'free' offers[/bold green]")
        else:
            console.print("[bold red]❌ Incorrect. The correct answer is 3 - Ignore and report[/bold red]")
            console.print("[yellow]This is a classic phishing attempt using a typosquatted domain[/yellow]")
    
    def discord_webhook_security_guide(self):
        """Discord webhook security best practices"""
        banner("Discord Webhook Security Guide")
        console.print("[bold red]EDUCATIONAL PURPOSE ONLY[/bold red]\n")
        
        console.print("[bold cyan]Understanding Webhooks:[/bold cyan]")
        console.print("Webhooks allow external applications to send messages to Discord channels.")
        console.print("While useful, they can pose security risks if not properly managed.\n")
        
        console.print("[bold yellow]Common Webhook Security Risks:[/bold yellow]")
        console.print("🔴 Exposed webhook URLs in public code repositories")
        console.print("🔴 Webhooks with overly broad permissions")
        console.print("🔴 Unvalidated input leading to spam/abuse")
        console.print("🔴 Webhook URLs shared in insecure channels")
        console.print("🔴 No rate limiting or abuse protection\n")
        
        console.print("[bold green]Security Best Practices:[/bold green]")
        console.print("✅ Keep webhook URLs private and secure")
        console.print("✅ Use environment variables for webhook URLs in code")
        console.print("✅ Implement rate limiting on webhook usage")
        console.print("✅ Validate and sanitize all webhook input")
        console.print("✅ Monitor webhook usage for abuse")
        console.print("✅ Rotate webhook URLs periodically")
        console.print("✅ Limit webhook permissions to minimum necessary\n")
        
        console.print("[bold cyan]Safe Webhook Implementation Example:[/bold cyan]")
        console.print("```python")
        console.print("import os")
        console.print("import requests")
        console.print("from ratelimit import limits, sleep_and_retry")
        console.print("")
        console.print("# Store webhook URL securely")
        console.print("WEBHOOK_URL = os.getenv('DISCORD_WEBHOOK_URL')")
        console.print("")
        console.print("@sleep_and_retry")
        console.print("@limits(calls=5, period=60)  # Rate limiting")
        console.print("def send_webhook_message(content):")
        console.print("    # Validate input")
        console.print("    if not content or len(content) > 2000:")
        console.print("        return False")
        console.print("    ")
        console.print("    # Sanitize content")
        console.print("    safe_content = content.replace('@everyone', '@​everyone')")
        console.print("    ")
        console.print("    data = {'content': safe_content}")
        console.print("    response = requests.post(WEBHOOK_URL, json=data)")
        console.print("    return response.status_code == 204")
        console.print("```\n")
        
        console.print("[bold red]⚠️ Never Do This:[/bold red]")
        console.print("❌ Hard-code webhook URLs in your source code")
        console.print("❌ Share webhook URLs in public channels")
        console.print("❌ Allow unlimited webhook usage")
        console.print("❌ Send user input directly without validation")
        console.print("❌ Ignore webhook abuse reports\n")
        
        info("Remember: Webhooks are powerful tools that require responsible implementation")
    
    def discord_security_best_practices(self):
        """Comprehensive Discord security guide"""
        banner("Discord Security Best Practices")
        console.print("[bold red]EDUCATIONAL PURPOSE ONLY[/bold red]\n")
        
        console.print("[bold cyan]Complete Discord Security Checklist:[/bold cyan]\n")
        
        categories = {
            "Account Security": [
                "Enable Two-Factor Authentication (2FA)",
                "Use a strong, unique password",
                "Never share your login credentials",
                "Log out from shared/public computers",
                "Review authorized applications regularly"
            ],
            "Server Management": [
                "Set appropriate verification levels",
                "Use role-based permissions system",
                "Enable audit logging",
                "Implement member screening",
                "Regular permission audits"
            ],
            "Bot Security": [
                "Only invite trusted, verified bots",
                "Grant minimum necessary permissions",
                "Regularly audit bot permissions",
                "Remove unused bots",
                "Monitor bot activity"
            ],
            "Communication Safety": [
                "Be cautious of suspicious links",
                "Don't click unknown file attachments", 
                "Verify identity before sharing sensitive info",
                "Report suspicious behavior",
                "Use privacy settings appropriately"
            ],
            "Development Security": [
                "Secure API tokens and webhooks",
                "Use environment variables for secrets",
                "Implement proper input validation",
                "Regular security code reviews",
                "Follow Discord's developer policies"
            ]
        }
        
        for category, practices in categories.items():
            console.print(f"[bold yellow]{category}:[/bold yellow]")
            for practice in practices:
                console.print(f"  ✅ {practice}")
            console.print()
        
        console.print("[bold red]🚨 Immediate Action Required If:[/bold red]")
        console.print("• You suspect your account is compromised")
        console.print("• You clicked a suspicious link")
        console.print("• Someone gained unauthorized access to your server")
        console.print("• You shared sensitive information accidentally")
        console.print("• A bot is behaving unexpectedly\n")
        
        console.print("[bold green]Emergency Response Steps:[/bold green]")
        console.print("1. Change your Discord password immediately")
        console.print("2. Revoke all authorized applications")
        console.print("3. Enable 2FA if not already enabled")
        console.print("4. Check and update server permissions")
        console.print("5. Contact Discord Support if needed")
        console.print("6. Scan your computer for malware\n")
        
        console.print("[bold cyan]Educational Resources:[/bold cyan]")
        console.print("• Discord Safety Center: https://discord.com/safety")
        console.print("• Discord Developer Documentation")
        console.print("• Community Security Guidelines")
        console.print("• Regular security awareness training")
        
        info("Remember: Security is everyone's responsibility in a Discord community!")
    
    # ===============================
    # INDIVIDUAL TOOL FUNCTIONS
    # ===============================
    
    def run_theharvester(self):
        """Run TheHarvester - Email harvesting"""
        banner("TheHarvester - Email & Subdomain Harvesting")
        
        domain = get_user_input("Enter target domain (e.g., example.com)")
        limit = get_user_input("Enter email limit [default: 100]") or "100"
        
        sources = ["google", "bing", "yahoo", "duckduckgo", "linkedin"]
        console.print("\n[bold cyan]Available sources:[/bold cyan]")
        for i, source in enumerate(sources, 1):
            console.print(f"  {i}. {source}")
        
        source_choice = get_user_input("Choose source (1-5)", choices=["1", "2", "3", "4", "5"]) or "1"
        selected_source = sources[int(source_choice) - 1]
        
        command = f"theHarvester -d {domain} -l {limit} -b {selected_source}"
        console.print(f"\n[bold yellow]Command:[/bold yellow] {command}")
        
        if check_tool_installed("theHarvester"):
            success, stdout, stderr = safe_subprocess_run(command, timeout=300)
            format_command_output(command, success, stdout, stderr)
        else:
            Warning("theHarvester not installed. Install with: sudo apt install theharvester")
    
    def run_sherlock(self):
        """Run Sherlock - Social media username hunter"""
        banner("Sherlock - Social Media Account Hunter")
        
        username = get_user_input("Enter username to search")
        
        command = f"sherlock {username}"
        console.print(f"\n[bold yellow]Command:[/bold yellow] {command}")
        
        if check_tool_installed("sherlock"):
            success, stdout, stderr = safe_subprocess_run(command, timeout=300)
            format_command_output(command, success, stdout, stderr)
        else:
            Warning("Sherlock not installed. Install with: pip install sherlock-project")
    
    def run_amass(self):
        """Run Amass - Subdomain enumeration"""
        banner("Amass - Subdomain Enumeration")
        
        domain = get_user_input("Enter target domain (e.g., example.com)")
        
        command = f"amass enum -d {domain}"
        console.print(f"\n[bold yellow]Command:[/bold yellow] {command}")
        
        if check_tool_installed("amass"):
            success, stdout, stderr = safe_subprocess_run(command, timeout=600)
            format_command_output(command, success, stdout, stderr)
        else:
            Warning("Amass not installed. Install with: sudo apt install amass")
    
    def run_recon_ng(self):
        """Run Recon-ng - Reconnaissance framework"""
        banner("Recon-ng - Reconnaissance Framework")
        
        console.print("Recon-ng is a full-featured reconnaissance framework.")
        console.print("This will launch the interactive Recon-ng console.")
        
        if check_tool_installed("recon-ng"):
            console.print(f"\n[bold yellow]Launching recon-ng...[/bold yellow]")
            os.system("recon-ng")
        else:
            Warning("Recon-ng not installed. Install with: sudo apt install recon-ng")
    
    def run_nmap(self):
        """Run Nmap - Network scanner"""
        banner("Nmap - Network Discovery & Security Auditing")
        
        target = get_user_input("Enter target IP/domain (e.g., 192.168.1.1 or example.com)")
        
        console.print("\n[bold cyan]Scan types:[/bold cyan]")
        scan_types = {
            "1": ("-sS", "SYN Stealth Scan"),
            "2": ("-sT", "TCP Connect Scan"), 
            "3": ("-sV", "Version Detection"),
            "4": ("-A", "Aggressive Scan (OS, version, script, traceroute)")
        }
        
        for key, (flag, desc) in scan_types.items():
            console.print(f"  {key}. {desc}")
        
        scan_choice = get_user_input("Choose scan type (1-4)", choices=["1", "2", "3", "4"]) or "1"
        scan_flag = scan_types[scan_choice][0]
        
        ports = get_user_input("Enter ports (e.g., 22,80,443 or 1-1000) [default: top 1000]") or ""
        port_flag = f"-p {ports}" if ports else ""
        
        command = f"nmap {scan_flag} {port_flag} {target}".strip()
        console.print(f"\n[bold yellow]Command:[/bold yellow] {command}")
        
        if check_tool_installed("nmap"):
            success, stdout, stderr = safe_subprocess_run(command, timeout=600)
            format_command_output(command, success, stdout, stderr)
        else:
            Warning("Nmap not installed. Install with: sudo apt install nmap")
    
    def run_masscan(self):
        """Run Masscan - High-speed port scanner"""
        banner("Masscan - High-Speed Port Scanner")
        
        target = get_user_input("Enter target IP/range (e.g., 192.168.1.0/24)")
        ports = get_user_input("Enter ports (e.g., 1-1000 or 80,443)") or "1-1000"
        rate = get_user_input("Enter scan rate [default: 1000]") or "1000"
        
        command = f"masscan {target} -p{ports} --rate={rate}"
        console.print(f"\n[bold yellow]Command:[/bold yellow] {command}")
        
        if check_tool_installed("masscan"):
            Warning("Masscan requires root privileges")
            console.print("Run manually: sudo " + command)
        else:
            Warning("Masscan not installed. Install with: sudo apt install masscan")
    
    def run_gobuster(self):
        """Run Gobuster - Directory/DNS brute-forcer"""
        banner("Gobuster - Directory & DNS Brute-Forcing")
        
        console.print("[bold cyan]Gobuster modes:[/bold cyan]")
        console.print("1. Directory brute-forcing")
        console.print("2. DNS subdomain brute-forcing")
        
        mode = get_user_input("Choose mode (1-2)", choices=["1", "2"]) or "1"
        
        if mode == "1":
            url = get_user_input("Enter target URL (e.g., https://example.com)")
            wordlist = get_user_input("Enter wordlist path [default: /usr/share/wordlists/dirb/common.txt]") or "/usr/share/wordlists/dirb/common.txt"
            command = f"gobuster dir -u {url} -w {wordlist}"
        else:
            domain = get_user_input("Enter target domain (e.g., example.com)")
            wordlist = get_user_input("Enter subdomain wordlist [default: /usr/share/wordlists/dirb/common.txt]") or "/usr/share/wordlists/dirb/common.txt"
            command = f"gobuster dns -d {domain} -w {wordlist}"
        
        console.print(f"\n[bold yellow]Command:[/bold yellow] {command}")
        
        if check_tool_installed("gobuster"):
            success, stdout, stderr = safe_subprocess_run(command, timeout=300)
            format_command_output(command, success, stdout, stderr)
        else:
            Warning("Gobuster not installed. Install with: sudo apt install gobuster")
    
    def run_nikto(self):
        """Run Nikto - Web server scanner"""
        banner("Nikto - Web Server Scanner")
        
        target = get_user_input("Enter target URL (e.g., https://example.com)")
        
        command = f"nikto -h {target}"
        console.print(f"\n[bold yellow]Command:[/bold yellow] {command}")
        
        if check_tool_installed("nikto"):
            success, stdout, stderr = safe_subprocess_run(command, timeout=600)
            format_command_output(command, success, stdout, stderr)
        else:
            Warning("Nikto not installed. Install with: sudo apt install nikto")
    
    def run_custom_web_scanner(self):
        """Run custom web vulnerability scanner"""
        banner("Custom Web Vulnerability Scanner")
        
        from modules.web_vulnerability import WebVulnerabilityScanner
        scanner = WebVulnerabilityScanner()
        scanner.custom_web_scan()
    
    def run_sqlmap(self):
        """Run SQLMap - SQL injection tool"""
        banner("SQLMap - Automated SQL Injection Tool")
        
        from modules.sql_injection import SQLInjectionToolkit
        toolkit = SQLInjectionToolkit()
        toolkit.run_sqlmap()
    
    def run_xss_scanner(self):
        """Run XSS Scanner"""
        banner("XSS Scanner - Cross-Site Scripting Detection")
        
        url = get_user_input("Enter target URL with parameter (e.g., https://example.com/search?q=test)")
        
        console.print("[bold yellow]This is a basic XSS detection example.[/bold yellow]")
        console.print("For comprehensive XSS testing, use tools like:")
        console.print("• XSSer: xsser -u " + url)
        console.print("• Burp Suite Professional")
        console.print("• OWASP ZAP")
        
        if check_tool_installed("xsser"):
            command = f"xsser -u {url}"
            console.print(f"\n[bold yellow]Command:[/bold yellow] {command}")
            success, stdout, stderr = safe_subprocess_run(command, timeout=300)
            format_command_output(command, success, stdout, stderr)
        else:
            Warning("XSSer not installed. Install with: sudo apt install xsser")
    
    def run_hydra(self):
        """Enhanced Hydra - Network login brute-forcer with real-time output"""
        banner("Hydra - Network Login Brute-Forcer")
        
        # Target specification with better examples
        console.print("[bold cyan]Target Examples:[/bold cyan]")
        console.print("  • Web server: localhost (port specified separately)")
        console.print("  • SSH server: 10.0.0.1 or example.com") 
        console.print("  • Remote host: 192.168.1.100")
        console.print("  • Domain: example.com")
        console.print("\n[bold yellow]💡 Note: Don't include port in target - specify it separately[/bold yellow]")
        
        target = get_user_input("Enter target IP/domain (without port)")
        
        # Service selection with better descriptions
        console.print("\n[bold cyan]Available services:[/bold cyan]")
        services = {
            "1": "ssh", "2": "ftp", "3": "telnet", "4": "http-get", 
            "5": "http-post-form", "6": "smb", "7": "rdp", "8": "mysql",
            "9": "postgres", "10": "vnc"
        }
        
        service_descriptions = {
            "1": "SSH - Secure Shell login (port 22)",
            "2": "FTP - File Transfer Protocol (port 21)", 
            "3": "Telnet - Remote terminal (port 23)",
            "4": "HTTP-GET - Basic HTTP authentication (port 80/443)",
            "5": "HTTP-POST-FORM - Web login forms (port 80/443)",
            "6": "SMB - Windows file sharing (port 445)",
            "7": "RDP - Remote Desktop Protocol (port 3389)",
            "8": "MySQL - Database server (port 3306)",
            "9": "PostgreSQL - Database server (port 5432)",
            "10": "VNC - Remote desktop (port 5900)"
        }
        
        for key, service in services.items():
            console.print(f"  {key}. {service_descriptions[key]}")
        
        service_choice = get_user_input("Choose service (1-10)", choices=[str(i) for i in range(1, 11)])
        selected_service = services[service_choice]
        
        # Port specification
        port_map = {
            "1": "22", "2": "21", "3": "23", "4": "80", "5": "80",
            "6": "445", "7": "3389", "8": "3306", "9": "5432", "10": "5900"
        }
        default_port = port_map.get(service_choice, "80")
        
        # Extract port from target if present
        if ':' in target and not target.startswith('http'):
            host, target_port = target.split(':', 1)
            port = get_user_input(f"Enter port [default: {target_port}]") or target_port
            target = host
        else:
            port = get_user_input(f"Enter port [default: {default_port}]") or default_port
        
        # Username configuration
        console.print("\n[bold cyan]Username configuration:[/bold cyan]")
        console.print("  1. Single username")
        console.print("  2. Choose from wordlist directory")
        console.print("  3. Specify custom wordlist path")
        
        user_choice = get_user_input("Choose username option (1-3)", choices=["1", "2", "3"])
        
        if user_choice == "1":
            username = get_user_input("Enter username")
            user_param = f"-l {username}"
        elif user_choice == "2":
            username_file = select_wordlist_from_directory("usernames", "Select username wordlist")
            if username_file:
                user_param = f"-L {username_file}"
            else:
                Warning("No username wordlist selected, using 'admin'")
                user_param = "-l admin"
        else:
            user_input = get_user_input("Enter path to username wordlist")
            if os.path.isfile(user_input):
                user_param = f"-L {user_input}"
            else:
                Warning(f"File not found: {user_input}")
                username = get_user_input("Enter username")
                user_param = f"-l {username}"
        
        # Password configuration
        console.print("\n[bold cyan]Password configuration:[/bold cyan]")
        console.print("  1. Single password")
        console.print("  2. Choose from wordlist directory")
        console.print("  3. Specify custom wordlist path")
        
        pass_choice = get_user_input("Choose password option (1-3)", choices=["1", "2", "3"])
        
        if pass_choice == "1":
            password = get_user_input("Enter password")
            pass_param = f"-p {password}"
        elif pass_choice == "2":
            password_file = select_wordlist_from_directory("passwords", "Select password wordlist")
            if password_file:
                pass_param = f"-P {password_file}"
            else:
                Warning("No password wordlist selected")
                return
        else:
            pass_input = get_user_input("Enter path to password wordlist")
            if os.path.isfile(pass_input):
                pass_param = f"-P {pass_input}"
            else:
                Warning(f"File not found: {pass_input}")
                password = get_user_input("Enter password")
                pass_param = f"-p {password}"
        
        # Thread configuration - moved before form setup
        console.print("\n[bold cyan]🔧 Performance Settings:[/bold cyan]")
        console.print("  • Low threads (1-4): Slower but less likely to trigger rate limiting")
        console.print("  • Medium threads (8-16): Balanced performance")
        console.print("  • High threads (32+): Faster but may cause false positives")
        
        threads = get_user_input("Number of threads [default: 16]") or "16"
        
        # Special handling for HTTP POST forms with auto-detection
        if selected_service == "http-post-form":
            console.print("\n[bold cyan]📋 HTTP POST Form Configuration[/bold cyan]")
            
            # Enhanced login path handling
            console.print("\n[bold yellow]Login Path Examples:[/bold yellow]")
            console.print("  • /login.php (PHP login)")
            console.print("  • /login (Simple path)")
            console.print("  • /admin/login (Admin panel)")
            console.print("  • /auth/signin (Authentication)")
            
            login_path = get_user_input("Enter login path (e.g., /login.php)")
            
            console.print("\n[bold cyan]Form field setup:[/bold cyan]")
            console.print("  1. 📝 Auto-detect from target (recommended)")
            console.print("  2. 👤 Common preset: user/pass")
            console.print("  3. 🔑 Common preset: username/password")
            console.print("  4. 📧 Common preset: email/password")
            console.print("  5. ⚙️  Custom field names")
            
            field_choice = get_user_input("Choose option (1-5)", choices=["1", "2", "3", "4", "5"])
            
            if field_choice == "1":
                console.print("[bold yellow]🔍 Auto-detecting form fields...[/bold yellow]")
                console.print("💡 Tip: Visit the login page manually to see field names")
                console.print("     Common field names are: username, password, user, pass, email")
                
                # Provide smart defaults for common scenarios
                if "login.php" in login_path.lower():
                    form_params = "username=^USER^&password=^PASS^"
                    console.print(f"[bold green]✅ Detected PHP login - using:[/bold green] {form_params}")
                else:
                    form_params = "username=^USER^&password=^PASS^"
                    console.print(f"[bold green]✅ Using standard fields:[/bold green] {form_params}")
                    
            elif field_choice == "2":
                form_params = "user=^USER^&pass=^PASS^"
            elif field_choice == "3":
                form_params = "username=^USER^&password=^PASS^"
            elif field_choice == "4":
                form_params = "email=^USER^&password=^PASS^"
            else:
                console.print("\n[bold yellow]💡 Check the HTML source to find field names:[/bold yellow]")
                console.print("   <input name=\"username\" type=\"text\">")
                console.print("   <input name=\"password\" type=\"password\">")
                username_field = get_user_input("Enter username field name")
                password_field = get_user_input("Enter password field name")
                form_params = f"{username_field}=^USER^&{password_field}=^PASS^"
            
            console.print(f"\n[bold green]📋 Generated form data:[/bold green] {form_params}")
            
            # Enhanced failure string detection
            console.print("\n[bold yellow]Failure String Examples:[/bold yellow]")
            console.print("  • 'Invalid credentials' or 'Invalid username'")
            console.print("  • 'Login failed' or 'Authentication failed'")
            console.print("  • 'Incorrect password' or 'Wrong password'")
            console.print("  • 'Access denied' or 'Login error'")
            
            failure_string = get_user_input("Enter failure string (text that appears on failed login)")
            
            # Offer to test the failure string first
            console.print(f"\n[bold yellow]🧪 Want to test your failure string first?[/bold yellow]")
            if get_user_input("Test failure string with known bad credentials? [y/n]", choices=["y", "n"]) == "y":
                test_user = get_user_input("Enter test username (e.g., 'baduser')")
                test_pass = get_user_input("Enter test password (e.g., 'wrongpass')")
                
                test_command = f"hydra -l {test_user} -p {test_pass} -s {port} -V {target} http-post-form \"{login_path}:{form_params}:{failure_string}\""
                console.print(f"\n[bold cyan]🔍 Test command:[/bold cyan] {test_command}")
                console.print("[bold yellow]💡 This should show NO valid credentials if failure string is correct[/bold yellow]")
                
                if get_user_input("Run test? [y/n]", choices=["y", "n"]) == "y":
                    console.print("\n[bold blue]Running test...[/bold blue]")
                    try:
                        result = subprocess.run(test_command, shell=True, capture_output=True, text=True, timeout=30)
                        if "valid password found" in result.stdout.lower() or "[VALID]" in result.stdout:
                            console.print("[bold red]⚠️  WARNING: Test found 'valid' credentials with known bad login![/bold red]")
                            console.print("[bold yellow]Your failure string might be wrong. Check the exact error message.[/bold yellow]")
                            
                            if get_user_input("Continue anyway? [y/n]", choices=["y", "n"]) != "y":
                                return
                        else:
                            console.print("[bold green]✅ Test passed - failure string looks correct[/bold green]")
                    except Exception as e:
                        console.print(f"[yellow]Test failed: {e}[/yellow]")
            
            service_param = f'"{login_path}:{form_params}:{failure_string}"'
        else:
            service_param = selected_service
        
        # Ask for verbose output first
        verbose = get_user_input("Enable verbose output? [y/n] (y)", choices=["y", "n"]) or "y"
        
        # Build command as one continuous string (don't split into parts)
        verbose_flag = "-V" if verbose.lower() == 'y' else ""
        
        if selected_service == "http-post-form":
            command = f"hydra {user_param} {pass_param} -s {port} -t {threads} {verbose_flag} {target} http-post-form {service_param}".strip()
        else:
            command = f"hydra {user_param} {pass_param} -s {port} -t {threads} {verbose_flag} {target} {service_param}".strip()
        
        # Clean up any double spaces
        command = " ".join(command.split())
        
        console.print(f"\n[bold yellow]Command:[/bold yellow] {command}")
        console.print("⚠ Hydra will attempt password brute-forcing. Use only on authorized targets.")
        
        if not get_user_input("Continue? [y/n]", choices=["y", "n"]) == "y":
            console.print("Operation cancelled.")
            return
        
        # Setup logging and run with enhanced real-time output and credential filtering
        log_file = setup_session_logging("hydra")
        
        try:
            console.print("\n[bold green]🚀 Starting Hydra attack...[/bold green]")
            console.print("[dim]Press Ctrl+C to stop[/dim]\n")
            
            # Start process with shell=True to handle the complete command string
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Track credentials and statistics
            valid_credentials = []
            attempt_count = 0
            error_count = 0
            
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    line = output.strip()
                    
                    # Real-time credential success detection
                    if "[VALID]" in line or "login:" in line.lower() and "password:" in line.lower():
                        # Extract credentials from successful attempt
                        if "login:" in line and "password:" in line:
                            try:
                                login_part = line.split("login:")[1].split("password:")[0].strip()
                                password_part = line.split("password:")[1].strip()
                                valid_credentials.append((login_part, password_part))
                                console.print(f"[bold green]✅ FOUND VALID CREDENTIALS: {login_part}:{password_part}[/bold green]")
                            except:
                                console.print(f"[bold green]✅ SUCCESS: {line}[/bold green]")
                                valid_credentials.append(("unknown", "unknown"))
                    
                    # Track attempts and errors
                    elif "attempt" in line.lower() or "trying" in line.lower():
                        attempt_count += 1
                        if attempt_count % 50 == 0:  # Show progress every 50 attempts
                            console.print(f"[dim]📊 Progress: {attempt_count} attempts made...[/dim]")
                    
                    elif "error" in line.lower() or "fail" in line.lower():
                        error_count += 1
                        if error_count < 5:  # Only show first few errors
                            console.print(f"[yellow]⚠️  {line}[/yellow]")
                    
                    # Display other output (filtered)
                    elif not line.startswith("[") and len(line) > 5:
                        safe_output = line.replace('[', r'\[').replace(']', r'\]')
                        console.print(safe_output)
                    
                    # Log everything
                    with open(log_file, 'a') as f:
                        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {line}\n")
            
            # Get remaining output
            remaining_stdout, stderr = process.communicate()
            if remaining_stdout:
                for line in remaining_stdout.strip().split('\n'):
                    if line and "[VALID]" in line:
                        console.print(f"[bold green]✅ FINAL RESULT: {line}[/bold green]")
            
            # Show results summary
            console.print("\n" + "="*60)
            console.print("[bold cyan]🎯 ATTACK SUMMARY[/bold cyan]")
            console.print("="*60)
            
            if valid_credentials:
                console.print(f"[bold green]✅ Found {len(valid_credentials)} valid credential(s):[/bold green]")
                for i, (user, pwd) in enumerate(valid_credentials, 1):
                    console.print(f"  {i}. Username: [bold green]{user}[/bold green] | Password: [bold green]{pwd}[/bold green]")
                
                # Save valid credentials to file
                creds_file = f"logs/hydra_valid_credentials_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                with open(creds_file, 'w') as f:
                    f.write(f"Hydra Valid Credentials - {datetime.now()}\n")
                    f.write(f"Target: {target}\n")
                    f.write(f"Service: {selected_service}\n")
                    f.write("="*50 + "\n")
                    for user, pwd in valid_credentials:
                        f.write(f"{user}:{pwd}\n")
                
                Success(f"Valid credentials saved to: {creds_file}")
                
                # Offer to verify credentials
                console.print("\n[bold yellow]🔍 CREDENTIAL VERIFICATION[/bold yellow]")
                if get_user_input("Verify credentials manually? [y/n]", choices=["y", "n"]) == "y":
                    for i, (user, pwd) in enumerate(valid_credentials, 1):
                        console.print(f"\n[bold cyan]Testing credential {i}: {user}:{pwd}[/bold cyan]")
                        
                        # Single credential test
                        verify_command = f"hydra -l {user} -p {pwd} -s {port} -V {target} http-post-form {service_param}"
                        console.print(f"[dim]Command: {verify_command}[/dim]")
                        
                        try:
                            result = subprocess.run(verify_command, shell=True, capture_output=True, text=True, timeout=15)
                            
                            if "valid password found" in result.stdout.lower() or "[VALID]" in result.stdout:
                                console.print(f"[bold green]✅ VERIFIED: {user}:{pwd} is valid[/bold green]")
                            else:
                                console.print(f"[bold red]❌ FALSE POSITIVE: {user}:{pwd} failed verification[/bold red]")
                                console.print("[yellow]This was likely a false positive from Hydra[/yellow]")
                        except Exception as e:
                            console.print(f"[yellow]Verification failed: {e}[/yellow]")
                
                # Suggest next steps for valid credentials
                console.print("\n[bold yellow]🔄 NEXT STEPS:[/bold yellow]")
                console.print("  • Test credentials manually in browser")
                console.print("  • Check for password reuse on other services")
                console.print("  • Document findings for reporting")
                console.print("  • Consider if this was a false positive")
                
            else:
                console.print("[bold red]❌ No valid credentials found[/bold red]")
                console.print("[bold yellow]💡 Consider:[/bold yellow]")
                console.print("  • Using different wordlists")
                console.print("  • Checking if service is actually vulnerable")
                console.print("  • Verifying target is accessible")
            
            console.print(f"\n📊 Total attempts: {attempt_count}")
            console.print(f"📝 Complete log: {log_file}")
            
        except KeyboardInterrupt:
            try:
                process.terminate()
                process.wait(timeout=5)
            except:
                process.kill()
        except Exception as e:
            Warning(f"Error running Hydra: {e}")
        
        show_next_steps("Credential Access", CATEGORIES["credential_access"]["next_steps"])
    
    def run_john(self):
        """Run John the Ripper - Password cracker"""
        banner("John the Ripper - Password Cracker")
        
        hash_file = get_user_input("Enter path to hash file")
        wordlist = get_user_input("Enter wordlist path [default: /usr/share/wordlists/rockyou.txt]") or "/usr/share/wordlists/rockyou.txt"
        
        command = f"john --wordlist={wordlist} {hash_file}"
        console.print(f"\n[bold yellow]Command:[/bold yellow] {command}")
        
        if check_tool_installed("john"):
            success, stdout, stderr = safe_subprocess_run(command, timeout=600)
            format_command_output(command, success, stdout, stderr)
        else:
            Warning("John not installed. Install with: sudo apt install john")
    
    def run_hashcat(self):
        """Run Hashcat - Advanced password recovery"""
        banner("Hashcat - Advanced Password Recovery")
        
        hash_file = get_user_input("Enter path to hash file")
        wordlist = get_user_input("Enter wordlist path [default: /usr/share/wordlists/rockyou.txt]") or "/usr/share/wordlists/rockyou.txt"
        hash_type = get_user_input("Enter hash type (e.g., 0 for MD5, 100 for SHA1) [default: 0]") or "0"
        
        command = f"hashcat -m {hash_type} -a 0 {hash_file} {wordlist}"
        console.print(f"\n[bold yellow]Command:[/bold yellow] {command}")
        
        if check_tool_installed("hashcat"):
            success, stdout, stderr = safe_subprocess_run(command, timeout=600)
            format_command_output(command, success, stdout, stderr)
        else:
            Warning("Hashcat not installed. Install with: sudo apt install hashcat")
    
    def run_winpeas(self):
        """Run WinPEAS information"""
        banner("WinPEAS - Windows Privilege Escalation Scanner")
        
        console.print("WinPEAS is a Windows privilege escalation scanner.")
        console.print("Download and run on Windows target systems.")
        console.print("\n[bold cyan]Download URLs:[/bold cyan]")
        console.print("• https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.bat")
        console.print("• https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.exe")
        
        console.print(f"\n[bold yellow]Usage on Windows target:[/bold yellow]")
        console.print("1. Download winPEAS.exe to target system")
        console.print("2. Run: .\\winPEAS.exe")
        console.print("3. Analyze output for privilege escalation vectors")
    
    def run_msfvenom(self):
        """Run MSFVenom - Payload generator"""
        banner("MSFVenom - Payload Generator")
        
        from modules.advanced_offensive import AdvancedOffensiveToolkit
        toolkit = AdvancedOffensiveToolkit()
        toolkit.generate_windows_payload()
    
    def run_metasploit(self):
        """Launch Metasploit Console"""
        banner("Metasploit Console - Exploitation Framework")
        
        console.print("Launching Metasploit Console...")
        console.print("This will open the interactive Metasploit framework.")
        
        if check_tool_installed("msfconsole"):
            if Confirm.ask("Launch Metasploit Console?"):
                os.system("msfconsole")
        else:
            Warning("Metasploit not installed. Install with: sudo apt install metasploit-framework")
    
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