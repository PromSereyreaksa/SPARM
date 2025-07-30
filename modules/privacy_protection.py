#!/usr/bin/env python3
"""
Privacy Protection Module for SPARM
Handles VPN, Tor, and network isolation for lab environments
"""

import os
import sys
import subprocess
import time
import requests
from core.utils import *
from core.config import *

class PrivacyProtection:
    def __init__(self):
        self.original_ip = None
        self.current_ip = None
        self.vpn_status = False
        self.tor_status = False
        
    def check_current_ip(self):
        """Check current external IP address"""
        try:
            response = requests.get('https://ifconfig.me', timeout=10)
            return response.text.strip()
        except:
            try:
                response = requests.get('https://api.ipify.org', timeout=10)
                return response.text.strip()
        except:
                return None
                
    def check_tor_status(self):
        """Check if Tor is running and accessible"""
        try:
            # Check if Tor service is running
            result = subprocess.run(['systemctl', 'is-active', 'tor'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                # Test Tor connectivity
                proxies = {
                    'http': 'socks5://127.0.0.1:9050',
                    'https': 'socks5://127.0.0.1:9050'
                }
                response = requests.get('https://check.torproject.org/api/ip', 
                                      proxies=proxies, timeout=10)
                data = response.json()
                return data.get('IsTor', False)
            return False
        except:
            return False
            
    def setup_tor(self):
        """Setup and configure Tor"""
        banner("Tor Network Setup")
        
        console.print("[bold cyan]Setting up Tor for anonymous browsing...[/bold cyan]\n")
        
        # Check if Tor is installed
        if not os.path.exists('/usr/bin/tor'):
            console.print("[bold yellow]Installing Tor...[/bold yellow]")
            subprocess.run(['sudo', 'apt', 'update'], check=True)
            subprocess.run(['sudo', 'apt', 'install', '-y', 'tor'], check=True)
            
        # Start Tor service
        console.print("[bold cyan]Starting Tor service...[/bold cyan]")
        subprocess.run(['sudo', 'systemctl', 'start', 'tor'], check=True)
        subprocess.run(['sudo', 'systemctl', 'enable', 'tor'], check=True)
        
        # Wait for Tor to establish circuits
        console.print("[bold yellow]Waiting for Tor to establish circuits...[/bold yellow]")
        time.sleep(10)
        
        if self.check_tor_status():
            Success("Tor is running and accessible!")
            self.tor_status = True
            
            # Show Tor IP
            try:
                proxies = {
                    'http': 'socks5://127.0.0.1:9050',
                    'https': 'socks5://127.0.0.1:9050'
                }
                response = requests.get('https://ifconfig.me', proxies=proxies, timeout=10)
                tor_ip = response.text.strip()
                console.print(f"[bold green]Tor IP Address:[/bold green] {tor_ip}")
        except:
                console.print("[bold yellow]Could not verify Tor IP address[/bold yellow]")
                
        else:
            ErrorModule("Failed to setup Tor properly!")
            
    def configure_vpn(self):
        """Configure VPN connection"""
        banner("VPN Configuration")
        
        console.print("[bold cyan]VPN Setup Options:[/bold cyan]\n")
        console.print("1. OpenVPN Configuration")
        console.print("2. WireGuard Setup") 
        console.print("3. Manual VPN Instructions")
        console.print("4. Back to main menu")
        
        choice = get_user_input("Select VPN option (1-4)", choices=["1", "2", "3", "4"])
        
        if choice == "1":
            self.setup_openvpn()
        elif choice == "2":
            self.setup_wireguard()
        elif choice == "3":
            self.show_manual_vpn_instructions()
        elif choice == "4":
            return
            
    def setup_openvpn(self):
        """Setup OpenVPN"""
        console.print("[bold cyan]OpenVPN Setup[/bold cyan]\n")
        
        # Check if OpenVPN is installed
        if not os.path.exists('/usr/sbin/openvpn'):
            console.print("[bold yellow]Installing OpenVPN...[/bold yellow]")
            subprocess.run(['sudo', 'apt', 'update'], check=True)
            subprocess.run(['sudo', 'apt', 'install', '-y', 'openvpn'], check=True)
            
        config_path = get_user_input("Enter path to OpenVPN config file (.ovpn)")
        
        if os.path.exists(config_path):
            console.print("[bold cyan]Starting OpenVPN connection...[/bold cyan]")
            
            # Start OpenVPN in background
            cmd = ['sudo', 'openvpn', '--config', config_path, '--daemon']
            subprocess.run(cmd)
            
            # Wait for connection
            time.sleep(5)
            
            # Check if IP changed
            new_ip = self.check_current_ip()
            if new_ip and new_ip != self.original_ip:
                Success(f"VPN connected! New IP: {new_ip}")
                self.vpn_status = True
                self.current_ip = new_ip
            else:
            Warning("VPN connection may not be established. Check configuration.")
                
        else:
            ErrorModule("OpenVPN config file not found!")
            
    def setup_wireguard(self):
        """Setup WireGuard VPN"""
        console.print("[bold cyan]WireGuard Setup[/bold cyan]\n")
        
        # Check if WireGuard is installed
        if not os.path.exists('/usr/bin/wg'):
            console.print("[bold yellow]Installing WireGuard...[/bold yellow]")
            subprocess.run(['sudo', 'apt', 'update'], check=True)
            subprocess.run(['sudo', 'apt', 'install', '-y', 'wireguard'], check=True)
            
        config_path = get_user_input("Enter path to WireGuard config file (.conf)")
        
        if os.path.exists(config_path):
            # Copy config to WireGuard directory
            config_name = os.path.basename(config_path).replace('.conf', '')
            subprocess.run(['sudo', 'cp', config_path, f'/etc/wireguard/{config_name}.conf'])
            
            console.print("[bold cyan]Starting WireGuard connection...[/bold cyan]")
            subprocess.run(['sudo', 'wg-quick', 'up', config_name])
            
            # Check connection
            time.sleep(3)
            new_ip = self.check_current_ip()
            if new_ip and new_ip != self.original_ip:
                Success(f"WireGuard connected! New IP: {new_ip}")
                self.vpn_status = True
                self.current_ip = new_ip
            else:
            Warning("WireGuard connection may not be established.")
                
        else:
            ErrorModule("WireGuard config file not found!")
            
    def show_manual_vpn_instructions(self):
        """Show manual VPN setup instructions"""
        Title("Manual VPN Setup Instructions")
        
        console.print("[bold cyan]Commercial VPN Services:[/bold cyan]")
        console.print("• NordVPN: Supports OpenVPN and WireGuard")
        console.print("• ExpressVPN: Strong encryption and no-logs policy")
        console.print("• Surfshark: Multiple simultaneous connections")
        console.print("• ProtonVPN: Privacy-focused with free tier")
        
        console.print("\n[bold cyan]Setup Steps:[/bold cyan]")
        console.print("1. Subscribe to a reputable VPN service")
        console.print("2. Download OpenVPN or WireGuard configuration files")
        console.print("3. Use the configuration options above to connect")
        console.print("4. Verify your IP address has changed")
        
        console.print("\n[bold yellow]Lab Environment Considerations:[/bold yellow]")
        console.print("• Use VPN for all external reconnaissance")
        console.print("• Avoid VPN for internal lab network traffic")
        console.print("• Consider using different VPN servers for different tests")
        console.print("• Keep VPN logs for compliance and documentation")
        
        Continue()
        
    def network_isolation_setup(self):
        """Setup network isolation for lab environment"""
        banner("Network Isolation Setup")
        
        console.print("[bold cyan]Network Isolation Options:[/bold cyan]\n")
        console.print("1. Create isolated network namespace")
        console.print("2. Configure iptables rules")
        console.print("3. Setup VM network isolation")
        console.print("4. Monitor network traffic")
        console.print("5. Back to main menu")
        
        choice = get_user_input("Select isolation method (1-5)", choices=["1", "2", "3", "4", "5"])
        
        if choice == "1":
            self.create_network_namespace()
        elif choice == "2":
            self.configure_iptables()
        elif choice == "3":
            self.show_vm_isolation_guide()
        elif choice == "4":
            self.network_monitoring()
        elif choice == "5":
            return
            
    def create_network_namespace(self):
        """Create isolated network namespace"""
        console.print("[bold cyan]Creating isolated network namespace...[/bold cyan]\n")
        
        namespace_name = get_user_input("Enter namespace name", default="lab_env")
        
        commands = [
            f"sudo ip netns add {namespace_name}",
            f"sudo ip netns exec {namespace_name} ip link set lo up",
            f"sudo ip netns exec {namespace_name} bash"
        ]
        
        console.print("[bold cyan]Commands to execute:[/bold cyan]")
        for cmd in commands:
            console.print(f"[bold white]{cmd}[/bold white]")
            
        console.print(f"\n[bold green]To enter namespace:[/bold green]")
        console.print(f"sudo ip netns exec {namespace_name} bash")
        
        console.print(f"\n[bold green]To delete namespace:[/bold green]")
        console.print(f"sudo ip netns delete {namespace_name}")
        
        Continue()
        
    def configure_iptables(self):
        """Configure iptables for lab isolation"""
        console.print("[bold cyan]Configuring iptables for lab isolation...[/bold cyan]\n")
        
        console.print("[bold yellow]Warning:[/bold yellow] This will modify system firewall rules!")
            
        # Backup current rules
        console.print("[bold cyan]Backing up current iptables rules...[/bold cyan]")
        subprocess.run(['sudo', 'iptables-save', '>', '/tmp/iptables.backup'], shell=True)
        
        lab_network = get_user_input("Enter lab network CIDR", default="192.168.1.0/24")
        
        rules = [
            f"sudo iptables -A OUTPUT -d {lab_network} -j ACCEPT",
            "sudo iptables -A OUTPUT -d 127.0.0.1 -j ACCEPT",
            "sudo iptables -A OUTPUT -o lo -j ACCEPT",
            "sudo iptables -A OUTPUT -j LOG --log-prefix='BLOCKED: '",
            "sudo iptables -A OUTPUT -j DROP"
        ]
        
        console.print("[bold cyan]Applying iptables rules:[/bold cyan]")
        for rule in rules:
            console.print(f"[bold white]{rule}[/bold white]")
            subprocess.run(rule.split())
            
        Success("Iptables rules applied successfully!")
        
        console.print("\n[bold green]To restore original rules:[/bold green]")
        console.print("sudo iptables-restore < /tmp/iptables.backup")
        
        Continue()
        
    def show_vm_isolation_guide(self):
        """Show VM isolation best practices"""
        Title("Virtual Machine Isolation Guide")
        
        console.print("[bold cyan]VMware/VirtualBox Isolation:[/bold cyan]")
        console.print("• Use Host-Only networking for complete isolation")
        console.print("• Create internal networks for multi-VM labs")
        console.print("• Disable shared folders and clipboard")
        console.print("• Use NAT with port forwarding for controlled internet access")
        
        console.print("\n[bold cyan]Network Configuration:[/bold cyan]")
        console.print("• Host-Only: VMs can only communicate with host")
        console.print("• Internal: VMs can only communicate with each other")
        console.print("• NAT: Outbound internet access only")
        console.print("• Bridged: Full network access (use with caution)")
        
        console.print("\n[bold cyan]Security Best Practices:[/bold cyan]")
        console.print("• Regular VM snapshots before testing")
        console.print("• Disable unnecessary services in VMs")
        console.print("• Use separate VMs for different test scenarios")
        console.print("• Monitor and log all VM network traffic")
        
        Continue()
        
    def network_monitoring(self):
        """Setup network traffic monitoring"""
        console.print("[bold cyan]Network Traffic Monitoring[/bold cyan]\n")
        
        console.print("1. Start packet capture with tcpdump")
        console.print("2. Monitor with Wireshark")
        console.print("3. Setup network logging")
        console.print("4. View current connections")
        console.print("5. Back to main menu")
        
        choice = get_user_input("Select monitoring option (1-5)", choices=["1", "2", "3", "4", "5"])
        
        if choice == "1":
            interface = get_user_input("Enter network interface", default="eth0")
            console.print(f"[bold cyan]Starting tcpdump on {interface}...[/bold cyan]")
            console.print(f"[bold white]Command:[/bold white] sudo tcpdump -i {interface} -w /tmp/capture.pcap")
            console.print("[bold yellow]Press Ctrl+C to stop capture[/bold yellow]")
            
        elif choice == "2":
            console.print("[bold cyan]Starting Wireshark...[/bold cyan]")
            console.print("[bold white]Command:[/bold white] sudo wireshark")
            
        elif choice == "3":
            console.print("[bold cyan]Network logging setup:[/bold cyan]")
            console.print("• Enable iptables logging: iptables -A INPUT -j LOG")
            console.print("• Monitor logs: tail -f /var/log/kern.log")
            console.print("• Setup rsyslog for network events")
            
        elif choice == "4":
            console.print("[bold cyan]Current network connections:[/bold cyan]")
            subprocess.run(['netstat', '-tuln'])
            
        Continue()
        
    def status_check(self):
        """Check current privacy protection status"""
        banner("Privacy Protection Status")
        
        # Check current IP
        current_ip = self.check_current_ip()
        if current_ip:
            console.print(f"[bold cyan]Current IP Address:[/bold cyan] {current_ip}")
            if self.original_ip and current_ip != self.original_ip:
                Success("IP address has changed from original")
            else:
            Warning("IP address appears to be unchanged")
        else:
            Warning("Could not determine current IP address")
            
        # Check VPN status
        console.print(f"[bold cyan]VPN Status:[/bold cyan] {'✓ Connected' if self.vpn_status else '✗ Not Connected'}")
        
        # Check Tor status
        tor_active = self.check_tor_status()
        console.print(f"[bold cyan]Tor Status:[/bold cyan] {'✓ Active' if tor_active else '✗ Not Active'}")
        
        # Network interface info
        console.print("\n[bold cyan]Network Interfaces:[/bold cyan]")
        subprocess.run(['ip', 'addr', 'show'])
        
        Continue()
        
def run():
    """Main privacy protection module"""
    privacy = PrivacyProtection()
    
    # Store original IP on first run
    privacy.original_ip = privacy.check_current_ip()
    
    while True:
        clear()
        banner("Privacy Protection & Lab Security")
        
        console.print("[bold yellow]⚠️  Lab Environment Security Module ⚠️[/bold yellow]")
        console.print("Protect your cybersecurity research and testing activities\n")
        
        menu_options = [
            ("1", "🌐", "VPN Configuration", "Setup VPN for external traffic"),
            ("2", "🧅", "Tor Network Setup", "Anonymous browsing via Tor"),
            ("3", "🔒", "Network Isolation", "Isolate lab environment"),
            ("4", "📊", "Status Check", "View current protection status"),
            ("5", "📋", "Privacy Guidelines", "Best practices for lab security"),
            ("6", "🔙", "Back to Main Menu", "Return to SPARM main menu")
        ]
        
        for choice, icon, name, description in menu_options:
            console.print(f"[bold cyan]{choice}.[/bold cyan] {icon} [bold white]{name}[/bold white]")
            console.print(f"   [dim]{description}[/dim]\n")
            
        choice = get_user_input("Select option (1-6)", choices=["1", "2", "3", "4", "5", "6"])
        
        if choice == "1":
            privacy.configure_vpn()
        elif choice == "2":
            privacy.setup_tor()
        elif choice == "3":
            privacy.network_isolation_setup()
        elif choice == "4":
            privacy.status_check()
        elif choice == "5":
            show_privacy_guidelines()
        elif choice == "6":
            break
            
def show_privacy_guidelines():
    """Show privacy and security guidelines"""
    Title("Privacy & Security Guidelines")
    
    console.print("[bold cyan]Lab Environment Security:[/bold cyan]")
    console.print("• Always use VPN for external reconnaissance")
    console.print("• Keep lab networks isolated from production")
    console.print("• Regular VM snapshots before testing")
    console.print("• Monitor and log all network activities")
    console.print("• Use different IP addresses for different test phases")
    
    console.print("\n[bold cyan]Legal and Ethical Considerations:[/bold cyan]")
    console.print("• Only test systems you own or have permission to test")
    console.print("• Follow responsible disclosure for any findings")
    console.print("• Maintain detailed logs for compliance")
    console.print("• Respect privacy and data protection laws")
    console.print("• Use tools only for educational purposes")
    
    console.print("\n[bold cyan]Technical Security:[/bold cyan]")
    console.print("• Encrypt all traffic between attacker and target machines")
    console.print("• Use secure communication channels (HTTPS, SSH)")
    console.print("• Implement proper access controls on lab systems")
    console.print("• Regular security updates on all systems")
    console.print("• Secure storage of any captured credentials or data")
    
    Continue()

if __name__ == "__main__":
    run()