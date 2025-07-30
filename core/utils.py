#!/usr/bin/env python3

import os
import sys
import time
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import print as rprint

console = Console()

def clear():
    """Clear terminal screen"""
    os.system('clear' if os.name == 'posix' else 'cls')

def ascii_art(text):
    """Display compact ASCII art banner"""
    art = """
┌─────────────────────────────────────────────────────────┐
│  ███████╗██████╗  █████╗ ██████╗ ███╗   ███╗             │
│  ██╔════╝██╔══██╗██╔══██╗██╔══██╗████╗ ████║             │
│  ███████╗██████╔╝███████║██████╔╝██╔████╔██║             │
│  ╚════██║██╔═══╝ ██╔══██║██╔══██╗██║╚██╔╝██║             │
│  ███████║██║     ██║  ██║██║  ██║██║ ╚═╝ ██║             │
│  ╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝             │
│                                                         │
│     [bold red]S[/bold red]ecurity [bold red]P[/bold red]enetration & [bold red]A[/bold red]ttack [bold red]R[/bold red]esearch [bold red]M[/bold red]ultitool     │
│                    [dim]v2.0.0 - Educational Use Only[/dim]           │
└─────────────────────────────────────────────────────────┘
    """
    console.print(art, style="bold cyan")

def Title(title):
    """Display formatted title"""
    console.print(Panel(title, style="bold green", padding=(1, 2)))

def banner(text):
    """Display banner with text"""
    console.print(Panel(f"[bold cyan]{text}[/bold cyan]", padding=(1, 2)))

def Success(message):
    """Display success message"""
    console.print(f"[bold green]✓[/bold green] {message}")

def Warning(message):
    """Display warning message"""
    console.print(f"[bold yellow]⚠[/bold yellow] {message}")

def ErrorModule(error):
    """Display error message and exit"""
    console.print(f"[bold red]✗ Error:[/bold red] {error}")
    sys.exit(1)

def info(message):
    """Display info message"""
    console.print(f"[bold blue]ℹ[/bold blue] {message}")

def Continue():
    """Wait for user input to continue"""
    Confirm.ask("\n[bold cyan]Press Enter to continue[/bold cyan]", default=True, show_default=False)

def get_user_input(prompt_text, choices=None):
    """Get user input with validation"""
    if choices:
        return Prompt.ask(prompt_text, choices=choices)
    return Prompt.ask(prompt_text)

def display_tools_table(category, tools):
    """Display tools in a formatted table"""
    table = Table(title=f"{category} Tools")
    table.add_column("ID", style="cyan", width=6)
    table.add_column("Tool", style="green", width=20)
    table.add_column("Description", style="white")
    
    for i, (tool_name, description) in enumerate(tools.items(), 1):
        table.add_row(str(i), tool_name, description)
    
    console.print(table)

def show_next_steps(current_phase, suggestions):
    """Display next step suggestions"""
    console.print("\n[bold cyan]🎯 Suggested Next Steps:[/bold cyan]")
    for i, suggestion in enumerate(suggestions, 1):
        console.print(f"  {i}. {suggestion}")
    console.print()

def compact_menu_header():
    """Display compact menu header with system info"""
    import platform
    import datetime
    
    current_time = datetime.datetime.now().strftime("%H:%M:%S")
    
    header = f"""
[bold cyan]┌─[/bold cyan] [bold white]SPARM v2.0[/bold white] [bold cyan]─[/bold cyan] [bold green]{platform.node()}[/bold green] [bold cyan]─[/bold cyan] [bold yellow]{current_time}[/bold yellow] [bold cyan]─┐[/bold cyan]
[bold cyan]│[/bold cyan] [bold red]Security Penetration & Attack Research Multitool[/bold red] [bold cyan]│[/bold cyan]
[bold cyan]└─────────────────────────────────────────────────────┘[/bold cyan]
    """
    console.print(header)

def display_compact_menu_item(number, icon, name, description, color="cyan"):
    """Display a compact menu item"""
    console.print(f"[bold {color}]┌─[[/bold {color}][bold white]{number:02d}[/bold white][bold {color}]][/bold {color}] {icon} [bold white]{name}[/bold white]")
    console.print(f"[bold {color}]└──[/bold {color}] [dim]{description}[/dim]")

def display_three_row_menu(menu_items):
    """Display menu items in three rows"""
    rows = [[], [], []]
    
    # Distribute items across three rows
    for i, item in enumerate(menu_items):
        rows[i % 3].append(item)
    
    # Display each row
    for row_index, row in enumerate(rows):
        if row:  # Only display if row has items
            console.print(f"\n[bold cyan]Row {row_index + 1}:[/bold cyan]")
            for choice, icon, name, description, color in row:
                console.print(f"  [bold {color}][{choice}][/bold {color}] {icon} [bold white]{name}[/bold white] - [dim]{description}[/dim]")

def status_line(level, status):
    """Display compact status line"""
    level_colors = {
        "beginner": "green",
        "intermediate": "yellow", 
        "advanced": "red"
    }
    color = level_colors.get(level, "cyan")
    console.print(f"[bold {color}]▸[/bold {color}] Level: [bold white]{level.title()}[/bold white] [bold cyan]|[/bold cyan] Status: [bold green]{status}[/bold green]")

def separator():
    """Display a visual separator"""
    console.print("[dim cyan]" + "─" * 60 + "[/dim cyan]")

def check_tool_installed(tool_name):
    """Check if a tool is installed and accessible"""
    import shutil
    return shutil.which(tool_name) is not None

def safe_subprocess_run(command, timeout=300, show_output=True):
    """Safely run subprocess with proper error handling"""
    import subprocess
    try:
        if isinstance(command, str):
            command = command.split()
        
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            timeout=timeout,
            check=False
        )
        
        if show_output:
            if result.stdout:
                console.print("\n[bold green]Results:[/bold green]")
                console.print(result.stdout)
            if result.stderr:
                Warning(f"Errors: {result.stderr}")
        
        return result.returncode == 0, result.stdout, result.stderr
        
    except subprocess.TimeoutExpired:
        Warning(f"Command timed out after {timeout} seconds")
        return False, "", "Timeout"
    except FileNotFoundError:
        Warning(f"Command not found: {command[0] if command else 'Unknown'}")
        return False, "", "Command not found"
    except Exception as e:
        Warning(f"Error executing command: {e}")
        return False, "", str(e)

def validate_ip(ip_address):
    """Validate IP address format"""
    import ipaddress
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

def validate_domain(domain):
    """Validate domain name format"""
    import re
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return re.match(pattern, domain) is not None

def get_target_input(prompt="Enter target", allow_ip=True, allow_domain=True):
    """Get and validate target input (IP or domain)"""
    while True:
        target = get_user_input(prompt)
        
        if allow_ip and validate_ip(target):
            return target
        elif allow_domain and validate_domain(target):
            return target
        else:
            valid_types = []
            if allow_ip:
                valid_types.append("IP address")
            if allow_domain:
                valid_types.append("domain name")
            Warning(f"Invalid target. Please enter a valid {' or '.join(valid_types)}")

def format_command_output(command, success, stdout, stderr):
    """Format command output consistently"""
    console.print(f"\n[bold yellow]Command:[/bold yellow] {' '.join(command) if isinstance(command, list) else command}")
    
    if success:
        console.print("[bold green]✓ Command executed successfully[/bold green]")
        if stdout:
            console.print("\n[bold green]Output:[/bold green]")
            console.print(stdout)
    else:
        console.print("[bold red]✗ Command failed[/bold red]")
        if stderr:
            console.print(f"\n[bold red]Error:[/bold red] {stderr}")